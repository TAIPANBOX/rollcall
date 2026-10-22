// Package transport moves rollcall's messages between members. It knows no
// keys: it passes packets and frames to the caller untouched. The only check it
// makes on the bytes is the one the caller hands it at ListenPeers, which
// decides whether the first frame of a TCP connection is answered.
//
// UDP carries heartbeats: multicast to ff02::114 on each interface that has an
// IPv6 link-local address, and unicast to known peers. TCP carries the larger
// messages as one request frame and one reply frame per connection.
package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"
)

// DefaultPort is the UDP and TCP port rollcall listens on. Port 7431 is
// assigned to pmd (docs/notes/registry-check.md).
const DefaultPort = 7432

// retryDelay is the pause after a transient accept or read error.
const retryDelay = 50 * time.Millisecond

var (
	errNoAuthenticate = errors.New("transport: authenticate is required")
	errNoInterfaces   = errors.New("transport: no interfaces given")
	errNoAddress      = errors.New("transport: no address to listen on")
	errNilCallback    = errors.New("transport: Serve needs onPacket and onStream")
	errServing        = errors.New("transport: Serve already running")
	errClosed         = errors.New("transport: closed")
)

// Transport holds the sockets of the configured peer zones. Its methods are
// safe for concurrent use. Serve runs the receive loops; Close releases the
// sockets.
type Transport struct {
	port         int
	authenticate func(frame []byte) bool
	endpoints    []*endpoint // UDP sockets: unicast addresses and group sockets
	listeners    []*net.TCPListener
	slots        chan struct{} // one token per open TCP connection
	devSockets   int           // sockets for which SO_BINDTODEVICE was tried
	devFailed    int           // of those, the sockets the kernel did not pin

	done      chan struct{} // closed by Close
	closeOnce sync.Once
	wg        sync.WaitGroup // receive loops and connection handlers

	mu      sync.Mutex
	serving bool
	conns   map[net.Conn]struct{}
}

// ListenPeers binds the sockets for the given interfaces on port: a UDP socket
// and a TCP listener on each address of each interface, and for an interface
// with an IPv6 link-local address, a UDP socket joined to ff02::114. An
// interface without a link-local address still gets its unicast sockets, so
// static peers work there; Discovery reports it.
//
// authenticate decides whether the first frame of a TCP connection is answered.
// A frame that fails it closes the connection without a reply.
func ListenPeers(port int, ifaces []string, authenticate func(frame []byte) bool) (*Transport, error) {
	if authenticate == nil {
		return nil, errNoAuthenticate
	}
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("transport: port %d out of range", port)
	}
	if len(ifaces) == 0 {
		return nil, errNoInterfaces
	}
	t := &Transport{
		port:         port,
		authenticate: authenticate,
		slots:        make(chan struct{}, MaxConns),
		done:         make(chan struct{}),
		conns:        make(map[net.Conn]struct{}),
	}
	seen := make(map[string]bool, len(ifaces))
	for _, name := range ifaces {
		if seen[name] {
			continue
		}
		seen[name] = true
		if err := t.listenIface(name); err != nil {
			t.Close()
			return nil, err
		}
	}
	if len(t.endpoints) == 0 && len(t.listeners) == 0 {
		t.Close()
		return nil, errNoAddress
	}
	return t, nil
}

// BoundToDevice reports whether every socket was pinned to its interface with
// SO_BINDTODEVICE. It is always false off Linux, and on Linux when the kernel
// refuses the pin to an unprivileged process. The sockets stay bound to their
// interface's addresses either way.
func (t *Transport) BoundToDevice() bool {
	return t.devSockets > 0 && t.devFailed == 0
}

// noteBind records the outcome of the SO_BINDTODEVICE attempt for one socket.
func (t *Transport) noteBind(pinned bool) {
	t.devSockets++
	if !pinned {
		t.devFailed++
	}
}

// Serve runs the receive loops until ctx is done, then closes the transport and
// returns nil. onPacket gets each UDP datagram of at most MaxDatagram bytes;
// larger datagrams are dropped. onStream gets each authenticated TCP frame and
// returns the reply frame, where nil is an empty reply.
//
// The callbacks run on the goroutine of the socket that received the bytes, so
// they can run at the same time as each other. Serve runs once.
func (t *Transport) Serve(ctx context.Context, onPacket func(from netip.AddrPort, b []byte), onStream func(from netip.AddrPort, b []byte) []byte) error {
	if onPacket == nil || onStream == nil {
		return errNilCallback
	}
	t.mu.Lock()
	if t.serving {
		t.mu.Unlock()
		return errServing
	}
	t.serving = true
	t.mu.Unlock()
	select {
	case <-t.done:
		return errClosed
	default:
	}

	for _, ep := range t.endpoints {
		t.wg.Add(1)
		go t.readLoop(ep, onPacket)
	}
	for _, ln := range t.listeners {
		t.wg.Add(1)
		go t.acceptLoop(ln, onStream)
	}
	<-ctx.Done()
	t.Close()
	t.wg.Wait()
	return nil
}

// Close stops the receive loops, closes every socket and open connection, and
// makes further sends fail. It is safe to call more than once.
func (t *Transport) Close() error {
	var first error
	t.closeOnce.Do(func() {
		close(t.done)
		for _, ep := range t.endpoints {
			if err := ep.conn.Close(); err != nil && first == nil {
				first = err
			}
		}
		for _, ln := range t.listeners {
			if err := ln.Close(); err != nil && first == nil {
				first = err
			}
		}
		t.mu.Lock()
		for c := range t.conns {
			c.Close()
		}
		t.mu.Unlock()
	})
	return first
}

// pause waits after a transient error. It reports false once the transport is
// closed, which is the signal for a loop to return.
func (t *Transport) pause() bool {
	select {
	case <-t.done:
		return false
	case <-time.After(retryDelay):
		return true
	}
}

// track records an open connection so Close can shut it. It refuses one that
// arrives after Close has begun.
func (t *Transport) track(c net.Conn) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	select {
	case <-t.done:
		return false
	default:
	}
	t.conns[c] = struct{}{}
	return true
}

func (t *Transport) untrack(c net.Conn) {
	t.mu.Lock()
	delete(t.conns, c)
	t.mu.Unlock()
}

// boundAddrs lists every address the transport listens on, for tests.
func (t *Transport) boundAddrs() []netip.AddrPort {
	var out []netip.AddrPort
	for _, ep := range t.endpoints {
		out = append(out, netip.AddrPortFrom(ep.addr, uint16(t.port)))
	}
	for _, ln := range t.listeners {
		out = append(out, ln.Addr().(*net.TCPAddr).AddrPort())
	}
	return out
}
