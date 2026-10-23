// Package transport moves rollcall's messages between members. It knows no
// keys: it passes packets and frames to the caller untouched. The only check it
// makes on the bytes is the one the caller hands it at Open, which decides
// whether the first frame of a TCP connection is answered.
//
// UDP carries heartbeats: multicast to ff02::114 on each interface that has an
// IPv6 link-local address, and unicast to known peers. TCP carries the larger
// messages as one request frame and one reply frame per connection.
//
// The sockets follow the peer-zone devices as they are now, not as they were
// at the start: a pass over the devices binds what appeared, closes what left,
// and binds again what the kernel recreated under a new index. It runs every
// ReconcileEvery and at once on Refresh. A device or an address that cannot be
// bound is reported by Devices and tried again on the next pass; it stops
// nothing else.
package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"
)

// DefaultPort is the UDP and TCP port rollcall listens on. Port 7431 is
// assigned to pmd (docs/notes/registry-check.md).
const DefaultPort = 7432

// ReconcileEvery spaces the passes over the peer-zone devices that no event
// asks for. Hotplug reports ifup and ifdown (Refresh), but not the end of
// IPv6 duplicate address detection, a renumbered prefix, or a device that
// "network restart" recreated before its event; one pass per heartbeat
// interval (5 s) costs those at most one or two of the six heartbeats a peer
// may miss before it is silent, and a pass is two netlink dumps per device.
const ReconcileEvery = 5 * time.Second

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

// DeviceStatus is what the transport holds on one peer-zone device after the
// latest pass.
type DeviceStatus struct {
	Index int          // the kernel's index of the device; 0 while it does not exist
	Addrs []netip.Addr // the addresses with a UDP socket and a TCP listener
	Group bool         // a socket joined to ff02::114 there
	Err   error        // why the device, or one of its addresses, is not bound; nil when nothing is missing
}

// Transport holds the sockets of the configured peer zones. Its methods are
// safe for concurrent use. Serve runs the receive loops and the passes over
// the devices; Close releases the sockets.
type Transport struct {
	port         int
	authenticate func(frame []byte) bool
	devices      []string      // the configured peer-zone devices, once each, in order
	every        time.Duration // between passes; ReconcileEvery outside tests
	slots        chan struct{} // one token per open TCP connection
	kick         chan struct{} // Refresh: a pass now
	done         chan struct{} // closed by Close
	closeOnce    sync.Once
	wg           sync.WaitGroup // receive loops, connection handlers and the pass loop

	mu        sync.Mutex
	closed    bool
	serving   bool
	onPacket  func(netip.AddrPort, []byte)
	onStream  func(netip.AddrPort, []byte) []byte
	endpoints []*endpoint // UDP sockets: unicast addresses and group sockets
	listeners []*listener
	devs      map[string]DeviceStatus
	conns     map[net.Conn]struct{}
}

// Open makes a transport for the given peer-zone devices on port and binds
// what they carry now: a UDP socket and a TCP listener on each address, and
// for a device with an IPv6 link-local address, a UDP socket joined to
// ff02::114. A device without a link-local address still gets its unicast
// sockets, so static peers work there; Discovery reports it.
//
// Nothing outside ifaces is ever bound. A device that does not exist yet, or
// an address the kernel refuses (still tentative, or dadfailed), is reported
// by Devices and tried again on every pass; Open fails only on arguments no
// pass can fix.
//
// authenticate decides whether the first frame of a TCP connection is answered.
// A frame that fails it closes the connection without a reply.
func Open(port int, ifaces []string, authenticate func(frame []byte) bool) (*Transport, error) {
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
		every:        ReconcileEvery,
		slots:        make(chan struct{}, MaxConns),
		kick:         make(chan struct{}, 1),
		done:         make(chan struct{}),
		conns:        make(map[net.Conn]struct{}),
	}
	for _, name := range ifaces {
		if !slices.Contains(t.devices, name) {
			t.devices = append(t.devices, name)
		}
	}
	t.reconcile()
	return t, nil
}

// ListenPeers is Open that binds all or nothing: it fails when a device does
// not exist or one of its addresses cannot be bound, and when no device has
// an address at all.
func ListenPeers(port int, ifaces []string, authenticate func(frame []byte) bool) (*Transport, error) {
	t, err := Open(port, ifaces, authenticate)
	if err != nil {
		return nil, err
	}
	for _, name := range t.devices {
		if err := t.devs[name].Err; err != nil && !errors.Is(err, errNoAddress) {
			t.Close()
			return nil, err
		}
	}
	if len(t.boundAddrs()) == 0 {
		t.Close()
		return nil, errNoAddress
	}
	return t, nil
}

// Refresh asks for a pass over the devices now, for an interface event. It
// does not wait for the pass, and passes asked for while one is pending are
// one pass.
func (t *Transport) Refresh() {
	select {
	case t.kick <- struct{}{}:
	default:
	}
}

// Devices reports, for each configured device, what the latest pass bound
// there and what it could not.
func (t *Transport) Devices() map[string]DeviceStatus {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make(map[string]DeviceStatus, len(t.devs))
	for name, st := range t.devs {
		st.Addrs = slices.Clone(st.Addrs)
		out[name] = st
	}
	return out
}

// BoundToDevice reports whether every socket held now was pinned to its
// interface with SO_BINDTODEVICE. It is always false off Linux, and on Linux
// when the kernel refuses the pin to an unprivileged process. The sockets stay
// bound to their interface's addresses either way.
func (t *Transport) BoundToDevice() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := 0
	for _, ep := range t.endpoints {
		if !ep.pinned {
			return false
		}
		n++
	}
	for _, l := range t.listeners {
		if !l.pinned {
			return false
		}
		n++
	}
	return n > 0
}

// Serve runs the receive loops and the passes over the devices until ctx is
// done, then closes the transport and returns nil. onPacket gets each UDP
// datagram of at most MaxDatagram bytes; larger datagrams are dropped.
// onStream gets each authenticated TCP frame and returns the reply frame,
// where nil is an empty reply.
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
	if t.closed {
		t.mu.Unlock()
		return errClosed
	}
	t.onPacket, t.onStream = onPacket, onStream
	for _, ep := range t.endpoints {
		t.startReadLocked(ep)
	}
	for _, l := range t.listeners {
		t.startAcceptLocked(l)
	}
	t.wg.Add(1)
	go t.passes()
	t.mu.Unlock()

	<-ctx.Done()
	t.Close()
	t.wg.Wait()
	return nil
}

// passes runs a pass over the devices every t.every and on each Refresh,
// until the transport closes.
func (t *Transport) passes() {
	defer t.wg.Done()
	tick := time.NewTicker(t.every)
	defer tick.Stop()
	for {
		select {
		case <-t.done:
			return
		case <-tick.C:
		case <-t.kick:
		}
		t.reconcile()
	}
}

// Close stops the receive loops, closes every socket and open connection, and
// makes further sends fail. It is safe to call more than once.
func (t *Transport) Close() error {
	var first error
	t.closeOnce.Do(func() {
		t.mu.Lock()
		defer t.mu.Unlock()
		t.closed = true
		close(t.done)
		for _, ep := range t.endpoints {
			if err := ep.conn.Close(); err != nil && first == nil {
				first = err
			}
		}
		for _, l := range t.listeners {
			if err := l.ln.Close(); err != nil && first == nil {
				first = err
			}
		}
		t.endpoints, t.listeners = nil, nil
		for c := range t.conns {
			c.Close()
		}
	})
	return first
}

// startReadLocked runs the read loop of ep once Serve has begun. t.mu is held.
func (t *Transport) startReadLocked(ep *endpoint) {
	if !t.serving || t.closed {
		return
	}
	t.wg.Add(1)
	go t.readLoop(ep, t.onPacket)
}

// startAcceptLocked runs the accept loop of l once Serve has begun. t.mu is held.
func (t *Transport) startAcceptLocked(l *listener) {
	if !t.serving || t.closed {
		return
	}
	t.wg.Add(1)
	go t.acceptLoop(l.ln, t.onStream)
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
	if t.closed {
		return false
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
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []netip.AddrPort
	for _, ep := range t.endpoints {
		out = append(out, netip.AddrPortFrom(ep.addr, uint16(t.port)))
	}
	for _, l := range t.listeners {
		out = append(out, l.ln.Addr().(*net.TCPAddr).AddrPort())
	}
	return out
}

// sockRef identifies one held socket, for tests.
type sockRef struct {
	ifindex int
	conn    any // the *net.UDPConn or *net.TCPListener itself
}

// sockets lists the sockets held now, for tests.
func (t *Transport) sockets() []sockRef {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []sockRef
	for _, ep := range t.endpoints {
		out = append(out, sockRef{ep.ifindex, ep.conn})
	}
	for _, l := range t.listeners {
		out = append(out, sockRef{l.key.ifindex, l.ln})
	}
	return out
}
