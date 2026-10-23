package transport

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
)

// MaxDatagram is the largest UDP payload in bytes. A received datagram above it
// is dropped, and Unicast and Multicast refuse to send one.
const MaxDatagram = 1200

var (
	errDatagramTooLarge = errors.New("transport: datagram exceeds MaxDatagram")
	errNeedZone         = errors.New("transport: link-local destination needs a zone (interface)")
	errNoSocket         = errors.New("transport: no socket for that destination")
)

// endpoint is one bound UDP socket.
type endpoint struct {
	conn      *net.UDPConn
	addr      netip.Addr // the bound address; carries the zone for link-local and group sockets
	iface     string
	ifindex   int  // the kernel's index of iface when the socket was bound
	group     bool // bound to the discovery group: receives multicast
	linkLocal bool // IPv6 link-local unicast: multicast leaves from here
	pinned    bool // SO_BINDTODEVICE was accepted
}

// Multicast sends b to ff02::114 on each interface that has an IPv6 link-local
// address, and skips the others. It returns ErrNoLinkLocal when no interface
// has one, and the joined errors when a send fails.
func (t *Transport) Multicast(b []byte) error {
	if len(b) > MaxDatagram {
		return errDatagramTooLarge
	}
	var errs []error
	sent := 0
	seen := make(map[string]bool)
	for _, ep := range t.unicastEndpoints() {
		if !ep.linkLocal || seen[ep.iface] {
			continue
		}
		seen[ep.iface] = true
		dst := netip.AddrPortFrom(group.WithZone(ep.iface), uint16(t.port))
		if _, err := ep.conn.WriteToUDPAddrPort(b, dst); err != nil {
			errs = append(errs, fmt.Errorf("transport: multicast on %s: %w", ep.iface, err))
			continue
		}
		sent++
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	if sent == 0 {
		return ErrNoLinkLocal
	}
	return nil
}

// Unicast sends b to to, from a socket of the same address family, on the zone
// of to when it has one.
func (t *Transport) Unicast(to netip.AddrPort, b []byte) error {
	if len(b) > MaxDatagram {
		return errDatagramTooLarge
	}
	to = netip.AddrPortFrom(to.Addr().Unmap(), to.Port())
	ep, err := t.sender(to.Addr())
	if err != nil {
		return err
	}
	_, err = ep.conn.WriteToUDPAddrPort(b, to)
	return err
}

// unicastEndpoints is a copy of the UDP sockets held now, for a send. A
// socket a pass closes after the copy fails that one send.
func (t *Transport) unicastEndpoints() []*endpoint {
	t.mu.Lock()
	defer t.mu.Unlock()
	return slices.Clone(t.endpoints)
}

// readLoop passes each datagram to onPacket until ep is closed, by Close or
// by a pass that no longer wants it. Each read spends the read budget, and
// waits when it is spent; the datagram then goes on only if the limiter
// admits it (limiter.go): at most MaxDatagram bytes, within its source's rate
// and the rate of all sources. The buffer is one byte longer than the limit,
// so a larger datagram shows up as one.
func (t *Transport) readLoop(ep *endpoint, onPacket func(netip.AddrPort, []byte)) {
	defer t.wg.Done()
	buf := make([]byte, MaxDatagram+1)
	for {
		n, from, err := ep.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) || !t.pause() {
				return
			}
			continue
		}
		if d := t.lim.pace(); d > 0 && !t.wait(d) {
			return
		}
		if !t.lim.admit(from.Addr(), n) {
			continue
		}
		onPacket(from, append([]byte(nil), buf[:n]...))
	}
}
