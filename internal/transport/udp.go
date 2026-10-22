package transport

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
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
	group     bool // bound to the discovery group: receives multicast
	linkLocal bool // IPv6 link-local unicast: multicast leaves from here
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
	for _, ep := range t.endpoints {
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

// sender picks the socket a datagram to dst leaves from. A link-local
// destination needs a link-local source on its zone. Any other destination
// prefers a global source and falls back to a link-local one.
func (t *Transport) sender(dst netip.Addr) (*endpoint, error) {
	ll := isLinkLocal(dst)
	if ll && dst.Zone() == "" {
		return nil, errNeedZone
	}
	var fallback *endpoint
	for _, ep := range t.endpoints {
		if ep.group || ep.addr.Is4() != dst.Is4() {
			continue
		}
		if z := dst.Zone(); z != "" && ep.iface != z {
			continue
		}
		if ep.linkLocal == ll {
			return ep, nil
		}
		if !ll && fallback == nil {
			fallback = ep
		}
	}
	if fallback != nil {
		return fallback, nil
	}
	return nil, errNoSocket
}

// readLoop passes each datagram to onPacket. A datagram larger than MaxDatagram
// is dropped whole; the buffer is one byte longer than the limit, so a larger
// datagram shows up as one.
func (t *Transport) readLoop(ep *endpoint, onPacket func(netip.AddrPort, []byte)) {
	defer t.wg.Done()
	buf := make([]byte, MaxDatagram+1)
	for {
		n, from, err := ep.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if !t.pause() {
				return
			}
			continue
		}
		if n > MaxDatagram {
			continue
		}
		onPacket(from, append([]byte(nil), buf[:n]...))
	}
}
