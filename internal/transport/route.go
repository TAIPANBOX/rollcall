package transport

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"syscall"
)

// route is the kernel's routing decision for one destination.
type route struct {
	ifindex int        // the interface a datagram to the destination leaves through
	src     netip.Addr // the source address the kernel would pick; invalid when it names none
}

// lookupRoute asks the kernel how it routes dst (route_linux.go,
// route_other.go). Tests replace it.
var lookupRoute = kernelRoute

// sender picks the socket a datagram to dst leaves from.
//
// A link-local destination, or one that names a zone, needs a socket on that
// zone. Any other destination gets a socket on the interface the kernel routes
// it through, the one bound to the source address the kernel picks when there
// is one: with peer zones on br-lan and wan, a static peer behind wan must not
// get its datagrams from the br-lan socket, which SO_BINDTODEVICE would send
// out of br-lan. A route through a device of no peer zone has no socket, and
// nothing is sent. Only when the kernel cannot be asked is the socket chosen
// by address family alone, preferring a global source.
func (t *Transport) sender(dst netip.Addr) (*endpoint, error) {
	ll := isLinkLocal(dst)
	zone := dst.Zone()
	if ll && zone == "" {
		return nil, errNeedZone
	}
	eps := t.unicastEndpoints()
	if zone != "" {
		return pick(eps, dst, func(ep *endpoint) bool { return ep.iface == zone }, netip.Addr{})
	}
	r, err := lookupRoute(dst)
	if err != nil {
		return pick(eps, dst, nil, netip.Addr{})
	}
	ep, err := pick(eps, dst, func(ep *endpoint) bool { return ep.ifindex == r.ifindex }, r.src)
	if err != nil {
		return nil, fmt.Errorf("%w: the route to %s leaves through interface %d, where no peer zone has a socket", err, dst, r.ifindex)
	}
	return ep, nil
}

// pick chooses among the unicast sockets of dst's address family that on
// accepts (all when on is nil): the one bound to src when src is valid; else,
// for a link-local dst, a link-local socket, and for any other dst a global
// socket, then a link-local one.
func pick(eps []*endpoint, dst netip.Addr, on func(*endpoint) bool, src netip.Addr) (*endpoint, error) {
	ll := isLinkLocal(dst)
	src = src.WithZone("")
	var match, fallback *endpoint
	for _, ep := range eps {
		if ep.group || ep.addr.Is4() != dst.Is4() || (on != nil && !on(ep)) {
			continue
		}
		if src.IsValid() && ep.addr.WithZone("") == src {
			return ep, nil
		}
		switch {
		case ep.linkLocal == ll:
			if match == nil {
				match = ep
			}
		case !ll && fallback == nil:
			fallback = ep
		}
	}
	if match != nil {
		return match, nil
	}
	if fallback != nil {
		return fallback, nil
	}
	return nil, errNoSocket
}

// The rtnetlink values a route lookup needs (linux/netlink.h,
// linux/rtnetlink.h, linux/socket.h). They are written out so the codec
// builds and is tested on every system; only route_linux.go sends it.
const (
	nlmsgHdrLen  = 16
	rtmsgLen     = 12
	nlmsgError   = 2
	rtmNewRoute  = 24
	rtmGetRoute  = 26
	nlmFRequest  = 1
	rtaDst       = 1
	rtaOif       = 4
	rtaPrefsrc   = 7
	linuxAFInet  = 2
	linuxAFInet6 = 10
)

var errRouteReply = errors.New("transport: malformed route reply")

func align4(n int) int { return (n + 3) &^ 3 }

// routeRequest is the RTM_GETROUTE request "ip route get dst" sends: a
// question, so the kernel answers it without any privilege. Netlink is in
// host byte order.
func routeRequest(seq uint32, dst netip.Addr) []byte {
	a := dst.WithZone("").AsSlice()
	attrLen := 4 + len(a)
	total := nlmsgHdrLen + rtmsgLen + align4(attrLen)
	b := make([]byte, total)
	ne := binary.NativeEndian
	ne.PutUint32(b[0:], uint32(total))
	ne.PutUint16(b[4:], rtmGetRoute)
	ne.PutUint16(b[6:], nlmFRequest)
	ne.PutUint32(b[8:], seq)
	r := b[nlmsgHdrLen:]
	r[0] = linuxAFInet6
	if dst.Is4() {
		r[0] = linuxAFInet
	}
	r[1] = byte(8 * len(a)) // rtm_dst_len: the whole address
	at := r[rtmsgLen:]
	ne.PutUint16(at[0:], uint16(attrLen))
	ne.PutUint16(at[2:], rtaDst)
	copy(at[4:], a)
	return b
}

// parseRouteReply reads the kernel's answer to routeRequest(seq, ...): the
// interface the route leaves through and the source address it prefers. A
// refusal (no route, unreachable) is the kernel's errno.
func parseRouteReply(b []byte, seq uint32) (route, error) {
	ne := binary.NativeEndian
	for len(b) >= nlmsgHdrLen {
		l := int(ne.Uint32(b[0:]))
		if l < nlmsgHdrLen || l > len(b) {
			return route{}, errRouteReply
		}
		typ, mseq, body := ne.Uint16(b[4:]), ne.Uint32(b[8:]), b[nlmsgHdrLen:l]
		b = b[min(align4(l), len(b)):]
		if mseq != seq {
			continue
		}
		switch typ {
		case nlmsgError:
			if len(body) < 4 {
				return route{}, errRouteReply
			}
			if code := int32(ne.Uint32(body)); code < 0 {
				return route{}, fmt.Errorf("transport: route lookup: %w", syscall.Errno(-code))
			}
		case rtmNewRoute:
			return parseRouteAttrs(body)
		}
	}
	return route{}, errRouteReply
}

// parseRouteAttrs reads RTA_OIF and RTA_PREFSRC from an RTM_NEWROUTE body.
func parseRouteAttrs(body []byte) (route, error) {
	if len(body) < rtmsgLen {
		return route{}, errRouteReply
	}
	ne := binary.NativeEndian
	var r route
	at := body[rtmsgLen:]
	for len(at) >= 4 {
		l, typ := int(ne.Uint16(at[0:])), ne.Uint16(at[2:])
		if l < 4 || l > len(at) {
			return route{}, errRouteReply
		}
		v := at[4:l]
		switch typ {
		case rtaOif:
			if len(v) != 4 {
				return route{}, errRouteReply
			}
			r.ifindex = int(ne.Uint32(v))
		case rtaPrefsrc:
			if a, ok := netip.AddrFromSlice(v); ok {
				r.src = a.Unmap()
			}
		}
		at = at[min(align4(l), len(at)):]
	}
	if r.ifindex <= 0 {
		return route{}, errRouteReply
	}
	return r, nil
}
