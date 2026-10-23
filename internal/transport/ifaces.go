package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
)

// group is the IPv6 link-local multicast group rollcall announces on. The
// registry check is in docs/notes/registry-check.md.
var group = netip.MustParseAddr("ff02::114")

// ErrNoLinkLocal is reported for an interface that has no IPv6 link-local
// address, so discovery cannot run on it.
var ErrNoLinkLocal = errors.New("no IPv6 link-local address")

// ifaceAddrs lists an interface's addresses. Tests replace it to simulate an
// interface without a link-local address.
var ifaceAddrs = func(ifi *net.Interface) ([]net.Addr, error) { return ifi.Addrs() }

// lookupIface finds a device by name. Tests replace it.
var lookupIface = net.InterfaceByName

// joinGroupFn and multicastIfFn set the group membership and the outgoing
// multicast interface of a socket. Tests replace them.
var (
	joinGroupFn   = joinGroup
	multicastIfFn = func(fd, ifindex int) error {
		return syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, syscall.IPV6_MULTICAST_IF, ifindex)
	}
)

// Discovery reports, for each interface, whether discovery can run there: nil,
// or ErrNoLinkLocal. An interface that cannot be looked up reports that error.
// Static peers do not depend on this result.
func Discovery(ifaces []string) map[string]error {
	out := make(map[string]error, len(ifaces))
	for _, name := range ifaces {
		ifi, err := lookupIface(name)
		if err != nil {
			out[name] = err
			continue
		}
		raw, err := ifaceAddrs(ifi)
		if err != nil {
			out[name] = err
			continue
		}
		if _, ok := linkLocalOf(unicastAddrs(raw)); !ok {
			out[name] = ErrNoLinkLocal
			continue
		}
		out[name] = nil
	}
	return out
}

// isLinkLocal reports whether a is an IPv6 link-local unicast address (fe80::/10).
func isLinkLocal(a netip.Addr) bool {
	return a.Is6() && a.IsLinkLocalUnicast()
}

// linkLocalOf returns the first IPv6 link-local address in addrs.
func linkLocalOf(addrs []netip.Addr) (netip.Addr, bool) {
	for _, a := range addrs {
		if isLinkLocal(a) {
			return a, true
		}
	}
	return netip.Addr{}, false
}

// unicastAddrs returns the unicast addresses among raw, without prefix lengths,
// with IPv4-mapped addresses unmapped. Multicast and unspecified addresses are
// left out.
func unicastAddrs(raw []net.Addr) []netip.Addr {
	var out []netip.Addr
	for _, a := range raw {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		default:
			continue
		}
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			continue
		}
		addr = addr.Unmap()
		if addr.IsUnspecified() || addr.IsMulticast() {
			continue
		}
		out = append(out, addr)
	}
	return out
}

// sockKey names one socket the transport wants: an address of a device as
// the kernel indexes it now. A device recreated under a new index, or an
// address that left, no longer matches the key of its old socket.
type sockKey struct {
	iface   string
	ifindex int
	addr    netip.Addr // with the zone for link-local; the group for a group socket
	group   bool
}

func (ep *endpoint) key() sockKey {
	return sockKey{iface: ep.iface, ifindex: ep.ifindex, addr: ep.addr, group: ep.group}
}

// listener is one TCP listener, beside the UDP socket of the same key.
type listener struct {
	ln     *net.TCPListener
	key    sockKey
	pinned bool
}

// scan reads what the configured devices carry now: the sockets wanted, in
// order, and each device's index or the reason it has none. It reads the
// kernel and holds no lock.
func (t *Transport) scan() ([]sockKey, map[string]DeviceStatus) {
	var want []sockKey
	devs := make(map[string]DeviceStatus, len(t.devices))
	for _, name := range t.devices {
		ifi, err := lookupIface(name)
		if err != nil {
			devs[name] = DeviceStatus{Err: fmt.Errorf("transport: interface %s: %w", name, err)}
			continue
		}
		raw, err := ifaceAddrs(ifi)
		if err != nil {
			devs[name] = DeviceStatus{Index: ifi.Index, Err: fmt.Errorf("transport: interface %s: %w", name, err)}
			continue
		}
		addrs := unicastAddrs(raw)
		st := DeviceStatus{Index: ifi.Index}
		if len(addrs) == 0 {
			st.Err = fmt.Errorf("transport: interface %s: %w", name, errNoAddress)
		}
		devs[name] = st
		for _, a := range addrs {
			if isLinkLocal(a) {
				a = a.WithZone(ifi.Name)
			}
			want = append(want, sockKey{iface: ifi.Name, ifindex: ifi.Index, addr: a})
		}
		if _, ok := linkLocalOf(addrs); ok {
			want = append(want, sockKey{iface: ifi.Name, ifindex: ifi.Index, addr: group.WithZone(ifi.Name), group: true})
		}
	}
	return want, devs
}

// reconcile is one pass over the devices: it closes the sockets no device
// wants any more (the address left, or the device was recreated under a new
// index) and binds the wanted ones it does not hold. A bind that fails is
// recorded in the device's status and tried again on the next pass.
func (t *Transport) reconcile() {
	want, devs := t.scan()
	wanted := make(map[sockKey]bool, len(want))
	for _, k := range want {
		wanted[k] = true
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return
	}
	held := make(map[sockKey]bool)
	var eps []*endpoint
	for _, ep := range t.endpoints {
		if wanted[ep.key()] {
			eps = append(eps, ep)
			held[ep.key()] = true
			continue
		}
		ep.conn.Close()
	}
	var lns []*listener
	for _, l := range t.listeners {
		if wanted[l.key] {
			lns = append(lns, l)
			continue
		}
		l.ln.Close()
	}
	t.endpoints, t.listeners = eps, lns

	failed := make(map[string][]error)
	for _, k := range want {
		if held[k] {
			continue
		}
		var err error
		if k.group {
			err = t.bindGroupLocked(k)
		} else {
			err = t.bindUnicastLocked(k)
		}
		if err != nil {
			failed[k.iface] = append(failed[k.iface], err)
		}
	}

	for name, st := range devs {
		if errs := failed[name]; len(errs) > 0 {
			st.Err = errors.Join(append([]error{st.Err}, errs...)...)
		}
		for _, ep := range t.endpoints {
			if ep.iface != name || ep.ifindex != st.Index {
				continue
			}
			if ep.group {
				st.Group = true
			} else {
				st.Addrs = append(st.Addrs, ep.addr)
			}
		}
		devs[name] = st
	}
	t.devs = devs
}

// bindUnicastLocked binds a UDP socket and a TCP listener on k.addr, pinned to
// k.iface, and starts their loops once Serve runs. t.mu is held.
func (t *Transport) bindUnicastLocked(k sockKey) error {
	network, tcpNetwork := "udp4", "tcp4"
	if k.addr.Is6() {
		network, tcpNetwork = "udp6", "tcp6"
	}
	ap := netip.AddrPortFrom(k.addr, uint16(t.port))
	ll := isLinkLocal(k.addr)

	// A link-local socket is where multicast leaves from, so its outgoing
	// interface is pinned as well. An IPv6 socket shares its port with the
	// group socket of its device (bindGroupLocked).
	plan := &bindPlan{iface: k.iface, ifindex: k.ifindex, txIface: ll, share: k.addr.Is6()}
	lc := net.ListenConfig{Control: plan.control}
	pc, err := lc.ListenPacket(context.Background(), network, ap.String())
	if err != nil {
		return fmt.Errorf("transport: listen %s on %s: %w", ap, k.iface, err)
	}
	tplan := &bindPlan{iface: k.iface, ifindex: k.ifindex}
	tl := net.ListenConfig{Control: tplan.control}
	ln, err := tl.Listen(context.Background(), tcpNetwork, ap.String())
	if err != nil {
		pc.Close()
		return fmt.Errorf("transport: listen tcp %s on %s: %w", ap, k.iface, err)
	}
	ep := &endpoint{conn: pc.(*net.UDPConn), addr: k.addr, iface: k.iface, ifindex: k.ifindex, linkLocal: ll, pinned: plan.pinned}
	l := &listener{ln: ln.(*net.TCPListener), key: k, pinned: tplan.pinned}
	t.endpoints = append(t.endpoints, ep)
	t.listeners = append(t.listeners, l)
	t.startReadLocked(ep)
	t.startAcceptLocked(l)
	return nil
}

// bindGroupLocked binds the discovery group on k.iface and joins it on
// k.ifindex. The socket shares the port with the other interfaces' group
// sockets (SO_REUSEADDR), and receives only what arrives on the interfaces it
// joined. Go binds a group address as the wildcard [::] (golang.org/issue/2349),
// which Linux refuses beside the IPv6 unicast sockets of the same port and
// device unless they share the port too (sharePort). t.mu is held.
func (t *Transport) bindGroupLocked(k sockKey) error {
	plan := &bindPlan{iface: k.iface, ifindex: k.ifindex, join: true, reuse: true, share: true}
	lc := net.ListenConfig{Control: plan.control}
	ap := netip.AddrPortFrom(k.addr, uint16(t.port))
	pc, err := lc.ListenPacket(context.Background(), "udp6", ap.String())
	if err != nil {
		return fmt.Errorf("transport: join %s on %s: %w", group, k.iface, err)
	}
	ep := &endpoint{conn: pc.(*net.UDPConn), addr: k.addr, iface: k.iface, ifindex: k.ifindex, group: true, pinned: plan.pinned}
	t.endpoints = append(t.endpoints, ep)
	t.startReadLocked(ep)
	return nil
}

// bindPlan is applied to a socket before it is bound, through
// net.ListenConfig.Control.
type bindPlan struct {
	iface   string
	ifindex int
	join    bool // join the discovery group on ifindex
	reuse   bool // SO_REUSEADDR, so one group socket per interface can share the port
	share   bool // sharePort: the group socket and the IPv6 unicast sockets of its device share the port
	txIface bool // pin the outgoing multicast interface
	pinned  bool // result: SO_BINDTODEVICE was accepted
}

func (p *bindPlan) control(_, _ string, c syscall.RawConn) error {
	var opErr error
	err := c.Control(func(fd uintptr) {
		sock := int(fd)
		if p.reuse {
			opErr = syscall.SetsockoptInt(sock, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
		}
		if opErr == nil && p.share {
			opErr = sharePort(sock)
		}
		if opErr == nil && p.join {
			opErr = joinGroupFn(sock, p.ifindex)
		}
		if opErr == nil && p.txIface {
			opErr = multicastIfFn(sock, p.ifindex)
		}
		if opErr == nil {
			p.pinned, opErr = bindToDevice(fd, p.iface)
		}
	})
	if err != nil {
		return err
	}
	return opErr
}

// joinGroup adds the discovery group on the interface with index ifindex.
func joinGroup(fd, ifindex int) error {
	mreq := syscall.IPv6Mreq{Interface: uint32(ifindex)}
	copy(mreq.Multiaddr[:], group.AsSlice())
	return syscall.SetsockoptIPv6Mreq(fd, syscall.IPPROTO_IPV6, syscall.IPV6_JOIN_GROUP, &mreq)
}
