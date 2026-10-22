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

// Discovery reports, for each interface, whether discovery can run there: nil,
// or ErrNoLinkLocal. An interface that cannot be looked up reports that error.
// Static peers do not depend on this result.
func Discovery(ifaces []string) map[string]error {
	out := make(map[string]error, len(ifaces))
	for _, name := range ifaces {
		ifi, err := net.InterfaceByName(name)
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

// listenIface binds the sockets of one interface. It gets a UDP socket and a
// TCP listener on each unicast address, and when it has an IPv6 link-local
// address, a group socket joined to ff02::114.
func (t *Transport) listenIface(name string) error {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return fmt.Errorf("transport: interface %s: %w", name, err)
	}
	raw, err := ifaceAddrs(ifi)
	if err != nil {
		return fmt.Errorf("transport: interface %s: %w", name, err)
	}
	addrs := unicastAddrs(raw)
	for _, a := range addrs {
		if err := t.listenUnicast(ifi, a); err != nil {
			return err
		}
	}
	if _, ok := linkLocalOf(addrs); ok {
		return t.listenGroup(ifi)
	}
	return nil
}

// listenUnicast binds a UDP socket and a TCP listener on addr, which belongs
// to ifi. A link-local address gets the interface as its zone.
func (t *Transport) listenUnicast(ifi *net.Interface, addr netip.Addr) error {
	if isLinkLocal(addr) {
		addr = addr.WithZone(ifi.Name)
	}
	network, tcpNetwork := "udp4", "tcp4"
	if addr.Is6() {
		network, tcpNetwork = "udp6", "tcp6"
	}
	ap := netip.AddrPortFrom(addr, uint16(t.port))
	ll := isLinkLocal(addr)

	// A link-local socket is where multicast leaves from, so its outgoing
	// interface is pinned as well.
	plan := &bindPlan{iface: ifi.Name, ifindex: ifi.Index, txIface: ll}
	lc := net.ListenConfig{Control: plan.control}
	pc, err := lc.ListenPacket(context.Background(), network, ap.String())
	if err != nil {
		return fmt.Errorf("transport: listen %s on %s: %w", ap, ifi.Name, err)
	}
	t.noteBind(plan.pinned)
	t.endpoints = append(t.endpoints, &endpoint{conn: pc.(*net.UDPConn), addr: addr, iface: ifi.Name, linkLocal: ll})

	tplan := &bindPlan{iface: ifi.Name, ifindex: ifi.Index}
	tl := net.ListenConfig{Control: tplan.control}
	ln, err := tl.Listen(context.Background(), tcpNetwork, ap.String())
	if err != nil {
		return fmt.Errorf("transport: listen tcp %s on %s: %w", ap, ifi.Name, err)
	}
	t.noteBind(tplan.pinned)
	t.listeners = append(t.listeners, ln.(*net.TCPListener))
	return nil
}

// listenGroup binds the discovery group on ifi and joins it there. The socket
// shares the port with the other interfaces' group sockets (SO_REUSEADDR), and
// receives only what arrives on the interfaces it joined.
func (t *Transport) listenGroup(ifi *net.Interface) error {
	g := group.WithZone(ifi.Name)
	plan := &bindPlan{iface: ifi.Name, ifindex: ifi.Index, join: true, reuse: true}
	lc := net.ListenConfig{Control: plan.control}
	ap := netip.AddrPortFrom(g, uint16(t.port))
	pc, err := lc.ListenPacket(context.Background(), "udp6", ap.String())
	if err != nil {
		return fmt.Errorf("transport: join %s on %s: %w", group, ifi.Name, err)
	}
	t.noteBind(plan.pinned)
	t.endpoints = append(t.endpoints, &endpoint{conn: pc.(*net.UDPConn), addr: g, iface: ifi.Name, group: true})
	return nil
}

// bindPlan is applied to a socket before it is bound, through
// net.ListenConfig.Control.
type bindPlan struct {
	iface   string
	ifindex int
	join    bool // join the discovery group on iface
	reuse   bool // SO_REUSEADDR, so one group socket per interface can share the port
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
		if opErr == nil && p.join {
			opErr = joinGroup(sock, p.ifindex)
		}
		if opErr == nil && p.txIface {
			opErr = syscall.SetsockoptInt(sock, syscall.IPPROTO_IPV6, syscall.IPV6_MULTICAST_IF, p.ifindex)
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
