//go:build !linux

package transport

import (
	"fmt"
	"net"
	"net/netip"
)

// kernelRoute asks the kernel through a connected UDP socket where rtnetlink
// does not exist (developer builds): connecting routes the socket, and its
// local address is the source the kernel picked. Nothing is sent. The
// interface is the one carrying that address.
func kernelRoute(dst netip.Addr) (route, error) {
	c, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(dst, 9)))
	if err != nil {
		return route{}, err
	}
	src := c.LocalAddr().(*net.UDPAddr).AddrPort().Addr().Unmap().WithZone("")
	c.Close()
	ifs, err := net.Interfaces()
	if err != nil {
		return route{}, err
	}
	for _, ifi := range ifs {
		raw, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range unicastAddrs(raw) {
			if a == src {
				return route{ifindex: ifi.Index, src: src}, nil
			}
		}
	}
	return route{}, fmt.Errorf("transport: no interface carries %s, the source towards %s", src, dst)
}
