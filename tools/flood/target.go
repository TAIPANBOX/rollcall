package main

import (
	"errors"
	"fmt"
	"net/netip"
)

// checkTarget accepts an IP address and port only when the address is loopback, link-local or
// private: RFC 1918 or loopback for IPv4; loopback, link-local or unique-local (fc00::/7) for
// IPv6. Names, public addresses, multicast, and the shared range 100.64/10 that the tailnet uses
// are refused, so the tool cannot be aimed at the internet.
func checkTarget(s string) (netip.AddrPort, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("-to %q: want an IP address and port such as 192.168.1.1:7432 (names are refused)", s)
	}
	if ap.Port() == 0 {
		return netip.AddrPort{}, errors.New("-to: port 0 is refused")
	}
	a := ap.Addr().Unmap()
	if !(a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsPrivate()) {
		return netip.AddrPort{}, fmt.Errorf("-to %s: %s is not loopback, link-local or private; flood refuses it", ap, a)
	}
	return netip.AddrPortFrom(a, ap.Port()), nil
}
