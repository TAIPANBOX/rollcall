//go:build linux

package transport

import (
	"net"
	"net/netip"
	"testing"
)

// TestListensOnlyOnGivenIfaces is invariant 1: every bound address belongs to
// one of the given interfaces, or is the discovery group.
func TestListensOnlyOnGivenIfaces(t *testing.T) {
	name := loopbackName(t)
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := ifi.Addrs()
	if err != nil {
		t.Fatal(err)
	}
	own := map[netip.Addr]bool{}
	for _, a := range raw {
		if got, ok := addrOf(a); ok {
			own[got] = true
		}
	}

	tr := listen(t, freePort(t), allowAll)
	bound := tr.boundAddrs()
	if len(bound) == 0 {
		t.Fatal("transport bound no address")
	}
	for _, ap := range bound {
		addr := ap.Addr().WithZone("").Unmap()
		if addr == group {
			continue
		}
		if !own[addr] {
			t.Fatalf("transport bound %s, which is neither on %s nor the group %s", ap, name, group)
		}
	}
}
