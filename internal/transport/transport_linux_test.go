//go:build linux

package transport

import (
	"net"
	"net/netip"
	"os"
	"testing"
	"time"
)

// linkLocalDevice returns a running multicast device, not loopback, that
// carries an IPv6 link-local address: eth0 on a CI runner, the LAN bridge on a
// router. Linux's lo has none, so the tests on lo never bind a group socket.
// Where no device has one the test skips, except on a GitHub Actions runner,
// whose eth0 always has one: a skip there would hide the case it covers.
func linkLocalDevice(t *testing.T) string {
	t.Helper()
	ifs, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	const want = net.FlagUp | net.FlagRunning | net.FlagMulticast
	for _, ifi := range ifs {
		if ifi.Flags&want != want || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		if realLinkLocal(t, ifi.Name) {
			return ifi.Name
		}
	}
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		t.Fatal("no running multicast device with an IPv6 link-local address on this GitHub Actions runner")
	}
	t.Skip("no running multicast device with an IPv6 link-local address")
	return ""
}

// groupBound fails the test unless name holds the discovery group socket, a
// link-local unicast socket, and no error.
func groupBound(t *testing.T, tr *Transport, name, when string) {
	t.Helper()
	st := tr.Devices()[name]
	ll := false
	for _, a := range st.Addrs {
		ll = ll || isLinkLocal(a)
	}
	if st.Err != nil || !st.Group || !ll {
		t.Fatalf("%s %s: group socket %v, unicast %v, err %v; want the group and a link-local socket bound, no error", name, when, st.Group, st.Addrs, st.Err)
	}
}

// TestGroupSocketBindsBesideLinkLocalSocket: on a device with an IPv6
// link-local address, the discovery group socket binds on the port the
// device's unicast sockets hold, and a multicast sent there comes back through
// it. Go binds a group address as the wildcard [::] (golang.org/issue/2349),
// and Linux refuses that next to a bound IPv6 address of the same port and
// device unless the two sockets share the port.
func TestGroupSocketBindsBesideLinkLocalSocket(t *testing.T) {
	name := linkLocalDevice(t)
	tr, err := Open(freePort(t), []string{name}, allowAll)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { tr.Close() })
	groupBound(t, tr, name, "after Open")

	got := make(chan received, 16)
	serve(t, tr, func(from netip.AddrPort, b []byte) {
		got <- received{from, append([]byte(nil), b...)}
	}, echo)
	if err := tr.Multicast([]byte("announce")); err != nil {
		t.Fatalf("Multicast: %v", err)
	}
	deadline := time.After(3 * time.Second)
	for {
		select {
		case r := <-got:
			if string(r.b) != "announce" {
				continue
			}
		case <-deadline:
			t.Fatalf("the group socket on %s received no multicast within 3 s", name)
		}
		break
	}

	// A pass over the devices keeps both sockets and binds nothing twice.
	tr.reconcile()
	groupBound(t, tr, name, "after a pass")
}

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
