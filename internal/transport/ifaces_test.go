package transport

import (
	"errors"
	"net"
	"net/netip"
	"testing"
)

func TestLinkLocalOf(t *testing.T) {
	cases := []struct {
		name  string
		addrs []string
		want  string // empty when there is none
	}{
		{"global only", []string{"2001:db8::1", "192.0.2.1"}, ""},
		{"IPv6 link-local", []string{"2001:db8::1", "fe80::1"}, "fe80::1"},
		{"IPv4 169.254 is not IPv6 link-local", []string{"169.254.1.1"}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var addrs []netip.Addr
			for _, s := range c.addrs {
				addrs = append(addrs, netip.MustParseAddr(s))
			}
			got, ok := linkLocalOf(addrs)
			if c.want == "" {
				if ok {
					t.Fatalf("linkLocalOf = %v, want none", got)
				}
				return
			}
			if !ok || got != netip.MustParseAddr(c.want) {
				t.Fatalf("linkLocalOf = %v, %v; want %s", got, ok, c.want)
			}
		})
	}
}

func TestDiscoveryReportsEachInterface(t *testing.T) {
	name := loopbackName(t)
	const unknown = "no-such-iface-0"
	res := Discovery([]string{name, unknown})
	if len(res) != 2 {
		t.Fatalf("Discovery returned %d entries, want 2", len(res))
	}
	if res[unknown] == nil || errors.Is(res[unknown], ErrNoLinkLocal) {
		t.Fatalf("unknown interface: err = %v, want a lookup error", res[unknown])
	}
	// The result must agree with what the host really has on loopback.
	wantOK := realLinkLocal(t, name)
	if wantOK != (res[name] == nil) {
		t.Fatalf("Discovery(%s) = %v, but the interface has a link-local address: %v", name, res[name], wantOK)
	}
	if !wantOK && res[name].Error() != "no IPv6 link-local address" {
		t.Fatalf("Discovery(%s) = %q, want %q", name, res[name], "no IPv6 link-local address")
	}
}

// stripLinkLocal makes every interface look as if it had no IPv6 link-local
// address, until the test ends.
func stripLinkLocal(t *testing.T) {
	t.Helper()
	orig := ifaceAddrs
	ifaceAddrs = func(ifi *net.Interface) ([]net.Addr, error) {
		addrs, err := orig(ifi)
		var kept []net.Addr
		for _, a := range addrs {
			if got, ok := addrOf(a); ok && got.Is6() && got.IsLinkLocalUnicast() {
				continue
			}
			kept = append(kept, a)
		}
		return kept, err
	}
	t.Cleanup(func() { ifaceAddrs = orig })
}

// TestNoLinkLocalReported is Review Focus 5: an interface without a link-local
// address is reported by Discovery, and static peers on it keep working.
func TestNoLinkLocalReported(t *testing.T) {
	name := loopbackName(t)
	stripLinkLocal(t)

	res := Discovery([]string{name})
	if res[name] == nil || res[name].Error() != "no IPv6 link-local address" {
		t.Fatalf("Discovery(%s) = %v, want no IPv6 link-local address", name, res[name])
	}

	port := freePort(t)
	tr, err := ListenPeers(port, []string{name}, allowAll)
	if err != nil {
		t.Fatalf("ListenPeers without a link-local address: %v", err)
	}
	t.Cleanup(func() { tr.Close() })
	serve(t, tr, noPacket, echo)

	reply, err := tr.Stream(loop4(port), []byte("static"))
	if err != nil || string(reply) != "re:static" {
		t.Fatalf("static peer Stream = %q, %v; want %q", reply, err, "re:static")
	}
	if err := tr.Multicast([]byte("announce")); !errors.Is(err, ErrNoLinkLocal) {
		t.Fatalf("Multicast with no link-local address: err = %v, want ErrNoLinkLocal", err)
	}
}
