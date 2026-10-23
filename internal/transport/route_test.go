package transport

import (
	"encoding/binary"
	"errors"
	"math/rand/v2"
	"net"
	"net/netip"
	"testing"
)

// fakeRoutes makes lookupRoute answer from table until the test ends; a
// destination not in table has no route.
func fakeRoutes(t *testing.T, table map[string]route) {
	t.Helper()
	orig := lookupRoute
	lookupRoute = func(dst netip.Addr) (route, error) {
		if r, ok := table[dst.String()]; ok {
			return r, nil
		}
		return route{}, errors.New("no route (fake)")
	}
	t.Cleanup(func() { lookupRoute = orig })
}

// fakeEndpoints is a transport holding endpoints without sockets: sender only
// picks one, it never writes.
func fakeEndpoints(eps ...*endpoint) *Transport {
	return &Transport{endpoints: eps}
}

func ep(iface string, index int, addr string) *endpoint {
	a := netip.MustParseAddr(addr)
	return &endpoint{addr: a, iface: iface, ifindex: index, linkLocal: isLinkLocal(a)}
}

// TestSenderFollowsTheRoute is I2: with peer zones on several interfaces, a
// static peer behind wan or wg0 gets its datagrams from the socket of the
// interface the kernel routes it through, not from the first socket of the
// same address family (br-lan, which would send them out the wrong port).
func TestSenderFollowsTheRoute(t *testing.T) {
	lan4 := ep("br-lan", 5, "192.168.1.1")
	lan6 := ep("br-lan", 5, "fd00:1::1")
	lanGUA := ep("br-lan", 5, "2001:db8:1::1")
	lanLL := ep("br-lan", 5, "fe80::1%br-lan")
	wan4 := ep("wan", 7, "10.0.0.2")
	wan6 := ep("wan", 7, "2001:db8:ffff::2")
	wg4 := ep("wg0", 9, "10.8.0.2")
	grp := &endpoint{addr: group.WithZone("br-lan"), iface: "br-lan", ifindex: 5, group: true}
	tr := fakeEndpoints(grp, lan4, lanLL, lan6, lanGUA, wan4, wan6, wg4)
	fakeRoutes(t, map[string]route{
		"192.168.1.50":   {ifindex: 5, src: lan4.addr},
		"203.0.113.9":    {ifindex: 7, src: wan4.addr},                           // cascaded NAT: the peer is upstream
		"10.8.0.1":       {ifindex: 9, src: wg4.addr},                            // overlay
		"2001:db8:9::9":  {ifindex: 7, src: wan6.addr},                           // routed, over wan
		"2001:db8:1::50": {ifindex: 5, src: lanGUA.addr},                         // the kernel picks the GUA, not the ULA
		"fd00:1::50":     {ifindex: 5},                                           // no source named: a non-link-local one on br-lan
		"198.51.100.7":   {ifindex: 3, src: netip.MustParseAddr("198.51.100.1")}, // a device of no peer zone
	})
	cases := []struct {
		dst  string
		want *endpoint
	}{
		{"192.168.1.50", lan4},
		{"203.0.113.9", wan4},
		{"10.8.0.1", wg4},
		{"2001:db8:9::9", wan6},
		{"2001:db8:1::50", lanGUA},
		{"fd00:1::50", lan6},
		{"fe80::99%br-lan", lanLL},
	}
	for _, c := range cases {
		got, err := tr.sender(netip.MustParseAddr(c.dst))
		if err != nil {
			t.Fatalf("sender(%s): %v", c.dst, err)
		}
		if got != c.want {
			t.Errorf("sender(%s) = %s on %s, want %s on %s", c.dst, got.addr, got.iface, c.want.addr, c.want.iface)
		}
	}

	// The route leaves through a device of no peer zone: nothing is sent
	// from a peer-zone socket, which would put it on the wrong wire.
	if got, err := tr.sender(netip.MustParseAddr("198.51.100.7")); err == nil {
		t.Errorf("sender(198.51.100.7) = %s on %s; the route leaves through a device of no peer zone, want an error", got.addr, got.iface)
	} else if !errors.Is(err, errNoSocket) {
		t.Errorf("sender(198.51.100.7): err = %v, want errNoSocket", err)
	}
}

// TestSenderWithoutARouteLookup: when the kernel cannot be asked, the socket
// is chosen as before, by address family, preferring a global source.
func TestSenderWithoutARouteLookup(t *testing.T) {
	lanLL := ep("br-lan", 5, "fe80::1%br-lan")
	lan4 := ep("br-lan", 5, "192.168.1.1")
	lan6 := ep("br-lan", 5, "2001:db8:1::1")
	tr := fakeEndpoints(lanLL, lan4, lan6)
	fakeRoutes(t, nil)
	for dst, want := range map[string]*endpoint{"192.0.2.1": lan4, "2001:db8:9::1": lan6} {
		got, err := tr.sender(netip.MustParseAddr(dst))
		if err != nil || got != want {
			t.Errorf("sender(%s) = %v, %v; want %s", dst, got, err, want.addr)
		}
	}
	// Only a link-local IPv6 socket: the fallback still finds it.
	only := fakeEndpoints(lanLL)
	if got, err := only.sender(netip.MustParseAddr("2001:db8:9::1")); err != nil || got != lanLL {
		t.Errorf("sender with only a link-local socket = %v, %v; want %s", got, err, lanLL.addr)
	}
	// No socket of the family at all.
	v6only := fakeEndpoints(lan6)
	if _, err := v6only.sender(netip.MustParseAddr("192.0.2.1")); !errors.Is(err, errNoSocket) {
		t.Errorf("sender(192.0.2.1) with no IPv4 socket: err = %v, want errNoSocket", err)
	}
}

// nlAttr is one rtnetlink attribute, padded to 4 bytes.
func nlAttr(typ uint16, v []byte) []byte {
	b := make([]byte, align4(4+len(v)))
	binary.NativeEndian.PutUint16(b[0:], uint16(4+len(v)))
	binary.NativeEndian.PutUint16(b[2:], typ)
	copy(b[4:], v)
	return b
}

// nlMsg is one netlink message of type typ carrying body.
func nlMsg(typ uint16, seq uint32, body []byte) []byte {
	b := make([]byte, 16+len(body))
	binary.NativeEndian.PutUint32(b[0:], uint32(len(b)))
	binary.NativeEndian.PutUint16(b[4:], typ)
	binary.NativeEndian.PutUint32(b[8:], seq)
	copy(b[16:], body)
	return b
}

// routeBody is an RTM_NEWROUTE body: an rtmsg of family, then attrs.
func routeBody(family byte, attrs ...[]byte) []byte {
	b := make([]byte, 12)
	b[0] = family
	for _, a := range attrs {
		b = append(b, a...)
	}
	return b
}

func u32(v uint32) []byte {
	b := make([]byte, 4)
	binary.NativeEndian.PutUint32(b, v)
	return b
}

func TestRouteRequestIsAnRTMGetRoute(t *testing.T) {
	for _, c := range []struct {
		dst    string
		family byte
		bits   byte
	}{{"203.0.113.9", 2, 32}, {"2001:db8::9", 10, 128}} {
		dst := netip.MustParseAddr(c.dst)
		b := routeRequest(77, dst)
		ne := binary.NativeEndian
		if int(ne.Uint32(b[0:])) != len(b) || len(b)%4 != 0 {
			t.Fatalf("%s: nlmsg_len %d for %d bytes", c.dst, ne.Uint32(b[0:]), len(b))
		}
		if ne.Uint16(b[4:]) != 26 || ne.Uint16(b[6:]) != 1 || ne.Uint32(b[8:]) != 77 {
			t.Fatalf("%s: header type %d flags %d seq %d, want RTM_GETROUTE(26), NLM_F_REQUEST(1), 77",
				c.dst, ne.Uint16(b[4:]), ne.Uint16(b[6:]), ne.Uint32(b[8:]))
		}
		if b[16] != c.family || b[17] != c.bits {
			t.Fatalf("%s: rtm_family %d rtm_dst_len %d, want %d and %d", c.dst, b[16], b[17], c.family, c.bits)
		}
		at := b[28:]
		alen := int(ne.Uint16(at[0:]))
		if ne.Uint16(at[2:]) != 1 || alen != 4+len(dst.AsSlice()) {
			t.Fatalf("%s: attribute type %d len %d, want RTA_DST(1) of %d", c.dst, ne.Uint16(at[2:]), alen, 4+len(dst.AsSlice()))
		}
		if got, _ := netip.AddrFromSlice(at[4:alen]); got != dst {
			t.Fatalf("%s: RTA_DST carries %s", c.dst, got)
		}
	}
	// A zone is not part of the question.
	b := routeRequest(1, netip.MustParseAddr("fe80::1%br-lan"))
	if got, _ := netip.AddrFromSlice(b[32:48]); got != netip.MustParseAddr("fe80::1") {
		t.Fatalf("RTA_DST for a zoned address = %s", got)
	}
}

func TestParseRouteReply(t *testing.T) {
	v4 := netip.MustParseAddr("10.0.0.2").AsSlice()
	v6 := netip.MustParseAddr("2001:db8::2").AsSlice()
	table := nlAttr(15, u32(254))
	ok4 := nlMsg(24, 9, routeBody(2, table, nlAttr(1, v4), nlAttr(4, u32(7)), nlAttr(7, v4)))
	ok6 := nlMsg(24, 9, routeBody(10, nlAttr(4, u32(3)), nlAttr(7, v6)))
	noSrc := nlMsg(24, 9, routeBody(2, nlAttr(4, u32(5))))
	other := nlMsg(24, 8, routeBody(2, nlAttr(4, u32(99))))

	cases := []struct {
		name string
		b    []byte
		want route
	}{
		{"IPv4 with a source", ok4, route{7, netip.MustParseAddr("10.0.0.2")}},
		{"IPv6 with a source", ok6, route{3, netip.MustParseAddr("2001:db8::2")}},
		{"no source named", noSrc, route{ifindex: 5}},
		{"another request's answer first", append(append([]byte(nil), other...), ok4...), route{7, netip.MustParseAddr("10.0.0.2")}},
		{"an acknowledgement before the answer", append(nlMsg(2, 9, u32(0)), ok4...), route{7, netip.MustParseAddr("10.0.0.2")}},
	}
	for _, c := range cases {
		got, err := parseRouteReply(c.b, 9)
		if err != nil || got != c.want {
			t.Errorf("%s: parseRouteReply = %+v, %v; want %+v", c.name, got, err, c.want)
		}
	}

	bad := []struct {
		name string
		b    []byte
	}{
		{"no route: ENETUNREACH", nlMsg(2, 9, append(u32(uint32(0x100000000-101)), make([]byte, 16)...))},
		{"error without a code", nlMsg(2, 9, []byte{1})},
		{"only another request's answer", other},
		{"no RTA_OIF", nlMsg(24, 9, routeBody(2, nlAttr(7, v4)))},
		{"RTA_OIF of 2 bytes", nlMsg(24, 9, routeBody(2, nlAttr(4, []byte{1, 0})))},
		{"attribute longer than the message", nlMsg(24, 9, append(routeBody(2), 0xff, 0, 4, 0))},
		{"attribute shorter than its header", nlMsg(24, 9, append(routeBody(2), 2, 0, 4, 0))},
		{"rtmsg cut short", nlMsg(24, 9, []byte{2, 0, 0})},
		{"nlmsg_len past the end", ok4[:20]},
		{"nlmsg_len below the header", append([]byte{4, 0, 0, 0}, make([]byte, 12)...)},
		{"empty", nil},
	}
	for _, c := range bad {
		if got, err := parseRouteReply(c.b, 9); err == nil {
			t.Errorf("%s: parseRouteReply = %+v, want an error", c.name, got)
		}
	}
}

// TestParseRouteReplySurvivesHostileBytes sweeps random and mutated replies:
// the parser returns an error or a route with a positive index, and never
// panics or reads past the buffer.
func TestParseRouteReplySurvivesHostileBytes(t *testing.T) {
	good := nlMsg(24, 9, routeBody(2, nlAttr(4, u32(7)), nlAttr(7, []byte{10, 0, 0, 2})))
	for seed := range int64(200) {
		rng := rand.New(rand.NewPCG(uint64(seed), 0))
		b := append([]byte(nil), good...)
		if seed%2 == 0 {
			b = make([]byte, rng.IntN(64))
			for i := range b {
				b[i] = byte(rng.Uint32())
			}
			if len(b) >= 12 {
				binary.NativeEndian.PutUint32(b[8:], 9)
			}
		} else {
			for range 1 + rng.IntN(4) {
				b[rng.IntN(len(b))] = byte(rng.Uint32())
			}
		}
		r, err := parseRouteReply(b, 9)
		if err == nil && r.ifindex <= 0 {
			t.Fatalf("seed %d: route %+v without an interface and no error", seed, r)
		}
	}
}

// TestKernelRouteLoopback asks the real kernel (rtnetlink on Linux, a
// connected socket elsewhere) for a loopback address: the route leaves
// through the loopback interface.
func TestKernelRouteLoopback(t *testing.T) {
	name := loopbackName(t)
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatal(err)
	}
	r, err := kernelRoute(netip.MustParseAddr("127.0.0.1"))
	if err != nil {
		t.Fatalf("kernelRoute(127.0.0.1): %v", err)
	}
	if r.ifindex != ifi.Index {
		t.Fatalf("kernelRoute(127.0.0.1) leaves through interface %d, want %s (%d)", r.ifindex, name, ifi.Index)
	}
	if r.src.IsValid() && r.src != netip.MustParseAddr("127.0.0.1") {
		t.Fatalf("kernelRoute(127.0.0.1) source %s, want 127.0.0.1", r.src)
	}
}
