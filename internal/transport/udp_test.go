package transport

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"testing"
)

func TestUnicastDeliversBothFamilies(t *testing.T) {
	port := freePort(t)
	tr := listen(t, port, allowAll)
	got := make(chan received, 4)
	serve(t, tr, func(from netip.AddrPort, b []byte) {
		got <- received{from, append([]byte(nil), b...)}
	}, echo)

	for _, host := range []string{"127.0.0.1", "::1"} {
		addr := netip.MustParseAddr(host)
		if !hasAddr(t, loopbackName(t), addr) {
			t.Logf("no %s on the loopback interface; skipped", host)
			continue
		}
		msg := []byte("hello " + host)
		if err := tr.Unicast(netip.AddrPortFrom(addr, uint16(port)), msg); err != nil {
			t.Fatalf("Unicast to %s: %v", host, err)
		}
		r := waitPacket(t, got)
		if !bytes.Equal(r.b, msg) {
			t.Fatalf("%s: received %q, want %q", host, r.b, msg)
		}
		if r.from.Addr().Unmap() != addr || r.from.Port() != uint16(port) {
			t.Fatalf("%s: received from %s, want %s:%d", host, r.from, host, port)
		}
	}
}

func TestOversizeDatagramDropped(t *testing.T) {
	port := freePort(t)
	tr := listen(t, port, allowAll)
	got := make(chan received, 4)
	serve(t, tr, func(from netip.AddrPort, b []byte) {
		got <- received{from, append([]byte(nil), b...)}
	}, echo)

	raw, err := net.Dial("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { raw.Close() })
	// The oversize datagram goes first. If it were delivered, it would be the
	// first thing received.
	if _, err := raw.Write(make([]byte, MaxDatagram+1)); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Write(bytes.Repeat([]byte{7}, MaxDatagram)); err != nil {
		t.Fatal(err)
	}
	r := waitPacket(t, got)
	if len(r.b) != MaxDatagram {
		t.Fatalf("first delivered datagram is %d bytes; the %d-byte one must be dropped", len(r.b), MaxDatagram+1)
	}
}

func TestUnicastRejectsOversize(t *testing.T) {
	tr := listen(t, freePort(t), allowAll)
	err := tr.Unicast(netip.MustParseAddrPort("127.0.0.1:9"), make([]byte, MaxDatagram+1))
	if !errors.Is(err, errDatagramTooLarge) {
		t.Fatalf("Unicast of %d bytes: err = %v, want errDatagramTooLarge", MaxDatagram+1, err)
	}
}

func TestUnicastNeedsAZoneForLinkLocal(t *testing.T) {
	tr := listen(t, freePort(t), allowAll)
	// No zone: a link-local destination cannot be routed.
	if err := tr.Unicast(netip.MustParseAddrPort("[fe80::1]:7432"), []byte("x")); err == nil {
		t.Fatal("Unicast to a link-local address without a zone returned no error")
	}
}

func TestUnicastToUnknownZoneFails(t *testing.T) {
	tr := listen(t, freePort(t), allowAll)
	// The transport has sockets on the loopback interface only.
	to := netip.MustParseAddrPort("[::1%no-such-iface-0]:9")
	if err := tr.Unicast(to, []byte("x")); err == nil {
		t.Fatalf("Unicast to %s returned no error with no socket on that zone", to)
	}
}

func TestUnicastToLinkLocalNeedsLinkLocalSocket(t *testing.T) {
	name := loopbackName(t)
	if realLinkLocal(t, name) {
		t.Skip("the loopback interface has an IPv6 link-local address on this OS")
	}
	tr := listen(t, freePort(t), allowAll)
	to := netip.AddrPortFrom(netip.MustParseAddr("fe80::1%"+name), 7432)
	if err := tr.Unicast(to, []byte("x")); err == nil {
		t.Fatalf("Unicast to %s returned no error with no link-local socket on %s", to, name)
	}
}

func TestMulticastDeliversToGroupMembers(t *testing.T) {
	name := loopbackName(t)
	if !multicastOn(t, name) {
		t.Skip("no IPv6 multicast with a link-local address on the loopback interface on this OS")
	}
	port := freePort(t)
	tr, err := ListenPeers(port, []string{name}, allowAll)
	if err != nil {
		t.Fatalf("ListenPeers: %v", err)
	}
	t.Cleanup(func() { tr.Close() })
	got := make(chan received, 4)
	serve(t, tr, func(from netip.AddrPort, b []byte) {
		got <- received{from, append([]byte(nil), b...)}
	}, echo)

	if err := tr.Multicast([]byte("announce")); err != nil {
		t.Fatalf("Multicast: %v", err)
	}
	r := waitPacket(t, got)
	if string(r.b) != "announce" {
		t.Fatalf("received %q, want %q", r.b, "announce")
	}
}

func TestMulticastRejectsOversize(t *testing.T) {
	tr := listen(t, freePort(t), allowAll)
	if err := tr.Multicast(make([]byte, MaxDatagram+1)); !errors.Is(err, errDatagramTooLarge) {
		t.Fatalf("Multicast of %d bytes: err = %v, want errDatagramTooLarge", MaxDatagram+1, err)
	}
}
