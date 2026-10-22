package transport

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"syscall"
	"testing"
	"time"
)

func allowAll([]byte) bool { return true }

// noPacket is the onPacket callback for tests that only exercise streams.
func noPacket(netip.AddrPort, []byte) {}

// echo replies "re:" followed by the request.
func echo(_ netip.AddrPort, b []byte) []byte { return append([]byte("re:"), b...) }

type received struct {
	from netip.AddrPort
	b    []byte
}

// loop4 is 127.0.0.1 on port.
func loop4(port int) netip.AddrPort {
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port))
}

// loopbackName returns the loopback interface name: lo on Linux, lo0 on macOS.
func loopbackName(t *testing.T) string {
	t.Helper()
	ifs, err := net.Interfaces()
	if err != nil {
		t.Fatalf("net.Interfaces: %v", err)
	}
	for _, ifi := range ifs {
		if ifi.Flags&net.FlagLoopback != 0 {
			return ifi.Name
		}
	}
	t.Skip("no loopback interface")
	return ""
}

// freePort returns a port that TCP and UDP on 127.0.0.1 both accept right now.
func freePort(t *testing.T) int {
	t.Helper()
	for range 50 {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		port := l.Addr().(*net.TCPAddr).Port
		p, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		l.Close()
		if err != nil {
			continue
		}
		p.Close()
		return port
	}
	t.Fatal("no port free for both TCP and UDP")
	return 0
}

// listen starts a transport on the loopback interface; it is closed at test end.
func listen(t *testing.T, port int, auth func([]byte) bool) *Transport {
	t.Helper()
	tr, err := ListenPeers(port, []string{loopbackName(t)}, auth)
	if err != nil {
		t.Fatalf("ListenPeers(%d): %v", port, err)
	}
	t.Cleanup(func() { tr.Close() })
	return tr
}

// serve runs tr's receive loops until the test ends. It fails the test if
// Serve reports an error or does not return after its context is cancelled.
func serve(t *testing.T, tr *Transport, onPacket func(netip.AddrPort, []byte), onStream func(netip.AddrPort, []byte) []byte) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- tr.Serve(ctx, onPacket, onStream) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve returned %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("Serve did not return after its context was cancelled")
		}
	})
}

// waitPacket returns the next datagram, or fails the test after 3 s.
func waitPacket(t *testing.T, got <-chan received) received {
	t.Helper()
	select {
	case r := <-got:
		return r
	case <-time.After(3 * time.Second):
		t.Fatal("no datagram within 3 s")
	}
	return received{}
}

// rawFrame builds a frame by hand, so the tests do not depend on the code
// they check. declared is the length written in the header.
func rawFrame(payload []byte, declared uint32) []byte {
	b := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(b, declared)
	copy(b[4:], payload)
	return b
}

// dial opens a raw TCP connection to ap.
func dial(t *testing.T, ap netip.AddrPort) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", ap.String(), 3*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", ap, err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// expectClosed reads until the server closes c. It fails if the server sent
// any bytes, or if c stays open for 3 s. A reset counts as closed.
func expectClosed(t *testing.T, c net.Conn) {
	t.Helper()
	if err := c.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(c)
	if err != nil && !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("server left the connection open: %v", err)
	}
	if len(data) != 0 {
		t.Fatalf("server replied with %d bytes, want no reply", len(data))
	}
}

// addrOf returns the address of an interface address entry, without its prefix length.
func addrOf(a net.Addr) (netip.Addr, bool) {
	p, err := netip.ParsePrefix(a.String())
	if err != nil {
		return netip.Addr{}, false
	}
	return p.Addr().Unmap(), true
}

// hasAddr reports whether interface name carries addr.
func hasAddr(t *testing.T, name string, addr netip.Addr) bool {
	t.Helper()
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatal(err)
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range addrs {
		if got, ok := addrOf(a); ok && got == addr {
			return true
		}
	}
	return false
}

// realLinkLocal reports whether interface name has an IPv6 link-local address on this host.
func realLinkLocal(t *testing.T, name string) bool {
	t.Helper()
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatal(err)
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range addrs {
		if got, ok := addrOf(a); ok && got.Is6() && got.IsLinkLocalUnicast() {
			return true
		}
	}
	return false
}

// multicastOn reports whether multicast can be tried on name: the interface
// must carry the MULTICAST flag and an IPv6 link-local address. Linux's lo has
// neither by default, so the multicast test skips there.
func multicastOn(t *testing.T, name string) bool {
	t.Helper()
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatal(err)
	}
	return ifi.Flags&net.FlagMulticast != 0 && realLinkLocal(t, name)
}
