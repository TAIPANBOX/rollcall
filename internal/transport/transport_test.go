package transport

import (
	"context"
	"net/netip"
	"runtime"
	"testing"
)

// The node package declares its Net interface from these three methods.
var _ interface {
	Multicast(b []byte) error
	Unicast(to netip.AddrPort, b []byte) error
	Stream(to netip.AddrPort, b []byte) ([]byte, error)
} = (*Transport)(nil)

func TestDefaultPort(t *testing.T) {
	if DefaultPort != 7432 {
		t.Fatalf("DefaultPort = %d, want 7432 (7431 is assigned to pmd)", DefaultPort)
	}
}

func TestListenPeersRejectsBadInput(t *testing.T) {
	lo := loopbackName(t)
	port := freePort(t)
	cases := []struct {
		name   string
		port   int
		ifaces []string
		auth   func([]byte) bool
	}{
		{"no authenticate", port, []string{lo}, nil},
		{"port zero", 0, []string{lo}, allowAll},
		{"port too large", 70000, []string{lo}, allowAll},
		{"no interfaces", port, nil, allowAll},
		{"unknown interface", port, []string{"no-such-iface-0"}, allowAll},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tr, err := ListenPeers(c.port, c.ifaces, c.auth)
			if err == nil {
				tr.Close()
				t.Fatal("ListenPeers succeeded, want an error")
			}
		})
	}
}

func TestServeRejectsNilCallbacks(t *testing.T) {
	tr := listen(t, freePort(t), allowAll)
	if err := tr.Serve(context.Background(), nil, echo); err == nil {
		t.Fatal("Serve without onPacket returned no error")
	}
	if err := tr.Serve(context.Background(), noPacket, nil); err == nil {
		t.Fatal("Serve without onStream returned no error")
	}
}

func TestBoundToDeviceIsFalseOffLinux(t *testing.T) {
	tr := listen(t, freePort(t), allowAll)
	if runtime.GOOS != "linux" && tr.BoundToDevice() {
		t.Fatalf("BoundToDevice() = true on %s, where SO_BINDTODEVICE does not exist", runtime.GOOS)
	}
}
