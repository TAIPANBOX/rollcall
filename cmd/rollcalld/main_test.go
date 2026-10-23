package main

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TAIPANBOX/rollcall/internal/transport"
)

// procStatus makes a root whose proc/self/status holds text; a nil text
// leaves the file out, as a jail without /proc does.
func procStatus(t *testing.T, text *string) string {
	t.Helper()
	root := t.TempDir()
	if text == nil {
		return root
	}
	dir := filepath.Join(root, "proc", "self")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "status"), []byte(*text), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func ptr(s string) *string { return &s }

// TestSandboxGate is security spec 1.5 and 4.10: the daemon listens only when
// the kernel reports no_new_privs set and seccomp in filter mode; anything
// else, an unreadable status included, refuses with the reason.
func TestSandboxGate(t *testing.T) {
	cases := []struct {
		name   string
		status *string
		want   string // "" allows; otherwise a word the refusal must carry
	}{
		{"enforced", ptr("Name:\trollcalld\nNoNewPrivs:\t1\nSeccomp:\t2\nSeccomp_filters:\t1\n"), ""},
		{"no seccomp", ptr("NoNewPrivs:\t1\nSeccomp:\t0\n"), "seccomp"},
		{"seccomp strict, not filter", ptr("NoNewPrivs:\t1\nSeccomp:\t1\n"), "seccomp"},
		{"no no_new_privs", ptr("NoNewPrivs:\t0\nSeccomp:\t2\n"), "no_new_privs"},
		{"nothing set", ptr("NoNewPrivs:\t0\nSeccomp:\t0\n"), "no_new_privs"},
		{"lines missing", ptr("Name:\trollcalld\n"), "no_new_privs"},
		{"seccomp line missing", ptr("NoNewPrivs:\t1\n"), "seccomp"},
		{"status unreadable", nil, "cannot be checked"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := sandboxGate(procStatus(t, c.status))
			if c.want == "" {
				if err != nil {
					t.Fatalf("sandboxGate refused an enforced sandbox: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("sandboxGate allowed listening; want a refusal naming %q", c.want)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("refusal %q does not name %q", err, c.want)
			}
		})
	}
}

func loopback(t *testing.T) string {
	t.Helper()
	ifs, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, ifi := range ifs {
		if ifi.Flags&net.FlagLoopback != 0 {
			return ifi.Name
		}
	}
	t.Skip("no loopback interface")
	return ""
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// TestOpenPeersRunsWithADeviceMissing is I3 (c): a peer-zone device that
// does not exist (wg0 not up) no longer stops the daemon after two minutes;
// the others are listened on and the missing one is reported.
func TestOpenPeersRunsWithADeviceMissing(t *testing.T) {
	lo := loopback(t)
	tr, err := openPeers(freePort(t), []string{lo, "no-such-iface-0"}, func([]byte) bool { return false })
	if err != nil {
		t.Fatalf("openPeers with one device missing: %v", err)
	}
	defer tr.Close()
	devs := tr.Devices()
	if devs["no-such-iface-0"].Err == nil {
		t.Fatalf("the missing device is not reported: %+v", devs)
	}
	if devs[lo].Err != nil || len(devs[lo].Addrs) == 0 {
		t.Fatalf("the loopback device is not listened on: %+v", devs[lo])
	}
	if _, err := openPeers(freePort(t), nil, func([]byte) bool { return false }); err == nil {
		t.Fatal("openPeers with no device at all succeeded")
	}
}

// TestRefreshOnIfaceEvent: an interface event from hotplug asks the
// transport for a pass; other commands do not, and the reply is the
// daemon's.
func TestRefreshOnIfaceEvent(t *testing.T) {
	calls := 0
	h := refreshOnIface(func(cmd string, args []string, uid uint32) ([]byte, error) {
		return []byte(cmd), nil
	}, func() { calls++ })
	for _, c := range []struct {
		cmd  string
		args []string
		want int
	}{
		{"notify", []string{"iface", "ifup", "wan"}, 1},
		{"notify", []string{"iface", "ifdown", "lan"}, 2},
		{"notify", []string{"clock-synced"}, 2},
		{"status", nil, 2},
	} {
		out, err := h(c.cmd, c.args, 0)
		if err != nil || string(out) != c.cmd {
			t.Fatalf("%s %v: reply %q, %v; want the daemon's", c.cmd, c.args, out, err)
		}
		if calls != c.want {
			t.Fatalf("after %s %v: %d passes asked, want %d", c.cmd, c.args, calls, c.want)
		}
	}
}

// TestDiscoveryShowsUnboundDevices: status lists a peer-zone device the
// transport could not bind, beside the ones without a link-local address.
func TestDiscoveryShowsUnboundDevices(t *testing.T) {
	missing := errors.New("transport: interface wg0: no such network interface")
	unbound := errors.New("transport: listen [fd00::1]:7432 on br-lan: bind: cannot assign requested address")
	disc := map[string]error{"br-lan": nil, "wan": transport.ErrNoLinkLocal, "wg0": errors.New("no such network interface"), "eth1": nil}
	devs := map[string]transport.DeviceStatus{
		"br-lan": {Index: 5, Err: unbound},
		"wan":    {Index: 7, Err: errors.New("transport: interface wan: transport: no address to listen on")},
		"wg0":    {Err: missing},
		"eth1":   {Index: 9},
	}
	got := discoveryWith(disc, devs)
	if !errors.Is(got["br-lan"], unbound) {
		t.Errorf("br-lan: %v, want the bind failure", got["br-lan"])
	}
	if !errors.Is(got["wan"], transport.ErrNoLinkLocal) || !strings.Contains(fmt.Sprint(got["wan"]), "no address") {
		t.Errorf("wan: %v, want both the missing link-local address and the missing address", got["wan"])
	}
	if got["wg0"] == nil || errors.Is(got["wg0"], missing) {
		t.Errorf("wg0: %v, want the lookup error once, not twice", got["wg0"])
	}
	if got["eth1"] != nil {
		t.Errorf("eth1: %v, want nil", got["eth1"])
	}
}

// TestDeviceNotes: the log names a device when it stops being listened on
// and when it is listened on again, once each.
func TestDeviceNotes(t *testing.T) {
	ok := map[string]transport.DeviceStatus{"wan": {Index: 7, Addrs: []netip.Addr{netip.MustParseAddr("10.0.0.2")}}}
	bad := map[string]transport.DeviceStatus{"wan": {Err: errors.New("transport: interface wan: no such network interface")}}
	if n := deviceNotes(nil, bad); len(n) != 1 || !strings.Contains(n[0], "wan") || !strings.Contains(n[0], "no such network interface") {
		t.Fatalf("notes at start with wan missing = %q", n)
	}
	if n := deviceNotes(bad, bad); len(n) != 0 {
		t.Fatalf("notes with nothing changed = %q, want none", n)
	}
	if n := deviceNotes(bad, ok); len(n) != 1 || !strings.Contains(n[0], "10.0.0.2") {
		t.Fatalf("notes once wan is bound = %q", n)
	}
	if n := deviceNotes(ok, ok); len(n) != 0 {
		t.Fatalf("notes with nothing changed = %q, want none", n)
	}
}

// TestFloodNote: the log says when the transport starts refusing a flood on
// the peer zones, with what it dropped, and when the flood stops; nothing
// while the state holds.
func TestFloodNote(t *testing.T) {
	c := transport.Counters{SourceLimited: 1500, RateLimited: 20, Oversize: 3, SourcesFull: 0}
	if got := floodNote(false, true, c); !strings.Contains(got, "under flood") || !strings.Contains(got, "1500") {
		t.Fatalf("floodNote at the start of a flood = %q", got)
	}
	if got := floodNote(true, false, c); !strings.Contains(got, "stopped") {
		t.Fatalf("floodNote at the end of a flood = %q", got)
	}
	if got := floodNote(true, true, c) + floodNote(false, false, c); got != "" {
		t.Fatalf("floodNote with nothing changed = %q, want none", got)
	}
}
