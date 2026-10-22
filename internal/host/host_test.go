package host

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/TAIPANBOX/rollcall/internal/ids"
)

// setRoot points Root at testdata/<name> until the test ends.
func setRoot(t *testing.T, name string) {
	t.Helper()
	abs, err := filepath.Abs(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	old := Root
	Root = abs
	t.Cleanup(func() { Root = old })
}

// tempRoot points Root at a fresh directory holding the given files, relative path to content.
func tempRoot(t *testing.T, files map[string]string) {
	t.Helper()
	dir := t.TempDir()
	for rel, content := range files {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	old := Root
	Root = dir
	t.Cleanup(func() { Root = old })
}

// fixture returns the bytes of a file under testdata.
func fixture(t *testing.T, parts ...string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(append([]string{"testdata"}, parts...)...))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return b
}

func TestParseProcRoute(t *testing.T) {
	got, err := parseProcRoute(fixture(t, "router", "proc", "net", "route"))
	if err != nil {
		t.Fatalf("parseProcRoute: %v", err)
	}
	// The dsl0 default is not up (flags 0002) and br-lan is not a default route.
	want := []defaultRoute{{iface: "wwan", metric: 20}, {iface: "wan", metric: 10}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("default routes = %v, want %v", got, want)
	}
}

func TestParseProcRouteRejectsMalformedRow(t *testing.T) {
	header := "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
	good := header + "wan\t00000000\t0102A8C0\t0003\t0\t0\t10\t00000000\t0\t0\t0\n"
	got, err := parseProcRoute([]byte(good))
	if err != nil || len(got) != 1 {
		t.Fatalf("positive control: got %v, %v; want one default route", got, err)
	}
	bad := header + "wan\t00000000\t0102A8C0\t0003\t0\t0\tnotanumber\t00000000\t0\t0\t0\n"
	if _, err := parseProcRoute([]byte(bad)); err == nil {
		t.Fatal("a row with a non-numeric metric parsed without error")
	}
	short := header + "wan\t00000000\n"
	if _, err := parseProcRoute([]byte(short)); err == nil {
		t.Fatal("a row with too few fields parsed without error")
	}
}

func TestParseIPv6Route(t *testing.T) {
	got, err := parseIPv6Route(fixture(t, "router", "proc", "net", "ipv6_route"))
	if err != nil {
		t.Fatalf("parseIPv6Route: %v", err)
	}
	// Only the wan default is usable: the fe80 prefix is not a default and lo is a reject route.
	want := []defaultRoute{{iface: "wan", metric: 10}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("IPv6 default routes = %v, want %v", got, want)
	}
}

func TestParseIPv6RouteRejectsMalformedRow(t *testing.T) {
	good := "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 0000000a 00000000 00000000 00000003 wan\n"
	if got, err := parseIPv6Route([]byte(good)); err != nil || len(got) != 1 {
		t.Fatalf("positive control: got %v, %v; want one default route", got, err)
	}
	if _, err := parseIPv6Route([]byte("00000000000000000000000000000000 00 wan\n")); err == nil {
		t.Fatal("a short IPv6 row parsed without error")
	}
	if _, err := parseIPv6Route([]byte(strings.Replace(good, "0000000a", "zzzzzzzz", 1))); err == nil {
		t.Fatal("an IPv6 row with a non-hex metric parsed without error")
	}
}

func TestDefaultRouteIface(t *testing.T) {
	cases := []struct {
		root    string
		want    string
		wantErr bool
	}{
		{"router", "wan", false},       // wan metric 10 beats wwan metric 20, whatever the file order
		{"router-wwan", "wwan", false}, // wan removed from the table
		{"ipv6-only", "wwan", false},   // no IPv4 default: the IPv6 default decides
		{"no-default", "", true},       // only a link-local and a LAN route
	}
	for _, c := range cases {
		setRoot(t, c.root)
		got, err := DefaultRouteIface()
		if c.wantErr {
			if !errors.Is(err, ErrNoDefaultRoute) {
				t.Errorf("%s: err = %v, want ErrNoDefaultRoute", c.root, err)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("%s: DefaultRouteIface() = %q, %v; want %q", c.root, got, err, c.want)
		}
	}
}

func TestParseOpenWrtRelease(t *testing.T) {
	got := parseOpenWrtRelease(fixture(t, "router", "etc", "openwrt_release"))
	if got["DISTRIB_RELEASE"] != "24.10.0" {
		t.Fatalf("DISTRIB_RELEASE = %q, want 24.10.0", got["DISTRIB_RELEASE"])
	}
	quoting := parseOpenWrtRelease([]byte("# a comment\nDISTRIB_RELEASE=\"23.05.5\"\n\nDISTRIB_ID=OpenWrt\nNOT A PAIR\nDISTRIB_TAINTS=''\n"))
	if quoting["DISTRIB_RELEASE"] != "23.05.5" {
		t.Errorf("double-quoted value = %q, want 23.05.5", quoting["DISTRIB_RELEASE"])
	}
	if quoting["DISTRIB_ID"] != "OpenWrt" {
		t.Errorf("unquoted value = %q, want OpenWrt", quoting["DISTRIB_ID"])
	}
	if v, ok := quoting["DISTRIB_TAINTS"]; !ok || v != "" {
		t.Errorf("empty single-quoted value = %q, present %v; want empty and present", v, ok)
	}
}

func TestOpenWrtVersion(t *testing.T) {
	setRoot(t, "router")
	got, err := OpenWrtVersion()
	if err != nil || got != "24.10.0" {
		t.Fatalf("OpenWrtVersion() = %q, %v; want 24.10.0", got, err)
	}
	tempRoot(t, map[string]string{"etc/openwrt_release": "DISTRIB_ID='OpenWrt'\n"})
	if _, err := OpenWrtVersion(); err == nil {
		t.Fatal("OpenWrtVersion without DISTRIB_RELEASE returned no error")
	}
	tempRoot(t, map[string]string{})
	if _, err := OpenWrtVersion(); err == nil {
		t.Fatal("OpenWrtVersion with no etc/openwrt_release returned no error")
	}
}

func TestOperState(t *testing.T) {
	setRoot(t, "router")
	if got, err := OperState("wan"); err != nil || got != "up" {
		t.Fatalf("OperState(wan) = %q, %v; want up", got, err)
	}
	if got, err := OperState("wwan"); err != nil || got != "unknown" {
		t.Fatalf("OperState(wwan) = %q, %v; want unknown", got, err)
	}
	setRoot(t, "router-wwan")
	if got, err := OperState("wan"); err != nil || got != "down" {
		t.Fatalf("after uplink loss OperState(wan) = %q, %v; want down", got, err)
	}
	if _, err := OperState("../router"); err == nil {
		t.Fatal("OperState accepted a path traversal name")
	}
	if _, err := OperState("nosuchdev"); err == nil {
		t.Fatal("OperState of a missing device returned no error")
	}
}

func TestValidIface(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"wan", true},
		{"abcdefghijklmno", true}, // 15 bytes, the kernel limit
		{"abcdefghijklmnop", false},
		{"", false},
		{".", false},
		{"..", false},
		{"a/b", false},
	}
	for _, c := range cases {
		if got := validIface(c.name); got != c.want {
			t.Errorf("validIface(%q) = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestBootID(t *testing.T) {
	setRoot(t, "router")
	var want ids.BootID
	if err := want.UnmarshalText([]byte("0b5c1a2e3f4d4e5a9b6c7d8e9f0a1b2c")); err != nil {
		t.Fatal(err)
	}
	got, err := BootID()
	if err != nil || got != want {
		t.Fatalf("BootID() = %s, %v; want %s", got, err, want)
	}
	tempRoot(t, map[string]string{"proc/sys/kernel/random/boot_id": "not-a-boot-id\n"})
	if _, err := BootID(); err == nil {
		t.Fatal("BootID of a value that is not a UUID returned no error")
	}
}

func TestRouteChangeIsUplinkSwitch(t *testing.T) {
	w := &RouteWatch{}
	setRoot(t, "router")
	if switched, from, to := w.Tick(); switched {
		t.Fatalf("first Tick reported a switch %s -> %s; it only sets the baseline", from, to)
	}
	if switched, _, _ := w.Tick(); switched {
		t.Fatal("second Tick on an unchanged route reported a switch")
	}
	setRoot(t, "router-wwan")
	switched, from, to := w.Tick()
	if !switched || from != "wan" || to != "wwan" {
		t.Fatalf("Tick after wan went down: switched=%v from=%q to=%q, want switch wan -> wwan", switched, from, to)
	}
	if switched, _, _ := w.Tick(); switched {
		t.Fatal("Tick on the same new route reported a second switch")
	}
}

func TestRouteWatchKeepsLastRouteThroughGap(t *testing.T) {
	// A moment with no default route is not a switch; the last seen interface stays the reference.
	w := &RouteWatch{}
	setRoot(t, "router")
	w.Tick()
	setRoot(t, "no-default")
	if switched, _, _ := w.Tick(); switched {
		t.Fatal("Tick with no default route reported a switch")
	}
	setRoot(t, "router-wwan")
	switched, from, to := w.Tick()
	if !switched || from != "wan" || to != "wwan" {
		t.Fatalf("Tick after the gap: switched=%v from=%q to=%q, want switch wan -> wwan", switched, from, to)
	}
}
