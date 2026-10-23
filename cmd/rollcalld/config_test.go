package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// The site's configuration as a router holds it. network and system are written mode 0000 here:
// on OpenWrt 25.12 they are root's alone (0600, they may hold PPPoE passwords and WireGuard
// private keys), and an unprivileged test process can no more read a 0000 file than the daemon,
// running as rollcall, can read a 0600 one of root's.
const (
	siteRollcall = "config rollcall 'main'\n\toption site 'Home'\n\tlist peer_zone 'lan'\n"
	siteFirewall = "config zone\n\toption name 'lan'\n\tlist network 'lan'\n\n" +
		"config zone\n\toption name 'wan'\n\tlist network 'wan'\n\toption masq '1'\n"
	siteNetwork = "config interface 'lan'\n\toption device 'br-lan'\n\n" +
		"config interface 'wan'\n\toption device 'eth1'\n\toption proto 'pppoe'\n\toption password 'CANARY-123:abc'\n"
	siteSystem = "config system\n\toption zonename 'Europe/Kyiv'\n"
)

// rootOnlySite writes the four files into a directory, network and system unreadable, and
// returns the path of the rollcall file.
func rootOnlySite(t *testing.T) string {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root reads a file of mode 0000; run the test as an unprivileged user")
	}
	dir := t.TempDir()
	for name, f := range map[string]struct {
		text string
		mode os.FileMode
	}{
		"rollcall": {siteRollcall, 0o644}, "firewall": {siteFirewall, 0o644},
		"network": {siteNetwork, 0o000}, "system": {siteSystem, 0o000},
	} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(f.text), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, f.mode); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(dir, "rollcall")
}

// rootSnapshot writes, as root's side would, the snapshot of the site in dir: the facts of
// siteFirewall, siteNetwork and siteSystem, stamped with the files as they are now.
func rootSnapshot(t *testing.T, dir, path string) {
	t.Helper()
	stamp := func(name string) (int64, int64) {
		fi, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return fi.Size(), fi.ModTime().UnixNano()
	}
	fwSum := sha256.Sum256([]byte(siteFirewall))
	nwSize, nwTime := stamp("network")
	sysSize, sysTime := stamp("system")
	text := fmt.Sprintf(`{"version":1,"sources":[`+
		`{"name":"firewall","size":%d,"sha256":"%x"},`+
		`{"name":"network","size":%d,"mtime_ns":%d},`+
		`{"name":"system","size":%d,"mtime_ns":%d}],`+
		`"zones":[{"name":"lan","devices":["br-lan"],"external":false},{"name":"wan","devices":["eth1"],"external":true}],`+
		`"tz":"Europe/Kyiv","tz_source":"zonename"}`+"\n",
		len(siteFirewall), fwSum, nwSize, nwTime, sysSize, sysTime)
	if err := os.WriteFile(path, []byte(text), 0o640); err != nil {
		t.Fatal(err)
	}
}

// TestDaemonNeverReadsRootOnlyConfig: the daemon takes what it needs from the network, firewall
// and system configuration from the snapshot root writes, so it starts when network and system
// are root's alone, and nothing of theirs but the facts reaches it.
func TestDaemonNeverReadsRootOnlyConfig(t *testing.T) {
	cfgPath := rootOnlySite(t)
	snap := filepath.Join(t.TempDir(), "snapshot.json")
	rootSnapshot(t, filepath.Dir(cfgPath), snap)

	cfg, zones, err := loadConfig(flags{config: cfgPath, snapshot: snap})
	if err != nil {
		t.Fatalf("loadConfig with network and system unreadable: %v", err)
	}
	if !reflect.DeepEqual(zones, map[string][]string{"lan": {"br-lan"}}) {
		t.Errorf("zones = %v; want lan on br-lan, from the snapshot", zones)
	}
	if cfg.TZ != "Europe/Kyiv" || cfg.Site != "Home" {
		t.Errorf("config = %+v; want the site from the rollcall file and the zone from the snapshot", cfg)
	}
}

// TestDaemonRefusesWithoutSnapshot: with no snapshot the daemon refuses to start and says how
// the snapshot is made; it never falls back to reading the files root keeps to itself.
func TestDaemonRefusesWithoutSnapshot(t *testing.T) {
	cfgPath := rootOnlySite(t)
	snap := filepath.Join(t.TempDir(), "snapshot.json")
	_, _, err := loadConfig(flags{config: cfgPath, snapshot: snap})
	if err == nil {
		t.Fatal("loadConfig without a snapshot succeeded")
	}
	for _, want := range []string{"refusing to start", snap, "rollcall snapshot"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not say %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "permission denied") {
		t.Errorf("error %q comes from opening a root-only file: the daemon fell back to reading it", err)
	}
}

// TestDaemonRefusesWithoutSnapshotWhenFilesAreReadable: where network and system happen to be
// readable (an image that leaves them 0644), a missing snapshot still stops the start: the
// daemon has no path that reads those files, whatever their mode.
func TestDaemonRefusesWithoutSnapshotWhenFilesAreReadable(t *testing.T) {
	dir := t.TempDir()
	for name, text := range map[string]string{"rollcall": siteRollcall, "firewall": siteFirewall, "network": siteNetwork, "system": siteSystem} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	_, _, err := loadConfig(flags{config: filepath.Join(dir, "rollcall"), snapshot: filepath.Join(t.TempDir(), "snapshot.json")})
	if err == nil || !strings.Contains(err.Error(), "refusing to start") {
		t.Fatalf("loadConfig with readable files and no snapshot: %v; want a refusal", err)
	}
}

// TestDaemonRefusesStaleSnapshot: a snapshot written before network changed is refused, so a
// respawned daemon never runs on zones the router no longer has.
func TestDaemonRefusesStaleSnapshot(t *testing.T) {
	cfgPath := rootOnlySite(t)
	dir := filepath.Dir(cfgPath)
	snap := filepath.Join(t.TempDir(), "snapshot.json")
	rootSnapshot(t, dir, snap)
	later := time.Now().Add(time.Minute)
	if err := os.Chtimes(filepath.Join(dir, "network"), later, later); err != nil {
		t.Fatal(err)
	}
	_, _, err := loadConfig(flags{config: cfgPath, snapshot: snap})
	if err == nil || !strings.Contains(err.Error(), "network changed after the snapshot was written") {
		t.Fatalf("loadConfig with network newer than the snapshot: %v; want a refusal naming network", err)
	}
	if strings.Contains(err.Error(), "CANARY-123:abc") {
		t.Errorf("error %q repeats a value of the network file", err)
	}
}
