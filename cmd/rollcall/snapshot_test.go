package main

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TAIPANBOX/rollcall/internal/config"
)

// snapshotFiles writes a firewall, network and system file into a new directory and returns
// the path rollcall's own file would have there.
func snapshotFiles(t *testing.T, network string) string {
	t.Helper()
	dir := t.TempDir()
	for name, text := range map[string]string{
		"firewall": "config zone\n\toption name 'lan'\n\tlist network 'lan'\n",
		"network":  network,
		"system":   "config system\n\toption zonename 'Europe/Kyiv'\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(dir, "rollcall")
}

const snapshotNetwork = "config interface 'lan'\n\toption device 'br-lan'\n\n" +
	"config interface 'wan'\n\toption proto 'pppoe'\n\toption password 'CANARY-123:abc'\n"

// TestSnapshotCommand: rollcall snapshot, run as root by the init script and hotplug, writes the
// facts from the files beside the configuration to the snapshot the daemon reads, mode 0640,
// and none of the network file's secrets.
func TestSnapshotCommand(t *testing.T) {
	cfgPath := snapshotFiles(t, snapshotNetwork)
	snap := filepath.Join(t.TempDir(), "snapshot.json")
	var out, errb bytes.Buffer
	c := &cli{stdout: &out, stderr: &errb, configPath: cfgPath, snapshotPath: snap}
	if code := c.run([]string{"snapshot"}); code != 0 {
		t.Fatalf("rollcall snapshot: exit %d, %q", code, errb.String())
	}
	s, err := config.ReadSnapshot(snap, filepath.Dir(cfgPath))
	if err != nil {
		t.Fatalf("the snapshot written does not read back: %v", err)
	}
	if len(s.Zones) != 1 || s.Zones[0].Name != "lan" || strings.Join(s.Zones[0].Devices, ",") != "br-lan" || s.TZ != "Europe/Kyiv" {
		t.Errorf("snapshot %+v; want lan on br-lan in Europe/Kyiv", s)
	}
	fi, err := os.Stat(snap)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o640 {
		t.Errorf("mode %v; want 0640", fi.Mode().Perm())
	}
	data, err := os.ReadFile(snap)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("CANARY")) {
		t.Errorf("the snapshot carries the PPPoE password: %s", data)
	}

	// --config names another configuration directory, as the CI harness does.
	other := snapshotFiles(t, "config interface 'lan'\n\toption device 'eth0'\n")
	c = &cli{stdout: &out, stderr: &errb, configPath: cfgPath, snapshotPath: snap}
	if code := c.run([]string{"snapshot", "--config", other}); code != 0 {
		t.Fatalf("rollcall snapshot --config: exit %d, %q", code, errb.String())
	}
	if s, err := config.ReadSnapshot(snap, filepath.Dir(other)); err != nil || s.Zones[0].Devices[0] != "eth0" {
		t.Errorf("after --config: %+v, %v; want lan on eth0", s, err)
	}
}

// TestSnapshotCommandFailsClosed: when the files cannot be described, the old snapshot goes too,
// so the daemon refuses to start instead of running on facts that may be out of date; the error
// names the line, never the file's text.
func TestSnapshotCommandFailsClosed(t *testing.T) {
	cfgPath := snapshotFiles(t, snapshotNetwork)
	snap := filepath.Join(t.TempDir(), "snapshot.json")
	var out, errb bytes.Buffer
	c := &cli{stdout: &out, stderr: &errb, configPath: cfgPath, snapshotPath: snap}
	if code := c.run([]string{"snapshot"}); code != 0 {
		t.Fatalf("rollcall snapshot: exit %d, %q", code, errb.String())
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(cfgPath), "network"), []byte("config interface 'wan'\n\tCANARY-123:abc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	errb.Reset()
	if code := c.run([]string{"snapshot"}); code != 1 {
		t.Fatalf("rollcall snapshot with a broken network file: exit %d; want 1", code)
	}
	if !strings.Contains(errb.String(), "line 2") || strings.Contains(errb.String(), "CANARY") {
		t.Errorf("error %q; want the line number and none of the text", errb.String())
	}
	if _, err := os.Stat(snap); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the old snapshot is still there after a failed rewrite: %v", err)
	}

	for _, args := range [][]string{{"snapshot", "extra"}, {"snapshot", "--", "x"}, {"snapshot", "--config"}, {"snapshot", "--out", "/etc/passwd"}} {
		if code := c.run(args); code != 2 {
			t.Errorf("%q: exit %d; want 2", args, code)
		}
	}
}
