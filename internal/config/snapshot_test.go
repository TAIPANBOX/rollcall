package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

// snapshotSite writes the fixture firewall, network and system files and returns their
// directory.
func snapshotSite(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for name, text := range map[string]string{
		"rollcall": "config rollcall\n", "firewall": fixtureFirewall,
		"network": fixtureNetwork + secretNetwork, "system": fixtureSystem,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// secretNetwork is what /etc/config/network may hold besides the devices: a PPPoE password and
// a WireGuard private key. None of it may reach the snapshot.
const secretNetwork = `
config interface 'dsl'
	option proto 'pppoe'
	option username 'CANARY-USER'
	option password 'CANARY-123:abc'

config interface 'wg0x'
	option proto 'wireguard'
	option private_key 'CANARY-KEY-yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk='
`

func factsOf(t *testing.T, dir string) Snapshot {
	t.Helper()
	s, err := Facts(filepath.Join(dir, "firewall"), filepath.Join(dir, "system"), filepath.Join(dir, "network"))
	if err != nil {
		t.Fatalf("Facts: %v", err)
	}
	return s
}

// TestFactsHoldOnlyTheFacts: the snapshot holds every named firewall zone with its devices and
// whether it faces the internet, and the time zone; no value of the network file but device
// names, so no password or key, ever reaches it.
func TestFactsHoldOnlyTheFacts(t *testing.T) {
	dir := snapshotSite(t)
	s := factsOf(t, dir)
	want := []SnapshotZone{
		{Name: "ghost", Devices: []string{}},
		{Name: "lan", Devices: []string{"br-lan", "lan3.20"}},
		{Name: "legacy", Devices: []string{"br-oldlan", "eth0.2"}},
		{Name: "loop", Devices: []string{}},
		{Name: "vpn", Devices: []string{"tailscale0", "wg0"}},
		{Name: "wan", Devices: []string{"eth1"}, External: true},
	}
	if !reflect.DeepEqual(s.Zones, want) {
		t.Errorf("zones:\n got %+v\nwant %+v", s.Zones, want)
	}
	if s.TZ != "Europe/Kyiv" || s.TZSource != TZSystem || s.Version != SnapshotVersion {
		t.Errorf("tz %q from %q, version %d", s.TZ, s.TZSource, s.Version)
	}
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"CANARY", "pppoe", "private_key", "password"} {
		if bytes.Contains(b, []byte(secret)) {
			t.Errorf("the snapshot carries %q: %s", secret, b)
		}
	}
}

// TestSnapshotMatchesLoad: the daemon's configuration from the rollcall file and the snapshot is
// the one Load builds from the four files, so the root side and the daemon parse one way.
func TestSnapshotMatchesLoad(t *testing.T) {
	dir := snapshotSite(t)
	rc := filepath.Join(dir, "rollcall")
	if err := os.WriteFile(rc, []byte(fixtureRollcall), 0o644); err != nil {
		t.Fatal(err)
	}
	wantCfg, wantZones, err := Load(rc, filepath.Join(dir, "firewall"), filepath.Join(dir, "system"), filepath.Join(dir, "network"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	path := filepath.Join(t.TempDir(), "snapshot.json")
	if err := WriteSnapshot(path, factsOf(t, dir)); err != nil {
		t.Fatalf("WriteSnapshot: %v", err)
	}
	s, err := ReadSnapshot(path, dir)
	if err != nil {
		t.Fatalf("ReadSnapshot: %v", err)
	}
	cfg, zones, err := LoadWithSnapshot(rc, s)
	if err != nil {
		t.Fatalf("LoadWithSnapshot: %v", err)
	}
	if !reflect.DeepEqual(cfg, wantCfg) || !reflect.DeepEqual(zones, wantZones) {
		t.Errorf("from the snapshot:\n %+v %v\nfrom the files:\n %+v %v", cfg, zones, wantCfg, wantZones)
	}

	// A zone that masquerades is still refused without static peers, from the snapshot alone.
	if err := os.WriteFile(rc, []byte("config rollcall\n\tlist peer_zone 'wan'\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadWithSnapshot(rc, s); err == nil || !strings.Contains(err.Error(), "faces the internet") {
		t.Errorf("wan without static peers from the snapshot: %v; want a refusal", err)
	}
}

// TestWriteSnapshotFile: the file is replaced whole, mode 0640, and reads back as written.
func TestWriteSnapshotFile(t *testing.T) {
	dir := snapshotSite(t)
	run := t.TempDir()
	path := filepath.Join(run, "snapshot.json")
	if err := os.WriteFile(path, []byte("an older snapshot\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := factsOf(t, dir)
	if err := WriteSnapshot(path, s); err != nil {
		t.Fatalf("WriteSnapshot: %v", err)
	}
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode() != SnapshotMode {
		t.Errorf("mode %v; want %v", fi.Mode(), SnapshotMode)
	}
	got, err := ReadSnapshot(path, dir)
	if err != nil {
		t.Fatalf("ReadSnapshot: %v", err)
	}
	if !reflect.DeepEqual(got, s) {
		t.Errorf("read back:\n got %+v\nwant %+v", got, s)
	}
	entries, err := os.ReadDir(run)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("the run directory holds %d entries; want only the snapshot, no temporary file left", len(entries))
	}
}

// TestWriteSnapshotRefusesALinkedDirectory: root never writes through a link put where the run
// directory should be.
func TestWriteSnapshotRefusesALinkedDirectory(t *testing.T) {
	s := factsOf(t, snapshotSite(t))
	target := t.TempDir()
	link := filepath.Join(t.TempDir(), "run")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := WriteSnapshot(filepath.Join(link, "snapshot.json"), s); err == nil {
		t.Fatal("WriteSnapshot wrote through a symbolic link")
	}
	if entries, _ := os.ReadDir(target); len(entries) != 0 {
		t.Errorf("the link's target holds %d entries", len(entries))
	}
	if err := WriteSnapshot(filepath.Join(t.TempDir(), "none", "snapshot.json"), s); err == nil {
		t.Fatal("WriteSnapshot made a missing run directory")
	}
}

// TestReadSnapshotRefusesStale: a snapshot is refused once a file it was made from is not the
// one it was made from: network or system with another size or time, firewall with other
// content, or a system file that was missing and now exists.
func TestReadSnapshotRefusesStale(t *testing.T) {
	cases := []struct {
		name   string
		change func(t *testing.T, dir string)
		want   string
	}{
		{"network touched", func(t *testing.T, dir string) {
			later := time.Now().Add(time.Minute)
			if err := os.Chtimes(filepath.Join(dir, "network"), later, later); err != nil {
				t.Fatal(err)
			}
		}, "network changed"},
		{"system rewritten", func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, "system"), []byte("config system\n\toption zonename 'UTC'\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, "system changed"},
		{"firewall content", func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, "firewall"), []byte("config zone\n\toption name 'lan'\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}, "firewall changed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := snapshotSite(t)
			path := filepath.Join(t.TempDir(), "snapshot.json")
			if err := WriteSnapshot(path, factsOf(t, dir)); err != nil {
				t.Fatal(err)
			}
			tc.change(t, dir)
			_, err := ReadSnapshot(path, dir)
			if !errors.Is(err, ErrSnapshotStale) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ReadSnapshot after %s: %v; want %v naming %q", tc.name, err, ErrSnapshotStale, tc.want)
			}
		})
	}

	t.Run("system created", func(t *testing.T) {
		dir := snapshotSite(t)
		if err := os.Remove(filepath.Join(dir, "system")); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "snapshot.json")
		s := factsOf(t, dir)
		if s.TZ != "UTC" || s.TZSource != TZDefault || !s.Sources[2].Missing {
			t.Fatalf("without a system file: %+v", s)
		}
		if err := WriteSnapshot(path, s); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadSnapshot(path, dir); err != nil {
			t.Fatalf("ReadSnapshot with system still missing: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "system"), []byte(fixtureSystem), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadSnapshot(path, dir); !errors.Is(err, ErrSnapshotStale) {
			t.Fatalf("ReadSnapshot after system appeared: %v; want %v", err, ErrSnapshotStale)
		}
	})

	t.Run("sources not visible", func(t *testing.T) {
		// Inside the jail the daemon sees none of the three files, so it cannot compare; the
		// root side keeps the snapshot current there.
		dir := snapshotSite(t)
		path := filepath.Join(t.TempDir(), "snapshot.json")
		if err := WriteSnapshot(path, factsOf(t, dir)); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadSnapshot(path, t.TempDir()); err != nil {
			t.Fatalf("ReadSnapshot where the sources are not visible: %v", err)
		}
	})
}

// validSnapshotJSON is a snapshot whose sources the stale check cannot see (it reads them from
// an empty directory), as the daemon sees it inside its jail.
func validSnapshotJSON() map[string]any {
	return map[string]any{
		"version": 1,
		"sources": []any{
			map[string]any{"name": "firewall", "size": 10, "sha256": strings.Repeat("ab", 32)},
			map[string]any{"name": "network", "size": 20, "mtime_ns": 1_700_000_000_000_000_000},
			map[string]any{"name": "system", "missing": true},
		},
		"zones": []any{
			map[string]any{"name": "lan", "devices": []any{"br-lan", "lan3.20"}, "external": false},
			map[string]any{"name": "wan", "devices": []any{"eth1"}, "external": true},
		},
		"tz":        "Europe/Kyiv",
		"tz_source": "zonename",
	}
}

// TestReadSnapshotRefusesHostile: the daemon reads a file in a directory it owns, so it reads it
// as untrusted: every field is checked, nothing unknown is passed over, and its size is bounded.
func TestReadSnapshotRefusesHostile(t *testing.T) {
	set := func(path string, v any) func(map[string]any) {
		return func(m map[string]any) {
			keys := strings.Split(path, ".")
			cur := m
			for _, k := range keys[:len(keys)-1] {
				cur = cur[k].(map[string]any)
			}
			cur[keys[len(keys)-1]] = v
		}
	}
	zone := func(i int, k string, v any) func(map[string]any) {
		return func(m map[string]any) { m["zones"].([]any)[i].(map[string]any)[k] = v }
	}
	source := func(i int, k string, v any) func(map[string]any) {
		return func(m map[string]any) { m["sources"].([]any)[i].(map[string]any)[k] = v }
	}
	many := func(n int, item func(int) any) []any {
		out := make([]any, n)
		for i := range out {
			out[i] = item(i)
		}
		return out
	}
	cases := []struct {
		name string
		edit func(map[string]any)
		want string
	}{
		{"unknown field", set("token", "CANARY-123:abc"), "unknown field"},
		{"version 2", set("version", 2), "version"},
		{"zone name with a slash", zone(0, "name", "lan/../x"), "zone name"},
		{"zone name with a space", zone(0, "name", "lan x"), "zone name"},
		{"zone name empty", zone(0, "name", ""), "zone name"},
		{"zone name too long", zone(0, "name", strings.Repeat("z", 65)), "zone name"},
		{"zones out of order", func(m map[string]any) {
			z := m["zones"].([]any)
			z[0], z[1] = z[1], z[0]
		}, "order"},
		{"zone twice", func(m map[string]any) {
			z := m["zones"].([]any)
			m["zones"] = append(z, z[1])
		}, "order"},
		{"device with a slash", zone(0, "devices", []any{"../etc"}), "device"},
		{"device too long", zone(0, "devices", []any{"averyveryverylongname0"}), "device"},
		{"device with a newline", zone(0, "devices", []any{"br-lan\nx"}), "device"},
		{"devices twice", zone(0, "devices", []any{"br-lan", "br-lan"}), "order"},
		{"too many devices", zone(0, "devices", many(MaxZoneDevices+1, func(i int) any { return "d" + strings.Repeat("0", 3-len(itoa(i))) + itoa(i) })), "devices"},
		{"too many zones", set("zones", many(MaxSnapshotZones+1, func(i int) any {
			return map[string]any{"name": "z" + strings.Repeat("0", 3-len(itoa(i))) + itoa(i), "devices": []any{}}
		})), "zones"},
		{"time zone path", set("tz", "../../etc/passwd"), "time zone"},
		{"time zone source", set("tz_source", "elsewhere"), "tz_source"},
		{"default zone not UTC", func(m map[string]any) { m["tz_source"] = "default" }, "UTC"},
		{"no sources", set("sources", []any{}), "sources"},
		{"source renamed", source(1, "name", "wireless"), "sources"},
		{"firewall missing", source(0, "missing", true), "missing"},
		{"firewall without a digest", source(0, "sha256", ""), "sha256"},
		{"firewall digest not hex", source(0, "sha256", strings.Repeat("zz", 32)), "sha256"},
		{"network size negative", source(1, "size", -1), "size"},
		{"network size too large", source(1, "size", MaxUCISize+1), "size"},
		{"network with a digest", source(1, "sha256", strings.Repeat("ab", 32)), "sha256"},
		{"wrong type", set("zones", "lan"), "cannot unmarshal"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := validSnapshotJSON()
			tc.edit(m)
			b, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "snapshot.json")
			if err := os.WriteFile(path, b, 0o640); err != nil {
				t.Fatal(err)
			}
			_, err = ReadSnapshot(path, t.TempDir())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ReadSnapshot accepted or misnamed %s: %v; want %q", tc.name, err, tc.want)
			}
			if strings.Contains(err.Error(), "CANARY") {
				t.Errorf("error repeats a value: %v", err)
			}
		})
	}

	write := func(t *testing.T, b []byte, mode os.FileMode) string {
		path := filepath.Join(t.TempDir(), "snapshot.json")
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	valid, err := json.Marshal(validSnapshotJSON())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReadSnapshot(write(t, valid, 0o640), t.TempDir()); err != nil {
		t.Fatalf("the valid snapshot: %v", err)
	}
	for name, tc := range map[string]struct {
		data []byte
		mode os.FileMode
		want string
	}{
		"oversize":         {append(valid, bytes.Repeat([]byte(" "), MaxSnapshotSize)...), 0o640, "larger than"},
		"trailing value":   {append(append([]byte{}, valid...), []byte(`{"version":1}`)...), 0o640, "trailing"},
		"group writable":   {valid, 0o660, "writable"},
		"world writable":   {valid, 0o646, "writable"},
		"empty":            {nil, 0o640, "EOF"},
		"not json":         {[]byte("config zone\n"), 0o640, "invalid character"},
		"null":             {[]byte("null"), 0o640, "version"},
		"sources not list": {[]byte(`{"version":1,"sources":{}}`), 0o640, "cannot unmarshal"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ReadSnapshot(write(t, tc.data, tc.mode), t.TempDir()); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ReadSnapshot of %s: %v; want %q", name, err, tc.want)
			}
		})
	}

	t.Run("symbolic link", func(t *testing.T) {
		target := write(t, valid, 0o640)
		link := filepath.Join(t.TempDir(), "snapshot.json")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadSnapshot(link, t.TempDir()); err == nil || !strings.Contains(err.Error(), "regular file") {
			t.Fatalf("ReadSnapshot through a link: %v; want a refusal", err)
		}
	})
	t.Run("missing", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "snapshot.json")
		if _, err := ReadSnapshot(path, t.TempDir()); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("ReadSnapshot of a missing file: %v; want %v", err, os.ErrNotExist)
		}
	})
}

// TestFactsRefuse: the root side refuses a firewall it cannot describe within the snapshot's
// bounds, and reports a broken network or system file by its line alone, never its text.
func TestFactsRefuse(t *testing.T) {
	dir := snapshotSite(t)
	var many strings.Builder
	for i := range MaxSnapshotZones + 1 {
		many.WriteString("config zone\n\toption name 'z" + itoa(i) + "'\n")
	}
	if err := os.WriteFile(filepath.Join(dir, "firewall"), []byte(many.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Facts(filepath.Join(dir, "firewall"), filepath.Join(dir, "system"), filepath.Join(dir, "network")); err == nil || !strings.Contains(err.Error(), "zones") {
		t.Errorf("Facts with %d zones: %v; want a refusal", MaxSnapshotZones+1, err)
	}

	dir = snapshotSite(t)
	if err := os.WriteFile(filepath.Join(dir, "network"), []byte("config interface 'wan'\n\tCANARY-123:abc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Facts(filepath.Join(dir, "firewall"), filepath.Join(dir, "system"), filepath.Join(dir, "network"))
	if err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("Facts with a broken network line: %v; want one naming line 2", err)
	}
	if strings.Contains(err.Error(), "CANARY") {
		t.Errorf("error repeats the network file's text: %v", err)
	}

	// Zone names the firewall rule builder gives no rule to are left out, not refused.
	dir = snapshotSite(t)
	if err := os.WriteFile(filepath.Join(dir, "firewall"), []byte(fixtureFirewall+"config zone\n\toption name 'odd.name'\n\tlist device 'eth9'\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, z := range factsOf(t, dir).Zones {
		if z.Name == "odd.name" {
			t.Errorf("a zone name outside [A-Za-z0-9_-] reached the snapshot")
		}
	}
}

func itoa(i int) string { return strconv.Itoa(i) }

// TestRemoveSnapshot: a failed rewrite leaves no snapshot behind, and a missing one is no error.
func TestRemoveSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snapshot.json")
	if err := RemoveSnapshot(path); err != nil {
		t.Fatalf("RemoveSnapshot of a missing file: %v", err)
	}
	if err := os.WriteFile(path, []byte("{}"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := RemoveSnapshot(path); err != nil {
		t.Fatalf("RemoveSnapshot: %v", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the snapshot is still there: %v", err)
	}
}
