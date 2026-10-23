package store

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// countSyncs replaces syncFile with a counting fake for the test.
func countSyncs(t *testing.T) *int {
	t.Helper()
	n := 0
	orig := syncFile
	syncFile = func(f *os.File) error {
		n++
		return orig(f)
	}
	t.Cleanup(func() { syncFile = orig })
	return &n
}

// TestOpenSyncs: a store from Open syncs every write, the file and then its
// directory, so the write survives a power cut.
func TestOpenSyncs(t *testing.T) {
	n := countSyncs(t)
	s, err := Open(filepath.Join(t.TempDir(), "s"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.WriteFileAtomic("a.json", []byte("{}")); err != nil {
		t.Fatal(err)
	}
	if *n != 2 {
		t.Fatalf("Open's store synced %d times for one write, want 2 (the file and its directory)", *n)
	}
}

// TestOpenNoSyncSkipsSync: a store from OpenNoSync writes the same file, mode
// 0600 and atomically, without a single sync.
func TestOpenNoSyncSkipsSync(t *testing.T) {
	n := countSyncs(t)
	dir := filepath.Join(t.TempDir(), "s")
	s, err := OpenNoSync(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{[]byte("one"), []byte("two")} {
		if err := s.WriteFileAtomic("a.json", data); err != nil {
			t.Fatal(err)
		}
	}
	if *n != 0 {
		t.Fatalf("OpenNoSync's store synced %d times, want none", *n)
	}
	b, err := s.ReadFile("a.json")
	if err != nil || !bytes.Equal(b, []byte("two")) {
		t.Fatalf("read back %q, %v; want two", b, err)
	}
	info, err := os.Stat(filepath.Join(dir, "a.json"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v, %v; want 0600", info.Mode().Perm(), err)
	}
	es, _ := os.ReadDir(dir)
	if len(es) != 1 {
		t.Fatalf("%d entries in the store after two writes, want 1 (no temporary file left)", len(es))
	}
	// The same refusals as Open's store.
	if _, err := OpenNoSync(filepath.Join(dir, "a.json")); err == nil {
		t.Fatal("OpenNoSync accepted a file in place of the directory")
	}
}

// noSyncCallers returns the Go files under root, other than tests, the
// simulator and this package, that call OpenNoSync.
func noSyncCallers(root string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if strings.HasPrefix(d.Name(), ".") && rel != "." || rel == "internal/sim" || rel == "internal/store" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if bytes.Contains(b, []byte("OpenNoSync(")) {
			out = append(out, rel)
		}
		return nil
	})
	return out, err
}

// TestOpenNoSyncOnlyInTestsAndSim: no code that runs on a router calls
// OpenNoSync; only tests and internal/sim do. The scan must find a planted
// caller, and must not count the simulator.
func TestOpenNoSyncOnlyInTestsAndSim(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("measured nothing: no go.mod at %s", root)
	}
	got, err := noSyncCallers(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("OpenNoSync is called outside tests and internal/sim: %v", got)
	}

	plant := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(plant, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("cmd/rollcalld/main.go", "package main\nvar _, _ = store.OpenNoSync(\"/etc/rollcall\")\n")
	write("internal/sim/sim.go", "package sim\nvar _, _ = store.OpenNoSync(\"x\")\n")
	write("internal/node/node_test.go", "package node\nvar _, _ = store.OpenNoSync(\"x\")\n")
	got, err = noSyncCallers(plant)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "cmd/rollcalld/main.go" {
		t.Fatalf("the scan found %v in the planted tree, want only cmd/rollcalld/main.go", got)
	}
}
