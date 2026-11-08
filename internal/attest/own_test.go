package attest

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/events"
	"github.com/TAIPANBOX/rollcall/internal/history"
	"github.com/TAIPANBOX/rollcall/internal/identity"
	"github.com/TAIPANBOX/rollcall/internal/ids"
	"github.com/TAIPANBOX/rollcall/internal/node"
	"github.com/TAIPANBOX/rollcall/internal/store"
)

// stateDir returns a private state directory holding a new identity.
func stateDir(t *testing.T) (string, *identity.Identity) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "rollcall")
	id, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := id.Save(dir); err != nil {
		t.Fatal(err)
	}
	return dir, id
}

// chainOf makes id's chain: for each boot (ID byte, seq, version) a boot
// record and then one event, in order.
func chainOf(t *testing.T, id *identity.Identity, boots ...node.BootBody) []history.Entry {
	t.Helper()
	var es []history.Entry
	head := history.Head{}
	add := func(e history.Entry, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		es = append(es, e)
		head = history.Head{Seq: e.Seq, Hash: e.Hash()}
	}
	for _, b := range boots {
		add(node.NewBoot(id, head, b))
		add(node.NewEvent(id, head, node.EventBody{Subject: id.ID, Type: events.WanDown,
			At: node.At{Wall: time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC), Mono: 1, Boot: b.Boot.ID}}))
	}
	return es
}

func boot(n byte, seq uint64, version string) node.BootBody {
	return node.BootBody{Boot: node.Boot{ID: ids.BootID{n, 15: n}, Seq: seq}, Version: version}
}

func writeChain(t *testing.T, dir string, id *identity.Identity, es []history.Entry) {
	t.Helper()
	b, err := json.Marshal(es)
	if err != nil {
		t.Fatal(err)
	}
	writeRaw(t, dir, id, b)
}

func writeRaw(t *testing.T, dir string, id *identity.Identity, b []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, node.HistoryFile(id.ID)), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestReadOwnTakesHeadAndLatestBoot: the head is the chain's newest entry,
// and the boot is the newest boot record's, also when events follow it and
// when the file starts past seq 1 (a pruned chain).
func TestReadOwnTakesHeadAndLatestBoot(t *testing.T) {
	dir, id := stateDir(t)
	es := chainOf(t, id, boot(1, 4, "25.12.4"), boot(2, 5, "25.12.5"))
	for name, kept := range map[string][]history.Entry{"whole": es, "pruned": es[1:]} {
		writeChain(t, dir, id, kept)
		o, err := ReadOwn(dir)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		last := es[len(es)-1]
		if o.ID.ID != id.ID || o.Head != (history.Head{Seq: last.Seq, Hash: last.Hash()}) {
			t.Errorf("%s: member %s head %+v, want %s and seq %d", name, o.ID.ID, o.Head, id.ID, last.Seq)
		}
		if o.BootID != (ids.BootID{2, 15: 2}) || o.BootSeq != 5 || o.OpenWrt != "25.12.5" {
			t.Errorf("%s: boot %s seq %d %q, want the latest record's", name, o.BootID, o.BootSeq, o.OpenWrt)
		}
		if !ed25519.PublicKey(o.ID.Sign.Public().(ed25519.PublicKey)).Equal(id.Sign.Public()) {
			t.Errorf("%s: another key", name)
		}
	}
	// The boot record itself as the head.
	writeChain(t, dir, id, es[:3])
	o, err := ReadOwn(dir)
	if err != nil || o.Head.Seq != 3 || o.BootSeq != 5 {
		t.Errorf("head on a boot record: %+v, %v", o, err)
	}
}

// TestReadOwnWithoutHistory: no history file, or an empty one, is an empty
// chain: head and boot zero; the member key is still read.
func TestReadOwnWithoutHistory(t *testing.T) {
	dir, id := stateDir(t)
	for _, name := range []string{"no file", "an empty chain"} {
		if name == "an empty chain" {
			writeRaw(t, dir, id, []byte("[]"))
		}
		o, err := ReadOwn(dir)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if o.ID == nil || o.ID.ID != id.ID || o.Head != (history.Head{}) || o.BootID != (ids.BootID{}) || o.BootSeq != 0 || o.OpenWrt != "" {
			t.Errorf("%s: %+v", name, o)
		}
	}
	// A chain with no boot record yet.
	e, err := node.NewEvent(id, history.Head{}, node.EventBody{Subject: id.ID, Type: events.WanUp})
	if err != nil {
		t.Fatal(err)
	}
	writeChain(t, dir, id, []history.Entry{e})
	if o, err := ReadOwn(dir); err != nil || o.Head.Seq != 1 || o.BootSeq != 0 {
		t.Errorf("a chain without a boot record: %+v, %v", o, err)
	}
}

// TestReadOwnRefusesBrokenHistory: nothing is taken from a history file
// that is not the member's own chain, verified whole.
func TestReadOwnRefusesBrokenHistory(t *testing.T) {
	dir, id := stateDir(t)
	es := chainOf(t, id, boot(1, 1, "25.12.4"), boot(2, 2, "25.12.5"))
	other, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	foreign := chainOf(t, other, boot(3, 1, "25.12.4"))
	// An entry the member signed whose boot body rollcall never writes.
	badBoot, err := history.NewEntry(id, history.Head{Seq: es[3].Seq, Hash: es[3].Hash()}, history.KindBoot,
		map[string]any{"boot": map[string]any{"id": ids.BootID{9}, "seq": 0}, "version": "25.12.5", "planned": false})
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]history.Entry{}, es...)
	tampered[1].Body = json.RawMessage(`{"subject":"` + id.ID.String() + `","type":"wan_up"}`)
	// A chain the member's own key signed, under another member's origin:
	// every signature verifies under the member's key, so only the origin
	// tells it is not the member's chain.
	impostor := chainOf(t, &identity.Identity{ID: other.ID, Sign: id.Sign, Recv: id.Recv}, boot(4, 1, "25.12.4"))
	// A chain under the member's ID signed by another key: origin and links
	// hold, only the signatures tell.
	forged := chainOf(t, &identity.Identity{ID: id.ID, Sign: other.Sign, Recv: other.Recv}, boot(5, 1, "25.12.4"))
	// The newest entry changed after signing: no later entry links to it, so
	// only its signature tells.
	lastChanged := append([]history.Entry{}, es...)
	lastChanged[3].Body = json.RawMessage(`{"subject":"` + id.ID.String() + `","type":"wan_up"}`)

	cases := map[string]func() []byte{
		"another member's chain":        func() []byte { return marshal(t, foreign) },
		"another origin, our signature": func() []byte { return marshal(t, impostor) },
		"our origin, another key":       func() []byte { return marshal(t, forged) },
		"the newest entry changed":      func() []byte { return marshal(t, lastChanged) },
		"a body changed after signing":  func() []byte { return marshal(t, tampered) },
		"an entry left out":             func() []byte { return marshal(t, append(append([]history.Entry{}, es[:1]...), es[2:]...)) },
		"two entries swapped":           func() []byte { return marshal(t, []history.Entry{es[0], es[2], es[1], es[3]}) },
		"a latest boot record not ours": func() []byte { return marshal(t, append(append([]history.Entry{}, es...), badBoot)) },
		"an unknown field":              func() []byte { return []byte(`[{"origin":"` + id.ID.String() + `","x":1}]`) },
		"data after the array":          func() []byte { return append(marshal(t, es), []byte(`[]`)...) },
		"not JSON":                      func() []byte { return []byte("history") },
		"an object":                     func() []byte { return []byte(`{}`) },
	}
	for name, file := range cases {
		writeRaw(t, dir, id, file())
		o, err := ReadOwn(dir)
		if !errors.Is(err, ErrHistory) || o.ID != nil {
			t.Errorf("%s: ReadOwn = %+v, %v; want ErrHistory and nothing", name, o, err)
		}
	}
	// The same chain whole is read, so each case above broke one thing.
	writeChain(t, dir, id, es)
	if _, err := ReadOwn(dir); err != nil {
		t.Errorf("control: the whole chain is refused: %v", err)
	}
}

func marshal(t *testing.T, es []history.Entry) []byte {
	t.Helper()
	b, err := json.Marshal(es)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestReadOwnKeyChecks: the key and the history are read with the checks
// the daemon's start makes: a missing identity, files open to group or
// others, a directory others may write, and a link in a file's place are
// refused, and nothing is signed.
func TestReadOwnKeyChecks(t *testing.T) {
	t.Run("no identity", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "empty")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadOwn(dir); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("ReadOwn = %v, want fs.ErrNotExist", err)
		}
	})
	t.Run("no directory", func(t *testing.T) {
		if _, err := ReadOwn(filepath.Join(t.TempDir(), "none")); err == nil {
			t.Error("ReadOwn of a missing directory succeeds")
		}
	})
	t.Run("identity open to others", func(t *testing.T) {
		dir, _ := stateDir(t)
		if err := os.Chmod(filepath.Join(dir, "identity.json"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadOwn(dir); !errors.Is(err, identity.ErrPermissions) {
			t.Errorf("ReadOwn = %v, want identity.ErrPermissions", err)
		}
	})
	t.Run("directory others may write", func(t *testing.T) {
		dir, _ := stateDir(t)
		if err := os.Chmod(dir, 0o777); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadOwn(dir); !errors.Is(err, identity.ErrPermissions) {
			t.Errorf("ReadOwn = %v, want identity.ErrPermissions", err)
		}
	})
	t.Run("history open to others", func(t *testing.T) {
		dir, id := stateDir(t)
		writeChain(t, dir, id, chainOf(t, id, boot(1, 1, "25.12.4")))
		if err := os.Chmod(filepath.Join(dir, node.HistoryFile(id.ID)), 0o640); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadOwn(dir); !errors.Is(err, store.ErrPermissions) {
			t.Errorf("ReadOwn = %v, want store.ErrPermissions", err)
		}
	})
	t.Run("history is a link", func(t *testing.T) {
		dir, id := stateDir(t)
		target := filepath.Join(t.TempDir(), "elsewhere.json")
		if err := os.WriteFile(target, marshal(t, chainOf(t, id, boot(1, 1, "25.12.4"))), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(dir, node.HistoryFile(id.ID))); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadOwn(dir); !errors.Is(err, store.ErrNotRegular) {
			t.Errorf("ReadOwn = %v, want store.ErrNotRegular", err)
		}
	})
}

// fileState is what a directory listing says of one file.
type fileState struct {
	mode  fs.FileMode
	size  int64
	mtime time.Time
	sum   [32]byte
}

// snapshot returns the state of every entry of dir, the directory itself
// included under ".".
func snapshot(t *testing.T, dir string) map[string]fileState {
	t.Helper()
	out := map[string]fileState{}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, err := os.Lstat(path)
		if err != nil {
			return err
		}
		st := fileState{mode: fi.Mode(), size: fi.Size(), mtime: fi.ModTime()}
		if fi.Mode().IsRegular() {
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			st.sum = sha256.Sum256(b)
		}
		rel, _ := filepath.Rel(dir, path)
		out[rel] = st
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// sameState reports the differences between two snapshots.
func sameState(before, after map[string]fileState) []string {
	var diffs []string
	for name, b := range before {
		a, ok := after[name]
		switch {
		case !ok:
			diffs = append(diffs, name+" removed")
		case a != b:
			diffs = append(diffs, fmt.Sprintf("%s changed: %+v -> %+v", name, b, a))
		}
	}
	for name := range after {
		if _, ok := before[name]; !ok {
			diffs = append(diffs, name+" added")
		}
	}
	sort.Strings(diffs)
	return diffs
}

// TestReadOwnWritesNothing: reading a state directory, many times over,
// leaves every file and the directory as they were, a stale temporary file
// that opening the store would delete included.
func TestReadOwnWritesNothing(t *testing.T) {
	dir, id := stateDir(t)
	writeChain(t, dir, id, chainOf(t, id, boot(1, 1, "25.12.4")))
	stale := filepath.Join(dir, ".alive.json.12345")
	if err := os.WriteFile(stale, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := filepath.WalkDir(dir, func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return os.Chtimes(p, old, old)
	}); err != nil {
		t.Fatal(err)
	}
	before := snapshot(t, dir)
	if _, ok := before[".alive.json.12345"]; !ok {
		t.Fatal("measured nothing: the stale temporary file is not in the snapshot")
	}
	for range 100 {
		if _, err := ReadOwn(dir); err != nil {
			t.Fatal(err)
		}
	}
	if d := sameState(before, snapshot(t, dir)); len(d) > 0 {
		t.Errorf("ReadOwn changed the state directory:\n  %v", d)
	}
	// The check sees a change: opening the store removes the stale file.
	if _, err := store.Open(dir); err != nil {
		t.Fatal(err)
	}
	if d := sameState(before, snapshot(t, dir)); len(d) == 0 {
		t.Error("control: store.Open changed nothing, so the snapshot cannot see a write")
	}
}
