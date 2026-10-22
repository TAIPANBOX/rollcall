package store

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// t0 is the fixed clock the flusher tests run on. No test sleeps: every time
// is passed to Tick explicitly.
var t0 = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)

// newStore opens a store in a directory that does not exist yet and returns
// it with the directory's path.
func newStore(t *testing.T) (*Store, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "state")
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("Open(%q): %v", dir, err)
	}
	return s, dir
}

// permOf returns the permission bits of path.
func permOf(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

// names lists the entries of dir.
func names(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out
}

// skipIfRoot skips a test that relies on directory mode bits: root ignores
// them, so such a test would pass for the wrong reason.
func skipIfRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permission bits")
	}
}

func TestOpenCreatesPrivateDir(t *testing.T) {
	_, dir := newStore(t)
	if got := permOf(t, dir); got != 0o700 {
		t.Errorf("new directory mode %04o, want 0700", got)
	}
	if _, err := Open(dir); err != nil {
		t.Errorf("reopening a private directory: %v", err)
	}
	// A directory that group members can write is refused.
	if err := os.Chmod(dir, 0o770); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir); !errors.Is(err, ErrPermissions) {
		t.Errorf("Open on a group-writable directory: %v, want ErrPermissions", err)
	}
}

func TestAtomicWrite(t *testing.T) {
	s, dir := newStore(t)
	path := filepath.Join(dir, "roster.json")
	if err := s.WriteFileAtomic("roster.json", []byte("one")); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if got := permOf(t, path); got != 0o600 {
		t.Errorf("file mode %04o, want 0600", got)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.WriteFileAtomic("roster.json", []byte("two")); err != nil {
		t.Fatalf("overwrite: %v", err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// A replacement is a rename of a new file, so the inode changes. An
	// in-place write would keep it.
	if os.SameFile(before, after) {
		t.Error("overwrite kept the old inode: the file was written in place, not renamed over")
	}
	got, err := s.ReadFile("roster.json")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "two" {
		t.Errorf("ReadFile = %q, want %q", got, "two")
	}
	if l := names(t, dir); len(l) != 1 || l[0] != "roster.json" {
		t.Errorf("directory holds %v, want only roster.json (no temporary file left)", l)
	}
}

func TestNamesThatEscapeAreRefused(t *testing.T) {
	s, dir := newStore(t)
	bad := []string{"", ".", "..", "../escape", "a/b", "sub/../x", "a..b", "/etc/passwd", `a\b`}
	for _, name := range bad {
		if err := s.WriteFileAtomic(name, []byte("x")); !errors.Is(err, ErrName) {
			t.Errorf("WriteFileAtomic(%q) = %v, want ErrName", name, err)
		}
		if _, err := s.ReadFile(name); !errors.Is(err, ErrName) {
			t.Errorf("ReadFile(%q) = %v, want ErrName", name, err)
		}
	}
	if l := names(t, filepath.Dir(dir)); len(l) != 1 {
		t.Errorf("parent of the store holds %v, want only the store", l)
	}
}

func TestReadRefusesFileOpenToGroupOrOthers(t *testing.T) {
	s, dir := newStore(t)
	if err := s.WriteFileAtomic("secret.json", []byte("x")); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "secret.json")
	for _, perm := range []os.FileMode{0o644, 0o640, 0o604} {
		if err := os.Chmod(path, perm); err != nil {
			t.Fatal(err)
		}
		if _, err := s.ReadFile("secret.json"); !errors.Is(err, ErrPermissions) {
			t.Errorf("mode %04o: ReadFile = %v, want ErrPermissions", perm, err)
		}
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := s.ReadFile("secret.json"); err != nil || string(got) != "x" {
		t.Errorf("mode 0600: ReadFile = %q, %v; want %q, nil", got, err, "x")
	}
}

func TestReadMissingFile(t *testing.T) {
	s, _ := newStore(t)
	if _, err := s.ReadFile("absent.json"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("ReadFile of a missing file = %v, want an error wrapping fs.ErrNotExist", err)
	}
}

func TestOpenRefusesFileInPlaceOfDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); !errors.Is(err, ErrPermissions) {
		t.Errorf("Open on a regular file = %v, want ErrPermissions", err)
	}
}

func TestReadRefusesNonRegularFile(t *testing.T) {
	s, dir := newStore(t)
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	// The message is checked, so the refusal is the regular-file check and not
	// a read error that happens to follow from it.
	if _, err := s.ReadFile("sub"); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("ReadFile of a directory = %v, want a not-a-regular-file error", err)
	}
}

func TestDirectoryOpenToOthersRefused(t *testing.T) {
	s, dir := newStore(t)
	if err := s.WriteFileAtomic("a.json", []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o770); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteFileAtomic("b.json", []byte("x")); !errors.Is(err, ErrPermissions) {
		t.Errorf("write into a group-writable directory = %v, want ErrPermissions", err)
	}
	if _, err := s.ReadFile("a.json"); !errors.Is(err, ErrPermissions) {
		t.Errorf("read from a group-writable directory = %v, want ErrPermissions", err)
	}
}

func TestSizeLimitIsSymmetric(t *testing.T) {
	s, dir := newStore(t)
	if err := s.WriteFileAtomic("big", make([]byte, maxFileSize+1)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversized write = %v, want ErrTooLarge", err)
	}
	if l := names(t, dir); len(l) != 0 {
		t.Errorf("a refused oversized write left %v behind", l)
	}
	if err := s.WriteFileAtomic("edge", make([]byte, maxFileSize)); err != nil {
		t.Fatalf("write at the limit: %v", err)
	}
	if got, err := s.ReadFile("edge"); err != nil || len(got) != maxFileSize {
		t.Errorf("read back at the limit: %d bytes, %v", len(got), err)
	}
	// A file written by hand over the limit is refused on read.
	if err := os.WriteFile(filepath.Join(dir, "hand"), make([]byte, maxFileSize+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReadFile("hand"); !errors.Is(err, ErrTooLarge) {
		t.Errorf("ReadFile of an oversized file = %v, want ErrTooLarge", err)
	}
}

func TestFailedRenameLeavesNoTempFile(t *testing.T) {
	s, dir := newStore(t)
	// A directory named sub makes the rename fail. The temporary file must
	// not be left behind.
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteFileAtomic("sub", []byte("x")); err == nil {
		t.Fatal("rename over a directory succeeded")
	}
	if l := names(t, dir); len(l) != 1 || l[0] != "sub" {
		t.Errorf("directory holds %v, want only sub", l)
	}
}

func TestLastErrorReportsLatestWrite(t *testing.T) {
	s, dir := newStore(t)
	if err := s.LastError(); err != nil {
		t.Errorf("LastError before any write = %v, want nil", err)
	}
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteFileAtomic("sub", []byte("x")); err == nil {
		t.Fatal("rename over a directory succeeded")
	}
	if s.LastError() == nil {
		t.Error("LastError after a failed write is nil")
	}
	if err := s.WriteFileAtomic("ok.json", []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := s.LastError(); err != nil {
		t.Errorf("LastError after a later success = %v, want nil", err)
	}
}

func TestFlushWritesOnlyWhenMarked(t *testing.T) {
	writes := 0
	f := NewFlusher(func() error { writes++; return nil })
	f.Mark()
	if err := f.Tick(t0); err != nil {
		t.Fatalf("marked Tick: %v", err)
	}
	if writes != 1 {
		t.Fatalf("marked Tick wrote %d times, want 1", writes)
	}
	// Nothing changed since the write, so a long wait writes nothing.
	if err := f.Tick(t0.Add(10 * time.Minute)); err != nil {
		t.Fatalf("unmarked Tick: %v", err)
	}
	if writes != 1 {
		t.Errorf("unmarked Tick wrote; writes = %d, want 1", writes)
	}
}

func TestFlushAtMostOncePerMinute(t *testing.T) {
	writes := 0
	f := NewFlusher(func() error { writes++; return nil })
	// Ten marks spread over 59 seconds.
	for i := 0; i < 10; i++ {
		f.Mark()
		if err := f.Tick(t0.Add(time.Duration(i) * 59 * time.Second / 9)); err != nil {
			t.Fatalf("Tick %d: %v", i, err)
		}
	}
	if writes != 1 {
		t.Fatalf("ten marks in 59 s gave %d writes, want 1", writes)
	}
	// Just short of a minute after the write: still no write.
	f.Mark()
	if err := f.Tick(t0.Add(59*time.Second + 999*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if writes != 1 {
		t.Errorf("a Tick 59.999 s after the write wrote; writes = %d, want 1", writes)
	}
	// Exactly a minute after the write: allowed.
	if err := f.Tick(t0.Add(60 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if writes != 2 {
		t.Errorf("a Tick 60 s after the write: writes = %d, want 2", writes)
	}
}

func TestFlushBackwardClockDoesNotStall(t *testing.T) {
	writes := 0
	f := NewFlusher(func() error { writes++; return nil })
	f.Mark()
	if err := f.Tick(t0); err != nil {
		t.Fatal(err)
	}
	// A router whose clock steps back must still flush: the step counts as a
	// new window, not as a stall until the old time comes round again.
	f.Mark()
	if err := f.Tick(t0.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if writes != 2 {
		t.Fatalf("Tick after the clock stepped back: writes = %d, want 2", writes)
	}
	f.Mark()
	if err := f.Tick(t0.Add(-time.Hour + 30*time.Second)); err != nil {
		t.Fatal(err)
	}
	if writes != 2 {
		t.Errorf("Tick 30 s after the step: writes = %d, want 2", writes)
	}
	f.Mark()
	if err := f.Tick(t0.Add(-time.Hour + 60*time.Second)); err != nil {
		t.Fatal(err)
	}
	if writes != 3 {
		t.Errorf("Tick 60 s after the step: writes = %d, want 3", writes)
	}
}

// Review Focus 4: a flush into a read-only directory returns an error, keeps
// the caller's in-memory state and the old file, and retries on the next
// allowed tick once the directory is writable again.
func TestFlushErrorKeepsData(t *testing.T) {
	skipIfRoot(t)
	s, dir := newStore(t)
	history := []string{"a", "b"}
	encode := func() []byte { return []byte(strings.Join(history, "\n")) }
	f := NewFlusher(func() error { return s.WriteFileAtomic("history.txt", encode()) })

	f.Mark()
	if err := f.Tick(t0); err != nil {
		t.Fatalf("first flush: %v", err)
	}
	history = append(history, "c")
	f.Mark()

	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	// Restore the mode even if the test fails part way, so cleanup works.
	t.Cleanup(func() { os.Chmod(dir, 0o700) })

	if err := f.Tick(t0.Add(60 * time.Second)); err == nil {
		t.Fatal("flush into a read-only directory returned nil")
	}
	if s.LastError() == nil {
		t.Error("LastError is nil after a failed flush")
	}
	if got := strings.Join(history, ","); got != "a,b,c" {
		t.Errorf("in-memory history = %q, want a,b,c", got)
	}
	// The file from before the failure is still whole.
	if got, err := s.ReadFile("history.txt"); err != nil || string(got) != "a\nb" {
		t.Errorf("file after failed flush = %q, %v; want the old content a\\nb", got, err)
	}

	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// A failed attempt counts toward the minute, so this tick is too early.
	if err := f.Tick(t0.Add(90 * time.Second)); err != nil {
		t.Fatalf("tick 30 s after the failed attempt: %v", err)
	}
	if got, _ := s.ReadFile("history.txt"); string(got) != "a\nb" {
		t.Errorf("a tick inside the minute wrote: file = %q", got)
	}
	// The mark survived the failure, so the next allowed tick retries.
	if err := f.Tick(t0.Add(120 * time.Second)); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if got, err := s.ReadFile("history.txt"); err != nil || string(got) != "a\nb\nc" {
		t.Errorf("file after retry = %q, %v; want a\\nb\\nc", got, err)
	}
	if err := s.LastError(); err != nil {
		t.Errorf("LastError after the successful retry = %v, want nil", err)
	}
}

// Mark, Tick, WriteFileAtomic and LastError run from several goroutines, as
// they do in the daemon. Under -race this checks the locking.
func TestMarkAndTickAreSafeConcurrently(t *testing.T) {
	s, _ := newStore(t)
	f := NewFlusher(func() error { return s.WriteFileAtomic("state.txt", []byte("x")) })
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				f.Mark()
				_ = f.Tick(t0.Add(time.Duration(g*50+i) * time.Millisecond))
				_ = s.LastError()
			}
		}(g)
	}
	wg.Wait()
	// An attempt an hour after every attempt above is allowed, so a pending
	// mark is written.
	f.Mark()
	if err := f.Tick(t0.Add(time.Hour)); err != nil {
		t.Fatalf("final Tick: %v", err)
	}
	if got, err := s.ReadFile("state.txt"); err != nil || string(got) != "x" {
		t.Errorf("final file = %q, %v; want x", got, err)
	}
}
