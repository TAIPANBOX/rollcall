package store

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
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

// names lists the entries of dir, sorted by name.
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

// A crash between creating a temporary file and renaming it leaves a file
// named like one. Open removes those, and nothing else.
func TestOpenRemovesStaleTempFiles(t *testing.T) {
	_, dir := newStore(t)
	for _, n := range []string{".roster.json.12345", ".x.12", "roster.json", ".notes", "x.12"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("partial"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// A directory with a temporary-looking name is not a temporary file.
	if err := os.Mkdir(filepath.Join(dir, ".sub.7"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir); err != nil {
		t.Fatalf("reopen: %v", err)
	}
	want := []string{".notes", ".sub.7", "roster.json", "x.12"}
	if got := names(t, dir); !slices.Equal(got, want) {
		t.Errorf("after Open, directory holds %v, want %v", got, want)
	}
}

// isTempName must match exactly the names writeFile creates, because Open
// deletes whatever it matches.
func TestIsTempName(t *testing.T) {
	for _, n := range []string{".roster.json.12345", ".x.12", ".a.12", ".a..1", ".a.b.7", "..x.1"} {
		if !isTempName(n) {
			t.Errorf("isTempName(%q) = false, want true", n)
		}
	}
	for _, n := range []string{"", ".", "..", ".1", "..5", ".x", ".x.", ".x.y", ".x.1a", ".x.1.", "x.12", ".a.b", ".a..b.1"} {
		if isTempName(n) {
			t.Errorf("isTempName(%q) = true, want false", n)
		}
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

// A symbolic link to a private file outside the store is refused, not
// followed: the store must never read a file it does not own.
func TestSymlinkToOutsideFileRefused(t *testing.T) {
	s, dir := newStore(t)
	outside := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(outside, []byte("CANARY-123:abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	got, err := s.ReadFile("link")
	if !errors.Is(err, ErrNotRegular) {
		t.Errorf("ReadFile through a symbolic link = %v, want ErrNotRegular", err)
	}
	if got != nil {
		t.Errorf("ReadFile returned %q through a symbolic link", got)
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
	_, err := Open(path)
	if !errors.Is(err, ErrNotDir) || errors.Is(err, ErrPermissions) {
		t.Errorf("Open on a regular file = %v, want ErrNotDir and not ErrPermissions", err)
	}
}

func TestReadRefusesNonRegularFile(t *testing.T) {
	s, dir := newStore(t)
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReadFile("sub"); !errors.Is(err, ErrNotRegular) {
		t.Errorf("ReadFile of a directory = %v, want ErrNotRegular", err)
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
	s, _ := newStore(t)
	writes := 0
	f := s.NewFlusher(func() error { writes++; return nil })
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
	s, _ := newStore(t)
	writes := 0
	f := s.NewFlusher(func() error { writes++; return nil })
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

// A clock that steps back is not a write. The minute is counted from the new
// time, so the next write comes at least 60 s after the step.
func TestFlushBackwardClockDoesNotStall(t *testing.T) {
	s, _ := newStore(t)
	writes := 0
	f := s.NewFlusher(func() error { writes++; return nil })
	f.Mark()
	if err := f.Tick(t0); err != nil {
		t.Fatal(err)
	}
	if writes != 1 {
		t.Fatalf("first Tick: writes = %d, want 1", writes)
	}
	f.Mark()
	if err := f.Tick(t0.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if writes != 1 {
		t.Errorf("Tick after the clock stepped back an hour: writes = %d, want 1 (a step is not a write)", writes)
	}
	f.Mark()
	if err := f.Tick(t0.Add(-time.Hour + 30*time.Second)); err != nil {
		t.Fatal(err)
	}
	if writes != 1 {
		t.Errorf("Tick 30 s after the step: writes = %d, want 1", writes)
	}
	f.Mark()
	if err := f.Tick(t0.Add(-time.Hour + 60*time.Second)); err != nil {
		t.Fatal(err)
	}
	if writes != 2 {
		t.Errorf("Tick 60 s after the step: writes = %d, want 2", writes)
	}
}

// Mark is what a packet handler calls. It must return while a flush is still
// writing, so a slow fsync cannot stall the daemon.
func TestMarkDoesNotWaitForWrite(t *testing.T) {
	s, _ := newStore(t)
	started := make(chan struct{})
	release := make(chan struct{})
	f := s.NewFlusher(func() error {
		close(started)
		<-release
		return nil
	})
	f.Mark()
	tickDone := make(chan error, 1)
	go func() { tickDone <- f.Tick(t0) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("the flush did not start")
	}
	marked := make(chan struct{})
	go func() {
		f.Mark()
		close(marked)
	}()
	select {
	case <-marked:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("Mark waited for a write in progress")
	}
	close(release)
	if err := <-tickDone; err != nil {
		t.Fatalf("Tick: %v", err)
	}
}

// Review Focus 4: a flush into a read-only directory returns an error and keeps
// the old file, and the next allowed tick retries once the directory is
// writable again. The retry writes what the caller holds then.
func TestFlushErrorKeepsData(t *testing.T) {
	skipIfRoot(t)
	s, dir := newStore(t)
	history := []string{"a", "b"}
	encode := func() []byte { return []byte(strings.Join(history, "\n")) }
	f := s.NewFlusher(func() error { return s.WriteFileAtomic("history.txt", encode()) })

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

	if err := f.Tick(t0.Add(60 * time.Second)); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("flush into a read-only directory = %v, want fs.ErrPermission", err)
	}
	if s.LastError() == nil || f.LastError() == nil {
		t.Error("status is nil after a failed flush")
	}
	// The file from before the failure is still whole.
	if got, err := s.ReadFile("history.txt"); err != nil || string(got) != "a\nb" {
		t.Errorf("file after failed flush = %q, %v; want the old content a\\nb", got, err)
	}

	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// The caller keeps changing its state during the outage.
	history = append(history, "d")
	// No Mark here: the mark set before the failure must survive it.
	// A failed attempt counts toward the minute, so this tick is too early.
	if err := f.Tick(t0.Add(90 * time.Second)); err != nil {
		t.Fatalf("tick 30 s after the failed attempt: %v", err)
	}
	if got, _ := s.ReadFile("history.txt"); string(got) != "a\nb" {
		t.Errorf("a tick inside the minute wrote: file = %q", got)
	}
	// The mark survived the failure, so the next allowed tick retries and
	// writes the history as it is now.
	if err := f.Tick(t0.Add(120 * time.Second)); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if got, err := s.ReadFile("history.txt"); err != nil || string(got) != "a\nb\nc\nd" {
		t.Errorf("file after retry = %q, %v; want a\\nb\\nc\\nd", got, err)
	}
	if err := s.LastError(); err != nil {
		t.Errorf("LastError after the successful retry = %v, want nil", err)
	}
	if err := f.LastError(); err != nil {
		t.Errorf("Flusher.LastError after the successful retry = %v, want nil", err)
	}
}

// A flush that writes two files, where the first fails and the second
// succeeds, still fails. The status must say so, not report only the last
// write.
func TestFlushLastErrorCoversEveryWrite(t *testing.T) {
	s, dir := newStore(t)
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	f := s.NewFlusher(func() error {
		errA := s.WriteFileAtomic("sub", []byte("first"))     // fails: a directory is in the way
		errB := s.WriteFileAtomic("b.json", []byte("second")) // succeeds
		return errors.Join(errA, errB)
	})
	f.Mark()
	if err := f.Tick(t0); err == nil {
		t.Fatal("Tick returned nil although the first file failed")
	}
	if f.LastError() == nil {
		t.Error("Flusher.LastError is nil after a failed flush")
	}
	if s.LastError() == nil {
		t.Error("Store.LastError is nil after a failed flush: the status would report a healthy store")
	}
	if got, err := s.ReadFile("b.json"); err != nil || string(got) != "second" {
		t.Errorf("second file = %q, %v; want it written", got, err)
	}
	// Once both writes succeed, both errors clear.
	if err := os.Remove(filepath.Join(dir, "sub")); err != nil {
		t.Fatal(err)
	}
	f.Mark()
	if err := f.Tick(t0.Add(time.Minute)); err != nil {
		t.Fatalf("flush after the fix: %v", err)
	}
	if err := f.LastError(); err != nil {
		t.Errorf("Flusher.LastError after a good flush = %v, want nil", err)
	}
	if err := s.LastError(); err != nil {
		t.Errorf("Store.LastError after a good flush = %v, want nil", err)
	}
}

// Mark, Tick, WriteFileAtomic and LastError run from several goroutines, as
// they do in the daemon. Under -race this checks the locking.
func TestMarkAndTickAreSafeConcurrently(t *testing.T) {
	s, _ := newStore(t)
	var writes atomic.Int32
	f := s.NewFlusher(func() error {
		writes.Add(1)
		return s.WriteFileAtomic("state.txt", []byte("x"))
	})
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				f.Mark()
				_ = f.Tick(t0)
				_ = f.LastError()
				_ = s.LastError()
			}
		}()
	}
	wg.Wait()
	// Every concurrent Tick is at t0, so the first one writes and the rest
	// find the minute still running.
	if n := writes.Load(); n != 1 {
		t.Fatalf("concurrent ticks in one minute wrote %d times, want 1", n)
	}
	// A mark left pending is written by the next allowed tick.
	f.Mark()
	if err := f.Tick(t0.Add(time.Hour)); err != nil {
		t.Fatalf("final Tick: %v", err)
	}
	if n := writes.Load(); n != 2 {
		t.Errorf("a pending mark an hour later: writes = %d, want 2", n)
	}
	if got, err := s.ReadFile("state.txt"); err != nil || string(got) != "x" {
		t.Errorf("final file = %q, %v; want x", got, err)
	}
}
