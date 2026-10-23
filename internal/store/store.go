// Package store keeps a member's state files in one private directory
// (/etc/rollcall on a router) and writes them to flash in batches.
//
// Router flash has a limited number of write cycles. State therefore lives in
// RAM, and a Flusher writes it to flash at most once a minute, and only when
// something changed. The flush's write function calls WriteFileAtomic.
//
// WriteFileAtomic writes a temporary file in the same directory, syncs it,
// renames it over the target and syncs the directory. A reader sees the old
// content or the new, never a mix, and a failed write leaves the old file in
// place. Files get mode 0600 and the directory mode 0700. If the final sync of
// the directory fails, the rename has already happened, so the new content can
// be visible even though an error is returned.
//
// Reading fails closed, as package identity does. A file that group or others
// can access is refused with ErrPermissions, and so is a directory that group
// or others can write. A symbolic link, a FIFO, a device or a directory is
// refused with ErrNotRegular and never opened. A name with a path separator or
// ".." is refused with ErrName, so nothing outside the directory is reached.
//
// Open removes the temporary files a crash left behind. Nothing here locks the
// directory across processes: one process owns it.
//
// OpenNoSync is for tests and simulations only: its store writes the same
// files the same atomic way but never syncs, so a write is not durable
// across a power cut. Nothing that runs on a router calls it
// (TestOpenNoSyncOnlyInTestsAndSim).
package store

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// flushInterval is the least time between two flush attempts, failed ones
// included.
const flushInterval = 60 * time.Second

// maxFileSize bounds a stored file, on write and on read alike, so that every
// file the store writes can be read back.
const maxFileSize = 1 << 20

var (
	// ErrPermissions reports a file or directory that group or others may
	// access in a way the store refuses.
	ErrPermissions = errors.New("store: file or directory is open to group or others")
	// ErrName reports a file name with a path separator or "..", or an empty
	// name.
	ErrName = errors.New("store: invalid file name")
	// ErrTooLarge reports data, or a stored file, over maxFileSize bytes.
	ErrTooLarge = errors.New("store: file is larger than the limit")
	// ErrNotDir reports a path that should be the store directory but is not
	// a directory.
	ErrNotDir = errors.New("store: not a directory")
	// ErrNotRegular reports a stored name that is not a regular file: a
	// symbolic link, a FIFO, a device, or a directory.
	ErrNotRegular = errors.New("store: not a regular file")
)

// Store is a private directory of state files. It is safe for concurrent use.
type Store struct {
	dir    string
	noSync bool // OpenNoSync: writes are not synced

	mu      sync.Mutex
	lastErr error // the outcome of the most recent write, see LastError
}

// Open returns the store in dir. It creates dir with mode 0700 if dir does
// not exist; its parent must exist. An existing dir that group or others can
// write is refused with ErrPermissions, and a path that is not a directory
// with ErrNotDir. Open then removes the temporary files a crash left in dir.
func Open(dir string) (*Store, error) {
	if err := makeDir(dir); err != nil {
		return nil, err
	}
	if err := removeStaleTemps(dir); err != nil {
		return nil, err
	}
	return &Store{dir: dir}, nil
}

// OpenNoSync is Open for tests and simulations only: the store it returns
// writes without syncing the file or the directory. A write is still atomic
// for readers (temporary file, rename), but not durable across a power cut.
// A router never uses it.
func OpenNoSync(dir string) (*Store, error) {
	s, err := Open(dir)
	if err != nil {
		return nil, err
	}
	s.noSync = true
	return s, nil
}

// WriteFileAtomic replaces name in the store with data, mode 0600, and
// returns the result. LastError reports the same result afterwards. A name
// that is not a plain file name, or data over maxFileSize, is refused and
// nothing is written.
func (s *Store) WriteFileAtomic(name string, data []byte) error {
	err := s.write(name, data)
	s.setLast(err)
	return err
}

func (s *Store) write(name string, data []byte) error {
	if err := checkName(name); err != nil {
		return err
	}
	if len(data) > maxFileSize {
		return fmt.Errorf("%w: %s would be %d bytes, limit %d", ErrTooLarge, name, len(data), maxFileSize)
	}
	return writeFile(s.dir, name, data, !s.noSync)
}

// ReadFile returns the content of name in the store. A missing file is an
// error wrapping fs.ErrNotExist. A file that group or others can access is
// refused with ErrPermissions, a symbolic link or other non-regular file with
// ErrNotRegular, and one over maxFileSize with ErrTooLarge.
func (s *Store) ReadFile(name string) ([]byte, error) {
	if err := checkName(name); err != nil {
		return nil, err
	}
	return readFile(s.dir, name)
}

// LastError returns the outcome of the most recent write: a WriteFileAtomic
// call, or a flush made by a Flusher from NewFlusher. A flush's outcome is what
// its write function returned, so a failure in any file the flush writes shows
// here, even when a later file in the same flush succeeded. It is nil after a
// later success. A daemon reports it in its status.
func (s *Store) LastError() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastErr
}

func (s *Store) setLast(err error) {
	s.mu.Lock()
	s.lastErr = err
	s.mu.Unlock()
}

// NewFlusher returns a Flusher that flushes by calling write. The outcome of
// each flush is also reported by the store's LastError.
func (s *Store) NewFlusher(write func() error) *Flusher {
	return &Flusher{store: s, write: write}
}

// Flusher decides when the caller's pending changes are written. Mark records
// that something changed. Tick calls the write function when something is
// marked and the last attempt was at least flushInterval ago. Both are safe
// for concurrent use. The write function must not call the Flusher.
type Flusher struct {
	store *Store // where each flush's outcome is also reported; may be nil
	write func() error

	// marked is set by Mark without taking mu, so Mark never waits for a
	// write in progress.
	marked atomic.Bool

	mu      sync.Mutex
	writing bool      // a write is in progress
	tried   bool      // an attempt has been made
	last    time.Time // when the last attempt was made
	lastErr error     // what the last write returned
}

// Mark records that there is something to write. It returns at once, even
// while a flush is writing.
func (f *Flusher) Mark() {
	f.marked.Store(true)
}

// Tick calls the write function if something is marked and the last attempt
// was at least flushInterval before now. A write that succeeds clears the
// mark. A write that fails keeps it, so the next allowed Tick retries, and
// Tick returns the error.
//
// Every attempt counts toward the interval, failed ones included, so a flash
// that refuses writes is not hammered. A now earlier than the last attempt,
// which happens when the router's clock steps back, is not a write: the
// minute is counted from now, so the next write comes at least flushInterval
// later.
//
// If the write function panics, the flush counts as failed, the mark stays set,
// and the panic propagates to the caller.
func (f *Flusher) Tick(now time.Time) error {
	f.mu.Lock()
	if f.writing || !f.marked.Load() {
		f.mu.Unlock()
		return nil
	}
	if f.tried {
		if now.Before(f.last) {
			f.last = now
			f.mu.Unlock()
			return nil
		}
		if now.Sub(f.last) < flushInterval {
			f.mu.Unlock()
			return nil
		}
	}
	f.tried = true
	f.last = now
	f.writing = true
	// Cleared before the write, so a Mark made during it stays set for the
	// next Tick.
	f.marked.Store(false)
	f.mu.Unlock()

	return f.flush()
}

// errFlushPanicked is the outcome recorded when the write function panics.
var errFlushPanicked = errors.New("store: flush write function panicked")

// flush calls the write function and records its outcome. If the write
// function panics, the outcome is a failed flush, and the panic propagates to
// the caller. The flusher is left ready for the next allowed Tick.
func (f *Flusher) flush() (err error) {
	err = errFlushPanicked
	defer func() { f.record(err) }()
	return f.write()
}

// record stores the outcome of a flush: it clears writing, keeps the mark on
// failure, and reports the outcome to the store. It holds f.mu while it
// reports, so an older outcome cannot overwrite a newer one in the store.
func (f *Flusher) record(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writing = false
	f.lastErr = err
	if err != nil {
		f.marked.Store(true)
	}
	if f.store != nil {
		f.store.setLast(err)
	}
}

// LastError returns what the most recent write function call returned, or nil
// after a later success. It covers every file the flush writes, not only the
// last one.
func (f *Flusher) LastError() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastErr
}

// checkName refuses a name that is empty, that starts with a dot, that contains
// "..", or that contains a path separator (either / or \). The leading-dot rule
// means no stored name has the shape of a temporary file (see isTempName), so
// Open can never delete a stored file.
func checkName(name string) error {
	if name == "" || name[0] == '.' || strings.Contains(name, "..") || strings.ContainsAny(name, `/\`) {
		return fmt.Errorf("%w: %q", ErrName, name)
	}
	return nil
}

// checkDir returns ErrNotDir if dir is not a directory, and ErrPermissions if
// group and others can write it. It follows a symbolic link.
func checkDir(dir string) error {
	fi, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("%w: %s", ErrNotDir, dir)
	}
	if perm := fi.Mode().Perm(); perm&0o022 != 0 {
		return fmt.Errorf("%w: directory %s has mode %04o; group and others must not write it", ErrPermissions, dir, perm)
	}
	return nil
}

// readFile returns the content of dir/name after checking dir with checkDir.
// The file is checked with Lstat before anything is opened, so a symbolic
// link, a FIFO or a device is refused without a read that could block on it.
// The opened file must then be the one that was checked, and it must have no
// access for group or others.
func readFile(dir, name string) ([]byte, error) {
	if err := checkDir(dir); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, name)
	li, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	if !li.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %s", ErrNotRegular, path)
	}
	f, err := os.OpenFile(path, os.O_RDONLY|readOpenFlags, 0)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	if !fi.Mode().IsRegular() || !os.SameFile(li, fi) {
		return nil, fmt.Errorf("%w: %s was replaced while it was being opened", ErrNotRegular, path)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("%w: %s has mode %04o; group and others must have no access", ErrPermissions, path, perm)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("store: read %s: %w", path, err)
	}
	if len(data) > maxFileSize {
		return nil, fmt.Errorf("%w: %s is larger than %d bytes", ErrTooLarge, path, maxFileSize)
	}
	return data, nil
}

// makeDir creates dir with mode 0700, or checks an existing one with
// checkDir. The parent must exist.
func makeDir(dir string) error {
	err := os.Mkdir(dir, 0o700)
	if errors.Is(err, fs.ErrExist) {
		return checkDir(dir)
	}
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	// Mkdir applies the umask; the mode must be 0700 whatever the umask is.
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("store: %w", err)
	}
	return nil
}

// removeStaleTemps removes the temporary files a crash left in dir. Removal is
// best effort: a file that cannot be removed is only wasted space, so the
// error from Remove is not reported. Only a failure to read dir is.
func removeStaleTemps(dir string) error {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	for _, e := range ents {
		if e.Type().IsRegular() && isTempName(e.Name()) {
			os.Remove(filepath.Join(dir, e.Name()))
		}
	}
	return nil
}

// isTempName reports whether n has the form "." + name + "." + digits, which
// is how writeFile names its temporary file, and name is a valid store name.
func isTempName(n string) bool {
	if len(n) < 3 || n[0] != '.' {
		return false
	}
	dot := strings.LastIndexByte(n, '.')
	if dot < 2 {
		return false
	}
	digits := n[dot+1:]
	if digits == "" {
		return false
	}
	for i := 0; i < len(digits); i++ {
		if digits[i] < '0' || digits[i] > '9' {
			return false
		}
	}
	return checkName(n[1:dot]) == nil
}

// writeFile replaces dir/name with data, mode 0600: it writes a temporary file
// in dir, syncs it, renames it over name and syncs dir; without durable, it
// skips both syncs. On failure before the rename, the temporary file is
// removed and name keeps its old content.
func writeFile(dir, name string, data []byte, durable bool) error {
	if err := makeDir(dir); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+name+".*")
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	if err := fillAndClose(tmp, data, durable); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	if err := os.Rename(tmp.Name(), filepath.Join(dir, name)); err != nil {
		os.Remove(tmp.Name())
		return fmt.Errorf("store: %w", err)
	}
	if !durable {
		return nil
	}
	return syncDir(dir)
}

// syncFile makes what was written to f durable; a test counts the calls.
var syncFile = (*os.File).Sync

// fillAndClose sets f to mode 0600, writes data, syncs f when durable, and
// closes it.
func fillAndClose(f *os.File, data []byte, durable bool) error {
	err := f.Chmod(0o600)
	if err == nil {
		_, err = f.Write(data)
	}
	if err == nil && durable {
		err = syncFile(f)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("store: write %s: %w", f.Name(), err)
	}
	return nil
}

// syncDir makes a rename in dir durable.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	err = syncFile(d)
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("store: sync %s: %w", dir, err)
	}
	return nil
}
