// Package store keeps a member's state files in one private directory
// (/etc/rollcall on a router) and writes them to flash in batches.
//
// Router flash has a limited number of write cycles. State therefore lives in
// RAM, and a Flusher writes it to flash at most once a minute, and only when
// something changed. The caller's write function calls WriteFileAtomic.
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
// or others can write. A name with a path separator or ".." is refused with
// ErrName, so nothing outside the directory is reached.
//
// Nothing here locks the directory across processes: one process owns it.
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
)

// Store is a private directory of state files. It is safe for concurrent use.
type Store struct {
	dir string

	mu      sync.Mutex
	lastErr error // the result of the most recent WriteFileAtomic
}

// Open returns the store in dir. It creates dir with mode 0700 if dir does
// not exist; its parent must exist. An existing dir that group or others can
// write is refused with ErrPermissions.
func Open(dir string) (*Store, error) {
	if err := makeDir(dir); err != nil {
		return nil, err
	}
	return &Store{dir: dir}, nil
}

// WriteFileAtomic replaces name in the store with data, mode 0600, and
// returns the result. LastError reports the same result afterwards. A name
// that is not a plain file name, or data over maxFileSize, is refused and
// nothing is written.
func (s *Store) WriteFileAtomic(name string, data []byte) error {
	err := s.write(name, data)
	s.mu.Lock()
	s.lastErr = err
	s.mu.Unlock()
	return err
}

func (s *Store) write(name string, data []byte) error {
	if err := checkName(name); err != nil {
		return err
	}
	if len(data) > maxFileSize {
		return fmt.Errorf("%w: %s would be %d bytes, limit %d", ErrTooLarge, name, len(data), maxFileSize)
	}
	return writeFile(s.dir, name, data)
}

// ReadFile returns the content of name in the store. A missing file is an
// error wrapping fs.ErrNotExist. A file that group or others can access is
// refused with ErrPermissions, and one over maxFileSize with ErrTooLarge.
func (s *Store) ReadFile(name string) ([]byte, error) {
	if err := checkName(name); err != nil {
		return nil, err
	}
	return readFile(s.dir, name)
}

// LastError returns the error of the most recent WriteFileAtomic, or nil if
// that write succeeded. A daemon reports it in its status.
func (s *Store) LastError() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastErr
}

// Flusher decides when the caller's pending changes are written. Mark records
// that something changed. Tick calls the write function when something is
// marked and the last attempt was at least flushInterval ago. It is safe for
// concurrent use. The write function must not call the Flusher.
type Flusher struct {
	write func() error

	mu     sync.Mutex
	marked bool      // something changed and has not been written yet
	tried  bool      // an attempt has been made
	last   time.Time // when the last attempt was made
}

// NewFlusher returns a Flusher that flushes by calling write.
func NewFlusher(write func() error) *Flusher {
	return &Flusher{write: write}
}

// Mark records that there is something to write.
func (f *Flusher) Mark() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.marked = true
}

// Tick calls the write function if something is marked and no attempt was
// made within the last flushInterval before now. A write that succeeds clears
// the mark. A write that fails keeps it, so the next allowed Tick retries, and
// Tick returns the error.
//
// Every attempt counts toward the interval, failed ones included, so a flash
// that refuses writes is not hammered. A now earlier than the last attempt,
// which happens when the router's clock steps back, is allowed, so flushing
// does not stall until the old time comes round again.
func (f *Flusher) Tick(now time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.marked {
		return nil
	}
	if f.tried && !now.Before(f.last) && now.Sub(f.last) < flushInterval {
		return nil
	}
	f.tried = true
	f.last = now
	if err := f.write(); err != nil {
		return err
	}
	f.marked = false
	return nil
}

// checkName refuses a name that is empty, "." or "..", that contains "..", or
// that contains a path separator (either / or \).
func checkName(name string) error {
	if name == "" || name == "." || strings.Contains(name, "..") || strings.ContainsAny(name, `/\`) {
		return fmt.Errorf("%w: %q", ErrName, name)
	}
	return nil
}

// checkDir returns ErrPermissions unless dir is a directory that group and
// others cannot write. It follows a symbolic link.
func checkDir(dir string) error {
	fi, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("%w: %s is not a directory", ErrPermissions, dir)
	}
	if perm := fi.Mode().Perm(); perm&0o022 != 0 {
		return fmt.Errorf("%w: directory %s has mode %04o; group and others must not write it", ErrPermissions, dir, perm)
	}
	return nil
}

// readFile returns the content of dir/name after checking dir with checkDir,
// and that the file it opened is a regular file that group and others cannot
// access.
func readFile(dir, name string) ([]byte, error) {
	if err := checkDir(dir); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, name)
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("store: %s is not a regular file", path)
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

// writeFile replaces dir/name with data, mode 0600: it writes a temporary file
// in dir, syncs it, renames it over name and syncs dir. On failure before the
// rename, the temporary file is removed and name keeps its old content.
func writeFile(dir, name string, data []byte) error {
	if err := makeDir(dir); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+name+".*")
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	if err := fillAndClose(tmp, data); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	if err := os.Rename(tmp.Name(), filepath.Join(dir, name)); err != nil {
		os.Remove(tmp.Name())
		return fmt.Errorf("store: %w", err)
	}
	return syncDir(dir)
}

// fillAndClose sets f to mode 0600, writes data, syncs and closes f.
func fillAndClose(f *os.File, data []byte) error {
	err := f.Chmod(0o600)
	if err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
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
	err = d.Sync()
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("store: sync %s: %w", dir, err)
	}
	return nil
}
