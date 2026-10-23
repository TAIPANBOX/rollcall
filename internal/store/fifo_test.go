//go:build linux || darwin

package store

import (
	"errors"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A FIFO in the store directory must not block ReadFile. Opening a FIFO for
// reading waits for a writer, so the file type is checked before anything is
// opened. The call runs in a goroutine so that a regression fails the test
// instead of hanging it.
func TestReadFIFOReturnsPromptly(t *testing.T) {
	s, dir := newStore(t)
	if err := syscall.Mkfifo(filepath.Join(dir, "pipe"), 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := s.ReadFile("pipe")
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, ErrNotRegular) {
			t.Errorf("ReadFile of a FIFO = %v, want ErrNotRegular", err)
		}
	case <-time.After(time.Second):
		t.Fatal("ReadFile blocked on a FIFO")
	}
}
