package identity

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestLoadRefusesSpecialFiles: a FIFO or a symbolic link in place of
// identity.json or bootseq.json is refused at once, never read through or
// waited on, so a planted FIFO cannot hang the start and a link cannot pull
// keys from elsewhere.
func TestLoadRefusesSpecialFiles(t *testing.T) {
	read := map[string]func(dir string) error{
		identityName: func(dir string) error { _, err := Load(dir); return err },
		bootSeqName:  func(dir string) error { _, err := NextBootSeq(dir); return err },
	}
	plant := map[string]func(t *testing.T, dir, name string){
		"fifo": func(t *testing.T, dir, name string) {
			if err := syscall.Mkfifo(filepath.Join(dir, name), 0o600); err != nil {
				t.Skipf("mkfifo: %v", err)
			}
		},
		"symlink": func(t *testing.T, dir, name string) {
			target := filepath.Join(t.TempDir(), "elsewhere")
			src := filepath.Join(dir, identityName)
			if name == bootSeqName {
				if err := os.WriteFile(target, []byte(`{"boot_seq":7}`), 0o600); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Rename(src, target); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, filepath.Join(dir, name)); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, call := range read {
		for kind, put := range plant {
			t.Run(name+"/"+kind, func(t *testing.T) {
				dir := newDir(t)
				mustSave(t, mustGenerate(t), dir)
				if name == identityName && kind == "fifo" {
					if err := os.Remove(filepath.Join(dir, identityName)); err != nil {
						t.Fatal(err)
					}
				}
				put(t, dir, name)
				done := make(chan error, 1)
				go func() { done <- call(dir) }()
				select {
				case err := <-done:
					if !errors.Is(err, ErrCorrupt) {
						t.Fatalf("%s as a %s: err = %v, want ErrCorrupt", name, kind, err)
					}
				case <-time.After(2 * time.Second):
					t.Fatalf("%s as a %s: still blocked after 2 s", name, kind)
				}
			})
		}
	}
}
