package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// procStatus makes a root whose proc/self/status holds text; a nil text
// leaves the file out, as a jail without /proc does.
func procStatus(t *testing.T, text *string) string {
	t.Helper()
	root := t.TempDir()
	if text == nil {
		return root
	}
	dir := filepath.Join(root, "proc", "self")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "status"), []byte(*text), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func ptr(s string) *string { return &s }

// TestSandboxGate is security spec 1.5 and 4.10: the daemon listens only when
// the kernel reports no_new_privs set and seccomp in filter mode; anything
// else, an unreadable status included, refuses with the reason.
func TestSandboxGate(t *testing.T) {
	cases := []struct {
		name   string
		status *string
		want   string // "" allows; otherwise a word the refusal must carry
	}{
		{"enforced", ptr("Name:\trollcalld\nNoNewPrivs:\t1\nSeccomp:\t2\nSeccomp_filters:\t1\n"), ""},
		{"no seccomp", ptr("NoNewPrivs:\t1\nSeccomp:\t0\n"), "seccomp"},
		{"seccomp strict, not filter", ptr("NoNewPrivs:\t1\nSeccomp:\t1\n"), "seccomp"},
		{"no no_new_privs", ptr("NoNewPrivs:\t0\nSeccomp:\t2\n"), "no_new_privs"},
		{"nothing set", ptr("NoNewPrivs:\t0\nSeccomp:\t0\n"), "no_new_privs"},
		{"lines missing", ptr("Name:\trollcalld\n"), "no_new_privs"},
		{"seccomp line missing", ptr("NoNewPrivs:\t1\n"), "seccomp"},
		{"status unreadable", nil, "cannot be checked"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := sandboxGate(procStatus(t, c.status))
			if c.want == "" {
				if err != nil {
					t.Fatalf("sandboxGate refused an enforced sandbox: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("sandboxGate allowed listening; want a refusal naming %q", c.want)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("refusal %q does not name %q", err, c.want)
			}
		})
	}
}
