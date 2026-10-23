package gates

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestDaemonDoesNotImportExec fails if the daemon's build graph contains
// os/exec. The daemon never runs a command; test code may.
func TestDaemonDoesNotImportExec(t *testing.T) {
	root := requireRoot(t)
	dir := filepath.Join(root, "cmd", "rollcalld")
	sources, err := goSourcesIn(dir)
	if err != nil || sources == 0 {
		t.Fatalf("measured nothing: no non-test Go files in %s (%v)", dir, err)
	}

	// The router target class is linux on arm64 (Flint 2 and Beryl AX).
	var stderr bytes.Buffer
	cmd := exec.Command("go", "list", "-deps", "-f", "{{.ImportPath}}", "./cmd/rollcalld")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=arm64")
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list -deps ./cmd/rollcalld: %v\n%s", err, stderr.String())
	}

	for _, pkg := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if pkg == "os/exec" {
			t.Errorf("cmd/rollcalld depends on os/exec; the daemon may not run commands")
		}
	}
}

// goSourcesIn counts the non-test .go files directly inside dir.
func goSourcesIn(dir string) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range entries {
		name := e.Name()
		if !e.IsDir() && strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, "_test.go") {
			n++
		}
	}
	return n, nil
}
