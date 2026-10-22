package gates

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// allowedModules are the only modules go.mod may require, directly or as
// indirect requirements. golang.org/x/sys is allowed because golang.org/x/crypto
// requires it.
var allowedModules = map[string]bool{
	"golang.org/x/crypto": true,
	"golang.org/x/sys":    true,
}

// TestDependencyAllowlist fails when go.mod requires a module outside
// allowedModules, or replaces a module with anything other than a local
// directory. A replace to another module would swap in code the allowlist
// never saw.
func TestDependencyAllowlist(t *testing.T) {
	root := requireRoot(t)
	gomod := filepath.Join(root, "go.mod")
	if _, err := os.Stat(gomod); err != nil {
		t.Fatalf("measured nothing: no go.mod at %s: %v", gomod, err)
	}

	// go mod edit -json reads go.mod with the toolchain's own parser and does
	// not resolve any module, so it needs no network.
	var stderr bytes.Buffer
	cmd := exec.Command("go", "mod", "edit", "-json")
	cmd.Dir = root
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go mod edit -json in %s: %v\n%s", root, err, stderr.String())
	}

	var mod struct {
		Require []struct {
			Path    string
			Version string
		}
		Replace []struct {
			Old struct {
				Path    string
				Version string
			}
			New struct {
				Path    string
				Version string
			}
		}
	}
	if err := json.Unmarshal(out, &mod); err != nil {
		t.Fatalf("decode go mod edit -json output: %v", err)
	}

	var offenders []string
	for _, r := range mod.Require {
		if !allowedModules[r.Path] {
			offenders = append(offenders, fmt.Sprintf("%s %s", r.Path, r.Version))
		}
	}
	if len(offenders) > 0 {
		t.Errorf("go.mod requires module(s) outside the allowlist (only %s are allowed): %s",
			allowedList(), strings.Join(offenders, ", "))
	}

	var replaces []string
	for _, r := range mod.Replace {
		if !isLocalPath(r.New.Path) {
			replaces = append(replaces, fmt.Sprintf("%s => %s %s", r.Old.Path, r.New.Path, r.New.Version))
		}
	}
	if len(replaces) > 0 {
		t.Errorf("go.mod replaces module(s) with something other than a local directory: %s",
			strings.Join(replaces, ", "))
	}
}

// isLocalPath reports whether a replace target is a relative directory.
func isLocalPath(p string) bool {
	return p == "." || p == ".." || strings.HasPrefix(p, "./") || strings.HasPrefix(p, "../")
}

// allowedList names the allowlist in order, for messages.
func allowedList() string {
	names := make([]string, 0, len(allowedModules))
	for name := range allowedModules {
		names = append(names, name)
	}
	sort.Strings(names)
	return strings.Join(names, " and ")
}
