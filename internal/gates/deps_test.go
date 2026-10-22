package gates

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// allowedModule is the only module go.mod may require.
const allowedModule = "golang.org/x/crypto"

// TestDependencyAllowlist fails when go.mod requires any module other than
// golang.org/x/crypto, naming each module it finds.
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
	}
	if err := json.Unmarshal(out, &mod); err != nil {
		t.Fatalf("decode go mod edit -json output: %v", err)
	}

	var offenders []string
	for _, r := range mod.Require {
		if r.Path != allowedModule {
			offenders = append(offenders, fmt.Sprintf("%s %s", r.Path, r.Version))
		}
	}
	if len(offenders) > 0 {
		t.Errorf("go.mod requires module(s) outside the allowlist (only %s is allowed): %s",
			allowedModule, strings.Join(offenders, ", "))
	}
}
