package gates

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// outcome is what a gate must do in a teeth case.
type outcome int

const (
	wantFail outcome = iota // a planted fault or a missing subject: the gate must fail
	wantPass                // a clean copy: the gate must pass
	wantSkip                // every feature file pending: the gate must skip, and only that
)

// toothCase is one run of one gate against one copy of the repository.
type toothCase struct {
	name     string                   // subtest name
	gate     string                   // gate test function to run in the copy
	coverage bool                     // run with ROLLCALL_COVERAGE=1
	env      []string                 // further KEY=VALUE settings for the gate run
	plant    func(*testing.T, string) // changes the copy; nil leaves it clean
	outcome  outcome
	expect   string // text the gate output must contain
}

// bindingFixture is a test that fixture scenarios bind to. It exists only in
// the copies, so the binding cases do not depend on any real test's name.
const bindingFixture = `package gates

import "testing"

// TestBindingFixture is the test the teeth fixtures bind to.
func TestBindingFixture(t *testing.T) {}
`

const fixtureBound = `Feature: fixture
  @test:TestBindingFixture
  Scenario: bound scenario
    Given a step
`

const fixtureUntagged = fixtureBound + `
  Scenario: untagged scenario
    Given another step
`

const fixtureMissingTest = `Feature: fixture
  @test:TestNoSuchTest
  Scenario: bound to nothing
    Given a step
`

// coverageProfileFixture is a mode-set profile with 4 statements, 2 covered: 50.0%.
const coverageProfileFixture = `mode: set
github.com/TAIPANBOX/rollcall/internal/ids/ids.go:10.1,12.2 2 1
github.com/TAIPANBOX/rollcall/internal/ids/ids.go:14.1,16.2 2 0
`

var toothCases = []toothCase{
	{
		name: "dependency_fake_require", gate: "TestDependencyAllowlist",
		plant: func(t *testing.T, dst string) {
			appendFile(t, filepath.Join(dst, "go.mod"), "\nrequire github.com/example/evil v1.0.0\n")
		},
		outcome: wantFail, expect: "github.com/example/evil",
	},
	{
		name: "dependency_allowed_modules", gate: "TestDependencyAllowlist",
		plant: func(t *testing.T, dst string) {
			appendFile(t, filepath.Join(dst, "go.mod"),
				"\nrequire (\n\tgolang.org/x/crypto v0.58.0\n\tgolang.org/x/sys v0.49.0 // indirect\n)\n")
		},
		outcome: wantPass,
	},
	{
		name: "dependency_fake_replace", gate: "TestDependencyAllowlist",
		plant: func(t *testing.T, dst string) {
			appendFile(t, filepath.Join(dst, "go.mod"),
				"\nreplace golang.org/x/crypto => example.com/evilfork v1.0.0\n")
		},
		outcome: wantFail, expect: "example.com/evilfork",
	},
	{
		name: "dependency_local_replace", gate: "TestDependencyAllowlist",
		plant: func(t *testing.T, dst string) {
			appendFile(t, filepath.Join(dst, "go.mod"), "\nreplace golang.org/x/crypto => ../crypto-fork\n")
		},
		outcome: wantPass,
	},
	{name: "dependency_clean", gate: "TestDependencyAllowlist", outcome: wantPass},
	{
		name: "dependency_no_go_mod", gate: "TestDependencyAllowlist",
		plant: func(t *testing.T, dst string) {
			removeFile(t, filepath.Join(dst, "go.mod"))
		},
		outcome: wantFail, expect: "measured nothing",
	},

	{
		name: "daemon_imports_os_exec", gate: "TestDaemonDoesNotImportExec",
		plant: func(t *testing.T, dst string) {
			writeFile(t, filepath.Join(dst, "cmd", "rollcalld", "planted.go"),
				"package main\n\nimport _ \"os/exec\"\n")
		},
		outcome: wantFail, expect: "os/exec",
	},
	{name: "daemon_clean", gate: "TestDaemonDoesNotImportExec", outcome: wantPass},
	{
		name: "daemon_no_sources", gate: "TestDaemonDoesNotImportExec",
		plant: func(t *testing.T, dst string) {
			if err := os.RemoveAll(filepath.Join(dst, "cmd", "rollcalld")); err != nil {
				t.Fatal(err)
			}
		},
		outcome: wantFail, expect: "measured nothing",
	},

	{
		name: "tls_insecure_skip_verify", gate: "TestNoInsecureSkipVerify",
		plant: func(t *testing.T, dst string) {
			writeFile(t, filepath.Join(dst, "cmd", "rollcalld", "planted_tls.go"),
				"package main\n\nimport \"crypto/tls\"\n\nvar planted = &tls.Config{InsecureSkipVerify: true}\n")
		},
		outcome: wantFail, expect: "planted_tls.go",
	},
	{
		name: "tls_verify_peer_certificate", gate: "TestNoInsecureSkipVerify",
		plant: func(t *testing.T, dst string) {
			writeFile(t, filepath.Join(dst, "cmd", "rollcalld", "planted_verify_peer.go"),
				"package main\n\nimport \"crypto/tls\"\n\nvar planted = &tls.Config{VerifyPeerCertificate: nil}\n")
		},
		outcome: wantFail, expect: "VerifyPeerCertificate",
	},
	{
		name: "tls_verify_connection", gate: "TestNoInsecureSkipVerify",
		plant: func(t *testing.T, dst string) {
			writeFile(t, filepath.Join(dst, "cmd", "rollcalld", "planted_verify_conn.go"),
				"package main\n\nimport \"crypto/tls\"\n\nvar planted = &tls.Config{VerifyConnection: nil}\n")
		},
		outcome: wantFail, expect: "VerifyConnection",
	},
	{name: "tls_clean", gate: "TestNoInsecureSkipVerify", outcome: wantPass},
	{
		name: "tls_no_sources", gate: "TestNoInsecureSkipVerify",
		plant: func(t *testing.T, dst string) {
			removeGoSources(t, dst)
		},
		outcome: wantFail, expect: "measured nothing",
	},

	{
		name: "features_untagged_scenario", gate: "TestFeatureBindings",
		plant: func(t *testing.T, dst string) {
			plantFeatures(t, dst, map[string]string{"group.feature": fixtureUntagged})
		},
		outcome: wantFail, expect: "untagged scenario",
	},
	{
		name: "features_tag_names_no_test", gate: "TestFeatureBindings",
		plant: func(t *testing.T, dst string) {
			plantFeatures(t, dst, map[string]string{"group.feature": fixtureMissingTest})
		},
		outcome: wantFail, expect: "TestNoSuchTest",
	},
	{
		name: "features_marked_file_does_not_excuse_others", gate: "TestFeatureBindings",
		plant: func(t *testing.T, dst string) {
			plantFeatures(t, dst, map[string]string{
				"a.feature": "# bindings-pending\n" + fixtureBound,
				"b.feature": fixtureUntagged,
			})
		},
		outcome: wantFail, expect: "features/b.feature:",
	},
	{
		name: "features_marked_file_excuses_only_itself", gate: "TestFeatureBindings",
		plant: func(t *testing.T, dst string) {
			plantFeatures(t, dst, map[string]string{
				"a.feature": "# bindings-pending\n" + fixtureUntagged,
				"b.feature": fixtureBound,
			})
		},
		outcome: wantPass,
	},
	{
		name: "features_pending_marker_skips", gate: "TestFeatureBindings",
		plant: func(t *testing.T, dst string) {
			plantFeatures(t, dst, map[string]string{"group.feature": "# bindings-pending\n" + fixtureUntagged})
		},
		outcome: wantSkip, expect: "bindings pending",
	},
	{
		name: "features_clean", gate: "TestFeatureBindings",
		plant: func(t *testing.T, dst string) {
			plantFeatures(t, dst, map[string]string{"group.feature": fixtureBound})
		},
		outcome: wantPass,
	},
	{
		name: "features_no_feature_dir", gate: "TestFeatureBindings",
		plant: func(t *testing.T, dst string) {
			if err := os.RemoveAll(filepath.Join(dst, "features")); err != nil {
				t.Fatal(err)
			}
		},
		outcome: wantFail, expect: "measured nothing",
	},

	{
		name: "coverage_below_baseline", gate: "TestCoverageNotBelowBaseline", coverage: true,
		plant: func(t *testing.T, dst string) {
			writeFile(t, filepath.Join(dst, "coverage.out"), coverageProfileFixture)
			writeFile(t, filepath.Join(dst, "coverage-baseline.txt"), "60.0\n")
		},
		outcome: wantFail, expect: "below the committed baseline",
	},
	{
		name: "coverage_clean", gate: "TestCoverageNotBelowBaseline", coverage: true,
		plant: func(t *testing.T, dst string) {
			writeFile(t, filepath.Join(dst, "coverage.out"), coverageProfileFixture)
			writeFile(t, filepath.Join(dst, "coverage-baseline.txt"), "50.0\n")
		},
		outcome: wantPass,
	},
	{
		name: "coverage_no_profile", gate: "TestCoverageNotBelowBaseline", coverage: true,
		plant: func(t *testing.T, dst string) {
			removeFile(t, filepath.Join(dst, "coverage.out"))
		},
		outcome: wantFail, expect: "measured nothing",
	},
}

// TestGatesHaveTeeth plants each gate's fault in a copy of the repository and
// requires the gate to fail there, passes a clean copy, and requires a
// "measured nothing" failure when the gate's subject is gone. The real
// checkout is never written to: every case works in its own temporary copy.
func TestGatesHaveTeeth(t *testing.T) {
	src := requireRoot(t)
	checkEveryGateHasTeeth(t, src)

	bin := filepath.Join(t.TempDir(), "gates.test")
	build := exec.Command("go", "test", "-c", "-o", bin, "./internal/gates")
	build.Dir = src
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build the gates test binary: %v\n%s", err, out)
	}

	for _, c := range toothCases {
		t.Run(c.name, func(t *testing.T) {
			dst := t.TempDir()
			copyTracked(t, src, dst)
			if c.plant != nil {
				c.plant(t, dst)
			}
			out, code := runGate(t, bin, dst, c)
			checkTooth(t, c, out, code)
		})
	}
}

// checkEveryGateHasTeeth fails for each Test function in internal/gates, other
// than TestGatesHaveTeeth, that no teeth case runs. A gate added without a
// planted fault is red here. It also fails for a teeth case that names no gate.
func checkEveryGateHasTeeth(t *testing.T, src string) {
	t.Helper()
	dir := filepath.Join(src, "internal", "gates")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("measured nothing: read %s: %v", dir, err)
	}
	fset := token.NewFileSet()
	gates := map[string]bool{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if ok && fn.Recv == nil && isTestName(fn.Name.Name) && fn.Name.Name != "TestGatesHaveTeeth" {
				gates[fn.Name.Name] = true
			}
		}
	}
	if len(gates) == 0 {
		t.Fatalf("measured nothing: no gate tests in %s", dir)
	}

	covered := map[string]bool{}
	for _, c := range toothCases {
		covered[c.gate] = true
	}
	var unpunished, unknown []string
	for name := range gates {
		if !covered[name] {
			unpunished = append(unpunished, name)
		}
	}
	for name := range covered {
		if !gates[name] {
			unknown = append(unknown, name)
		}
	}
	sort.Strings(unpunished)
	sort.Strings(unknown)
	if len(unpunished) > 0 {
		t.Errorf("gate(s) with no teeth case: %s; add a planted fault for each to toothCases",
			strings.Join(unpunished, ", "))
	}
	if len(unknown) > 0 {
		t.Errorf("teeth case(s) name no gate in internal/gates: %s", strings.Join(unknown, ", "))
	}
}

// copyTracked copies the files git lists for src into dst: the tracked files
// plus untracked files that git does not ignore, so a teeth run also works
// before a new file is staged.
func copyTracked(t *testing.T, src, dst string) {
	t.Helper()
	cmd := exec.Command("git", "ls-files", "-z", "--cached", "--others", "--exclude-standard")
	cmd.Dir = src
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git ls-files in %s: %v", src, err)
	}
	for _, rel := range strings.Split(string(out), "\x00") {
		if rel == "" {
			continue
		}
		from := filepath.Join(src, rel)
		info, err := os.Stat(from)
		if errors.Is(err, fs.ErrNotExist) {
			continue // listed but deleted in the working tree
		}
		if err != nil {
			t.Fatal(err)
		}
		if !info.Mode().IsRegular() {
			continue
		}
		data, err := os.ReadFile(from)
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(dst, rel), string(data))
	}
}

// runGate runs one gate test from the prebuilt binary, with its repository
// root pointed at root, and returns its output and exit code.
func runGate(t *testing.T, bin, root string, c toothCase) (string, int) {
	t.Helper()
	cmd := exec.Command(bin, "-test.run", "^"+c.gate+"$", "-test.v", "-test.count=1")
	cmd.Dir = root
	cmd.Env = append(gateEnv(root, c.coverage), c.env...)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return string(out), 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return string(out), exitErr.ExitCode()
	}
	t.Fatalf("run %s: %v", bin, err)
	return "", 0
}

// gateEnv is the environment for a gate run: the caller's environment with
// any ROLLCALL_ settings removed, then the root and the coverage switch.
func gateEnv(root string, coverage bool) []string {
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "ROLLCALL_") {
			env = append(env, kv)
		}
	}
	env = append(env, "ROLLCALL_REPO_ROOT="+root)
	if coverage {
		env = append(env, "ROLLCALL_COVERAGE=1")
	}
	return env
}

// checkTooth compares one gate run with what the case requires.
func checkTooth(t *testing.T, c toothCase, out string, code int) {
	t.Helper()
	var verdict string
	switch c.outcome {
	case wantFail:
		verdict = "FAIL"
		if code == 0 {
			t.Errorf("gate %s passed on a planted fault (exit 0); output:\n%s", c.gate, out)
		}
	case wantPass:
		verdict = "PASS"
		if code != 0 {
			t.Errorf("gate %s failed on a clean copy (exit %d); output:\n%s", c.gate, code, out)
		}
	case wantSkip:
		verdict = "SKIP"
		if code != 0 {
			t.Errorf("gate %s failed while skipping was required (exit %d); output:\n%s", c.gate, code, out)
		}
	}
	marker := fmt.Sprintf("--- %s: %s (", verdict, c.gate)
	if !strings.Contains(out, marker) {
		t.Errorf("output has no %q line, so the gate did not run as expected; output:\n%s", marker, out)
	}
	if c.expect != "" && !strings.Contains(out, c.expect) {
		t.Errorf("output does not name the offender %q; output:\n%s", c.expect, out)
	}
}

// plantFeatures gives the copy a bound test and replaces its features
// directory with the given files, keyed by file name.
func plantFeatures(t *testing.T, dst string, files map[string]string) {
	t.Helper()
	writeFile(t, filepath.Join(dst, "internal", "gates", "bindfixture_test.go"), bindingFixture)
	if err := os.RemoveAll(filepath.Join(dst, "features")); err != nil {
		t.Fatal(err)
	}
	for name, text := range files {
		writeFile(t, filepath.Join(dst, "features", name), text)
	}
}

// removeGoSources deletes every non-test Go file in the copy.
func removeGoSources(t *testing.T, dst string) {
	t.Helper()
	err := walkRepo(dst, func(path string) error {
		if strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
			return os.Remove(path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func writeFile(t *testing.T, path, text string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
}

func appendFile(t *testing.T, path, text string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(text); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func removeFile(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
}
