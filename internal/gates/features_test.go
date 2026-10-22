package gates

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode"
)

const (
	pendingMarker = "# bindings-pending"
	testTagPrefix = "@test:"
)

// TestFeatureBindings binds the feature files to the tests, in both
// directions: every scenario carries an @test:TestName tag directly above it,
// and every @test: tag names a test function that exists in the repository.
//
// The gate skips only while a file carries the line "# bindings-pending",
// which Task 22 removes once its tests exist.
func TestFeatureBindings(t *testing.T) {
	root := requireRoot(t)
	files, err := filepath.Glob(filepath.Join(root, "features", "*.feature"))
	if err != nil {
		t.Fatalf("glob features: %v", err)
	}
	if len(files) == 0 {
		t.Fatalf("measured nothing: no features/*.feature under %s", root)
	}

	tests, err := testFunctions(root)
	if err != nil {
		t.Fatalf("read test functions under %s: %v", root, err)
	}

	scenarios := 0
	var offenders, pending []string
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		rel := relPath(root, file)
		n, off, isPending := scanFeature(rel, string(data), tests)
		scenarios += n
		offenders = append(offenders, off...)
		if isPending {
			pending = append(pending, rel)
		}
	}
	if scenarios == 0 {
		t.Fatalf("measured nothing: no Scenario: lines in %s", strings.Join(relPaths(root, files), ", "))
	}
	if len(pending) > 0 {
		t.Skipf("bindings pending: %s carries %s until Task 22 binds it to its tests",
			strings.Join(pending, ", "), pendingMarker)
	}
	if len(offenders) > 0 {
		t.Errorf("%d feature binding problem(s):\n  %s", len(offenders), strings.Join(offenders, "\n  "))
	}
}

// scanFeature checks one feature file. It returns the number of scenarios,
// the binding problems found, and whether the file carries the pending marker.
func scanFeature(rel, text string, tests map[string]bool) (int, []string, bool) {
	var offenders []string
	scenarios := 0
	pending := false
	var tags []string // @test: names directly above the next scenario

	for i, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		where := fmt.Sprintf("%s:%d", rel, i+1)
		switch {
		case line == pendingMarker:
			pending = true
		case line == "" || strings.HasPrefix(line, "#"):
			// blank and comment lines keep the tags above them attached
		case strings.HasPrefix(line, "@"):
			for _, tok := range strings.Fields(line) {
				if !strings.HasPrefix(tok, testTagPrefix) {
					continue
				}
				name := strings.TrimPrefix(tok, testTagPrefix)
				if !tests[name] {
					offenders = append(offenders, fmt.Sprintf("%s: %s%s names no test function in the repository", where, testTagPrefix, name))
				}
				tags = append(tags, name)
			}
		case strings.HasPrefix(line, "Scenario:"), strings.HasPrefix(line, "Scenario Outline:"):
			scenarios++
			title := strings.TrimPrefix(strings.TrimPrefix(line, "Scenario Outline:"), "Scenario:")
			if len(tags) == 0 {
				offenders = append(offenders, fmt.Sprintf("%s: scenario %q has no %s tag directly above it",
					where, strings.TrimSpace(title), testTagPrefix))
			}
			tags = nil
		default:
			tags = nil
		}
	}
	return scenarios, offenders, pending
}

// testFunctions returns the names of the Test functions declared in the
// repository's _test.go files, using the same name rule as go test.
func testFunctions(root string) (map[string]bool, error) {
	names := map[string]bool{}
	fset := token.NewFileSet()
	err := walkRepo(root, func(path string) error {
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return fmt.Errorf("parse %s: %w", relPath(root, path), err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if ok && fn.Recv == nil && isTestName(fn.Name.Name) {
				names[fn.Name.Name] = true
			}
		}
		return nil
	})
	return names, err
}

// isTestName reports whether name is a Test function name under go test's
// rule: "Test" followed by something other than a lower-case letter.
func isTestName(name string) bool {
	if !strings.HasPrefix(name, "Test") {
		return false
	}
	rest := []rune(name[len("Test"):])
	return len(rest) == 0 || !unicode.IsLower(rest[0])
}

func relPaths(root string, paths []string) []string {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		out = append(out, relPath(root, p))
	}
	return out
}
