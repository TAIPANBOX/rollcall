package gates

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// TestNoInsecureSkipVerify fails on any InsecureSkipVerify identifier in
// non-test Go source. TLS verification is never disabled, anywhere in the
// repository. Test files are excluded so test code may build broken fixtures.
func TestNoInsecureSkipVerify(t *testing.T) {
	root := requireRoot(t)
	fset := token.NewFileSet()
	sources := 0
	var offenders []string

	err := walkRepo(root, func(path string) error {
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		sources++
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return fmt.Errorf("parse %s: %w", relPath(root, path), err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok && id.Name == "InsecureSkipVerify" {
				pos := fset.Position(id.Pos())
				offenders = append(offenders, fmt.Sprintf("%s:%d", relPath(root, pos.Filename), pos.Line))
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	if sources == 0 {
		t.Fatalf("measured nothing: no non-test .go files under %s", root)
	}
	if len(offenders) > 0 {
		t.Errorf("InsecureSkipVerify is never allowed; found at: %s", strings.Join(offenders, ", "))
	}
}
