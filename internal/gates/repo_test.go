// Package gates holds the repository gates. Each gate is a test that fails
// when the repository breaks an invariant, and TestGatesHaveTeeth proves that
// every gate actually goes red on a planted fault. Gates run against the
// repository found above the test's working directory, or against the
// directory named by ROLLCALL_REPO_ROOT, which the teeth test uses to point
// them at a planted copy.
package gates

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// repoRoot returns the repository the gates measure.
func repoRoot() (string, error) {
	if root := os.Getenv("ROLLCALL_REPO_ROOT"); root != "" {
		return filepath.Abs(root)
	}
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("no go.mod above the test's working directory")
		}
		dir = parent
	}
}

// walkRepo calls fn for every file under root. Hidden directories such as
// .git and .superpowers are skipped, so local scratch files never count.
func walkRepo(root string, fn func(path string) error) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		return fn(path)
	})
}

// relPath returns path relative to root, with forward slashes, for messages.
func relPath(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return path
	}
	return filepath.ToSlash(rel)
}

// requireRoot is used by every gate: a gate that cannot find its repository
// has measured nothing, so it fails rather than passing.
func requireRoot(t *testing.T) string {
	t.Helper()
	root, err := repoRoot()
	if err != nil {
		t.Fatalf("measured nothing: %v", err)
	}
	return root
}
