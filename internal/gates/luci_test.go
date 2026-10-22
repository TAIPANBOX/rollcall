package gates

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// luciMarkupSinks are the DOM calls that turn a string into markup. The LuCI
// app shows values that come from the daemon and from other routers, so none
// of these may appear in its JavaScript: every value goes in as text.
var luciMarkupSinks = []string{
	"innerHTML",
	"outerHTML",
	"insertAdjacentHTML",
	".html(",
	"document.write(",
}

// TestLuCINoInnerHTML fails on any .js file under luci-app-rollcall that names
// a markup sink. It fails when the app has no JavaScript at all, because a
// gate that finds nothing to read has measured nothing.
func TestLuCINoInnerHTML(t *testing.T) {
	root := requireRoot(t)
	dir := filepath.Join(root, "luci-app-rollcall")
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("measured nothing: %v", err)
	}

	files := 0
	var offenders []string
	err := walkRepo(dir, func(path string) error {
		if !strings.HasSuffix(path, ".js") {
			return nil
		}
		files++
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for i, line := range strings.Split(string(data), "\n") {
			for _, sink := range luciMarkupSinks {
				if strings.Contains(line, sink) {
					offenders = append(offenders, fmt.Sprintf("%s:%d (%s)", relPath(root, path), i+1, sink))
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
	if files == 0 {
		t.Fatalf("measured nothing: no .js files under %s", dir)
	}
	if len(offenders) > 0 {
		t.Errorf("LuCI values are shown as text only; markup sinks found at: %s",
			strings.Join(offenders, ", "))
	}
}

// luciViewDir is where the planted teeth files go, inside the copy.
var luciViewDir = filepath.Join("luci-app-rollcall", "htdocs", "luci-static", "resources", "view", "rollcall")

func init() {
	toothCases = append(toothCases,
		toothCase{
			name: "luci_inner_html", gate: "TestLuCINoInnerHTML",
			plant: func(t *testing.T, dst string) {
				writeFile(t, filepath.Join(dst, luciViewDir, "planted_inner.js"),
					"'use strict';\nvar el = document.body;\nel.innerHTML = '<b>x</b>';\n")
			},
			outcome: wantFail, expect: "planted_inner.js",
		},
		toothCase{
			name: "luci_jquery_html", gate: "TestLuCINoInnerHTML",
			plant: func(t *testing.T, dst string) {
				writeFile(t, filepath.Join(dst, luciViewDir, "planted_html.js"),
					"'use strict';\n$('#out').html(value);\n")
			},
			outcome: wantFail, expect: "planted_html.js",
		},
		toothCase{name: "luci_clean", gate: "TestLuCINoInnerHTML", outcome: wantPass},
		toothCase{
			name: "luci_no_app", gate: "TestLuCINoInnerHTML",
			plant: func(t *testing.T, dst string) {
				if err := os.RemoveAll(filepath.Join(dst, "luci-app-rollcall")); err != nil {
					t.Fatal(err)
				}
			},
			outcome: wantFail, expect: "measured nothing",
		},
	)
}
