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
// a markup sink, and on any E() call whose children argument is not an array,
// an E() call or a T() call. LuCI's E() treats a bare string child as markup,
// so every value reaches the page through T() (a text node) or an array.
// It fails when the app has no JavaScript at all, because a gate that finds
// nothing to read has measured nothing.
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
		src := string(data)
		for i, line := range strings.Split(src, "\n") {
			for _, sink := range luciMarkupSinks {
				if strings.Contains(line, sink) {
					offenders = append(offenders, fmt.Sprintf("%s:%d (%s)", relPath(root, path), i+1, sink))
				}
			}
		}
		for _, p := range luciBareChildren(src) {
			offenders = append(offenders, relPath(root, path)+":"+p)
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
		t.Errorf("LuCI values are shown as text only; found at: %s",
			strings.Join(offenders, ", "))
	}
}

// luciBareChildren returns one entry per E() call in src whose children
// argument is not an array, an E() call or a T() call. The entry carries the
// line and the argument as written. Quoted text and comments are ignored.
func luciBareChildren(src string) []string {
	masked := luciMaskSource(src)
	var out []string
	for i := 0; i+1 < len(masked); i++ {
		if masked[i] != 'E' || masked[i+1] != '(' {
			continue
		}
		if i > 0 && (luciIdentByte(masked[i-1]) || masked[i-1] == '.') {
			continue // part of a longer name, or a method call such as x.E(
		}
		line := 1 + strings.Count(src[:i], "\n")
		args, ok := luciCallArgs(masked, i+1)
		if !ok {
			out = append(out, fmt.Sprintf("%d (cannot read this E() call)", line))
			continue
		}
		if len(args) < 2 {
			continue // E(tag) has no children argument
		}
		idx := 1
		if strings.HasPrefix(strings.TrimSpace(masked[args[1][0]:args[1][1]]), "{") {
			if len(args) < 3 {
				continue // E(tag, attributes) has no children
			}
			idx = 2
		}
		child := args[idx]
		text := strings.TrimSpace(masked[child[0]:child[1]])
		if strings.HasPrefix(text, "[") || strings.HasPrefix(text, "E(") || strings.HasPrefix(text, "T(") {
			continue
		}
		out = append(out, fmt.Sprintf("%d (children argument %q is not an array, E() or T())",
			line, luciShorten(src[child[0]:child[1]])))
	}
	return out
}

// luciCallArgs splits the arguments of the call whose '(' is at open. Each
// argument is a [start, end) span of masked. ok is false when the call does
// not close.
func luciCallArgs(masked string, open int) ([][2]int, bool) {
	depth := 0
	var args [][2]int
	start := open + 1
	for i := open; i < len(masked); i++ {
		switch masked[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
			if depth == 0 {
				if strings.TrimSpace(masked[start:i]) != "" {
					args = append(args, [2]int{start, i})
				}
				return args, true
			}
		case ',':
			if depth == 1 {
				args = append(args, [2]int{start, i})
				start = i + 1
			}
		}
	}
	return nil, false
}

// luciMaskSource returns src with the text of comments and string literals
// replaced by spaces. Quote marks, newlines and every byte offset stay where
// they were, so positions in the masked text match src.
func luciMaskSource(src string) string {
	b := []byte(src)
	for i := 0; i < len(b); {
		switch {
		case b[i] == '/' && i+1 < len(b) && b[i+1] == '/':
			for i < len(b) && b[i] != '\n' {
				b[i] = ' '
				i++
			}
		case b[i] == '/' && i+1 < len(b) && b[i+1] == '*':
			b[i], b[i+1] = ' ', ' '
			i += 2
			for i < len(b) && !(b[i] == '*' && i+1 < len(b) && b[i+1] == '/') {
				if b[i] != '\n' {
					b[i] = ' '
				}
				i++
			}
			if i+1 < len(b) {
				b[i], b[i+1] = ' ', ' '
				i += 2
			}
		case b[i] == '\'' || b[i] == '"' || b[i] == '`':
			quote := b[i]
			i++
			for i < len(b) && b[i] != quote {
				if b[i] == '\\' && i+1 < len(b) {
					b[i], b[i+1] = ' ', ' '
					i += 2
					continue
				}
				if b[i] != '\n' {
					b[i] = ' '
				}
				i++
			}
			i++ // the closing quote stays
		default:
			i++
		}
	}
	return string(b)
}

// luciIdentByte reports whether c can appear inside a JavaScript identifier.
func luciIdentByte(c byte) bool {
	return c == '_' || c == '$' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// luciShorten collapses whitespace and cuts a long argument for a message.
func luciShorten(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 60 {
		return s[:60] + "..."
	}
	return s
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
		toothCase{
			name: "luci_bare_child", gate: "TestLuCINoInnerHTML",
			plant: func(t *testing.T, dst string) {
				writeFile(t, filepath.Join(dst, luciViewDir, "planted_bare_child.js"),
					"'use strict';\nvar cell = E('td', {}, name);\n")
			},
			outcome: wantFail, expect: "planted_bare_child.js",
		},
		toothCase{
			name: "luci_bare_second_argument", gate: "TestLuCINoInnerHTML",
			plant: func(t *testing.T, dst string) {
				writeFile(t, filepath.Join(dst, luciViewDir, "planted_bare_second.js"),
					"'use strict';\nvar item = E('li', name);\n")
			},
			outcome: wantFail, expect: "planted_bare_second.js",
		},
		toothCase{
			name: "luci_bare_translated_literal", gate: "TestLuCINoInnerHTML",
			plant: func(t *testing.T, dst string) {
				writeFile(t, filepath.Join(dst, luciViewDir, "planted_bare_literal.js"),
					"'use strict';\nvar note = E('p', {}, _('static text'));\n")
			},
			outcome: wantFail, expect: "planted_bare_literal.js",
		},
		toothCase{
			name: "luci_fixed_children", gate: "TestLuCINoInnerHTML",
			plant: func(t *testing.T, dst string) {
				writeFile(t, filepath.Join(dst, luciViewDir, "planted_fixed.js"),
					"'use strict';\n"+
						"var cell = E('td', {}, [ T(name) ]);\n"+
						"var item = E('li', {}, E('b', {}, [ T(name) ]));\n"+
						"var tail = E('p', {}, T(name));\n"+
						"var head = E('h3', {}, [ _('static') ]);\n")
			},
			outcome: wantPass,
		},
		toothCase{
			name: "luci_call_in_comment_or_string", gate: "TestLuCINoInnerHTML",
			plant: func(t *testing.T, dst string) {
				writeFile(t, filepath.Join(dst, luciViewDir, "planted_quoted.js"),
					"'use strict';\n// E('td', {}, name) is only a comment\n"+
						"/* E('td', {}, name) inside a block comment */\n"+
						"var text = \"E('td', {}, name)\";\n")
			},
			outcome: wantPass,
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
