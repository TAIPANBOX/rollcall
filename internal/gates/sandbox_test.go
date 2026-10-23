package gates

import (
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/TAIPANBOX/rollcall/internal/sandbox"
)

// TestSeccompDaemonListIsTheProfile requires the filter rollcalld installs to allow exactly the
// names of the profile the package ships, for every shipped target. The daemon reads the lists
// of packaging/seccomp through internal/sandbox, embedded when it is built; the package ships what
// generate.sh writes from the same files. A difference means the router runs a filter nobody can
// read in /etc/seccomp/rollcall.json, or a profile that describes no filter that runs.
func TestSeccompDaemonListIsTheProfile(t *testing.T) {
	root := requireRoot(t)
	if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(seccompGenerator))); err != nil {
		t.Fatalf("measured nothing: %s: %v", seccompGenerator, err)
	}
	for _, arch := range seccompTargets {
		goarch := seccompGoarch(arch)
		profile, err := seccompNames(root, arch)
		if err != nil {
			t.Errorf("%s: the generator: %v", arch, err)
			continue
		}
		daemon, err := sandbox.Allowed(goarch)
		if err != nil {
			t.Errorf("%s: the daemon's list for linux/%s: %v", arch, goarch, err)
			continue
		}
		for _, problem := range seccompListDiff(profile, daemon) {
			t.Errorf("%s (linux/%s): %s", arch, goarch, problem)
		}
	}
}

// seccompListDiff names each call one of the two lists allows and the other does not.
func seccompListDiff(profile map[string]bool, daemon []string) []string {
	var problems []string
	if len(daemon) == 0 {
		problems = append(problems, "the daemon's list is empty")
	}
	for _, name := range daemon {
		if !profile[name] {
			problems = append(problems, "the daemon's filter allows "+name+", which the shipped profile does not list")
		}
	}
	for _, name := range slices.Sorted(maps.Keys(profile)) {
		if !slices.Contains(daemon, name) {
			problems = append(problems, "the shipped profile lists "+name+", which the daemon's filter does not allow")
		}
	}
	return problems
}

// confineAllowedBefore are the calls main may make before it installs the seccomp filter:
// parsing the command line, printing the version or a usage error, exiting, and the log flags.
// None of them opens a file or a socket.
var confineAllowedBefore = map[string]bool{"log.SetFlags": true, "os.Exit": true}

// TestDaemonConfinesFirst reads cmd/rollcalld/main.go and requires main to install the seccomp
// filter (sandbox.Confine) before anything else it does, other than the command line and the
// log flags, and to end the process when the filter cannot be installed. Everything that opens a
// file or a socket comes after it (run), so it all runs filtered; a daemon that cannot filter
// itself does not run in a weaker mode (security spec 1.5, 4.10).
func TestDaemonConfinesFirst(t *testing.T) {
	root := requireRoot(t)
	path := filepath.Join(root, filepath.FromSlash(daemonMainRel))
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("measured nothing: %s: %v", daemonMainRel, err)
	}
	var main *ast.FuncDecl
	for _, d := range file.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Recv == nil && fn.Name.Name == "main" && fn.Body != nil {
			main = fn
		}
	}
	if main == nil {
		t.Fatalf("measured nothing: no func main in %s", daemonMainRel)
	}
	for _, problem := range confineProblems(main.Body.List) {
		t.Errorf("%s: %s", daemonMainRel, problem)
	}
}

// confineProblems applies the rule to the statements of main, in order.
func confineProblems(stmts []ast.Stmt) []string {
	var problems []string
	for _, stmt := range stmts {
		if ifs, ok := stmt.(*ast.IfStmt); ok && ifs.Init != nil && slices.Contains(callsIn(ifs.Init), "sandbox.Confine") {
			if !slices.Contains(callsIn(ifs.Body), "os.Exit") {
				problems = append(problems, "the process goes on when sandbox.Confine fails: its error branch has no os.Exit, so the daemon would run unfiltered")
			}
			return problems
		}
		for _, call := range callsIn(stmt) {
			if call == "sandbox.Confine" {
				return append(problems, "sandbox.Confine is not called as 'if n, err := sandbox.Confine(); err != nil { ... os.Exit(1) }', so a failure need not stop the daemon")
			}
			if !strings.HasPrefix(call, "flag.") && !strings.HasPrefix(call, "fmt.") && !confineAllowedBefore[call] {
				problems = append(problems, "main calls "+call+" before sandbox.Confine: anything but the command line and the log flags must run under the seccomp filter")
			}
		}
	}
	return append(problems, "main never calls sandbox.Confine: the daemon would run without its seccomp filter")
}

// callsIn lists the calls in a node as "pkg.Func" for a selector call and "Func" for a plain one.
func callsIn(n ast.Node) []string {
	var calls []string
	ast.Inspect(n, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fun := call.Fun.(type) {
		case *ast.SelectorExpr:
			if x, ok := fun.X.(*ast.Ident); ok {
				calls = append(calls, x.Name+"."+fun.Sel.Name)
			} else {
				calls = append(calls, "?."+fun.Sel.Name)
			}
		case *ast.Ident:
			calls = append(calls, fun.Name)
		default:
			calls = append(calls, "a function value")
		}
		return true
	})
	return calls
}

// init registers the teeth cases for the two gates. The list faults are planted in the generator,
// which the copy runs; the daemon's side is the list embedded in the gates binary itself, and its
// faults are the named mutants of internal/sandbox.
func init() {
	toothCases = append(toothCases,
		toothCase{name: "seccomp_daemon_list_clean", gate: "TestSeccompDaemonListIsTheProfile", outcome: wantPass},
		toothCase{
			name: "seccomp_daemon_list_profile_adds_a_name", gate: "TestSeccompDaemonListIsTheProfile",
			plant: func(t *testing.T, dst string) {
				editCopy(t, dst, seccompGenerator, func(s string) string {
					return strings.Replace(s, "| LC_ALL=C sort -u)", "| LC_ALL=C sort -u; echo ptrace)", 1)
				})
			},
			outcome: wantFail, expect: "x86_64 (linux/amd64): the shipped profile lists ptrace, which the daemon's filter does not allow",
		},
		toothCase{
			name: "seccomp_daemon_list_profile_wrong_family", gate: "TestSeccompDaemonListIsTheProfile",
			plant: func(t *testing.T, dst string) {
				editCopy(t, dst, seccompGenerator, func(s string) string {
					return strings.Replace(s, "aarch64_*) FAMILY=aarch64 ;;", "aarch64_*) FAMILY=amd64 ;;", 1)
				})
			},
			outcome: wantFail, expect: "aarch64_cortex-a53 (linux/arm64): the shipped profile lists arch_prctl",
		},
		toothCase{
			name: "seccomp_daemon_list_profile_drops_family", gate: "TestSeccompDaemonListIsTheProfile",
			plant: func(t *testing.T, dst string) {
				editCopy(t, dst, seccompGenerator, func(s string) string {
					return strings.Replace(s, `cat "$DIR/common.txt" "$DIR/$FAMILY.txt"`, `cat "$DIR/common.txt"`, 1)
				})
			},
			outcome: wantFail, expect: "mips_24kc (linux/mips): the daemon's filter allows stat64, which the shipped profile does not list",
		},
		toothCase{
			name: "seccomp_daemon_list_no_generator", gate: "TestSeccompDaemonListIsTheProfile",
			plant: func(t *testing.T, dst string) {
				removeFile(t, filepath.Join(dst, filepath.FromSlash(seccompGenerator)))
			},
			outcome: wantFail, expect: "measured nothing",
		},

		toothCase{name: "confine_clean", gate: "TestDaemonConfinesFirst", outcome: wantPass},
		toothCase{
			name: "confine_not_called", gate: "TestDaemonConfinesFirst",
			plant: func(t *testing.T, dst string) {
				editCopy(t, dst, daemonMainRel, func(s string) string {
					return strings.Replace(s, "sandbox.Confine()", "noFilter()", 1)
				})
			},
			outcome: wantFail, expect: "main never calls sandbox.Confine",
		},
		toothCase{
			name: "confine_after_a_read", gate: "TestDaemonConfinesFirst",
			plant: func(t *testing.T, dst string) {
				editCopy(t, dst, daemonMainRel, func(s string) string {
					return strings.Replace(s, "\tlog.SetFlags(0)\n", "\tlog.SetFlags(0)\n\t_, _ = os.ReadFile(\"/etc/rollcall/identity\")\n", 1)
				})
			},
			outcome: wantFail, expect: "main calls os.ReadFile before sandbox.Confine",
		},
		toothCase{
			name: "confine_after_run", gate: "TestDaemonConfinesFirst",
			plant: func(t *testing.T, dst string) {
				editCopy(t, dst, daemonMainRel, func(s string) string {
					return strings.Replace(s, "\tlog.SetFlags(0)\n", "\tlog.SetFlags(0)\n\t_ = run(context.Background(), f)\n", 1)
				})
			},
			outcome: wantFail, expect: "main calls run before sandbox.Confine",
		},
		toothCase{
			name: "confine_failure_goes_on", gate: "TestDaemonConfinesFirst",
			plant: func(t *testing.T, dst string) {
				editCopy(t, dst, daemonMainRel, func(s string) string {
					return strings.Replace(s, "\t\tos.Exit(1)\n\t} else if n > 0 {", "\t} else if n > 0 {", 1)
				})
			},
			outcome: wantFail, expect: "its error branch has no os.Exit",
		},
		toothCase{
			name: "confine_no_main", gate: "TestDaemonConfinesFirst",
			plant: func(t *testing.T, dst string) {
				removeFile(t, filepath.Join(dst, filepath.FromSlash(daemonMainRel)))
			},
			outcome: wantFail, expect: "measured nothing",
		},
	)
}
