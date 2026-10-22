package gates

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// initScriptRel is the procd service file that the package installs.
const initScriptRel = "packaging/files/etc/init.d/rollcall"

// initScriptRequired are lines the service file must carry, verbatim after trimming. Together
// they are the user, the no_new_privs flag and the seccomp profile of security section 7.
var initScriptRequired = []string{
	"USE_PROCD=1",
	"procd_set_param user rollcall",
	"procd_set_param group rollcall",
	"procd_set_param no_new_privs 1",
	"procd_set_param seccomp /etc/seccomp/rollcall.json",
}

// TestInitScriptHardening reads the service file and requires the hardening that every rollcall
// process runs with (invariant 13): its own user, no_new_privs, the seccomp profile and a jail
// with requirejail, so the daemon never starts unsandboxed. It also refuses ubus, which the
// daemon never touches, and capabilities outside the ICMP branch, because ICMP is the only probe
// that needs CAP_NET_RAW.
func TestInitScriptHardening(t *testing.T) {
	root := requireRoot(t)
	path := filepath.Join(root, filepath.FromSlash(initScriptRel))
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("measured nothing: read %s: %v", initScriptRel, err)
	}
	for _, problem := range initScriptProblems(string(data)) {
		t.Errorf("%s: %s", initScriptRel, problem)
	}
}

// initScriptProblems returns what the service text lacks or gets wrong. It works on a string so
// that the teeth cases and the gate read the same rules.
func initScriptProblems(text string) []string {
	var problems []string
	present := map[string]bool{}
	jailed := false
	// One entry per open if block: true when the block's condition tests the icmp option.
	var ifStack []bool
	inICMP := func() bool {
		for _, icmp := range ifStack {
			if icmp {
				return true
			}
		}
		return false
	}

	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, "ubus") {
			problems = append(problems, "uses ubus, which rollcall never touches: "+line)
		}
		switch {
		case strings.HasPrefix(line, "if "):
			ifStack = append(ifStack, strings.Contains(line, "icmp"))
		case line == "fi" || strings.HasPrefix(line, "fi "):
			if len(ifStack) > 0 {
				ifStack = ifStack[:len(ifStack)-1]
			}
		case strings.HasPrefix(line, "procd_set_param capabilities"):
			if !inICMP() {
				problems = append(problems, "capabilities set outside the icmp branch: "+line)
			}
		case strings.HasPrefix(line, "procd_add_jail rollcall"):
			if hasWord(line, "requirejail") {
				jailed = true
			}
		}
		present[line] = true
	}

	for _, want := range initScriptRequired {
		if !present[want] {
			problems = append(problems, "missing line: "+want)
		}
	}
	if !jailed {
		problems = append(problems, "no 'procd_add_jail rollcall ... requirejail' line: the daemon could start unjailed")
	}
	return problems
}

// hasWord reports whether word appears as a whitespace-separated field of line.
func hasWord(line, word string) bool {
	for _, field := range strings.Fields(line) {
		if field == word {
			return true
		}
	}
	return false
}

// editCopy rewrites one file inside a teeth copy of the repository.
func editCopy(t *testing.T, dst, rel string, edit func(string) string) {
	t.Helper()
	path := filepath.Join(dst, filepath.FromSlash(rel))
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, edit(string(data)))
}

// init registers the teeth cases for TestInitScriptHardening. Each one plants a fault a real edit
// could make and requires the gate to go red on it, plus a clean copy that must pass and a copy
// with no service file that must report "measured nothing".
func init() {
	toothCases = append(toothCases,
		toothCase{
			name: "initscript_clean", gate: "TestInitScriptHardening", outcome: wantPass,
		},
		toothCase{
			name: "initscript_no_new_privs_removed", gate: "TestInitScriptHardening",
			plant: func(t *testing.T, dst string) {
				editCopy(t, dst, initScriptRel, func(s string) string {
					return strings.Replace(s, "procd_set_param no_new_privs 1\n", "", 1)
				})
			},
			outcome: wantFail, expect: "no_new_privs",
		},
		toothCase{
			name: "initscript_seccomp_removed", gate: "TestInitScriptHardening",
			plant: func(t *testing.T, dst string) {
				editCopy(t, dst, initScriptRel, func(s string) string {
					return strings.Replace(s, "procd_set_param seccomp /etc/seccomp/rollcall.json\n", "", 1)
				})
			},
			outcome: wantFail, expect: "seccomp",
		},
		toothCase{
			name: "initscript_requirejail_removed", gate: "TestInitScriptHardening",
			plant: func(t *testing.T, dst string) {
				editCopy(t, dst, initScriptRel, func(s string) string {
					return strings.Replace(s, " requirejail", "", 1)
				})
			},
			outcome: wantFail, expect: "requirejail",
		},
		toothCase{
			name: "initscript_capabilities_outside_icmp", gate: "TestInitScriptHardening",
			plant: func(t *testing.T, dst string) {
				editCopy(t, dst, initScriptRel, func(s string) string {
					return strings.Replace(s, "procd_set_param no_new_privs 1\n",
						"procd_set_param no_new_privs 1\nprocd_set_param capabilities /etc/capabilities/rollcall.json\n", 1)
				})
			},
			outcome: wantFail, expect: "outside the icmp branch",
		},
		toothCase{
			name: "initscript_ubus_added", gate: "TestInitScriptHardening",
			plant: func(t *testing.T, dst string) {
				editCopy(t, dst, initScriptRel, func(s string) string {
					return s + "\nubus call network.interface status '{}'\n"
				})
			},
			outcome: wantFail, expect: "ubus",
		},
		toothCase{
			name: "initscript_no_file", gate: "TestInitScriptHardening",
			plant: func(t *testing.T, dst string) {
				removeFile(t, filepath.Join(dst, filepath.FromSlash(initScriptRel)))
			},
			outcome: wantFail, expect: "measured nothing",
		},
	)
}
