package gates

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// hotplugRel holds the hotplug scripts the package installs.
const hotplugRel = "packaging/files/etc/hotplug.d"

// rollcallCLI is the CLI path the hotplug scripts call.
const rollcallCLI = "/usr/bin/rollcall"

// TestHotplugNeverBlocks reads every hotplug script the package ships and requires each call of
// the CLI to run in the background with its output detached from hotplug's: netifd and ntpd wait
// for their hotplug scripts, so a daemon that is slow to answer must never hold them up. A test
// of the CLI's presence ([ -x /usr/bin/rollcall ]) is not a call.
func TestHotplugNeverBlocks(t *testing.T) {
	root := requireRoot(t)
	scripts, err := filepath.Glob(filepath.Join(root, filepath.FromSlash(hotplugRel), "*", "*"))
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(scripts)
	calls := 0
	for _, path := range scripts {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		rel, _ := filepath.Rel(root, path)
		n, problems := hotplugProblems(string(data))
		calls += n
		for _, p := range problems {
			t.Errorf("%s: %s", filepath.ToSlash(rel), p)
		}
	}
	if calls == 0 {
		t.Fatalf("measured nothing: no call of %s in %s", rollcallCLI, hotplugRel)
	}
}

// hotplugProblems returns the number of CLI calls in one script and what is wrong with them.
func hotplugProblems(text string) (int, []string) {
	calls := 0
	var problems []string
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || !strings.Contains(line, rollcallCLI) {
			continue
		}
		if strings.Contains(line, "-x "+rollcallCLI) {
			continue
		}
		calls++
		switch {
		case !strings.HasSuffix(line, "&"):
			problems = append(problems, "the CLI runs in the foreground, so hotplug waits for it: "+line)
		case !strings.Contains(line, ">/dev/null") || !strings.Contains(line, "2>&1"):
			problems = append(problems, "the background CLI keeps hotplug's output open, so hotplug may still wait for it: "+line)
		}
	}
	return calls, problems
}

// init registers the teeth cases for TestHotplugNeverBlocks.
func init() {
	const iface = hotplugRel + "/iface/50-rollcall"
	toothCases = append(toothCases,
		toothCase{name: "hotplug_clean", gate: "TestHotplugNeverBlocks", outcome: wantPass},
		toothCase{
			name: "hotplug_foreground_call", gate: "TestHotplugNeverBlocks",
			plant: func(t *testing.T, dst string) {
				editCopy(t, dst, iface, func(s string) string {
					return strings.Replace(s, "</dev/null &\n", "</dev/null\n", 1)
				})
			},
			outcome: wantFail, expect: "runs in the foreground",
		},
		toothCase{
			name: "hotplug_output_attached", gate: "TestHotplugNeverBlocks",
			plant: func(t *testing.T, dst string) {
				editCopy(t, dst, iface, func(s string) string {
					return strings.Replace(s, " >/dev/null 2>&1 </dev/null &\n", " &\n", 1)
				})
			},
			outcome: wantFail, expect: "keeps hotplug's output open",
		},
		toothCase{
			name: "hotplug_no_scripts", gate: "TestHotplugNeverBlocks",
			plant: func(t *testing.T, dst string) {
				if err := os.RemoveAll(filepath.Join(dst, filepath.FromSlash(hotplugRel))); err != nil {
					t.Fatal(err)
				}
			},
			outcome: wantFail, expect: "measured nothing",
		},
	)
}
