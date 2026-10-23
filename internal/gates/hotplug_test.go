package gates

import (
	"fmt"
	"os"
	"os/exec"
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

// ntpHotplugRel is the script busybox ntpd runs through hotplug (/usr/sbin/ntpd-hotplug hands
// ACTION and ntpd's own variables, stratum among them, to /etc/hotplug.d/ntp).
const ntpHotplugRel = hotplugRel + "/ntp/50-rollcall"

// ntpCase is one event of busybox ntpd and whether rollcalld must hear that the clock is synced.
type ntpCase struct {
	action, stratum string
	unset           bool // stratum is not in the environment at all
	told            bool
}

// ntpCases are the events busybox ntpd 1.37 runs its script with (networking/ntpd.c run_script):
// "stratum" when the stratum of a synchronised clock changes, "step" when it steps the clock,
// "unsync" when every peer stopped answering (stratum 16 from then on), and "periodic" every 11
// minutes after the last script run, synchronised or not, with stratum 16 while it is not.
var ntpCases = []ntpCase{
	{action: "stratum", stratum: "2", told: true},
	{action: "stratum", stratum: "15", told: true},
	{action: "stratum", stratum: "16"},
	{action: "stratum", stratum: ""},
	{action: "stratum", unset: true},
	{action: "stratum", stratum: "x2"},
	{action: "step", stratum: "16", told: true},
	{action: "step", unset: true, told: true},
	{action: "periodic", stratum: "3", told: true},
	{action: "periodic", stratum: "15", told: true},
	{action: "periodic", stratum: "16"},
	{action: "periodic", stratum: "255"},
	{action: "periodic", stratum: ""},
	{action: "periodic", unset: true},
	{action: "periodic", stratum: "-1"},
	{action: "periodic", stratum: "3 "},
	{action: "periodic", stratum: "1e1"},
	{action: "unsync", stratum: "16"},
	{action: "unsync", stratum: "3"},
	{action: "", stratum: "3"},
	{action: "Periodic", stratum: "3"},
}

// TestNtpHotplugTellsTheDaemon runs the shipped ntp hotplug script with each event of ntpCases
// and requires exactly one "notify clock-synced" for an event that says the clock is
// synchronised, and none for any other: a daemon started after the clock synced (a restart, or
// an install on a running router) hears it from the next periodic run, at most about 11 minutes
// later (lab finding L6). The script names the CLI by its absolute path, so a copy names a stub
// there instead and runs its calls in the foreground; each event runs once with timeout on PATH
// and once without, the two branches of the script.
func TestNtpHotplugTellsTheDaemon(t *testing.T) {
	root := requireRoot(t)
	src, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(ntpHotplugRel)))
	if err != nil {
		t.Fatalf("measured nothing: %v", err)
	}
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Fatalf("measured nothing: no sh: %v", err)
	}
	dir := t.TempDir()
	calls := filepath.Join(dir, "calls")
	stub := filepath.Join(dir, "rollcall")
	writeExec(t, stub, "#!/bin/sh\necho \"$*\" >> '"+calls+"'\n")
	withTimeout, without := filepath.Join(dir, "with-timeout"), filepath.Join(dir, "without")
	for _, d := range []string{withTimeout, without} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeExec(t, filepath.Join(withTimeout, "timeout"), "#!/bin/sh\nshift\nexec \"$@\"\n")

	text := string(src)
	cli, bg := strings.Count(text, rollcallCLI), strings.Count(text, " </dev/null &\n")
	if cli < 2 || bg < 2 {
		t.Fatalf("measured nothing: %s names %s %d times and backgrounds %d calls; want the presence test and both branches", ntpHotplugRel, rollcallCLI, cli, bg)
	}
	text = strings.ReplaceAll(text, rollcallCLI, stub)
	text = strings.ReplaceAll(text, " </dev/null &\n", " </dev/null\n")
	script := filepath.Join(dir, "50-rollcall")
	writeExec(t, script, text)

	for _, c := range ntpCases {
		for _, path := range []string{withTimeout, without} {
			name := fmt.Sprintf("ACTION=%q stratum=%q", c.action, c.stratum)
			if c.unset {
				name = fmt.Sprintf("ACTION=%q, no stratum", c.action)
			}
			name += ", " + filepath.Base(path)
			_ = os.Remove(calls)
			cmd := exec.Command(sh, script)
			cmd.Env = []string{"PATH=" + path, "ACTION=" + c.action}
			if !c.unset {
				cmd.Env = append(cmd.Env, "stratum="+c.stratum)
			}
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Errorf("%s: the script failed: %v\n%s", name, err, out)
				continue
			}
			got, _ := os.ReadFile(calls)
			want := ""
			if c.told {
				want = "notify clock-synced\n"
			}
			if string(got) != want {
				t.Errorf("%s: the CLI got %q, want %q", name, got, want)
			}
		}
	}
}

// init registers the teeth cases for TestNtpHotplugTellsTheDaemon.
func init() {
	toothCases = append(toothCases,
		toothCase{name: "ntp_hotplug_clean", gate: "TestNtpHotplugTellsTheDaemon", outcome: wantPass},
		toothCase{
			// The lab finding L6: periodic was ignored, so a daemon started after the sync never heard.
			name: "ntp_hotplug_periodic_ignored", gate: "TestNtpHotplugTellsTheDaemon",
			plant: func(t *testing.T, dst string) {
				editCopy(t, dst, ntpHotplugRel, func(s string) string {
					return strings.Replace(s, "stratum | periodic)", "stratum)", 1)
				})
			},
			outcome: wantFail, expect: `ACTION="periodic" stratum="3"`,
		},
		toothCase{
			name: "ntp_hotplug_stratum_16_trusted", gate: "TestNtpHotplugTellsTheDaemon",
			plant: func(t *testing.T, dst string) {
				editCopy(t, dst, ntpHotplugRel, func(s string) string {
					return strings.Replace(s, `-lt 16`, `-le 16`, 1)
				})
			},
			outcome: wantFail, expect: `stratum="16"`,
		},
		toothCase{
			name: "ntp_hotplug_no_file", gate: "TestNtpHotplugTellsTheDaemon",
			plant: func(t *testing.T, dst string) {
				removeFile(t, filepath.Join(dst, filepath.FromSlash(ntpHotplugRel)))
			},
			outcome: wantFail, expect: "measured nothing",
		},
	)
}
