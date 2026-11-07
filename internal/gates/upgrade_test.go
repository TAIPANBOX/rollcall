package gates

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

const (
	mkapkRel    = "scripts/mkapk.sh"
	mkipkRel    = "scripts/mkipk.sh"
	postinstRel = "packaging/postinst"
)

// The world a package script meets, in a sandbox. The script's absolute paths are rewritten into
// the sandbox, so what it runs is these stand-ins, and each writes down what it was asked.
const (
	// fakeFunctions is the part of /lib/functions.sh the postinst uses.
	fakeFunctions = `group_exists() { grep -q "^$1:" "$SANDBOX/group"; }
user_exists() { grep -q "^$1:" "$SANDBOX/passwd"; }
group_add() { echo "group_add $*" >>"$SANDBOX/log"; echo "$1:x:$2:" >>"$SANDBOX/group"; }
user_add() { echo "user_add $*" >>"$SANDBOX/log"; echo "$1:x:$2:" >>"$SANDBOX/passwd"; }
`
	fakeRollcallInit = `#!/bin/sh
echo "rollcall $1" >>"$SANDBOX/log"
case $1 in
enabled) [ -e "$SANDBOX/enabled" ] ;;
restart) [ ! -e "$SANDBOX/restart-fails" ] ;;
esac
`
	fakeFirewallInit = `#!/bin/sh
echo "firewall $1" >>"$SANDBOX/log"
`
	fakeChown = `#!/bin/sh
echo "chown $*" >>"$SANDBOX/log"
`
)

// upgradeCase is one run of a lifecycle script. script is "postinst", the file opkg runs for an
// install and an upgrade alike, or "post-upgrade", the script apk runs when it replaces a version,
// as mkapk.sh writes it. want and never are lines of the log; before says that the first of a pair
// comes before the second.
type upgradeCase struct {
	name      string
	script    string
	env       []string
	enabled   bool
	noAccount bool
	failing   bool // the restart fails
	want      []string
	never     []string
	before    [][2]string
}

var (
	serviceStarted = []string{"rollcall restart", "rollcall start"}
	accountMade    = []string{"group_add rollcall 1660", "user_add rollcall 1660 1660 rollcall /var/empty /bin/false"}
	stateDirGiven  = "chown rollcall:rollcall SANDBOX/etc/rollcall"
)

var upgradeCases = []upgradeCase{
	{
		name: "an install builds the rules and enables, and starts nothing", script: "postinst", noAccount: true,
		want:  append([]string{stateDirGiven, "rollcall firewall", "firewall reload", "rollcall enable"}, accountMade...),
		never: serviceStarted,
	},
	{
		name: "opkg says 0 on an install", script: "postinst", env: []string{"PKG_UPGRADE=0"}, noAccount: true,
		want:  append([]string{"rollcall firewall", "rollcall enable"}, accountMade...),
		never: serviceStarted,
	},
	{
		name: "apk replaces a version: an enabled service restarts onto the new binary", script: "post-upgrade", enabled: true,
		want:   []string{stateDirGiven, "rollcall restart"},
		never:  append([]string{"rollcall enable", "rollcall start"}, accountMade...),
		before: [][2]string{{stateDirGiven, "rollcall restart"}},
	},
	{
		name: "apk replaces a version: a service the owner switched off stays off, its rules current", script: "post-upgrade",
		want:  []string{stateDirGiven, "rollcall firewall", "firewall reload"},
		never: append([]string{"rollcall enable"}, serviceStarted...),
	},
	{
		name: "apk replaces a version on a router that lost the account", script: "post-upgrade", enabled: true, noAccount: true,
		want:   append([]string{"rollcall restart"}, accountMade...),
		never:  []string{"rollcall enable"},
		before: [][2]string{{accountMade[1], "rollcall restart"}, {accountMade[1], stateDirGiven}},
	},
	{
		name: "opkg upgrades: an enabled service restarts, and is not enabled again", script: "postinst",
		env: []string{"PKG_UPGRADE=1"}, enabled: true,
		want:  []string{"rollcall restart"},
		never: []string{"rollcall enable", "rollcall start"},
	},
	{
		name: "opkg upgrades: a service the owner switched off stays off", script: "postinst", env: []string{"PKG_UPGRADE=1"},
		want:  []string{"rollcall firewall"},
		never: append([]string{"rollcall enable"}, serviceStarted...),
	},
	{
		name: "a restart that fails does not fail the upgrade", script: "post-upgrade", enabled: true, failing: true,
		want: []string{"rollcall restart"},
	},
	{
		name: "in an image build nothing runs", script: "postinst", env: []string{"IPKG_INSTROOT=/build/root"},
		never: append([]string{"rollcall enable", "rollcall firewall", "firewall reload"}, serviceStarted...),
	},
}

// TestPackageUpgradeScripts holds what an upgrade does, in both package formats. apk runs
// post-upgrade, not post-install, when it replaces a version (apk_db_install_pkg), and opkg runs
// postinst for both with PKG_UPGRADE=1 on an upgrade, so it reads the scripts the packages carry
// and runs them against stand-ins. An upgrade makes sure of the account and the state directory,
// restarts an enabled service onto the new binary (its start brings the firewall rules in line and
// writes the snapshot), keeps the rules of a service that is not enabled current, and never enables
// one. scripts/gate-upgrade.sh does the same with OpenWrt's own apk, in CI's packaging job.
func TestPackageUpgradeScripts(t *testing.T) {
	root := requireRoot(t)
	mkapk := readSubject(t, root, mkapkRel)
	mkipk := readSubject(t, root, mkipkRel)
	postinst := readSubject(t, root, postinstRel)
	for _, p := range mkapkScriptProblems(mkapk) {
		t.Error(p)
	}
	for _, text := range []string{mkapk, mkipk} {
		if !strings.Contains(text, "/tmp/luci-indexcache.*") {
			t.Error("the LuCI scripts leave /tmp/luci-indexcache.*, where LuCI keeps its menu: a new page stays hidden")
		}
	}
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Fatalf("measured nothing: no sh: %v", err)
	}
	scripts := map[string]string{"postinst": postinst, "post-upgrade": packedPostUpgrade(t, sh, root, mkapk)}
	for _, c := range upgradeCases {
		t.Run(c.name, func(t *testing.T) {
			text := scripts[c.script]
			if text == "" {
				t.Fatalf("mkapk.sh writes no %s", c.script)
			}
			log, err := runPackageScript(t, sh, text, c)
			if err != nil {
				t.Errorf("the script failed, and apk would mark the package broken: %v\n%s", err, strings.Join(log, "\n"))
			}
			for _, w := range c.want {
				if !slices.Contains(log, w) {
					t.Errorf("no %q in what the script did:\n%s", w, strings.Join(log, "\n"))
				}
			}
			for _, n := range c.never {
				if slices.Contains(log, n) {
					t.Errorf("the script must not run %q:\n%s", n, strings.Join(log, "\n"))
				}
			}
			for _, b := range c.before {
				if i, j := slices.Index(log, b[0]), slices.Index(log, b[1]); i < 0 || j < 0 || i > j {
					t.Errorf("%q must come before %q:\n%s", b[0], b[1], strings.Join(log, "\n"))
				}
			}
		})
	}
}

// readSubject reads a file the gate is about.
func readSubject(t *testing.T, root, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("measured nothing: %v", err)
	}
	return string(b)
}

// scriptsLine matches the assignments of $SCRIPTS in mkapk.sh, one per package.
var scriptsLine = regexp.MustCompile(`(?m)^\s*SCRIPTS="(--script [^"]*)"$`)

// mkapkScriptProblems checks that each package mkapk.sh builds carries both scripts apk needs, and
// that the comment that sent an upgrade to post-install is gone.
func mkapkScriptProblems(text string) []string {
	lines := scriptsLine.FindAllStringSubmatch(text, -1)
	if len(lines) == 0 {
		return []string{"measured nothing: mkapk.sh assigns no SCRIPTS with a --script in it"}
	}
	var out []string
	for _, l := range lines {
		for _, stage := range []string{"post-install", "post-upgrade"} {
			if !strings.Contains(l[1], "--script "+stage+":") {
				out = append(out, "mkapk.sh packs no "+stage+" in: "+l[1])
			}
		}
	}
	if len(lines) != 2 {
		out = append(out, "mkapk.sh should assign SCRIPTS for two packages")
	}
	if strings.Contains(text, "post-install covers") {
		out = append(out, "mkapk.sh still says post-install covers an upgrade: apk runs post-upgrade then")
	}
	return out
}

// packedPostUpgrade runs the line of mkapk.sh that writes the rollcall package's post-upgrade and
// returns what it wrote, so the gate reads the script the package carries and not a copy of it.
// It returns nothing when mkapk.sh has no such line.
func packedPostUpgrade(t *testing.T, sh, root, mkapk string) string {
	t.Helper()
	for _, line := range strings.Split(mkapk, "\n") {
		if !strings.HasSuffix(strings.TrimSpace(line), `> "$BUILD/post-upgrade"`) {
			continue
		}
		build := t.TempDir()
		cmd := exec.Command(sh, "-c", line)
		cmd.Env = append(os.Environ(), "ROOT="+root, "BUILD="+build)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("the line of mkapk.sh that writes post-upgrade failed: %v\n%s", err, out)
		}
		b, err := os.ReadFile(filepath.Join(build, "post-upgrade"))
		if err != nil {
			t.Fatalf("post-upgrade: %v", err)
		}
		return string(b)
	}
	return ""
}

// runPackageScript runs a lifecycle script in a sandbox and returns what it did, with the
// sandbox's path written as SANDBOX.
func runPackageScript(t *testing.T, sh, text string, c upgradeCase) ([]string, error) {
	t.Helper()
	box := t.TempDir()
	for _, d := range []string{"etc/init.d", "lib", "bin"} {
		if err := os.MkdirAll(filepath.Join(box, filepath.FromSlash(d)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeExec(t, filepath.Join(box, "etc/init.d/rollcall"), fakeRollcallInit)
	writeExec(t, filepath.Join(box, "etc/init.d/firewall"), fakeFirewallInit)
	writeExec(t, filepath.Join(box, "bin/chown"), fakeChown)
	writeFile(t, filepath.Join(box, "lib/functions.sh"), fakeFunctions)
	account := "rollcall:x:1660:\n"
	if c.noAccount {
		account = ""
	}
	writeFile(t, filepath.Join(box, "group"), account)
	writeFile(t, filepath.Join(box, "passwd"), account)
	if c.enabled {
		writeFile(t, filepath.Join(box, "enabled"), "")
	}
	if c.failing {
		writeFile(t, filepath.Join(box, "restart-fails"), "")
	}
	rewritten := strings.NewReplacer("/etc/", box+"/etc/", "/lib/functions.sh", box+"/lib/functions.sh").Replace(text)
	script := filepath.Join(box, "script")
	writeFile(t, script, rewritten)

	cmd := exec.Command(sh, script)
	cmd.Env = append(append(os.Environ(), "SANDBOX="+box, "PATH="+filepath.Join(box, "bin")+string(os.PathListSeparator)+os.Getenv("PATH")), c.env...)
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if err != nil && !errors.As(err, &exit) {
		t.Fatalf("run the script: %v", err)
	}
	if err != nil {
		t.Logf("output: %s", out)
	}
	b, readErr := os.ReadFile(filepath.Join(box, "log"))
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		t.Fatal(readErr)
	}
	var log []string
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if l != "" {
			log = append(log, strings.ReplaceAll(l, box, "SANDBOX"))
		}
	}
	return log, err
}
