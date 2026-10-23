package gates

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
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

// daemonMainRel holds ControlDirPath, the directory the daemon creates its control socket in.
const daemonMainRel = "cmd/rollcalld/main.go"

// controlDirConst finds the value of ControlDirPath in the daemon's source.
var controlDirConst = regexp.MustCompile(`ControlDirPath\s*=\s*"([^"]+)"`)

// jailResolver are the read-only mounts the daemon resolves api.telegram.org and probe host names
// through. On OpenWrt 24.10 and 25.12 /etc/resolv.conf links to /tmp/resolv.conf, which boot links
// to /tmp/resolv.conf.d/resolv.conf.auto and dnsmasq may replace with a file, so the jail carries
// all three: whichever way ujail stages /etc/resolv.conf, the file it names is there.
var jailResolver = []string{"/etc/resolv.conf", "/tmp/resolv.conf", "/tmp/resolv.conf.d"}

// jailForbidden are the configuration files the jail must never carry. On OpenWrt 25.12 network
// and system are mode 0600 root and may hold PPPoE passwords and WireGuard private keys; the
// daemon takes what it needs from them, and from the firewall file, through the snapshot root
// writes (rollcall snapshot), so none of the three, nor a directory holding them, is mounted.
var jailForbidden = []string{"/etc/config/network", "/etc/config/system", "/etc/config/firewall"}

// snapshotCall is the service file's call that writes the snapshot, which must come before the
// instance is opened: without it the daemon refuses every start.
var snapshotCall = regexp.MustCompile(`(^|[\s;(!])("\$CLI"|\$CLI|/usr/bin/rollcall)\s+snapshot(\s|$)`)

// TestInitScriptHardening reads the service file and requires the hardening that every rollcall
// process runs with (invariant 13): its own user, no_new_privs, the seccomp profile and a jail
// with requirejail, so the daemon never starts unsandboxed. It also refuses ubus, which the
// daemon never touches, and capabilities outside the ICMP branch, because ICMP is the only probe
// that needs CAP_NET_RAW. Finally it applies the control server's own rule to the control
// directory the script makes (controlDirProblems), so the daemon is not refused at every start.
func TestInitScriptHardening(t *testing.T) {
	root := requireRoot(t)
	path := filepath.Join(root, filepath.FromSlash(initScriptRel))
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("measured nothing: read %s: %v", initScriptRel, err)
	}
	main, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(daemonMainRel)))
	if err != nil {
		t.Fatalf("measured nothing: read %s: %v", daemonMainRel, err)
	}
	m := controlDirConst.FindSubmatch(main)
	if m == nil {
		t.Fatalf("measured nothing: no ControlDirPath constant in %s", daemonMainRel)
	}
	problems := initScriptProblems(string(data))
	problems = append(problems, controlDirProblems(string(data), string(m[1]))...)
	for _, problem := range problems {
		t.Errorf("%s: %s", initScriptRel, problem)
	}
}

// daemonUser is the account procd runs rollcalld as (procd_set_param user).
const daemonUser = "rollcall"

// controlDirProblems checks the control directory the service file makes before the jail is
// built. internal/control (listen) refuses a socket directory that group or others may write to
// unless the sticky bit is set, so such a mode stops the daemon at every start and procd respawns
// it to exhaustion. The daemon, running as daemonUser, must also be able to create control.sock in
// it; root reaches the socket regardless of the mode, because root bypasses file permissions.
func controlDirProblems(text, dir string) []string {
	var owner, group, mode string
	for _, raw := range strings.Split(text, "\n") {
		f := strings.Fields(strings.TrimSpace(raw))
		if len(f) != 3 || f[2] != dir {
			continue
		}
		switch f[0] {
		case "chown":
			owner, group, _ = strings.Cut(f[1], ":")
		case "chmod":
			mode = f[1]
		}
	}
	if mode == "" {
		return []string{"the control directory " + dir + " gets no explicit mode (want a 'chmod <octal> " + dir + "' line)"}
	}
	if owner == "" {
		return []string{"the control directory " + dir + " gets no explicit owner (want a 'chown " + daemonUser + ":" + daemonUser + " " + dir + "' line)"}
	}
	m, err := strconv.ParseUint(mode, 8, 32)
	if err != nil || m > 0o7777 {
		return []string{"the control directory " + dir + " has mode " + mode + ", which is not an octal mode"}
	}
	perm, sticky := m&0o777, m&0o1000 != 0
	var problems []string
	if perm&0o022 != 0 && !sticky {
		problems = append(problems, fmt.Sprintf("the control directory %s is mode %04o: writable by group or others without the sticky bit, which internal/control refuses, so the daemon cannot start", dir, m))
	}
	ownerWrites := owner == daemonUser && perm&0o300 == 0o300
	groupWrites := group == daemonUser && perm&0o030 == 0o030
	if !ownerWrites && !groupWrites {
		problems = append(problems, fmt.Sprintf("the control directory %s is %s:%s mode %04o: user %s cannot create control.sock in it", dir, owner, group, m, daemonUser))
	}
	return problems
}

// initScriptProblems returns what the service text lacks or gets wrong. It works on a string so
// that the teeth cases and the gate read the same rules.
func initScriptProblems(text string) []string {
	var problems []string
	present := map[string]bool{}
	jailed, readOnly := false, false
	roMounts := map[string]bool{}
	snapshotAt, openAt := -1, -1
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

	for n, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if snapshotAt < 0 && snapshotCall.MatchString(line) {
			snapshotAt = n
		}
		if openAt < 0 && line == "procd_open_instance" {
			openAt = n
		}
		if strings.HasPrefix(line, "procd_add_jail_mount ") || strings.HasPrefix(line, "procd_add_jail_mount_rw ") {
			for _, p := range strings.Fields(line)[1:] {
				if held := jailHolds(p); held != "" {
					what := p
					if strings.TrimSuffix(p, "/") != held {
						what += ", which holds " + held
					}
					problems = append(problems, "the jail mounts "+what+": the daemon must not see the network, system or firewall "+
						"configuration (network and system are root's alone on OpenWrt 25.12 and may hold secrets); it reads the snapshot instead")
				}
			}
		}
		if strings.Contains(line, "ubus") {
			problems = append(problems, "uses ubus, which rollcall never touches: "+line)
		}
		// Root prepares nothing under /tmp: anyone can write there, so a path
		// planted as a symbolic link before the first start turns root's
		// mkdir, chown or chmod into a change of any file on the router.
		// /var/run is /tmp/run, which only root can write.
		if f := strings.Fields(line); len(f) > 1 && (f[0] == "mkdir" || f[0] == "chown" || f[0] == "chmod") {
			for _, a := range f[1:] {
				if strings.HasPrefix(a, "/tmp/") {
					problems = append(problems, "root runs "+f[0]+" on "+a+", under /tmp, which anyone can write: "+
						"a symbolic link planted there before the first start redirects it to any file; use a directory under /var/run")
				}
			}
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
		case strings.HasPrefix(line, "procd_add_jail_mount "):
			for _, p := range strings.Fields(line)[1:] {
				roMounts[p] = true
			}
		case strings.HasPrefix(line, "procd_add_jail rollcall"):
			if hasWord(line, "requirejail") {
				jailed = true
			}
			if hasWord(line, "ronly") {
				readOnly = true
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
	// Security section 7: the jail's root is read-only; only the procd_add_jail_mount_rw paths
	// are writable. procd.sh turns the word ronly into ujail -o, which remounts / read-only.
	for _, p := range jailResolver {
		if !roMounts[p] {
			problems = append(problems, "the jail does not mount "+p+" read-only: the daemon could not resolve api.telegram.org inside it")
		}
	}
	if !readOnly {
		problems = append(problems, "no 'ronly' on the procd_add_jail rollcall line: the jail's root would be writable (security section 7)")
	}
	switch {
	case openAt < 0:
		problems = append(problems, "no procd_open_instance line")
	case snapshotAt < 0 || snapshotAt > openAt:
		problems = append(problems, "the snapshot is not written (\"$CLI\" snapshot) before procd_open_instance: the daemon reads only the snapshot, so it would refuse every start")
	}
	return problems
}

// jailHolds returns the forbidden file a jail mount path is or contains, or "".
func jailHolds(p string) string {
	clean := strings.TrimSuffix(p, "/")
	for _, f := range jailForbidden {
		if clean == f || clean == "" || strings.HasPrefix(f, clean+"/") {
			return f
		}
	}
	return ""
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
			name: "initscript_ronly_removed", gate: "TestInitScriptHardening",
			plant: func(t *testing.T, dst string) {
				editCopy(t, dst, initScriptRel, func(s string) string {
					return strings.Replace(s, "procd_add_jail rollcall log procfs sysfs ronly requirejail",
						"procd_add_jail rollcall log procfs sysfs requirejail", 1)
				})
			},
			outcome: wantFail, expect: "no 'ronly'",
		},
		toothCase{
			name: "initscript_resolv_conf_removed", gate: "TestInitScriptHardening",
			plant: func(t *testing.T, dst string) {
				editCopy(t, dst, initScriptRel, func(s string) string {
					return strings.Replace(s, " /etc/resolv.conf /tmp/resolv.conf /tmp/resolv.conf.d", "", 1)
				})
			},
			outcome: wantFail, expect: "does not mount /etc/resolv.conf",
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
			// The lab defect L3: root chowned a directory under /tmp that anyone
			// could have planted as a symbolic link.
			name: "initscript_prepares_under_tmp", gate: "TestInitScriptHardening",
			plant: func(t *testing.T, dst string) {
				editCopy(t, dst, initScriptRel, func(s string) string {
					return strings.Replace(s, "procd_open_instance\n",
						"mkdir -p /tmp/rollcall\n\tchown rollcall:rollcall /tmp/rollcall\n\tprocd_open_instance\n", 1)
				})
			},
			outcome: wantFail, expect: "under /tmp",
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
			// The defect the gate was added for: root:rollcall 0770 stopped every start.
			name: "initscript_control_dir_group_writable", gate: "TestInitScriptHardening",
			plant: func(t *testing.T, dst string) {
				editCopy(t, dst, initScriptRel, func(s string) string {
					s = strings.Replace(s, "chown rollcall:rollcall /var/run/rollcall\n", "chown root:rollcall /var/run/rollcall\n", 1)
					return strings.Replace(s, "chmod 0700 /var/run/rollcall\n", "chmod 0770 /var/run/rollcall\n", 1)
				})
			},
			outcome: wantFail, expect: "without the sticky bit",
		},
		toothCase{
			name: "initscript_control_dir_root_owned", gate: "TestInitScriptHardening",
			plant: func(t *testing.T, dst string) {
				editCopy(t, dst, initScriptRel, func(s string) string {
					return strings.Replace(s, "chown rollcall:rollcall /var/run/rollcall\n", "chown root:root /var/run/rollcall\n", 1)
				})
			},
			outcome: wantFail, expect: "cannot create control.sock",
		},
		toothCase{
			name: "initscript_control_dir_no_mode", gate: "TestInitScriptHardening",
			plant: func(t *testing.T, dst string) {
				editCopy(t, dst, initScriptRel, func(s string) string {
					return strings.Replace(s, "chmod 0700 /var/run/rollcall\n", "", 1)
				})
			},
			outcome: wantFail, expect: "gets no explicit mode",
		},
		toothCase{
			name: "initscript_control_dir_sticky_group", gate: "TestInitScriptHardening",
			plant: func(t *testing.T, dst string) {
				// Group write with the sticky bit is what control accepts, so this one must pass.
				editCopy(t, dst, initScriptRel, func(s string) string {
					s = strings.Replace(s, "chown rollcall:rollcall /var/run/rollcall\n", "chown root:rollcall /var/run/rollcall\n", 1)
					return strings.Replace(s, "chmod 0700 /var/run/rollcall\n", "chmod 1770 /var/run/rollcall\n", 1)
				})
			},
			outcome: wantPass,
		},
		toothCase{
			// The defect the lab found: network and system are root's alone on 25.12.
			name: "initscript_network_mounted", gate: "TestInitScriptHardening",
			plant: func(t *testing.T, dst string) {
				editCopy(t, dst, initScriptRel, func(s string) string {
					return strings.Replace(s, "procd_add_jail_mount /etc/config/rollcall ", "procd_add_jail_mount /etc/config/rollcall /etc/config/network ", 1)
				})
			},
			outcome: wantFail, expect: "mounts /etc/config/network",
		},
		toothCase{
			name: "initscript_system_mounted", gate: "TestInitScriptHardening",
			plant: func(t *testing.T, dst string) {
				editCopy(t, dst, initScriptRel, func(s string) string {
					return strings.Replace(s, "procd_add_jail_mount /etc/config/rollcall ", "procd_add_jail_mount /etc/config/rollcall /etc/config/system ", 1)
				})
			},
			outcome: wantFail, expect: "mounts /etc/config/system",
		},
		toothCase{
			name: "initscript_config_dir_mounted", gate: "TestInitScriptHardening",
			plant: func(t *testing.T, dst string) {
				editCopy(t, dst, initScriptRel, func(s string) string {
					return strings.Replace(s, "procd_add_jail_mount /etc/config/rollcall ", "procd_add_jail_mount /etc/config/ ", 1)
				})
			},
			outcome: wantFail, expect: "mounts /etc/config/, which holds /etc/config/network",
		},
		toothCase{
			name: "initscript_etc_mounted_rw", gate: "TestInitScriptHardening",
			plant: func(t *testing.T, dst string) {
				editCopy(t, dst, initScriptRel, func(s string) string {
					return strings.Replace(s, "procd_add_jail_mount_rw /etc/rollcall ", "procd_add_jail_mount_rw /etc /etc/rollcall ", 1)
				})
			},
			outcome: wantFail, expect: "mounts /etc, which holds",
		},
		toothCase{
			name: "initscript_snapshot_not_written", gate: "TestInitScriptHardening",
			plant: func(t *testing.T, dst string) {
				editCopy(t, dst, initScriptRel, func(s string) string {
					return strings.Replace(s, `"$CLI" snapshot`, `"$CLI" version`, 1)
				})
			},
			outcome: wantFail, expect: "snapshot is not written",
		},
		toothCase{
			name: "initscript_snapshot_after_instance", gate: "TestInitScriptHardening",
			plant: func(t *testing.T, dst string) {
				editCopy(t, dst, initScriptRel, func(s string) string {
					s = strings.Replace(s, `"$CLI" snapshot`, `"$CLI" version`, 1)
					return strings.Replace(s, "\tprocd_close_instance\n", "\tprocd_close_instance\n\t\"$CLI\" snapshot\n", 1)
				})
			},
			outcome: wantFail, expect: "snapshot is not written",
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
