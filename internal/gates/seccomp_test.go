package gates

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// seccompGenerator writes one architecture's seccomp profile on stdout. The package build calls
// it, so the gate tests the file that ships, not a copy of it.
const seccompGenerator = "packaging/seccomp/generate.sh"

// seccompTargets are the OpenWrt architectures the Makefile ships.
var seccompTargets = []string{
	"x86_64",
	"aarch64_cortex-a53",
	"aarch64_generic",
	"arm_cortex-a7",
	"arm_cortex-a9",
	"mipsel_24kc",
	"mips_24kc",
}

// seccompLegacy32 are 32-bit system call names. No aarch64 profile may carry one of them.
var seccompLegacy32 = []string{
	"_llseek", "clock_gettime64", "fcntl64", "fstat64", "fstatat64",
	"getegid32", "geteuid32", "getgid32", "getuid32", "mmap2", "sigreturn", "ugetrlimit",
}

// seccompProfile is the procd format the generator writes.
type seccompProfile struct {
	DefaultAction string `json:"defaultAction"`
	Syscalls      []struct {
		Names  []string `json:"names"`
		Action string   `json:"action"`
	} `json:"syscalls"`
}

// seccompFamily maps an OpenWrt architecture to its list family. The generator does the same.
func seccompFamily(arch string) string {
	switch {
	case arch == "x86_64":
		return "amd64"
	case strings.HasPrefix(arch, "aarch64_"):
		return "aarch64"
	case strings.HasPrefix(arch, "arm_"):
		return "arm"
	case strings.HasPrefix(arch, "mips_"), strings.HasPrefix(arch, "mipsel_"):
		return "mips"
	}
	return ""
}

// TestSeccompProfilesPerArch runs the generator for every shipped architecture and checks each
// profile: it parses as JSON, its default action kills the process, arch_prctl is present only
// where Go needs it (amd64), and an aarch64 profile carries no 32-bit legacy name.
func TestSeccompProfilesPerArch(t *testing.T) {
	root := requireRoot(t)
	if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(seccompGenerator))); err != nil {
		t.Fatalf("measured nothing: %s: %v", seccompGenerator, err)
	}
	for _, arch := range seccompTargets {
		for _, problem := range seccompProblems(root, arch) {
			t.Errorf("%s: %s", arch, problem)
		}
	}
}

// seccompProblems runs the generator for one architecture and returns what its profile gets wrong.
func seccompProblems(root, arch string) []string {
	cmd := exec.Command("sh", seccompGenerator, arch)
	cmd.Dir = root
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return []string{"generator failed: " + err.Error() + ": " + strings.TrimSpace(stderr.String())}
	}
	return seccompCheck(arch, out)
}

// seccompCheck applies the rules to one generated profile. It works on bytes, so the teeth cases
// and the gate read the same rules.
func seccompCheck(arch string, data []byte) []string {
	var p seccompProfile
	if err := json.Unmarshal(data, &p); err != nil {
		return []string{"not JSON: " + err.Error()}
	}
	var problems []string
	if p.DefaultAction != "SCMP_ACT_KILL_PROCESS" {
		problems = append(problems, "defaultAction is "+p.DefaultAction+", want SCMP_ACT_KILL_PROCESS")
	}
	if len(p.Syscalls) != 1 || p.Syscalls[0].Action != "SCMP_ACT_ALLOW" || len(p.Syscalls[0].Names) == 0 {
		return append(problems, "want one SCMP_ACT_ALLOW rule with names")
	}

	have := map[string]bool{}
	for _, name := range p.Syscalls[0].Names {
		if have[name] {
			problems = append(problems, "duplicate name "+name)
		}
		have[name] = true
	}

	family := seccompFamily(arch)
	switch family {
	case "":
		return append(problems, "no list family for this architecture")
	case "amd64":
		if !have["arch_prctl"] {
			problems = append(problems, "amd64 lacks arch_prctl, which Go uses to set up TLS")
		}
	case "aarch64":
		if have["arch_prctl"] {
			problems = append(problems, "arch_prctl is amd64 only")
		}
		for _, name := range seccompLegacy32 {
			if have[name] {
				problems = append(problems, "aarch64 carries 32-bit legacy name "+name)
			}
		}
	case "arm", "mips":
		if have["arch_prctl"] {
			problems = append(problems, "arch_prctl is amd64 only")
		}
		if !have["mmap2"] {
			problems = append(problems, family+" profile lacks mmap2")
		}
	}
	return problems
}

// seccompNeed is one system call a profile must allow, with the source that makes it. Paths
// without a repository prefix are under $(go env GOROOT)/src of Go 1.27.3.
type seccompNeed struct{ name, source string }

// seccompRuntimeAll are the calls rollcalld makes on every run on every family: the Go runtime's
// own, the standard library's at start, and the daemon's at start. A missing one kills the
// daemon before it logs anything.
var seccompRuntimeAll = []seccompNeed{
	{"prctl", "runtime/set_vma_name_linux.go: prctl(PR_SET_VMA) names every new mapping (GODEBUG decoratemappings=1 by default, runtime/runtime1.go)"},
	{"eventfd2", "runtime/netpoll_epoll.go: netpollinit makes the netpoll break eventfd"},
	{"epoll_create1", "runtime/netpoll_epoll.go: netpollinit"},
	{"epoll_ctl", "runtime/netpoll_epoll.go: netpollopen"},
	{"epoll_pwait", "runtime/netpoll_epoll.go: netpoll (internal/runtime/syscall/linux EpollWait)"},
	{"futex", "runtime/os_linux.go: futexsleep and futexwakeup (on 32-bit only before kernel 5.1)"},
	{"clone", "runtime/os_linux.go: newosproc"},
	{"munmap", "runtime/mem_linux.go: sysFreeOS"},
	{"madvise", "runtime/mem_linux.go: sysUnusedOS and sysHugePageOS"},
	{"rt_sigaction", "runtime/os_linux.go: setsig"},
	{"rt_sigprocmask", "runtime/os_linux.go: sigprocmask"},
	{"rt_sigreturn", "runtime/sys_linux_*.s: sigreturn__sigaction, the restorer of every handler"},
	{"sigaltstack", "runtime/os_linux.go: minitSignalStack"},
	{"gettid", "runtime/os_linux.go: minit records the thread ID"},
	{"getpid", "runtime/os_linux.go: signalM, tgkill(getpid(), tid, SIGURG)"},
	{"tgkill", "runtime/os_linux.go: signalM, asynchronous preemption"},
	{"sched_getaffinity", "runtime/os_linux.go: getCPUCount at start and in the GOMAXPROCS update"},
	{"sched_yield", "runtime/os_linux.go: osyield"},
	{"nanosleep", "runtime/sys_linux_*.s: usleep (sysmon)"},
	{"fcntl", "runtime/fds_unix.go: checkfds; internal/syscall/unix.Fcntl (os.NewFile) through runtime.fcntl"},
	{"openat", "internal/runtime/cgroup/cgroup_linux.go: the CPU limit files; os.Open"},
	{"read", "internal/runtime/cgroup/cgroup_linux.go; every file and socket read"},
	{"pread64", "internal/runtime/cgroup/cgroup_linux.go: re-reads the CPU limit"},
	{"close", "internal/runtime/cgroup/cgroup_linux.go; every file and socket"},
	{"write", "os.Stderr: the daemon's log"},
	{"exit", "runtime/sys_linux_*.s: exitThread"},
	{"exit_group", "runtime/sys_linux_*.s: exit"},
	{"getrandom", "crypto/rand: internal/syscall/unix.GetRandom where the vDSO has no getrandom"},
	{"prlimit64", "syscall/rlimit.go: init raises RLIMIT_NOFILE through prlimit"},
	{"restart_syscall", "the kernel resumes a sleep a signal handler interrupted (nanosleep, futex with a timeout) through restart_syscall, and SIGURG preemption interrupts them"},
	{"execve", "procd jail/jail.c (openwrt/procd master): the in-process path installs the filter before execve; which path the procd of 24.10 and 25.12 takes is not established, so it is allowed"},
	{"socket", "syscall/netlink_linux.go: NetlinkRIB, which net.Interfaces runs at start and in every reconcile; internal/transport/route_linux.go: the route lookup before every unicast; every listener"},
	{"bind", "syscall/netlink_linux.go: NetlinkRIB; internal/transport/route_linux.go; every listener"},
	{"getsockname", "syscall/netlink_linux.go: NetlinkRIB"},
	{"sendto", "syscall/netlink_linux.go: NetlinkRIB; internal/transport/route_linux.go RTM_GETROUTE; internal/transport/udp.go WriteToUDPAddrPort"},
	{"recvfrom", "syscall/netlink_linux.go: NetlinkRIB; internal/transport/route_linux.go; internal/transport/udp.go ReadFromUDPAddrPort"},
	{"listen", "net.ListenUnix (internal/control) and net.ListenTCP (internal/transport)"},
	{"accept4", "internal/poll/sock_cloexec.go: accept on the control and TCP listeners"},
	{"setsockopt", "internal/transport/ifaces.go: SO_REUSEADDR, IPV6_MULTICAST_IF, IPV6_JOIN_GROUP; bind_linux.go SO_BINDTODEVICE; route_linux.go SO_RCVTIMEO"},
	{"getsockopt", "internal/control/cred_linux.go: SO_PEERCRED"},
}

// seccompRuntimeFamily are the calls that differ per family: the 32-bit runtime's own names,
// and the names the syscall package uses on each ABI for what os does at every start.
var seccompRuntimeFamily = map[string][]seccompNeed{
	"amd64": {
		{"arch_prctl", "runtime/sys_linux_amd64.s: settls sets the TLS base at start"},
		{"mmap", "runtime/sys_linux_amd64.s: runtime·mmap"},
		{"newfstatat", "syscall/syscall_linux_amd64.go: fstatat = SYS_NEWFSTATAT (os.Stat, os.Lstat)"},
	},
	"aarch64": {
		{"mmap", "runtime/sys_linux_arm64.s: runtime·mmap"},
		{"newfstatat", "syscall/syscall_linux_arm64.go: Fstatat, number 79, newfstatat in the kernel table (os.Stat, os.Lstat)"},
	},
	"arm": {
		{"mmap2", "runtime/sys_linux_arm.s: runtime·mmap uses SYS_mmap2"},
		{"brk", "runtime/malloc.go: mallocinit calls sbrk0 on 32-bit (runtime/sys_linux_arm.s SYS_brk)"},
		{"open", "runtime/os_linux.go: getHugePageSize at osinit; runtime/sys_linux_arm.s runtime·open uses SYS_open"},
		{"futex_time64", "runtime/os_linux32.go: every futex on kernels from 5.1"},
		{"uname", "runtime/os_linux32.go: configure64bitsTimeOn32BitsArchitectures reads the kernel release"},
		{"fstat64", "syscall/syscall_linux_arm.go: Fstat = SYS_FSTAT64 (os.File.Stat, os.ReadFile)"},
		{"fstatat64", "syscall/syscall_linux_arm.go: fstatat = SYS_FSTATAT64 (os.Stat, os.Lstat)"},
		{"geteuid32", "syscall/syscall_linux_arm.go: Geteuid = SYS_GETEUID32 (internal/control after bind)"},
	},
	"mips": {
		{"mmap", "runtime/sys_linux_mipsx.s: runtime·mmap uses SYS_mmap"},
		{"brk", "runtime/malloc.go: mallocinit calls sbrk0 on 32-bit (runtime/sys_linux_mipsx.s SYS_brk)"},
		{"open", "runtime/os_linux.go: getHugePageSize at osinit; runtime/sys_linux_mipsx.s runtime·open uses SYS_open"},
		{"futex_time64", "runtime/os_linux32.go: every futex on kernels from 5.1"},
		{"uname", "runtime/os_linux32.go: configure64bitsTimeOn32BitsArchitectures reads the kernel release"},
		{"clock_gettime", "runtime/sys_linux_mipsx.s: walltime and nanotime1 call it directly (no vDSO)"},
		{"fstat64", "syscall/syscall_linux_mipsx.go: Fstat = SYS_FSTAT64 (os.File.Stat, os.ReadFile)"},
		{"fstatat64", "internal/syscall/unix/at_sysnum_fstatat64_linux.go: Fstatat on mips and mipsle"},
		{"stat64", "syscall/syscall_linux_mipsx.go: Stat = SYS_STAT64 (os.Stat)"},
		{"lstat64", "syscall/syscall_linux_mipsx.go: Lstat = SYS_LSTAT64 (os.Lstat in internal/control)"},
	},
}

// TestSeccompRuntimeSetPerArch runs the generator for every shipped architecture and requires
// the named runtime set of its family: what the Go runtime, the standard library and the daemon
// do on every run, each with the source that makes the call. A profile that lacks one kills the
// daemon at start (the defect this gate was added for: prctl, eventfd2, and on 32-bit brk, open
// and futex_time64 were missing on every family).
func TestSeccompRuntimeSetPerArch(t *testing.T) {
	root := requireRoot(t)
	if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(seccompGenerator))); err != nil {
		t.Fatalf("measured nothing: %s: %v", seccompGenerator, err)
	}
	for _, arch := range seccompTargets {
		names, err := seccompNames(root, arch)
		if err != nil {
			t.Errorf("%s: %v", arch, err)
			continue
		}
		family := seccompFamily(arch)
		for _, need := range append(append([]seccompNeed{}, seccompRuntimeAll...), seccompRuntimeFamily[family]...) {
			if !names[need.name] {
				t.Errorf("%s: the profile lacks %s, which %s", arch, need.name, need.source)
			}
		}
	}
}

// seccompToolDir holds the loader that installs a profile as a real filter in CI, and the
// syscall tables generated from golang.org/x/sys for it.
const seccompToolDir = "tools/seccomp-run"

// seccompGoarch is the GOARCH of an OpenWrt architecture.
func seccompGoarch(arch string) string {
	switch {
	case arch == "x86_64":
		return "amd64"
	case strings.HasPrefix(arch, "aarch64_"):
		return "arm64"
	case strings.HasPrefix(arch, "arm_"):
		return "arm"
	case strings.HasPrefix(arch, "mipsel_"):
		return "mipsle"
	case strings.HasPrefix(arch, "mips_"):
		return "mips"
	}
	return ""
}

// TestSeccompNamesExistPerArch requires every name in each shipped profile to be a system call
// of that architecture, as golang.org/x/sys/unix numbers it (tools/seccomp-run/zsysnum_linux_*.go,
// generated from x/sys). A name the architecture does not have protects nothing and leaves the
// call the daemon really makes out (newfstatat on mips, whose o32 ABI has fstatat64; mmap on
// arm, whose EABI has only mmap2), and procd's handling of such a name is not established.
func TestSeccompNamesExistPerArch(t *testing.T) {
	root := requireRoot(t)
	if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(seccompGenerator))); err != nil {
		t.Fatalf("measured nothing: %s: %v", seccompGenerator, err)
	}
	tables := map[string]map[string]bool{}
	for _, arch := range seccompTargets {
		goarch := seccompGoarch(arch)
		if tables[goarch] == nil {
			table, err := seccompTable(root, goarch)
			if err != nil {
				t.Fatalf("measured nothing: %v", err)
			}
			tables[goarch] = table
		}
		names, err := seccompNames(root, arch)
		if err != nil {
			t.Errorf("%s: %v", arch, err)
			continue
		}
		for name := range names {
			if !tables[goarch][name] {
				t.Errorf("%s: %s is not a system call on %s (golang.org/x/sys/unix has no SYS_%s there)", arch, name, goarch, strings.ToUpper(name))
			}
		}
	}
}

// seccompNames runs the generator for one architecture and returns the names it allows.
func seccompNames(root, arch string) (map[string]bool, error) {
	cmd := exec.Command("sh", seccompGenerator, arch)
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	var p seccompProfile
	if err := json.Unmarshal(out, &p); err != nil {
		return nil, err
	}
	names := map[string]bool{}
	for _, rule := range p.Syscalls {
		for _, n := range rule.Names {
			names[n] = true
		}
	}
	return names, nil
}

// seccompTable reads the keys of the sysnums map in the generated table of one GOARCH.
func seccompTable(root, goarch string) (map[string]bool, error) {
	path := filepath.Join(root, filepath.FromSlash(seccompToolDir), "zsysnum_linux_"+goarch+".go")
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	table := map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		kv, ok := n.(*ast.KeyValueExpr)
		if !ok {
			return true
		}
		if lit, ok := kv.Key.(*ast.BasicLit); ok && lit.Kind == token.STRING {
			if name, err := strconv.Unquote(lit.Value); err == nil {
				table[name] = true
			}
		}
		return false
	})
	if len(table) == 0 {
		return nil, os.ErrNotExist
	}
	return table, nil
}

// init registers the teeth cases for TestSeccompProfilesPerArch. Each one plants a fault a real edit
// could make: a 32-bit name on aarch64, arch_prctl on aarch64, a default that allows, a missing
// amd64 entry, output that is not JSON, and a missing generator.
func init() {
	toothCases = append(toothCases,
		toothCase{
			name: "seccomp_clean", gate: "TestSeccompProfilesPerArch", outcome: wantPass,
		},
		toothCase{
			name: "seccomp_arch_prctl_on_aarch64", gate: "TestSeccompProfilesPerArch",
			plant: func(t *testing.T, dst string) {
				appendFile(t, filepath.Join(dst, "packaging", "seccomp", "aarch64.txt"), "arch_prctl\n")
			},
			outcome: wantFail, expect: "arch_prctl is amd64 only",
		},
		toothCase{
			name: "seccomp_legacy_name_on_aarch64", gate: "TestSeccompProfilesPerArch",
			plant: func(t *testing.T, dst string) {
				appendFile(t, filepath.Join(dst, "packaging", "seccomp", "aarch64.txt"), "mmap2\n")
			},
			outcome: wantFail, expect: "aarch64 carries 32-bit legacy name mmap2",
		},
		toothCase{
			name: "seccomp_amd64_without_arch_prctl", gate: "TestSeccompProfilesPerArch",
			plant: func(t *testing.T, dst string) {
				editCopy(t, dst, "packaging/seccomp/amd64.txt", func(s string) string {
					return strings.Replace(s, "arch_prctl\n", "", 1)
				})
			},
			outcome: wantFail, expect: "amd64 lacks arch_prctl",
		},
		toothCase{
			name: "seccomp_default_allows", gate: "TestSeccompProfilesPerArch",
			plant: func(t *testing.T, dst string) {
				// The printf line, not the header comment, which also names the constant.
				editCopy(t, dst, seccompGenerator, func(s string) string {
					return strings.Replace(s, `"defaultAction": "SCMP_ACT_KILL_PROCESS"`, `"defaultAction": "SCMP_ACT_ALLOW"`, 1)
				})
			},
			outcome: wantFail, expect: "defaultAction is SCMP_ACT_ALLOW",
		},
		toothCase{
			name: "seccomp_output_not_json", gate: "TestSeccompProfilesPerArch",
			plant: func(t *testing.T, dst string) {
				editCopy(t, dst, seccompGenerator, func(s string) string {
					return strings.Replace(s, `"defaultAction": `, `"defaultAction" `, 1)
				})
			},
			outcome: wantFail, expect: "not JSON",
		},
		toothCase{
			name: "seccomp_no_generator", gate: "TestSeccompProfilesPerArch",
			plant: func(t *testing.T, dst string) {
				removeFile(t, filepath.Join(dst, filepath.FromSlash(seccompGenerator)))
			},
			outcome: wantFail, expect: "measured nothing",
		},
	)
}

// init registers the teeth cases for TestSeccompRuntimeSetPerArch and TestSeccompNamesExistPerArch.
// The faults are the ones the profiles shipped with: prctl and eventfd2 missing everywhere, brk
// missing on 32-bit, newfstatat on mips (no such o32 call) and mmap on arm (none on EABI).
func init() {
	dropName := func(file, name string) func(*testing.T, string) {
		return func(t *testing.T, dst string) {
			editCopy(t, dst, "packaging/seccomp/"+file, func(s string) string {
				return strings.Replace(s, "\n"+name+"\n", "\n", 1)
			})
		}
	}
	addName := func(file, name string) func(*testing.T, string) {
		return func(t *testing.T, dst string) {
			appendFile(t, filepath.Join(dst, "packaging", "seccomp", file), name+"\n")
		}
	}
	toothCases = append(toothCases,
		toothCase{name: "seccomp_runtime_clean", gate: "TestSeccompRuntimeSetPerArch", outcome: wantPass},
		toothCase{
			name: "seccomp_runtime_no_prctl", gate: "TestSeccompRuntimeSetPerArch",
			plant: dropName("common.txt", "prctl"), outcome: wantFail,
			expect: "x86_64: the profile lacks prctl, which runtime/set_vma_name_linux.go",
		},
		toothCase{
			name: "seccomp_runtime_no_eventfd2", gate: "TestSeccompRuntimeSetPerArch",
			plant: dropName("common.txt", "eventfd2"), outcome: wantFail,
			expect: "aarch64_cortex-a53: the profile lacks eventfd2",
		},
		toothCase{
			name: "seccomp_runtime_no_brk_on_arm", gate: "TestSeccompRuntimeSetPerArch",
			plant: dropName("arm.txt", "brk"), outcome: wantFail,
			expect: "arm_cortex-a7: the profile lacks brk",
		},
		toothCase{
			name: "seccomp_runtime_no_lstat64_on_mips", gate: "TestSeccompRuntimeSetPerArch",
			plant: dropName("mips.txt", "lstat64"), outcome: wantFail,
			expect: "mipsel_24kc: the profile lacks lstat64",
		},
		toothCase{
			name: "seccomp_runtime_no_generator", gate: "TestSeccompRuntimeSetPerArch",
			plant: func(t *testing.T, dst string) {
				removeFile(t, filepath.Join(dst, filepath.FromSlash(seccompGenerator)))
			},
			outcome: wantFail, expect: "measured nothing",
		},

		toothCase{name: "seccomp_names_clean", gate: "TestSeccompNamesExistPerArch", outcome: wantPass},
		toothCase{
			name: "seccomp_names_newfstatat_on_mips", gate: "TestSeccompNamesExistPerArch",
			plant: addName("mips.txt", "newfstatat"), outcome: wantFail,
			expect: "mips_24kc: newfstatat is not a system call on mips",
		},
		toothCase{
			name: "seccomp_names_mmap_on_arm", gate: "TestSeccompNamesExistPerArch",
			plant: addName("common.txt", "mmap"), outcome: wantFail,
			expect: "arm_cortex-a7: mmap is not a system call on arm",
		},
		toothCase{
			name: "seccomp_names_no_table", gate: "TestSeccompNamesExistPerArch",
			plant: func(t *testing.T, dst string) {
				removeFile(t, filepath.Join(dst, filepath.FromSlash(seccompToolDir), "zsysnum_linux_mipsle.go"))
			},
			outcome: wantFail, expect: "measured nothing",
		},
	)
}
