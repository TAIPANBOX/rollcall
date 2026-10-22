package gates

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
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
