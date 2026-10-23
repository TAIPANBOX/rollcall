package gates

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// # Capabilities of the daemon (security section 7)
//
// procd hands the file of `procd_set_param capabilities` to ujail (-C), which reads it before it
// builds the jail (jail/capabilities.c of procd 2026.03.13~58eb263d, the procd of OpenWrt 25.12):
// a JSON object with the arrays bounding, effective, inheritable, permitted and ambient, each a
// list of names such as CAP_NET_RAW. Each listed set is set to exactly its names; a set that is
// absent is left as it is (parseOCIcap returns every capability for a missing key), and without
// a file ujail touches no set at all. The setuid to the rollcall user then empties the effective
// and permitted sets but leaves the bounding set full: the lab run of 2026-10-23 read CapBnd
// 000001ffffffffff on all three routers. So the gate requires a file on every start: one whose
// five sets are all present and empty when ICMP probes are off, one that grants CAP_NET_RAW and
// nothing else when they are on.
//
// rollcalld cannot empty its own bounding set: PR_CAPBSET_DROP needs CAP_SETPCAP in the effective
// set, and the daemon runs with none (CapEff 0), under no_new_privs, which also means nothing it
// executes could gain a capability back. Only ujail, still root, can drop it.

// capSets are the five sets of a procd capabilities file, as jail/capabilities.c names them.
var capSets = []string{"bounding", "effective", "inheritable", "permitted", "ambient"}

// icmpCap is the one capability the ICMP probe needs; nothing else is ever granted.
const icmpCap = "CAP_NET_RAW"

// packageScripts stage the package trees; each capabilities file the init script names must be
// installed by both, or the router has no such file and ujail refuses every start.
var packageScripts = []string{"scripts/mkapk.sh", "scripts/mkipk.sh"}

// capFrame is one open if block of the init script.
type capFrame struct {
	icmp   bool // the condition tests the icmp option
	thenOn bool // the then part is the start with ICMP probes on
	inElse bool // past the block's else
}

// capabilityProblems returns what is wrong with the capabilities the init script asks procd for.
// root is the repository, whose packaging/files holds the files the script names and whose
// scripts install them.
func capabilityProblems(text, root string) []string {
	var problems []string
	var stack []capFrame
	var on, off []string
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		switch {
		case f[0] == "if":
			fr := capFrame{icmp: strings.Contains(line, "icmp")}
			if fr.icmp {
				var known bool
				if fr.thenOn, known = icmpThenIsOn(line); !known {
					problems = append(problems, "cannot tell which branch of the icmp test starts with ICMP probes on: "+line)
				}
			}
			stack = append(stack, fr)
		case f[0] == "elif" && len(stack) > 0 && stack[len(stack)-1].icmp:
			problems = append(problems, "the icmp test has an elif, so the two starts are not one then and one else: "+line)
		case f[0] == "else" && len(stack) > 0:
			stack[len(stack)-1].inElse = true
		case f[0] == "fi" && len(stack) > 0:
			stack = stack[:len(stack)-1]
		case len(f) >= 2 && f[0] == "procd_set_param" && f[1] == "capabilities":
			i := len(stack) - 1
			for i >= 0 && !stack[i].icmp {
				i--
			}
			if i < 0 {
				problems = append(problems, "capabilities set outside the icmp branch: "+line)
				continue
			}
			if len(f) != 3 {
				problems = append(problems, "the capabilities line names no single file: "+line)
				continue
			}
			if stack[i].thenOn != stack[i].inElse {
				on = append(on, f[2])
			} else {
				off = append(off, f[2])
			}
		}
	}
	if len(off) == 0 {
		problems = append(problems, "a start without ICMP probes names no capabilities file: ujail then leaves the bounding set full "+
			"(lab run 2026-10-23: CapBnd 000001ffffffffff); name one whose five sets are all empty")
	}
	if len(on) == 0 {
		problems = append(problems, "a start with ICMP probes names no capabilities file: the probe would have no "+icmpCap)
	}
	for _, p := range off {
		problems = append(problems, capFileProblems(root, p, nil)...)
	}
	for _, p := range on {
		problems = append(problems, capFileProblems(root, p, []string{icmpCap})...)
	}
	return problems
}

// icmpThenIsOn reads an if line that tests the icmp option ([ "$icmp" = 1 ] and its variants)
// and reports whether its then part is the start with ICMP probes on.
func icmpThenIsOn(line string) (on, known bool) {
	f := strings.Fields(strings.NewReplacer(";", " ", `"`, " ", "'", " ").Replace(line))
	for i := 1; i+1 < len(f); i++ {
		v := f[i+1]
		if v != "0" && v != "1" {
			continue
		}
		switch f[i] {
		case "=", "==", "-eq":
			return v == "1", true
		case "!=", "-ne":
			return v == "0", true
		}
	}
	return false, false
}

// capFileProblems checks one capabilities file the init script names: it ships in
// packaging/files, both package scripts install it, it names all five sets and nothing else, and
// each set holds no capability outside allowed.
func capFileProblems(root, path string, allowed []string) []string {
	if !strings.HasPrefix(path, "/etc/capabilities/") || strings.Contains(path, "..") {
		return []string{"capabilities file " + path + " is not under /etc/capabilities, where the package installs them"}
	}
	rel := "packaging/files" + path
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		return []string{"cannot read the capabilities file " + rel + ", which the init script names: " + err.Error()}
	}
	var problems []string
	for _, s := range packageScripts {
		b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(s)))
		if err != nil || !bytes.Contains(b, []byte(`"$DATA`+path+`"`)) {
			problems = append(problems, path+" is not installed by "+s+": the router would not have it, and ujail refuses to start without it")
		}
	}
	var sets map[string][]string
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&sets); err != nil || sets == nil {
		return append(problems, rel+" is not a JSON object of capability lists")
	}
	for k := range sets {
		if !slices.Contains(capSets, k) {
			problems = append(problems, rel+": key "+k+" is not one of the five sets ujail reads")
		}
	}
	for _, k := range capSets {
		caps, ok := sets[k]
		if !ok {
			problems = append(problems, rel+": set "+k+" is absent, which procd 2026.03 reads as every capability")
			continue
		}
		for _, c := range caps {
			if !slices.Contains(allowed, strings.ToUpper(c)) {
				want := "none"
				if len(allowed) > 0 {
					want = strings.Join(allowed, ", ") + " only"
				}
				problems = append(problems, rel+": set "+k+" grants "+c+", want "+want)
			}
		}
	}
	return problems
}

// init registers the teeth cases of the capabilities part of TestInitScriptHardening.
func init() {
	const (
		none = "packaging/files/etc/capabilities/rollcall-none.json"
		icmp = "packaging/files/etc/capabilities/rollcall.json"
	)
	toothCases = append(toothCases,
		toothCase{
			// The lab finding L5: without a file the bounding set stayed full.
			name: "initscript_no_caps_without_icmp", gate: "TestInitScriptHardening",
			plant: func(t *testing.T, dst string) {
				editCopy(t, dst, initScriptRel, func(s string) string {
					return strings.Replace(s, "\telse\n\t\tprocd_set_param capabilities /etc/capabilities/rollcall-none.json\n", "", 1)
				})
			},
			outcome: wantFail, expect: "a start without ICMP probes names no capabilities file",
		},
		toothCase{
			name: "initscript_caps_none_grants_raw", gate: "TestInitScriptHardening",
			plant: func(t *testing.T, dst string) {
				editCopy(t, dst, none, func(s string) string {
					return strings.Replace(s, `"bounding": []`, `"bounding": ["CAP_NET_RAW"]`, 1)
				})
			},
			outcome: wantFail, expect: "set bounding grants CAP_NET_RAW, want none",
		},
		toothCase{
			// procd 2026.03 reads an absent set as every capability.
			name: "initscript_caps_none_set_absent", gate: "TestInitScriptHardening",
			plant: func(t *testing.T, dst string) {
				editCopy(t, dst, none, func(s string) string {
					return strings.Replace(s, `"bounding": [],`, ``, 1)
				})
			},
			outcome: wantFail, expect: "set bounding is absent",
		},
		toothCase{
			name: "initscript_caps_none_misspelt_set", gate: "TestInitScriptHardening",
			plant: func(t *testing.T, dst string) {
				editCopy(t, dst, none, func(s string) string {
					return strings.Replace(s, `"bounding"`, `"bouding"`, 1)
				})
			},
			outcome: wantFail, expect: "key bouding is not one of the five sets",
		},
		toothCase{
			name: "initscript_caps_icmp_grants_more", gate: "TestInitScriptHardening",
			plant: func(t *testing.T, dst string) {
				editCopy(t, dst, icmp, func(s string) string {
					return strings.Replace(s, `"effective": ["CAP_NET_RAW"]`, `"effective": ["CAP_NET_RAW", "CAP_SYS_ADMIN"]`, 1)
				})
			},
			outcome: wantFail, expect: "set effective grants CAP_SYS_ADMIN, want CAP_NET_RAW only",
		},
		toothCase{
			name: "initscript_caps_icmp_branch_swapped", gate: "TestInitScriptHardening",
			plant: func(t *testing.T, dst string) {
				editCopy(t, dst, initScriptRel, func(s string) string {
					return strings.Replace(s, `if [ "$icmp" = 1 ]; then`, `if [ "$icmp" = 0 ]; then`, 1)
				})
			},
			outcome: wantFail, expect: "set bounding grants CAP_NET_RAW, want none",
		},
		toothCase{
			name: "initscript_caps_not_shipped", gate: "TestInitScriptHardening",
			plant: func(t *testing.T, dst string) {
				editCopy(t, dst, "scripts/mkapk.sh", func(s string) string {
					return strings.Replace(s, `"$DATA/etc/capabilities/rollcall-none.json"`, `"$DATA/etc/capabilities/other.json"`, 1)
				})
			},
			outcome: wantFail, expect: "is not installed by scripts/mkapk.sh",
		},
		toothCase{
			name: "initscript_caps_file_missing", gate: "TestInitScriptHardening",
			plant: func(t *testing.T, dst string) {
				removeFile(t, filepath.Join(dst, filepath.FromSlash(none)))
			},
			outcome: wantFail, expect: "cannot read the capabilities file",
		},
	)
}
