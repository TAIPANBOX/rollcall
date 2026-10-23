package main

import (
	"slices"
	"strings"
	"testing"
)

const testArch = 0xc000003e // AUDIT_ARCH_X86_64

var testTable = map[string]uint32{"read": 0, "write": 1, "close": 3, "prctl": 157, "execve": 59, "getppid": 110}

func TestReadProfile(t *testing.T) {
	good := `{"defaultAction": "SCMP_ACT_KILL_PROCESS", "syscalls": [{"names": ["read", "write"], "action": "SCMP_ACT_ALLOW"}]}`
	names, err := readProfile([]byte(good))
	if err != nil || !slices.Equal(names, []string{"read", "write"}) {
		t.Fatalf("readProfile(good) = %v, %v", names, err)
	}
	bad := map[string]string{
		"default allows":   `{"defaultAction": "SCMP_ACT_ALLOW", "syscalls": [{"names": ["read"], "action": "SCMP_ACT_ALLOW"}]}`,
		"default errno":    `{"defaultAction": "SCMP_ACT_ERRNO", "syscalls": [{"names": ["read"], "action": "SCMP_ACT_ALLOW"}]}`,
		"rule not allow":   `{"defaultAction": "SCMP_ACT_KILL_PROCESS", "syscalls": [{"names": ["read"], "action": "SCMP_ACT_LOG"}]}`,
		"no names":         `{"defaultAction": "SCMP_ACT_KILL_PROCESS", "syscalls": [{"names": [], "action": "SCMP_ACT_ALLOW"}]}`,
		"no rules":         `{"defaultAction": "SCMP_ACT_KILL_PROCESS", "syscalls": []}`,
		"unknown field":    `{"defaultAction": "SCMP_ACT_KILL_PROCESS", "args": 1, "syscalls": [{"names": ["read"], "action": "SCMP_ACT_ALLOW"}]}`,
		"not json":         `{"defaultAction" "SCMP_ACT_KILL_PROCESS"}`,
		"trailing garbage": good + `{}`,
	}
	for name, text := range bad {
		if _, err := readProfile([]byte(text)); err == nil {
			t.Errorf("%s: readProfile accepted %s", name, text)
		}
	}
}

func TestNumbers(t *testing.T) {
	nrs, err := numbers([]string{"read", "prctl", "write", "read"}, testTable, map[string]bool{"write": true})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(nrs, []uint32{0, 157}) {
		t.Fatalf("numbers = %v; want [0 157] (sorted, once each, write left out)", nrs)
	}
	if _, err := numbers([]string{"read", "frobnicate", "newfstatat"}, testTable, nil); err == nil ||
		!strings.Contains(err.Error(), "frobnicate") || !strings.Contains(err.Error(), "newfstatat") {
		t.Fatalf("numbers with unknown names: %v; want an error naming both", err)
	}
	if _, err := numbers([]string{"read"}, testTable, map[string]bool{"nosuch": true}); err == nil {
		t.Fatal("numbers accepted -without of a name the profile does not hold")
	}
}

// TestFilterAllowsOnlyTheList runs the program with the classic BPF interpreter below: the listed
// numbers of the right architecture are allowed, everything else kills the process.
func TestFilterAllowsOnlyTheList(t *testing.T) {
	allowed := []uint32{0, 1, 3, 59, 157}
	prog, err := buildFilter(testArch, allowed)
	if err != nil {
		t.Fatal(err)
	}
	for nr := uint32(0); nr < 512; nr++ {
		want := uint32(retKillProcess)
		if slices.Contains(allowed, nr) {
			want = retAllow
		}
		if got := runFilter(t, prog, testArch, nr); got != want {
			t.Errorf("nr %d: action %#x; want %#x", nr, got, want)
		}
	}
	// Another architecture's call with an allowed number, and an x32 call (bit 30), are killed.
	if got := runFilter(t, prog, 0x40000003, 0); got != retKillProcess {
		t.Errorf("i386 read: action %#x; want kill", got)
	}
	if got := runFilter(t, prog, testArch, 0x40000000|157); got != retKillProcess {
		t.Errorf("x32 prctl: action %#x; want kill", got)
	}
}

func TestFilterLimits(t *testing.T) {
	if _, err := buildFilter(testArch, nil); err == nil {
		t.Error("buildFilter accepted an empty list")
	}
	many := make([]uint32, maxAllowed+1)
	for i := range many {
		many[i] = uint32(i)
	}
	if _, err := buildFilter(testArch, many); err == nil {
		t.Errorf("buildFilter accepted %d numbers; jump offsets stop at %d", len(many), maxAllowed)
	}
	prog, err := buildFilter(testArch, many[:maxAllowed])
	if err != nil {
		t.Fatal(err)
	}
	for _, nr := range []uint32{0, maxAllowed - 1} {
		if got := runFilter(t, prog, testArch, nr); got != retAllow {
			t.Errorf("nr %d of a full list: action %#x; want allow", nr, got)
		}
	}
	if got := runFilter(t, prog, testArch, maxAllowed); got != retKillProcess {
		t.Errorf("nr %d past a full list: action %#x; want kill", maxAllowed, got)
	}
}

// runFilter interprets the instructions buildFilter emits (ld [k], jeq #k, ret #k) over one
// seccomp_data, and fails the test on anything else or on a jump out of the program.
func runFilter(t *testing.T, prog []insn, arch, nr uint32) uint32 {
	t.Helper()
	var acc uint32
	for pc := 0; pc < len(prog); pc++ {
		in := prog[pc]
		switch in.code {
		case bpfLD | bpfW | bpfABS:
			switch in.k {
			case offNr:
				acc = nr
			case offArch:
				acc = arch
			default:
				t.Fatalf("pc %d: load of offset %d", pc, in.k)
			}
		case bpfJMP | bpfJEQ | bpfK:
			if acc == in.k {
				pc += int(in.jt)
			} else {
				pc += int(in.jf)
			}
		case bpfRET | bpfK:
			return in.k
		default:
			t.Fatalf("pc %d: unexpected instruction %#x", pc, in.code)
		}
	}
	t.Fatalf("the program ran off its end (arch %#x, nr %d)", arch, nr)
	return 0
}
