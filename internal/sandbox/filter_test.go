package sandbox

import (
	"slices"
	"strings"
	"testing"
)

const testArch = 0xc000003e // AUDIT_ARCH_X86_64

var testTable = map[string]uint32{"read": 0, "write": 1, "close": 3, "prctl": 157, "execve": 59, "getppid": 110}

func TestNumbers(t *testing.T) {
	nrs, err := Numbers([]string{"read", "prctl", "write", "read"}, testTable, map[string]bool{"write": true})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(nrs, []uint32{0, 157}) {
		t.Fatalf("numbers = %v; want [0 157] (sorted, once each, write left out)", nrs)
	}
	if _, err := Numbers([]string{"read", "frobnicate", "newfstatat"}, testTable, nil); err == nil ||
		!strings.Contains(err.Error(), "frobnicate") || !strings.Contains(err.Error(), "newfstatat") {
		t.Fatalf("numbers with unknown names: %v; want an error naming both", err)
	}
	if _, err := Numbers([]string{"read"}, testTable, map[string]bool{"nosuch": true}); err == nil {
		t.Fatal("numbers accepted -without of a name the profile does not hold")
	}
}

// TestFilterAllowsOnlyTheList runs the program with the classic BPF interpreter below: the listed
// numbers of the right architecture are allowed, everything else kills the process.
func TestFilterAllowsOnlyTheList(t *testing.T) {
	allowed := []uint32{0, 1, 3, 59, 157}
	prog, err := Build(testArch, allowed)
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
	if _, err := Build(testArch, nil); err == nil {
		t.Error("buildFilter accepted an empty list")
	}
	many := make([]uint32, maxAllowed+1)
	for i := range many {
		many[i] = uint32(i)
	}
	if _, err := Build(testArch, many); err == nil {
		t.Errorf("buildFilter accepted %d numbers; jump offsets stop at %d", len(many), maxAllowed)
	}
	prog, err := Build(testArch, many[:maxAllowed])
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
func runFilter(t *testing.T, prog []Insn, arch, nr uint32) uint32 {
	t.Helper()
	var acc uint32
	for pc := 0; pc < len(prog); pc++ {
		in := prog[pc]
		switch in.Code {
		case bpfLD | bpfW | bpfABS:
			switch in.K {
			case offNr:
				acc = nr
			case offArch:
				acc = arch
			default:
				t.Fatalf("pc %d: load of offset %d", pc, in.K)
			}
		case bpfJMP | bpfJEQ | bpfK:
			if acc == in.K {
				pc += int(in.Jt)
			} else {
				pc += int(in.Jf)
			}
		case bpfRET | bpfK:
			return in.K
		default:
			t.Fatalf("pc %d: unexpected instruction %#x", pc, in.Code)
		}
	}
	t.Fatalf("the program ran off its end (arch %#x, nr %d)", arch, nr)
	return 0
}
