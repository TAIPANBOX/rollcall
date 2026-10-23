// Package sandbox builds the seccomp filter of rollcalld from the system call list of its
// architecture (packaging/seccomp) and installs it on every thread of the process.
//
// The program is classic BPF: kill a call made with any other audit architecture, allow the
// listed numbers, kill everything else (SECCOMP_RET_KILL_PROCESS). This file builds it on any
// system, so it is tested everywhere; installing it is Linux only (sandbox_linux.go).
package sandbox

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
)

// Classic BPF and seccomp values (linux/bpf_common.h, linux/filter.h, linux/seccomp.h). They are
// spelled out here so the filter builds and is tested on any system; consts_linux_test.go checks
// them against golang.org/x/sys/unix on Linux.
const (
	bpfLD  = 0x00
	bpfW   = 0x00
	bpfABS = 0x20
	bpfJMP = 0x05
	bpfJEQ = 0x10
	bpfK   = 0x00
	bpfRET = 0x06

	retKillProcess = 0x80000000 // SECCOMP_RET_KILL_PROCESS
	retAllow       = 0x7fff0000 // SECCOMP_RET_ALLOW

	offNr   = 0 // offsetof(struct seccomp_data, nr)
	offArch = 4 // offsetof(struct seccomp_data, arch)

	// maxAllowed bounds the list: each allowed number is one jeq whose true branch jumps to the
	// final allow, and a classic BPF jump offset is 8 bits.
	maxAllowed = 255
)

// Insn is one classic BPF instruction (struct sock_filter).
type Insn struct {
	Code   uint16
	Jt, Jf uint8
	K      uint32
}

// Numbers maps the names to this architecture's numbers, sorted and once each, leaving out the
// names in without (each must be in the list, so a typing mistake does not pass as a test).
// A name the table does not have is an error: the list would protect nothing with it, and the
// call the program really makes would be missing.
func Numbers(names []string, table map[string]uint32, without map[string]bool) ([]uint32, error) {
	var unknown []string
	var nrs []uint32
	in := map[string]bool{}
	for _, name := range names {
		in[name] = true
		if without[name] {
			continue
		}
		nr, ok := table[name]
		if !ok {
			unknown = append(unknown, name)
			continue
		}
		nrs = append(nrs, nr)
	}
	for name := range without {
		if !in[name] {
			unknown = append(unknown, name+" (in -without, not in the profile)")
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return nil, fmt.Errorf("not system calls of this architecture: %s", strings.Join(unknown, ", "))
	}
	slices.Sort(nrs)
	return slices.Compact(nrs), nil
}

// Build returns the program: kill a call of any other architecture, allow the listed numbers,
// kill everything else. The numbers are compared whole, so an x32 call (bit 30 set on x86_64)
// matches none of them.
func Build(arch uint32, nrs []uint32) ([]Insn, error) {
	switch {
	case len(nrs) == 0:
		return nil, errors.New("filter: no system call allowed")
	case len(nrs) > maxAllowed:
		return nil, fmt.Errorf("filter: %d system calls; at most %d", len(nrs), maxAllowed)
	}
	prog := []Insn{
		{Code: bpfLD | bpfW | bpfABS, K: offArch},
		{Code: bpfJMP | bpfJEQ | bpfK, Jt: 1, Jf: 0, K: arch},
		{Code: bpfRET | bpfK, K: retKillProcess},
		{Code: bpfLD | bpfW | bpfABS, K: offNr},
	}
	for i, nr := range nrs {
		// The allow is after the remaining comparisons and the final kill.
		prog = append(prog, Insn{Code: bpfJMP | bpfJEQ | bpfK, Jt: uint8(len(nrs) - i), Jf: 0, K: nr})
	}
	prog = append(prog,
		Insn{Code: bpfRET | bpfK, K: retKillProcess},
		Insn{Code: bpfRET | bpfK, K: retAllow},
	)
	return prog, nil
}
