package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

// insn is one classic BPF instruction (struct sock_filter).
type insn struct {
	code   uint16
	jt, jf uint8
	k      uint32
}

// profile is the procd seccomp format packaging/seccomp/generate.sh writes.
type profile struct {
	DefaultAction string `json:"defaultAction"`
	Syscalls      []struct {
		Names  []string `json:"names"`
		Action string   `json:"action"`
	} `json:"syscalls"`
}

// readProfile returns the allowed names of a profile, and refuses anything this loader would
// apply differently from the profile's words: a default other than killing the process, a rule
// that is not an allow rule, an empty rule, an unknown field, or anything after the object.
func readProfile(data []byte) ([]string, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var p profile
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("profile: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("profile: data after the object")
	}
	if p.DefaultAction != "SCMP_ACT_KILL_PROCESS" {
		return nil, fmt.Errorf("profile: defaultAction %q; this loader applies only SCMP_ACT_KILL_PROCESS", p.DefaultAction)
	}
	if len(p.Syscalls) == 0 {
		return nil, errors.New("profile: no rules")
	}
	var names []string
	for i, rule := range p.Syscalls {
		if rule.Action != "SCMP_ACT_ALLOW" {
			return nil, fmt.Errorf("profile: rule %d has action %q; this loader applies only SCMP_ACT_ALLOW", i, rule.Action)
		}
		if len(rule.Names) == 0 {
			return nil, fmt.Errorf("profile: rule %d has no names", i)
		}
		names = append(names, rule.Names...)
	}
	return names, nil
}

// numbers maps the names to this architecture's numbers, sorted and once each, leaving out the
// names in without (each must be in the profile, so a typing mistake does not pass as a test).
// A name the table does not have is an error: the profile would protect nothing with it, and
// the call the program really makes would be missing.
func numbers(names []string, table map[string]uint32, without map[string]bool) ([]uint32, error) {
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

// buildFilter returns the program: kill a call of any other architecture, allow the listed
// numbers, kill everything else. The numbers are compared whole, so an x32 call (bit 30 set on
// x86_64) matches none of them.
func buildFilter(arch uint32, nrs []uint32) ([]insn, error) {
	switch {
	case len(nrs) == 0:
		return nil, errors.New("filter: no system call allowed")
	case len(nrs) > maxAllowed:
		return nil, fmt.Errorf("filter: %d system calls; at most %d", len(nrs), maxAllowed)
	}
	prog := []insn{
		{code: bpfLD | bpfW | bpfABS, k: offArch},
		{code: bpfJMP | bpfJEQ | bpfK, jt: 1, jf: 0, k: arch},
		{code: bpfRET | bpfK, k: retKillProcess},
		{code: bpfLD | bpfW | bpfABS, k: offNr},
	}
	for i, nr := range nrs {
		// The allow is after the remaining comparisons and the final kill.
		prog = append(prog, insn{code: bpfJMP | bpfJEQ | bpfK, jt: uint8(len(nrs) - i), jf: 0, k: nr})
	}
	prog = append(prog,
		insn{code: bpfRET | bpfK, k: retKillProcess},
		insn{code: bpfRET | bpfK, k: retAllow},
	)
	return prog, nil
}
