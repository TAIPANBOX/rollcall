//go:build linux && (amd64 || arm64 || arm || mips || mipsle)

package main

import (
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// TestConstantsMatchXSys ties the values filter.go spells out to golang.org/x/sys/unix, so the
// portable builder and its tests use exactly what the kernel reads.
func TestConstantsMatchXSys(t *testing.T) {
	pairs := []struct {
		name      string
		mine, sys uint64
	}{
		{"BPF_LD", bpfLD, unix.BPF_LD}, {"BPF_W", bpfW, unix.BPF_W}, {"BPF_ABS", bpfABS, unix.BPF_ABS},
		{"BPF_JMP", bpfJMP, unix.BPF_JMP}, {"BPF_JEQ", bpfJEQ, unix.BPF_JEQ}, {"BPF_K", bpfK, unix.BPF_K},
		{"BPF_RET", bpfRET, unix.BPF_RET},
		{"SECCOMP_RET_KILL_PROCESS", retKillProcess, unix.SECCOMP_RET_KILL_PROCESS},
		{"SECCOMP_RET_ALLOW", retAllow, unix.SECCOMP_RET_ALLOW},
		{"sizeof(sock_filter)", uint64(unsafe.Sizeof(insn{})), uint64(unsafe.Sizeof(unix.SockFilter{}))},
	}
	for _, p := range pairs {
		if p.mine != p.sys {
			t.Errorf("%s: filter.go has %#x, x/sys %#x", p.name, p.mine, p.sys)
		}
	}
	if len(sysnums) < 200 {
		t.Errorf("only %d system calls in the table", len(sysnums))
	}
	for _, name := range []string{"read", "write", "execve", "prctl", "eventfd2", "futex", "exit_group"} {
		if _, ok := sysnums[name]; !ok {
			t.Errorf("the table has no %s", name)
		}
	}
}
