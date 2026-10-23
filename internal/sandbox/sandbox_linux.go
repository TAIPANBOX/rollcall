//go:build linux && (amd64 || arm64 || arm || mips || mipsle)

package sandbox

import (
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Confine installs the seccomp filter of this architecture on every thread of the process and
// returns the number of system calls it allows. From then on any other call, and any call made
// with another architecture's numbering, ends the whole process with SIGSYS. It sets
// no_new_privs first, which an unprivileged process needs for a filter and which the filter
// cannot be removed without; a filter, once installed, stays for the life of the process.
//
// rollcalld calls it once at start. procd cannot do it for the daemon: it applies a profile
// through LD_PRELOAD=/lib/libpreload-seccomp.so, which a statically linked binary never loads.
func Confine() (int, error) {
	names, err := Allowed(runtime.GOARCH)
	if err != nil {
		return 0, err
	}
	nrs, err := Numbers(names, sysnums, nil)
	if err != nil {
		return 0, err
	}
	prog, err := Build(auditArch, nrs)
	if err != nil {
		return 0, err
	}
	if err := install(prog); err != nil {
		return 0, err
	}
	return len(nrs), nil
}

// install sets no_new_privs and installs prog with SECCOMP_FILTER_FLAG_TSYNC, so the kernel puts
// the filter, and no_new_privs, on every thread of the process at once: the Go runtime runs
// several threads before main starts, and a thread left out would run unfiltered.
func install(prog []Insn) error {
	if len(prog) == 0 || len(prog) > unix.BPF_MAXINSNS {
		return fmt.Errorf("seccomp: a program of %d instructions", len(prog))
	}
	filter := make([]unix.SockFilter, len(prog))
	for i, in := range prog {
		filter[i] = unix.SockFilter{Code: in.Code, Jt: in.Jt, Jf: in.Jf, K: in.K}
	}
	fprog := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}

	// no_new_privs is per thread and the kernel checks it on the thread that installs the
	// filter, so both calls are made on one thread.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("no_new_privs: %w", err)
	}
	r, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER,
		unix.SECCOMP_FILTER_FLAG_TSYNC, uintptr(unsafe.Pointer(&fprog)))
	runtime.KeepAlive(filter)
	return seccompResult(r, errno)
}

// seccompResult reads what seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC) returned:
// 0 when every thread has the filter, an errno when the kernel refused it, and otherwise the ID
// of a thread it could not synchronise. That thread would run unfiltered, so it fails too.
func seccompResult(r uintptr, errno syscall.Errno) error {
	switch {
	case errno != 0:
		return fmt.Errorf("seccomp: %w", errno)
	case r != 0:
		return fmt.Errorf("seccomp: thread %d could not be given the filter, so it would run unfiltered", r)
	}
	return nil
}
