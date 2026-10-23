//go:build linux && (amd64 || arm64 || arm || mips || mipsle)

package sandbox

import (
	"strings"
	"syscall"
	"testing"
)

// TestSeccompResult reads what seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC) returns:
// 0 is success; an errno is a refusal; a positive value is the ID of a thread the kernel could not
// synchronise, which would run unfiltered, so it is a failure too (fail closed).
func TestSeccompResult(t *testing.T) {
	if err := seccompResult(0, 0); err != nil {
		t.Fatalf("seccompResult(0, 0) = %v; want success", err)
	}
	if err := seccompResult(^uintptr(0), syscall.EACCES); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("seccompResult(-1, EACCES) = %v; want the errno", err)
	}
	if err := seccompResult(4242, 0); err == nil || !strings.Contains(err.Error(), "4242") {
		t.Errorf("seccompResult(4242, 0) = %v; want a failure naming thread 4242", err)
	}
}
