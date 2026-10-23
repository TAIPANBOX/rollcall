//go:build linux && !(amd64 || arm64 || arm || mips || mipsle)

package sandbox

import (
	"fmt"
	"runtime"
)

// Confine refuses on a Linux architecture rollcall ships no system call list for: the daemon
// does not run there without a filter.
func Confine() (int, error) {
	return 0, fmt.Errorf("no seccomp list for linux/%s, so rollcalld cannot filter itself there", runtime.GOARCH)
}
