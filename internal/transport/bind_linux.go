//go:build linux

package transport

import (
	"errors"
	"runtime"
	"strings"
	"syscall"
)

// bindToDevice pins fd to iface with SO_BINDTODEVICE and reports whether the
// kernel accepted the pin. EPERM (an unprivileged process where the kernel
// refuses the pin) and ENOPROTOOPT are not errors: the socket stays bound to
// its address, and BoundToDevice reports false.
func bindToDevice(fd uintptr, iface string) (bool, error) {
	err := syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, iface)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.ENOPROTOOPT) {
		return false, nil
	}
	return false, err
}

// soReusePort is SO_REUSEPORT, which package syscall leaves out on amd64, 386
// and arm: 0x200 on MIPS, 15 on every other Linux architecture Go builds for.
var soReusePort = func() int {
	if strings.HasPrefix(runtime.GOARCH, "mips") {
		return 0x200
	}
	return 15
}()

// sharePort sets SO_REUSEPORT on fd. Go binds a group socket to the wildcard
// [::], and Linux refuses a wildcard bind beside a bound address of the same
// port and device, or the reverse, unless both sockets carry SO_REUSEADDR or
// both SO_REUSEPORT. SO_REUSEPORT is the one Linux limits to sockets of one
// user: no other user's process can bind beside rollcall's unicast addresses,
// where SO_REUSEADDR would let any process take their datagrams.
func sharePort(fd int) error {
	return syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, soReusePort, 1)
}
