//go:build linux

package transport

import (
	"errors"
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
