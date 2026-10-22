//go:build !linux

package transport

// bindToDevice does nothing where SO_BINDTODEVICE does not exist. The socket
// stays bound to its address, and BoundToDevice reports false.
func bindToDevice(uintptr, string) (bool, error) { return false, nil }
