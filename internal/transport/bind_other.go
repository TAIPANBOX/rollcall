//go:build !linux

package transport

// bindToDevice does nothing where SO_BINDTODEVICE does not exist. The socket
// stays bound to its address, and BoundToDevice reports false.
func bindToDevice(uintptr, string) (bool, error) { return false, nil }

// sharePort does nothing off Linux: BSD lets the wildcard bind of a group
// socket, which Go gives SO_REUSEADDR and SO_REUSEPORT, sit beside a bound
// address of the same port.
func sharePort(int) error { return nil }
