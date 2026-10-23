//go:build !linux

package sandbox

// Confine does nothing off Linux: rollcalld ships for Linux only, and a build for another system
// is a developer build with no seccomp to install.
func Confine() (int, error) { return 0, nil }
