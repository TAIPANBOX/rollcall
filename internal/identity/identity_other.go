//go:build !(linux || darwin)

package identity

// readOpenFlags: this platform has no O_NOFOLLOW or O_NONBLOCK used here. The
// Lstat check before the open is the guard on it.
const readOpenFlags = 0
