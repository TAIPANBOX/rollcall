//go:build linux || darwin

package store

import "syscall"

// readOpenFlags are added to O_RDONLY when a stored file is opened. O_NOFOLLOW
// refuses a symbolic link that replaced the file after it was checked, and
// O_NONBLOCK keeps a FIFO that replaced it from blocking the open.
const readOpenFlags = syscall.O_NOFOLLOW | syscall.O_NONBLOCK
