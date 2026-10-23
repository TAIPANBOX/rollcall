//go:build unix

package config

import (
	"io/fs"
	"syscall"
)

// groupOf is the group that owns a file: the snapshot gets the run directory's group, which the
// init script sets to rollcall, so the daemon reads it through the group bit.
func groupOf(fi fs.FileInfo) (int, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(st.Gid), true
}
