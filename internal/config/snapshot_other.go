//go:build !unix

package config

import "io/fs"

// groupOf has no group to report where files have no unix owner.
func groupOf(fs.FileInfo) (int, bool) { return 0, false }
