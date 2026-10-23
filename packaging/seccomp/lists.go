// Package seccomp carries the system call lists of this directory into rollcalld. generate.sh
// writes the profile each package ships (/etc/seccomp/rollcall.json) from the same files, and
// internal/sandbox builds the filter the daemon installs from these, so the two cannot be built
// from different lists; the gate TestSeccompDaemonListIsTheProfile holds the two readings of them
// to one result for every shipped target.
package seccomp

import "embed"

// Lists holds common.txt and the list of every family (amd64, aarch64, arm, mips).
//
//go:embed *.txt
var Lists embed.FS
