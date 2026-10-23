//go:build linux && (amd64 || arm64 || arm || mips || mipsle)

// Command seccomp-run answers the CI seccomp job's questions about rollcalld's seccomp filter on
// the architecture it is built for (tools/seccomp-run/prove.sh):
//
//	seccomp-run -arch       print this architecture (a check that this binary runs here)
//	seccomp-run -name 157   print the name of system call 157 on this architecture
//	seccomp-run -allowed    print how many system calls the daemon's filter allows, then their names
//
// It installs nothing: rollcalld installs its filter itself (internal/sandbox), and the job runs
// the daemon as it runs on a router. It once installed a profile and exec'd the daemon under it,
// the way procd was thought to; procd cannot filter the static daemon, so that path proved
// nothing about a router and is gone. The names and numbers are internal/sandbox's, from
// golang.org/x/sys/unix. Test-only: nothing under cmd/ or internal/ imports it, and no release
// builds it.
package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"

	"github.com/TAIPANBOX/rollcall/internal/sandbox"
)

func main() {
	name := flag.Int("name", -1, "print the name of this system call number and exit")
	arch := flag.Bool("arch", false, "print the architecture and exit")
	allowed := flag.Bool("allowed", false, "print the number of system calls the daemon's filter allows, then their names")
	flag.Parse()
	table := sandbox.Table()
	switch {
	case *arch:
		fmt.Printf("%s audit arch %#x, %d system calls known\n", runtime.GOARCH, sandbox.Arch(), len(table))
	case *name >= 0:
		for n, nr := range table {
			if int(nr) == *name {
				fmt.Println(n)
				return
			}
		}
		fmt.Printf("unknown(%d)\n", *name)
	case *allowed:
		names, err := sandbox.Allowed(runtime.GOARCH)
		if err == nil {
			var nrs []uint32
			nrs, err = sandbox.Numbers(names, table)
			if err == nil {
				fmt.Println(len(nrs))
				for _, n := range names {
					fmt.Println(n)
				}
				return
			}
		}
		fmt.Fprintln(os.Stderr, "seccomp-run:", err)
		os.Exit(2)
	default:
		fmt.Fprintln(os.Stderr, "usage: seccomp-run -arch | -name <number> | -allowed")
		os.Exit(2)
	}
}
