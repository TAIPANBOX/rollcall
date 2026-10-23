//go:build !linux || !(amd64 || arm64 || arm || mips || mipsle)

package main

import (
	"fmt"
	"os"
)

// main exists so the package builds everywhere; the loader runs only on the Linux architectures
// rollcall ships (main_linux.go).
func main() {
	fmt.Fprintln(os.Stderr, "seccomp-run: runs only on linux/amd64, arm64, arm, mips and mipsle")
	os.Exit(2)
}
