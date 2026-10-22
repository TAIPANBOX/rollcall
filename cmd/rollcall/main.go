// Command rollcall is the rollcall command-line tool. Task 1 only prints its version.
package main

import "fmt"

// version is set at build time with -ldflags "-X main.version=<tag>".
var version = "dev"

func main() {
	fmt.Println("rollcall", version)
}
