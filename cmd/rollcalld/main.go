// Command rollcalld is the rollcall daemon.
package main

import "fmt"

// version is set at build time with -ldflags "-X main.version=<tag>".
var version = "dev"

func main() {
	fmt.Println("rollcalld", version)
}
