package sandbox

import (
	"fmt"
	"io/fs"
	"slices"
	"strings"
	"unicode"

	"github.com/TAIPANBOX/rollcall/packaging/seccomp"
)

// family is the list of packaging/seccomp that a GOARCH takes beside common.txt. generate.sh maps
// the OpenWrt architectures to the same families.
func family(goarch string) string {
	switch goarch {
	case "amd64":
		return "amd64"
	case "arm64":
		return "aarch64"
	case "arm":
		return "arm"
	case "mips", "mipsle":
		return "mips"
	}
	return ""
}

// Allowed returns the system calls the filter for goarch allows: common.txt plus the family's
// list, read as packaging/seccomp/generate.sh reads them for the profile the package ships.
func Allowed(goarch string) ([]string, error) {
	return allowedFrom(seccomp.Lists, goarch)
}

// allowedFrom applies generate.sh's rules: a line starting with # and a blank line drop out,
// trailing white space goes, and every other line must be one name of [a-z0-9_]; the result is
// sorted, once each.
func allowedFrom(lists fs.FS, goarch string) ([]string, error) {
	fam := family(goarch)
	if fam == "" {
		return nil, fmt.Errorf("no system call list for linux/%s", goarch)
	}
	var names []string
	for _, file := range []string{"common.txt", fam + ".txt"} {
		data, err := fs.ReadFile(lists, file)
		if err != nil {
			return nil, err
		}
		for i, line := range strings.Split(string(data), "\n") {
			line = strings.TrimRightFunc(line, unicode.IsSpace)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if !isName(line) {
				return nil, fmt.Errorf("%s:%d: %q is not a system call name", file, i+1, line)
			}
			names = append(names, line)
		}
	}
	slices.Sort(names)
	return slices.Compact(names), nil
}

// isName reports whether s is made of [a-z0-9_] only, as generate.sh requires.
func isName(s string) bool {
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '_' {
			return false
		}
	}
	return s != ""
}
