package sandbox

import (
	"slices"
	"strings"
	"testing"
	"testing/fstest"
)

// TestAllowedPerFamily reads the lists embedded from packaging/seccomp: each GOARCH gets
// common.txt plus its family's list, sorted and once each, and only the names of its own ABI.
func TestAllowedPerFamily(t *testing.T) {
	cases := []struct {
		goarch     string
		has, lacks []string
	}{
		{"amd64", []string{"arch_prctl", "mmap", "newfstatat", "prctl", "eventfd2", "epoll_pwait", "futex"}, []string{"mmap2", "_llseek", "futex_time64"}},
		{"arm64", []string{"mmap", "newfstatat", "prctl", "eventfd2", "epoll_pwait"}, []string{"arch_prctl", "mmap2", "fstat64"}},
		{"arm", []string{"mmap2", "futex_time64", "brk", "open", "fstatat64"}, []string{"mmap", "arch_prctl", "newfstatat", "stat64"}},
		{"mips", []string{"mmap", "mmap2", "stat64", "lstat64", "futex_time64"}, []string{"newfstatat", "arch_prctl", "geteuid32"}},
		{"mipsle", []string{"mmap", "mmap2", "stat64", "lstat64", "futex_time64"}, []string{"newfstatat", "arch_prctl", "geteuid32"}},
	}
	for _, c := range cases {
		names, err := Allowed(c.goarch)
		if err != nil {
			t.Errorf("%s: %v", c.goarch, err)
			continue
		}
		if len(names) < 50 {
			t.Errorf("%s: only %d names", c.goarch, len(names))
		}
		if !slices.IsSorted(names) || len(slices.Compact(slices.Clone(names))) != len(names) {
			t.Errorf("%s: the names are not sorted once each: %v", c.goarch, names)
		}
		for _, n := range c.has {
			if !slices.Contains(names, n) {
				t.Errorf("%s: the list lacks %s", c.goarch, n)
			}
		}
		for _, n := range c.lacks {
			if slices.Contains(names, n) {
				t.Errorf("%s: the list carries %s, which belongs to another ABI", c.goarch, n)
			}
		}
	}
	for _, goarch := range []string{"riscv64", "386", "ppc64le", ""} {
		if names, err := Allowed(goarch); err == nil {
			t.Errorf("Allowed(%q) = %d names; want an error, there is no list for it", goarch, len(names))
		}
	}
}

// TestListRules applies generate.sh's rules to small lists: lines starting with # and blank
// lines drop out, trailing white space goes, the result is sorted once each, and any other
// line that is not a name of [a-z0-9_] is an error naming its file and line.
func TestListRules(t *testing.T) {
	fsys := fstest.MapFS{
		"common.txt":  {Data: []byte("# a comment\nread\n\n  \nwrite  \nread\n_llseek\n")},
		"aarch64.txt": {Data: []byte("mmap\t\r\n# another\nwrite\n")},
	}
	names, err := allowedFrom(fsys, "arm64")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"_llseek", "mmap", "read", "write"}; !slices.Equal(names, want) {
		t.Fatalf("allowedFrom = %v; want %v", names, want)
	}
	bad := map[string]string{
		"leading space":     " read\n",
		"upper case":        "Read\n",
		"two names":         "read write\n",
		"indented comment":  "  # comment\n",
		"dash":              "read-only\n",
		"name and comment":  "read # the read call\n",
		"non-ASCII letter":  "réad\n",
		"carriage in names": "re\rad\n",
	}
	for name, text := range bad {
		fsys := fstest.MapFS{"common.txt": {Data: []byte("write\n" + text)}, "aarch64.txt": {Data: []byte("mmap\n")}}
		_, err := allowedFrom(fsys, "arm64")
		if err == nil || !strings.Contains(err.Error(), "common.txt:2") {
			t.Errorf("%s: allowedFrom error %v; want one naming common.txt:2", name, err)
		}
	}
	if _, err := allowedFrom(fstest.MapFS{"common.txt": {Data: []byte("read\n")}}, "arm64"); err == nil {
		t.Error("allowedFrom accepted a missing family list")
	}
	if _, err := allowedFrom(fstest.MapFS{"aarch64.txt": {Data: []byte("read\n")}}, "arm64"); err == nil {
		t.Error("allowedFrom accepted a missing common.txt")
	}
}
