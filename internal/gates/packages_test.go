package gates

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The packages make release writes, and the text `apk adbdump` prints for each .apk. The CI job
// packaging writes one dump per .apk as dist/adbdump/<package file name>.txt: apk v3 packages are
// ADB blobs that only apk-tools reads, so the gate reads apk's own listing of them.
const (
	packagesRel = "dist/release"
	adbdumpRel  = "dist/adbdump"
	// maxInnerTar bounds control.tar.gz and data.tar.gz held in memory while an .ipk is read.
	maxInnerTar = 64 << 20
)

// TestPackagesOwnedByRoot requires every entry of every built package, files and directories,
// to be owned by root. procd runs /etc/init.d/rollcall as root and hotplug runs /usr/bin/rollcall
// as root, and the seccomp and capability files and the rpcd ACL decide the sandbox: an entry any
// other account owns lets that account replace it and gain root or weaken the sandbox. The first
// lab packages had every entry owned by nobody:nogroup.
//
// An .ipk is a gzipped tar of debian-binary, control.tar.gz and data.tar.gz: every header of all
// three tars must carry uid 0, gid 0 and no owner name other than root. An .apk is read through
// its `apk adbdump` text: every acl must name user root and group root. It runs only with
// ROLLCALL_PACKAGES=1, after make release and the dumps (ci.yml, job packaging).
func TestPackagesOwnedByRoot(t *testing.T) {
	if os.Getenv("ROLLCALL_PACKAGES") != "1" {
		t.Skip("set ROLLCALL_PACKAGES=1 after make release and apk adbdump of each .apk into dist/adbdump/<name>.txt to check the owners")
	}
	root := requireRoot(t)
	dir := filepath.Join(root, filepath.FromSlash(packagesRel))
	ipks, _ := filepath.Glob(filepath.Join(dir, "*.ipk"))
	apks, _ := filepath.Glob(filepath.Join(dir, "*.apk"))
	if len(ipks) == 0 || len(apks) == 0 {
		t.Fatalf("measured nothing: %s holds %d .ipk and %d .apk; make release writes both", packagesRel, len(ipks), len(apks))
	}
	entries := 0
	for _, path := range ipks {
		n, problems, err := ipkOwnerProblems(path)
		if err != nil {
			t.Errorf("%s: %v", filepath.Base(path), err)
			continue
		}
		if n == 0 {
			t.Errorf("%s: no entry read: measured nothing", filepath.Base(path))
		}
		entries += n
		for _, p := range problems {
			t.Errorf("%s: %s", filepath.Base(path), p)
		}
	}
	for _, path := range apks {
		name := filepath.Base(path)
		dump, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(adbdumpRel), name+".txt"))
		if err != nil {
			t.Errorf("%s: its owners were not measured: no %s/%s.txt from apk adbdump: %v", name, adbdumpRel, name, err)
			continue
		}
		n, problems := adbdumpOwnerProblems(string(dump))
		if n == 0 {
			t.Errorf("%s: the adbdump lists no entry with an owner: measured nothing", name)
		}
		entries += n
		for _, p := range problems {
			t.Errorf("%s: %s", name, p)
		}
	}
	t.Logf("%d entries in %d .ipk and %d .apk read", entries, len(ipks), len(apks))
}

// ipkOwnerProblems reads an .ipk and returns the number of tar entries it read in all three tars
// and every entry not owned by root.
func ipkOwnerProblems(path string) (int, []string, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, nil, err
	}
	defer f.Close()
	n, problems, inner, err := tarOwnerProblems(f, "", true)
	if err != nil {
		return 0, nil, err
	}
	for _, name := range []string{"control.tar.gz", "data.tar.gz"} {
		data, ok := inner[name]
		if !ok {
			return 0, nil, fmt.Errorf("no %s in the outer archive", name)
		}
		m, p, _, err := tarOwnerProblems(bytes.NewReader(data), name+":", false)
		if err != nil {
			return 0, nil, fmt.Errorf("%s: %w", name, err)
		}
		n += m
		problems = append(problems, p...)
	}
	return n, problems, nil
}

// tarOwnerProblems reads one gzipped tar and checks the owner of every header. With keep, it
// also returns the contents of the members named control.tar.gz and data.tar.gz.
func tarOwnerProblems(r io.Reader, prefix string, keep bool) (int, []string, map[string][]byte, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return 0, nil, nil, err
	}
	tr := tar.NewReader(gz)
	n := 0
	var problems []string
	inner := map[string][]byte{}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return 0, nil, nil, err
		}
		n++
		if p := tarOwnerProblem(h); p != "" {
			problems = append(problems, prefix+h.Name+": "+p)
		}
		base := strings.TrimPrefix(h.Name, "./")
		if keep && (base == "control.tar.gz" || base == "data.tar.gz") {
			data, err := io.ReadAll(io.LimitReader(tr, maxInnerTar+1))
			if err != nil {
				return 0, nil, nil, err
			}
			if len(data) > maxInnerTar {
				return 0, nil, nil, fmt.Errorf("%s is larger than %d bytes", base, maxInnerTar)
			}
			inner[base] = data
		}
	}
	return n, problems, inner, nil
}

// tarOwnerProblem describes a header not owned by root, or returns "". opkg sets the owner from
// the numbers; a name other than root is refused as well, since another tar would use it.
func tarOwnerProblem(h *tar.Header) string {
	var bad []string
	if h.Uid != 0 {
		bad = append(bad, fmt.Sprintf("uid %d", h.Uid))
	}
	if h.Gid != 0 {
		bad = append(bad, fmt.Sprintf("gid %d", h.Gid))
	}
	if h.Uname != "" && h.Uname != "root" {
		bad = append(bad, fmt.Sprintf("user name %q", h.Uname))
	}
	if h.Gname != "" && h.Gname != "root" {
		bad = append(bad, fmt.Sprintf("group name %q", h.Gname))
	}
	if len(bad) == 0 {
		return ""
	}
	return "owned by " + strings.Join(bad, ", ") + "; want uid 0, gid 0"
}

// adbdumpOwnerProblems reads `apk adbdump` text and returns the number of acl blocks and every
// user or group that is not root, named by the entry it belongs to. Each acl must carry exactly
// one user and one group line, so an entry whose owner the dump does not show is not passed.
func adbdumpOwnerProblems(text string) (int, []string) {
	var problems []string
	acls, users, groups := 0, 0, 0
	dir, entry := "/", "/"
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		raw := sc.Text()
		line := strings.TrimSpace(raw)
		item := strings.HasPrefix(line, "- ")
		key, value, ok := strings.Cut(strings.TrimPrefix(line, "- "), ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch key {
		case "name":
			// A directory is an item of paths (two spaces in); a file is an item of its files.
			switch indent := len(raw) - len(strings.TrimLeft(raw, " ")); {
			case item && indent <= 2:
				dir, entry = value, value
			case item:
				entry = dir + "/" + value
			}
		case "acl":
			acls++
			if item {
				dir, entry = "/", "/" // the root directory's entry has an acl and no name
			}
		case "user", "group":
			if key == "user" {
				users++
			} else {
				groups++
			}
			if value != "root" {
				problems = append(problems, fmt.Sprintf("%s: %s %s; want root", entry, key, value))
			}
		}
	}
	if users != acls || groups != acls {
		problems = append(problems, fmt.Sprintf("%d acl blocks but %d user and %d group lines: an entry's owner is not shown", acls, users, groups))
	}
	return acls, problems
}

// adbdumpClean is apk adbdump text of a small package, the shape apk-tools 3.0.7 prints, with
// every entry owned by root.
const adbdumpClean = `#%SCHEMA: 676B6370
# ADB block, size: 1176, compat: 0, ver: 0
info:
  name: luci-app-rollcall
  version: 0.0.0_pre0-r1
  arch: noarch
paths: # 3 items
  - acl:
      mode: 0755
      user: root
      group: root
  - name: usr
    acl:
      mode: 0755
      user: root
      group: root
  - name: usr/share/rpcd/acl.d
    acl:
      mode: 0755
      user: root
      group: root
    files: # 1 items
      - name: luci-app-rollcall.json
        acl:
          mode: 0644
          user: root
          group: root
        size: 1755
`

// writeIPK writes a minimal .ipk at path: the outer tar and the two inner tars, every entry
// owned by uid 0 except data.tar.gz's ./usr/bin/rollcall, which gets dataUID and dataGID.
func writeIPK(t *testing.T, path string, dataUID, dataGID int) {
	t.Helper()
	gzTar := func(entries []tar.Header, body map[string][]byte) []byte {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		tw := tar.NewWriter(gz)
		for _, h := range entries {
			h.Size = int64(len(body[h.Name]))
			if err := tw.WriteHeader(&h); err != nil {
				t.Fatal(err)
			}
			if _, err := tw.Write(body[h.Name]); err != nil {
				t.Fatal(err)
			}
		}
		if err := tw.Close(); err != nil {
			t.Fatal(err)
		}
		if err := gz.Close(); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}
	dir := func(name string) tar.Header { return tar.Header{Name: name, Typeflag: tar.TypeDir, Mode: 0o755} }
	file := func(name string, mode int64) tar.Header {
		return tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: mode}
	}
	cli := file("./usr/bin/rollcall", 0o755)
	cli.Uid, cli.Gid = dataUID, dataGID
	data := gzTar([]tar.Header{dir("./"), dir("./usr/"), dir("./usr/bin/"), cli},
		map[string][]byte{"./usr/bin/rollcall": []byte("#!/bin/sh\n")})
	control := gzTar([]tar.Header{dir("./"), file("./control", 0o644)},
		map[string][]byte{"./control": []byte("Package: rollcall\n")})
	outer := gzTar([]tar.Header{file("./debian-binary", 0o644), file("./control.tar.gz", 0o644), file("./data.tar.gz", 0o644)},
		map[string][]byte{"./debian-binary": []byte("2.0\n"), "./control.tar.gz": control, "./data.tar.gz": data})
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, outer, 0o644); err != nil {
		t.Fatal(err)
	}
}

// plantPackages gives a teeth copy one .ipk and one .apk with its dump. The .apk's bytes are not
// read by the gate, only its dump.
func plantPackages(t *testing.T, dst string, dataUID, dataGID int, dump string) {
	t.Helper()
	rel := filepath.Join(dst, filepath.FromSlash(packagesRel))
	writeIPK(t, filepath.Join(rel, "rollcall_0.0.0-ci_x86_64.ipk"), dataUID, dataGID)
	writeFile(t, filepath.Join(rel, "rollcall-0.0.0_pre0-r1-x86_64.apk"), "not read by the gate\n")
	if dump != "" {
		writeFile(t, filepath.Join(dst, filepath.FromSlash(adbdumpRel), "rollcall-0.0.0_pre0-r1-x86_64.apk.txt"), dump)
	}
}

// init registers the teeth cases for TestPackagesOwnedByRoot: the owners the first lab packages
// had (every apk entry nobody), a CI runner's uid in an .ipk, an .apk nobody dumped, no packages
// at all, and a clean set that must pass.
func init() {
	env := []string{"ROLLCALL_PACKAGES=1"}
	toothCases = append(toothCases,
		toothCase{
			name: "packages_clean", gate: "TestPackagesOwnedByRoot", env: env,
			plant:   func(t *testing.T, dst string) { plantPackages(t, dst, 0, 0, adbdumpClean) },
			outcome: wantPass,
		},
		toothCase{
			name: "packages_apk_owned_by_nobody", gate: "TestPackagesOwnedByRoot", env: env,
			plant: func(t *testing.T, dst string) {
				plantPackages(t, dst, 0, 0, strings.ReplaceAll(adbdumpClean, ": root", ": nobody"))
			},
			outcome: wantFail, expect: "usr/share/rpcd/acl.d/luci-app-rollcall.json: user nobody",
		},
		toothCase{
			name: "packages_apk_one_group_not_root", gate: "TestPackagesOwnedByRoot", env: env,
			plant: func(t *testing.T, dst string) {
				plantPackages(t, dst, 0, 0, strings.Replace(adbdumpClean, "group: root", "group: rollcall", 1))
			},
			outcome: wantFail, expect: "/: group rollcall",
		},
		toothCase{
			name: "packages_apk_owner_not_shown", gate: "TestPackagesOwnedByRoot", env: env,
			plant: func(t *testing.T, dst string) {
				plantPackages(t, dst, 0, 0, strings.Replace(adbdumpClean, "      user: root\n", "", 1))
			},
			outcome: wantFail, expect: "owner is not shown",
		},
		toothCase{
			name: "packages_ipk_runner_uid", gate: "TestPackagesOwnedByRoot", env: env,
			plant:   func(t *testing.T, dst string) { plantPackages(t, dst, 1001, 1001, adbdumpClean) },
			outcome: wantFail, expect: "data.tar.gz:./usr/bin/rollcall: owned by uid 1001, gid 1001",
		},
		toothCase{
			name: "packages_apk_not_dumped", gate: "TestPackagesOwnedByRoot", env: env,
			plant:   func(t *testing.T, dst string) { plantPackages(t, dst, 0, 0, "") },
			outcome: wantFail, expect: "were not measured",
		},
		toothCase{
			name: "packages_none", gate: "TestPackagesOwnedByRoot", env: env,
			outcome: wantFail, expect: "measured nothing",
		},
	)
}
