package gates

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// feedKeyRel is the public half of the apk feed's signing pair (scripts/feed-keygen.sh). Every
// router that installs from the feed copies it into /etc/apk/keys.
const feedKeyRel = "keys/rollcall.pem"

// privateKeyPEM matches the first line of any PEM private key: EC, RSA, PKCS#8, OpenSSH,
// encrypted. It is assembled from parts so that this file, and any secret scanner reading it,
// never sees the marker itself.
var privateKeyPEM = regexp.MustCompile("-----BEGIN ([A-Z0-9]+ )*" + "PRIVATE" + " KEY-----")

// TestFeedPublicKey requires keys/rollcall.pem to be exactly one PEM block of type PUBLIC KEY
// that holds an EC key on P-256 (prime256v1): the only kind apk-tools v3 verifies, and the kind
// OpenWrt's own /etc/apk/keys/openwrt-25.12.pem is. A private key in its place, another curve or
// another algorithm is red, and so is anything after the block. A missing file has measured
// nothing.
func TestFeedPublicKey(t *testing.T) {
	root := requireRoot(t)
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(feedKeyRel)))
	if err != nil {
		t.Fatalf("measured nothing: %v", err)
	}
	problems := feedKeyProblems(data)
	for _, p := range problems {
		t.Errorf("%s: %s", feedKeyRel, p)
	}
	if len(problems) == 0 {
		t.Logf("%s: EC public key on P-256", feedKeyRel)
	}
}

// feedKeyProblems returns what is wrong with a PEM public key file for the feed.
func feedKeyProblems(data []byte) []string {
	block, rest := pem.Decode(data)
	if block == nil {
		return []string{"no PEM block"}
	}
	var problems []string
	if len(bytes.TrimSpace(rest)) != 0 {
		problems = append(problems, "more than one PEM block, or text after it")
	}
	if block.Type != "PUBLIC KEY" {
		return append(problems, fmt.Sprintf("the PEM block is %q, not PUBLIC KEY", block.Type))
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return append(problems, "not a public key: "+err.Error())
	}
	ec, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return append(problems, fmt.Sprintf("%T is not an EC key", key))
	}
	if name := ec.Curve.Params().Name; name != "P-256" {
		problems = append(problems, fmt.Sprintf("curve %s, not P-256 (prime256v1)", name))
	}
	return problems
}

// TestNoPrivateKeyCommittable requires that no file git would commit holds a private key: the
// tracked files and the untracked ones .gitignore does not exclude, each read in full, and no
// path ending in .private.pem among them. The feed's private half lives in
// keys/rollcall.private.pem on the signing workstation only, so this is red when that file is
// force-added, when .gitignore stops excluding it, and when any private key sits where
// .gitignore misses it. It reads git's own list of the files, so a root that is not the top of a
// git checkout has measured nothing.
func TestNoPrivateKeyCommittable(t *testing.T) {
	root := requireRoot(t)
	files, err := committableFiles(root)
	if err != nil {
		t.Fatalf("measured nothing: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("measured nothing: git lists no file")
	}
	read := 0
	for _, rel := range files {
		if strings.HasSuffix(rel, ".private.pem") {
			t.Errorf("%s: a private key file is tracked or would be committed", rel)
			continue
		}
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if errors.Is(err, fs.ErrNotExist) {
			continue // tracked but deleted in the working tree
		}
		if err != nil {
			t.Errorf("%s: %v", rel, err)
			continue
		}
		read++
		if privateKeyPEM.Match(data) {
			t.Errorf("%s: holds a private key", rel)
		}
	}
	t.Logf("%d of %d committable files read", read, len(files))
}

// committableFiles lists, through git, the tracked files of root and the untracked files that
// .gitignore does not exclude, relative to root with forward slashes.
func committableFiles(root string) ([]string, error) {
	top := exec.Command("git", "rev-parse", "--show-toplevel")
	top.Dir = root
	out, err := top.Output()
	if err != nil {
		return nil, fmt.Errorf("%s is not a git checkout: %v", root, err)
	}
	got, err := filepath.EvalSymlinks(strings.TrimSpace(string(out)))
	if err != nil {
		return nil, err
	}
	want, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}
	if got != want {
		return nil, fmt.Errorf("%s is not the top of a git checkout (git found %s)", root, got)
	}
	ls := exec.Command("git", "ls-files", "-z", "--cached", "--others", "--exclude-standard")
	ls.Dir = root
	out, err = ls.Output()
	if err != nil {
		return nil, fmt.Errorf("git ls-files in %s: %v", root, err)
	}
	var files []string
	seen := map[string]bool{}
	for _, rel := range strings.Split(string(out), "\x00") {
		if rel != "" && !seen[rel] {
			seen[rel] = true
			files = append(files, rel)
		}
	}
	return files, nil
}

// gitInit makes a teeth copy a git checkout of its own, so the gate reads git's list there.
func gitInit(t *testing.T, dst string, args ...[]string) {
	t.Helper()
	runs := append([][]string{{"-c", "init.defaultBranch=main", "init", "-q"}}, args...)
	for _, a := range runs {
		cmd := exec.Command("git", a...)
		cmd.Dir = dst
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %s in the copy: %v\n%s", strings.Join(a, " "), err, out)
		}
	}
}

// throwawayPEM returns a freshly generated key of the given kind as PEM, so no key, not even a
// fake one, is written into this file.
func throwawayPEM(t *testing.T, kind string) string {
	t.Helper()
	var block *pem.Block
	switch kind {
	case "ec-private":
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			t.Fatal(err)
		}
		block = &pem.Block{Type: "EC " + "PRIVATE" + " KEY", Bytes: der}
	case "p384-public":
		k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		block = &pem.Block{Type: "PUBLIC KEY", Bytes: der}
	case "ed25519-public":
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			t.Fatal(err)
		}
		block = &pem.Block{Type: "PUBLIC KEY", Bytes: der}
	default:
		t.Fatalf("unknown key kind %q", kind)
	}
	return string(pem.EncodeToMemory(block))
}

func init() {
	feedKey := func(dst string) string { return filepath.Join(dst, filepath.FromSlash(feedKeyRel)) }
	privateRel := "keys/rollcall.private.pem"
	toothCases = append(toothCases,
		toothCase{name: "feedkey_clean", gate: "TestFeedPublicKey", outcome: wantPass},
		toothCase{
			name: "feedkey_missing", gate: "TestFeedPublicKey",
			plant:   func(t *testing.T, dst string) { removeFile(t, feedKey(dst)) },
			outcome: wantFail, expect: "measured nothing",
		},
		toothCase{
			name: "feedkey_private_half_in_its_place", gate: "TestFeedPublicKey",
			plant: func(t *testing.T, dst string) {
				writeFile(t, feedKey(dst), throwawayPEM(t, "ec-private"))
			},
			outcome: wantFail, expect: "not PUBLIC KEY",
		},
		toothCase{
			name: "feedkey_wrong_curve", gate: "TestFeedPublicKey",
			plant: func(t *testing.T, dst string) {
				writeFile(t, feedKey(dst), throwawayPEM(t, "p384-public"))
			},
			outcome: wantFail, expect: "curve P-384",
		},
		toothCase{
			name: "feedkey_not_ec", gate: "TestFeedPublicKey",
			plant: func(t *testing.T, dst string) {
				writeFile(t, feedKey(dst), throwawayPEM(t, "ed25519-public"))
			},
			outcome: wantFail, expect: "is not an EC key",
		},
		toothCase{
			name: "feedkey_second_block", gate: "TestFeedPublicKey",
			plant: func(t *testing.T, dst string) {
				appendFile(t, feedKey(dst), throwawayPEM(t, "p384-public"))
			},
			outcome: wantFail, expect: "more than one PEM block",
		},

		toothCase{
			name: "privatekey_clean_checkout", gate: "TestNoPrivateKeyCommittable",
			plant:   func(t *testing.T, dst string) { gitInit(t, dst) },
			outcome: wantPass,
		},
		toothCase{
			name: "privatekey_not_a_checkout", gate: "TestNoPrivateKeyCommittable",
			outcome: wantFail, expect: "measured nothing",
		},
		toothCase{
			name: "privatekey_force_added", gate: "TestNoPrivateKeyCommittable",
			plant: func(t *testing.T, dst string) {
				writeFile(t, filepath.Join(dst, filepath.FromSlash(privateRel)), throwawayPEM(t, "ec-private"))
				gitInit(t, dst, []string{"add", "-f", privateRel})
			},
			outcome: wantFail, expect: privateRel + ": a private key file is tracked",
		},
		toothCase{
			name: "privatekey_gitignore_loses_the_rule", gate: "TestNoPrivateKeyCommittable",
			plant: func(t *testing.T, dst string) {
				writeFile(t, filepath.Join(dst, filepath.FromSlash(privateRel)), throwawayPEM(t, "ec-private"))
				ignore := filepath.Join(dst, ".gitignore")
				data, err := os.ReadFile(ignore)
				if err != nil {
					t.Fatal(err)
				}
				var kept []string
				for _, line := range strings.Split(string(data), "\n") {
					if line != "*.pem" && line != "keys/*" && line != "keys/*.private.pem" {
						kept = append(kept, line)
					}
				}
				writeFile(t, ignore, strings.Join(kept, "\n"))
				gitInit(t, dst)
			},
			outcome: wantFail, expect: privateRel + ": a private key file is tracked or would be committed",
		},
		toothCase{
			name: "privatekey_under_another_name", gate: "TestNoPrivateKeyCommittable",
			plant: func(t *testing.T, dst string) {
				writeFile(t, filepath.Join(dst, "docs", "signing-key.txt"), throwawayPEM(t, "ec-private"))
				gitInit(t, dst)
			},
			outcome: wantFail, expect: "docs/signing-key.txt: holds a private key",
		},
	)
}
