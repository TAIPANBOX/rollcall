package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/attest"
	"github.com/TAIPANBOX/rollcall/internal/history"
	"github.com/TAIPANBOX/rollcall/internal/identity"
	"github.com/TAIPANBOX/rollcall/internal/ids"
	"github.com/TAIPANBOX/rollcall/internal/node"
)

var tAttest = time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)

// attestRun is one run of the CLI for attest: as the user euid, with the
// kernel's boot ID kernel, the clock at now and the state directory dir.
// It counts the reads of the boot ID, and fails the test on any call to
// rollcalld: attest never asks it.
type attestRun struct {
	t        *testing.T
	dir      string
	euid     int
	kernel   ids.BootID
	bootErr  error
	now      time.Time
	bootRead int
}

func (a *attestRun) run(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	c := &cli{
		stdin: strings.NewReader(""), stdout: &out, stderr: &errb,
		getenv: func(string) string { return "" },
		call: func(context.Context, string, ...string) ([]byte, error) {
			a.t.Errorf("attest called rollcalld")
			return nil, errors.New("no daemon")
		},
		stateDir: a.dir, configPath: filepath.Join(a.dir, "none"),
		hostname: func() (string, error) { return "gw", nil },
		euid:     func() int { return a.euid },
		bootID: func() (ids.BootID, error) {
			a.bootRead++
			return a.kernel, a.bootErr
		},
		now: func() time.Time { return a.now },
	}
	code := c.run(args)
	return code, out.String(), errb.String()
}

// runningRouter is a group of one whose daemon ran long enough to write
// this boot's record, then stopped (so nothing writes while the test reads).
func runningRouter(t *testing.T) *router {
	t.Helper()
	s := newSite(t)
	r := s.add("gateway")
	r.initGroup()
	r.start()
	s.run(90 * time.Second)
	r.stop()
	return r
}

// ownChain reads the member's own history file without internal/attest.
func ownChain(t *testing.T, dir string, id ids.MemberID) []history.Entry {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, node.HistoryFile(id)))
	if err != nil {
		t.Fatal(err)
	}
	var es []history.Entry
	if err := json.Unmarshal(b, &es); err != nil {
		t.Fatal(err)
	}
	return es
}

// TestAttestCommand: on a router whose daemon wrote its chain, attest
// prints one line, a statement that verifies under the router's member key
// over the nonce given, and names its member ID, the head of its own chain,
// the kernel's boot ID, the boot ID, sequence number and OpenWrt release of
// its latest boot record, the rollcall version and the time. Another nonce
// gives another signature, which the first statement does not carry.
func TestAttestCommand(t *testing.T) {
	r := runningRouter(t)
	id, err := identity.Load(r.dir)
	if err != nil {
		t.Fatal(err)
	}
	pub := id.Sign.Public().(ed25519.PublicKey)
	es := ownChain(t, r.dir, id.ID)
	if len(es) == 0 {
		t.Fatal("measured nothing: the daemon wrote no own chain")
	}
	head := history.Head{Seq: es[len(es)-1].Seq, Hash: es[len(es)-1].Hash()}
	var rec node.BootBody
	for i := len(es) - 1; i >= 0; i-- {
		if es[i].Kind == history.KindBoot {
			if rec, err = node.DecodeBoot(es[i]); err != nil {
				t.Fatal(err)
			}
			break
		}
	}
	if rec.Boot.ID != r.boot {
		t.Fatalf("measured nothing: the latest boot record names %s, the daemon ran in %s", rec.Boot.ID, r.boot)
	}

	a := &attestRun{t: t, dir: r.dir, euid: 0, kernel: r.boot, now: tAttest.Add(1500 * time.Millisecond)}
	nonce := strings.Repeat("5a", 32)
	code, out, errs := a.run("attest", "--nonce", nonce)
	if code != 0 || errs != "" {
		t.Fatalf("attest: exit %d, stderr %q", code, errs)
	}
	if strings.Count(out, "\n") != 1 || !strings.HasSuffix(out, "}\n") {
		t.Errorf("attest printed more than one line: %q", out)
	}
	s, sg, err := attest.Decode([]byte(out))
	if err != nil {
		t.Fatalf("the output does not read as a statement: %v\n%s", err, out)
	}
	if !attest.Verify(pub, s, sg) {
		t.Error("the statement does not verify under the member key")
	}
	want := attest.Statement{
		Nonce: bytes.Repeat([]byte{0x5a}, 32), Member: id.ID, Head: head, KernelBoot: r.boot,
		BootID: rec.Boot.ID, BootSeq: rec.Boot.Seq, OpenWrt: rec.Version, Rollcall: version,
		Time: tAttest.Add(time.Second), // whole seconds: 12:00:01.5 is signed as 12:00:01
	}
	if !bytes.Equal(s.SigningBytes(), want.SigningBytes()) {
		t.Errorf("statement\n got %+v\nwant %+v", s, want)
	}
	if rec.Version != "25.12.0" || rec.Boot.Seq == 0 {
		t.Errorf("measured nothing: the boot record says %q seq %d", rec.Version, rec.Boot.Seq)
	}

	code, out2, _ := a.run("attest", "--nonce", strings.Repeat("a5", 32))
	s2, sg2, err := attest.Decode([]byte(out2))
	if code != 0 || err != nil || !attest.Verify(pub, s2, sg2) {
		t.Fatalf("a second attest: exit %d, %v", code, err)
	}
	if bytes.Equal(sg, sg2) || attest.Verify(pub, s2, sg) {
		t.Error("the answer to one nonce passes for another")
	}
}

// TestAttestShowsACopy: the files of a router copied elsewhere still sign
// (a copy holds the key), but an answer kept from before does not verify
// for a new nonce, and the copy names a kernel boot ID other than the one
// its latest boot record names.
func TestAttestShowsACopy(t *testing.T) {
	r := runningRouter(t)
	id, err := identity.Load(r.dir)
	if err != nil {
		t.Fatal(err)
	}
	pub := id.Sign.Public().(ed25519.PublicKey)
	live := &attestRun{t: t, dir: r.dir, kernel: r.boot, now: tAttest}
	_, kept, _ := live.run("attest", "--nonce", strings.Repeat("01", 16))

	copyDir := filepath.Join(t.TempDir(), "copy")
	copyTree(t, r.dir, copyDir)
	elsewhere := &attestRun{t: t, dir: copyDir, kernel: ids.BootID{0xee, 15: 0xee}, now: tAttest.Add(time.Hour)}
	fresh := strings.Repeat("02", 16)
	code, out, errs := elsewhere.run("attest", "--nonce", fresh)
	if code != 0 {
		t.Fatalf("attest on the copy: exit %d, %s", code, errs)
	}
	s, sg, err := attest.Decode([]byte(out))
	if err != nil || !attest.Verify(pub, s, sg) {
		t.Fatalf("the copy's statement: %v", err)
	}
	if s.KernelBoot == s.BootID {
		t.Errorf("the copy names its kernel boot ID %s as its latest boot record's", s.KernelBoot)
	}
	k, ksg, err := attest.Decode([]byte(kept))
	if err != nil || k.KernelBoot != k.BootID {
		t.Fatalf("control: the live router's statement %+v, %v", k, err)
	}
	k.Nonce = s.Nonce
	if attest.Verify(pub, k, ksg) {
		t.Error("an answer kept from before verifies for a new nonce")
	}
}

func copyTree(t *testing.T, from, to string) {
	t.Helper()
	if err := os.Mkdir(to, 0o700); err != nil {
		t.Fatal(err)
	}
	ents, err := os.ReadDir(from)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if !e.Type().IsRegular() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(from, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(to, e.Name()), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// TestAttestNonceArgv: attest takes exactly --nonce with 16 to 64 bytes in
// hex; any other command line is refused as a usage error before anything
// is read (no boot ID, no state directory), with exit 2, or with exit 1 and
// the JSON failure reply under --json.
func TestAttestNonceArgv(t *testing.T) {
	ok16, ok64 := strings.Repeat("0f", 16), strings.Repeat("F0", 64)
	refused := [][]string{
		{"attest"},
		{"attest", "--nonce"},
		{"attest", "--nonce", ""},
		{"attest", "--nonce", strings.Repeat("0f", 15)},
		{"attest", "--nonce", strings.Repeat("0f", 65)},
		{"attest", "--nonce", ok16 + "0"},
		{"attest", "--nonce", "0x" + ok16[2:]},
		{"attest", "--nonce", ok16[:30] + "zz"},
		{"attest", "--nonce", strings.Repeat("0", 1<<16)},
		{"attest", "--nonce", ok16, "--nonce", ok16},
		{"attest", "--nonce", ok16, "extra"},
		{"attest", "--nonce", ok16, "--"},
		{"attest", "--nonce", "--", ok16},
		{"attest", ok16},
		{"attest", "--nonce=" + ok16},
		{"attest", "--key", "x", "--nonce", ok16},
	}
	dir := filepath.Join(t.TempDir(), "never-read")
	for _, args := range refused {
		a := &attestRun{t: t, dir: dir, now: tAttest}
		code, out, errs := a.run(args...)
		name := fmt.Sprintf("%.60q", strings.Join(args, " "))
		if code != 2 || out != "" || !strings.HasPrefix(errs, "rollcall: ") {
			t.Errorf("%s: exit %d, stdout %q, stderr %q; want a usage error", name, code, out, errs)
		}
		if a.bootRead != 0 {
			t.Errorf("%s: the boot ID was read before the command line was checked", name)
		}
		a = &attestRun{t: t, dir: dir, now: tAttest}
		code, out, _ = a.run(append(args[:1:1], append([]string{"--json"}, args[1:]...)...)...)
		if code != 1 || !strings.HasPrefix(out, `{"ok":false,"error":`) || a.bootRead != 0 {
			t.Errorf("%s with --json: exit %d, stdout %q", name, code, out)
		}
	}
	// The bounds themselves are accepted: the command gets as far as the
	// state directory, which is not there.
	for _, n := range []string{ok16, ok64} {
		a := &attestRun{t: t, dir: dir, now: tAttest}
		code, out, errs := a.run("attest", "--nonce", n)
		if code != 1 || out != "" || a.bootRead != 1 || !strings.Contains(errs, "member key") {
			t.Errorf("nonce of %d digits: exit %d, stdout %q, stderr %q, boot ID read %d times", len(n), code, out, errs, a.bootRead)
		}
	}
	var o bytes.Buffer
	(&cli{stdout: &o, stderr: &o}).run([]string{"help"})
	if !strings.Contains(o.String(), "rollcall attest --nonce <hex>") {
		t.Error("the usage does not name rollcall attest --nonce <hex>")
	}
}

// TestAttestNeedsRoot: attest signs only for root; as another user, or with
// no way to tell the user, it refuses before it reads anything, and so it
// does when the kernel's boot ID cannot be read.
func TestAttestNeedsRoot(t *testing.T) {
	r := runningRouter(t)
	nonce := strings.Repeat("77", 16)
	a := &attestRun{t: t, dir: r.dir, euid: 1000, kernel: r.boot, now: tAttest}
	code, out, errs := a.run("attest", "--nonce", nonce)
	if code != 1 || out != "" || !strings.Contains(errs, "run it as root") || a.bootRead != 0 {
		t.Errorf("as uid 1000: exit %d, stdout %q, stderr %q", code, out, errs)
	}
	var o, e bytes.Buffer
	c := &cli{stdout: &o, stderr: &e, stateDir: r.dir, bootID: func() (ids.BootID, error) { return r.boot, nil }, now: time.Now}
	if code := c.run([]string{"attest", "--nonce", nonce}); code != 1 || o.Len() != 0 {
		t.Errorf("with no user known: exit %d, stdout %q", code, o.String())
	}
	a = &attestRun{t: t, dir: r.dir, euid: 0, bootErr: errors.New("no proc"), now: tAttest}
	if code, out, errs := a.run("attest", "--nonce", nonce); code != 1 || out != "" || !strings.Contains(errs, "boot ID") {
		t.Errorf("no kernel boot ID: exit %d, stdout %q, stderr %q", code, out, errs)
	}
	a = &attestRun{t: t, dir: r.dir, euid: 0, kernel: r.boot, now: tAttest}
	if code, out, _ := a.run("attest", "--nonce", nonce); code != 0 || out == "" {
		t.Errorf("control: as root: exit %d, stdout %q", code, out)
	}
}

// TestAttestWritesNothing: an auditor that asks every hour wears nothing:
// a hundred runs of attest leave every file of the state directory, and the
// directory, as they were, a stale temporary file included.
func TestAttestWritesNothing(t *testing.T) {
	r := runningRouter(t)
	if err := os.WriteFile(filepath.Join(r.dir, ".epoch.json.4242"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := filepath.WalkDir(r.dir, func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return os.Chtimes(p, old, old)
	}); err != nil {
		t.Fatal(err)
	}
	before := treeState(t, r.dir)
	if len(before) < 5 {
		t.Fatalf("measured nothing: %d entries in the state directory", len(before))
	}
	a := &attestRun{t: t, dir: r.dir, kernel: r.boot, now: tAttest}
	for i := range 100 {
		if code, _, errs := a.run("attest", "--nonce", fmt.Sprintf("%032x", i+1)); code != 0 {
			t.Fatalf("run %d: exit %d, %s", i, code, errs)
		}
	}
	if d := treeDiff(before, treeState(t, r.dir)); len(d) > 0 {
		t.Errorf("attest changed the state directory:\n  %s", strings.Join(d, "\n  "))
	}
	// The comparison sees a write: a daemon start changes the directory.
	r.start()
	r.s.run(2 * time.Minute)
	r.stop()
	if d := treeDiff(before, treeState(t, r.dir)); len(d) == 0 {
		t.Error("control: a daemon run changed nothing either, so the comparison cannot see a write")
	}
}

type entryState struct {
	mode  fs.FileMode
	size  int64
	mtime time.Time
	sum   string
}

func treeState(t *testing.T, dir string) map[string]entryState {
	t.Helper()
	out := map[string]entryState{}
	err := filepath.WalkDir(dir, func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		st := entryState{mode: fi.Mode(), size: fi.Size(), mtime: fi.ModTime()}
		if fi.Mode().IsRegular() {
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			sum := sha256.Sum256(b)
			st.sum = hex.EncodeToString(sum[:])
		}
		rel, _ := filepath.Rel(dir, p)
		out[rel] = st
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func treeDiff(before, after map[string]entryState) []string {
	var d []string
	for k, b := range before {
		if a, ok := after[k]; !ok {
			d = append(d, k+" removed")
		} else if a != b {
			d = append(d, fmt.Sprintf("%s: %+v -> %+v", k, b, a))
		}
	}
	for k := range after {
		if _, ok := before[k]; !ok {
			d = append(d, k+" added")
		}
	}
	sort.Strings(d)
	return d
}
