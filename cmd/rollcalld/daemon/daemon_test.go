package daemon

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/config"
	"github.com/TAIPANBOX/rollcall/internal/epoch"
	"github.com/TAIPANBOX/rollcall/internal/events"
	"github.com/TAIPANBOX/rollcall/internal/identity"
	"github.com/TAIPANBOX/rollcall/internal/ids"
	"github.com/TAIPANBOX/rollcall/internal/node"
	"github.com/TAIPANBOX/rollcall/internal/probe"
	"github.com/TAIPANBOX/rollcall/internal/roster"
	"github.com/TAIPANBOX/rollcall/internal/store"
	"github.com/TAIPANBOX/rollcall/internal/wire"
)

var tStart = time.Date(2026, 10, 23, 9, 0, 0, 0, time.UTC)

// canary is the fake bot token the tests plant.
const canary = "CANARY-123:abc"

type fakeClock struct {
	mu   sync.Mutex
	wall time.Time
	mono time.Duration
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.wall
}

func (c *fakeClock) Mono() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.mono
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.wall, c.mono = c.wall.Add(d), c.mono+d
}

// recNet keeps what the node multicasts and reaches nobody.
type recNet struct {
	mu   sync.Mutex
	sent [][]byte
}

func (n *recNet) Multicast(b []byte) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.sent = append(n.sent, bytes.Clone(b))
	return nil
}
func (n *recNet) Unicast(netip.AddrPort, []byte) error { return nil }
func (n *recNet) Stream(netip.AddrPort, []byte) ([]byte, error) {
	return nil, errors.New("unreachable")
}

func (n *recNet) last() []byte {
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(n.sent) == 0 {
		return nil
	}
	return n.sent[len(n.sent)-1]
}

// fixture is one router's state, written as init or join leaves it.
type fixture struct {
	dir   string
	self  *identity.Identity
	other *identity.Identity // a second member, never online; nil for a group of one
	key   epoch.Key
}

// newFixture writes a group with this router as primary admin (with the
// sender role when sender is set) and, when two is set, a second member
// "ap-office".
func newFixture(t *testing.T, sender, two bool) fixture {
	t.Helper()
	f := fixture{dir: filepath.Join(t.TempDir(), "state")}
	var err error
	if f.self, err = identity.Generate(); err != nil {
		t.Fatal(err)
	}
	if err := f.self.Save(f.dir); err != nil {
		t.Fatal(err)
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	me := roster.Member{ID: f.self.ID, Name: "gateway", Roles: []roster.Role{roster.RolePrimary},
		SignPub: f.self.Sign.Public().(ed25519.PublicKey), RecvPub: f.self.Recv.PublicKey().Bytes()}
	if sender {
		me.Roles = append(me.Roles, roster.RoleSender)
	}
	r := roster.Roster{Version: 1, Site: "home", RecoveryPub: pub, Admins: []ids.MemberID{f.self.ID}, Members: []roster.Member{me}}
	if two {
		if f.other, err = identity.Generate(); err != nil {
			t.Fatal(err)
		}
		r.Members = append(r.Members, roster.Member{ID: f.other.ID, Name: "ap-office",
			SignPub: f.other.Sign.Public().(ed25519.PublicKey), RecvPub: f.other.Recv.PublicKey().Bytes()})
	}
	signed, err := roster.SignRoster(r, f.self.ID, f.self.Sign, false)
	if err != nil {
		t.Fatal(err)
	}
	secret := make([]byte, epoch.SecretSize)
	rand.Read(secret)
	f.key = epoch.Key{ID: 1 << 2, Secret: secret, NotAfter: tStart.Add(epoch.RotationPeriod)}
	st, err := store.Open(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := node.Bootstrap(st, signed, f.key); err != nil {
		t.Fatal(err)
	}
	return f
}

type harness struct {
	t   *testing.T
	clk *fakeClock
	net *recNet
	d   *Daemon
}

func start(t *testing.T, dir string, edit func(*Options)) *harness {
	t.Helper()
	h := &harness{t: t, clk: &fakeClock{wall: tStart, mono: 1000 * time.Second}, net: &recNet{}}
	o := Options{StateDir: dir, Net: h.net, Clock: h.clk, Boot: ids.BootID{1, 15: 1},
		Config: config.Config{Site: "Home", Port: 7432, Heartbeat: 5 * time.Second, SilentAfter: 30 * time.Second, Sender: true},
		Logf:   t.Logf}
	if edit != nil {
		edit(&o)
	}
	d, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	h.d = d
	d.Step()
	return h
}

func (h *harness) run(dur time.Duration) {
	for el := time.Duration(0); el < dur; el += time.Second {
		h.clk.advance(time.Second)
		h.d.Step()
	}
}

func (h *harness) handle(cmd string, args ...string) (reply, error) {
	h.t.Helper()
	b, err := h.d.Handle(cmd, args, 0)
	if err != nil {
		return reply{}, err
	}
	var r reply
	if err := json.Unmarshal(b, &r); err != nil || !r.OK {
		h.t.Fatalf("%s: answer %s", cmd, b)
	}
	return r, nil
}

func (h *harness) status() map[string]any {
	h.t.Helper()
	b, err := h.d.Handle("status", nil, 0)
	if err != nil {
		h.t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		h.t.Fatal(err)
	}
	return m
}

// bootSeqOf returns the boot sequence number of a heartbeat packet (member's
// layout: BootSeq at offset 21 of the heartbeat, after the type byte).
func bootSeqOf(t *testing.T, k epoch.Key, b []byte) uint64 {
	t.Helper()
	pk, err := wire.PacketKey(k.Secret)
	if err != nil {
		t.Fatal(err)
	}
	_, pt, err := wire.Open(func(uint32) ([]byte, bool) { return pk, true }, b)
	if err != nil || len(pt) < 1+29 || pt[0] != 1 {
		t.Fatalf("not a heartbeat: %v", err)
	}
	return binary.BigEndian.Uint64(pt[1+21 : 1+29])
}

func storedBootSeq(t *testing.T, dir string) uint64 {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "bootseq.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		BootSeq uint64 `json:"boot_seq"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v.BootSeq
}

// TestRebuildTakesNewBootSeq: set-token gives the running node its token
// without a restart, so it sends on under the same boot sequence number; a
// node started again in the same boot (after a join) sends under a higher
// one, which its peers accept; a daemon that waits for init or a roster
// never takes a new number, so it writes nothing to flash while it waits.
func TestRebuildTakesNewBootSeq(t *testing.T) {
	f := newFixture(t, true, false)
	h := start(t, f.dir, nil)
	h.run(6 * time.Second)
	nd, first := h.d.current(), bootSeqOf(t, f.key, h.net.last())
	if _, err := h.handle("set-token", canary); err != nil {
		t.Fatal(err)
	}
	h.run(6 * time.Second)
	if h.d.current() != nd {
		t.Fatal("set-token started a new node")
	}
	if seq := bootSeqOf(t, f.key, h.net.last()); seq != first {
		t.Fatalf("boot sequence number %d after set-token, want %d", seq, first)
	}
	h.d.mu.Lock()
	h.d.rebuild = true
	h.d.mu.Unlock()
	h.run(6 * time.Second)
	if again := bootSeqOf(t, f.key, h.net.last()); again <= first {
		t.Fatalf("boot sequence number %d after the restart of the node, want more than %d", again, first)
	}

	empty := filepath.Join(t.TempDir(), "state")
	w := start(t, empty, nil)
	w.run(2 * time.Minute)
	if seq := storedBootSeq(t, empty); seq != 1 {
		t.Fatalf("a daemon waiting for init stored boot sequence number %d, want 1", seq)
	}
	if w.d.current() != nil {
		t.Fatal("a node without an identity")
	}

	// An identity without a roster: a join that did not finish.
	half := filepath.Join(t.TempDir(), "state")
	id, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := id.Save(half); err != nil {
		t.Fatal(err)
	}
	w = start(t, half, nil)
	w.run(2 * time.Minute)
	if seq := storedBootSeq(t, half); seq != 1 {
		t.Fatalf("a daemon waiting for a roster stored boot sequence number %d, want 1", seq)
	}
}

// TestInitPickedUp: a daemon that started before init finds the state
// within pollEvery and runs the node with the same boot sequence number.
func TestInitPickedUp(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	h := start(t, dir, nil)
	if st := h.status(); st["initialised"] != false || len(st) != 3 {
		t.Fatalf("before init: %v", st)
	}
	f := newFixtureIn(t, dir)
	h.run(pollEvery + time.Second)
	if st := h.status(); st["initialised"] != true {
		t.Fatalf("after init: %v", st)
	}
	h.run(5 * time.Second)
	if seq := bootSeqOf(t, f.key, h.net.last()); seq != 1 {
		t.Fatalf("boot sequence number %d, want 1", seq)
	}
}

// newFixtureIn writes a group of one in dir.
func newFixtureIn(t *testing.T, dir string) fixture {
	t.Helper()
	f := newFixture(t, false, false)
	entries, _ := os.ReadDir(f.dir)
	for _, e := range entries {
		b, _ := os.ReadFile(filepath.Join(f.dir, e.Name()))
		if err := os.WriteFile(filepath.Join(dir, e.Name()), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	f.dir = dir
	return f
}

// fakeTelegram is the Bot API with a switch for getMe and the chat that
// sends the bind code.
type fakeTelegram struct {
	srv     *httptest.Server
	getMeOK atomic.Bool
	code    atomic.Value // the bind code the private chat sends, once known
	polls   atomic.Int32
	pings   atomic.Int32
}

func newFakeTelegram(t *testing.T) *fakeTelegram {
	f := &fakeTelegram{}
	f.code.Store("")
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		switch {
		case !strings.Contains(r.URL.Path, "/bot"+canary+"/"):
			w.WriteHeader(http.StatusNotFound)
		case strings.HasSuffix(r.URL.Path, "/getMe"):
			f.pings.Add(1)
			if !f.getMeOK.Load() {
				w.WriteHeader(http.StatusUnauthorized)
				fmt.Fprint(w, `{"ok":false,"error_code":401,"description":"Unauthorized"}`)
				return
			}
			fmt.Fprint(w, `{"ok":true,"result":{"id":1,"is_bot":true}}`)
		case strings.HasSuffix(r.URL.Path, "/getUpdates"):
			f.polls.Add(1)
			code := f.code.Load().(string)
			if code == "" {
				fmt.Fprint(w, `{"ok":true,"result":[]}`)
				return
			}
			fmt.Fprintf(w, `{"ok":true,"result":[{"update_id":7,"message":{"text":%q,"chat":{"id":4242,"type":"private"}}}]}`, code)
		default:
			fmt.Fprint(w, `{"ok":true,"result":{}}`)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

// TestBindTelegramPingsFirst: bind-telegram checks the token with getMe
// first, so a wrong token fails at once without a single getUpdates; with
// a good token it returns a bind code and binds the chat that sends it,
// after which this router reaches Telegram.
func TestBindTelegramPingsFirst(t *testing.T) {
	tg := newFakeTelegram(t)
	f := newFixture(t, true, false)
	h := start(t, f.dir, func(o *Options) { o.TelegramURL, o.HTTP = tg.srv.URL, tg.srv.Client() })
	if _, err := h.handle("bind-telegram"); err == nil || !strings.Contains(err.Error(), "set-token") {
		t.Fatalf("bind-telegram without a token: %v", err)
	}
	nd := h.d.current()
	if _, err := h.handle("set-token", canary); err != nil {
		t.Fatal(err)
	}
	h.run(time.Second)
	if st := h.status()["telegram"].(map[string]any)["state"]; st != "not_bound" {
		t.Fatalf("telegram state %v with a token and no chat, want not_bound", st)
	}

	began := time.Now()
	_, err := h.handle("bind-telegram")
	if err == nil || strings.Contains(err.Error(), canary) {
		t.Fatalf("bind-telegram with a refused token: %v", err)
	}
	if took := time.Since(began); took > 2*time.Second || tg.polls.Load() != 0 {
		t.Fatalf("a refused token took %s and %d getUpdates calls; want a fast failure and none", took, tg.polls.Load())
	}

	tg.getMeOK.Store(true)
	r, err := h.handle("bind-telegram")
	if err != nil || !regexp.MustCompile(`^[0-9]{10}$`).MatchString(r.BindCode) {
		t.Fatalf("bind-telegram: %+v, %v", r, err)
	}
	tg.code.Store(r.BindCode)
	deadline := time.Now().Add(10 * time.Second)
	for {
		h.d.mu.Lock()
		chat := h.d.chatID
		h.d.mu.Unlock()
		if chat == 4242 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the chat was not bound")
		}
		time.Sleep(20 * time.Millisecond)
	}
	pings := tg.pings.Load()
	h.run(2 * time.Second)
	if tg.pings.Load() == pings {
		t.Fatal("the node does not ping Telegram after the binding")
	}
	if h.d.current() != nd {
		t.Fatal("the binding started a new node")
	}
	if st := h.status()["telegram"].(map[string]any)["state"]; st != "ok" {
		t.Fatalf("telegram state %v after the binding, want ok", st)
	}
	b, _ := os.ReadFile(filepath.Join(f.dir, node.FileSecrets))
	if !bytes.Contains(b, []byte("4242")) {
		t.Fatal("the bound chat was not saved")
	}
	if out, _ := h.d.Handle("status", nil, 0); bytes.Contains(out, []byte(canary)) || bytes.Contains(out, []byte("4242")) {
		t.Fatal("the status shows the token or the chat ID")
	}
	// The token is redacted from every reply; a chat ID this short is not,
	// since it could match the digits of an ordinary number.
	if sec := h.d.Secrets(); !slices.Contains(sec, canary) || slices.Contains(sec, "4242") {
		t.Fatalf("redaction source %q", sec)
	}
}

// TestSetTokenOnlyOnASender: a router without the sender role holds no
// token.
func TestSetTokenOnlyOnASender(t *testing.T) {
	f := newFixture(t, false, false)
	h := start(t, f.dir, nil)
	if _, err := h.handle("set-token", canary); err == nil || !strings.Contains(err.Error(), "sender role") {
		t.Fatalf("set-token on a router without the sender role: %v", err)
	}
	if _, err := os.Stat(filepath.Join(f.dir, node.FileSecrets)); err == nil {
		t.Fatal("a token was stored on a router without the sender role")
	}
	if _, err := h.handle("set-token", "bad token"); err == nil || strings.Contains(err.Error(), "bad token") {
		t.Fatalf("set-token with a malformed token: %v", err)
	}
}

// TestRolesThroughTheNode: roles, remove and the refusals, signed by the
// running node.
func TestRolesThroughTheNode(t *testing.T) {
	f := newFixture(t, false, true)
	h := start(t, f.dir, nil)
	roles := func(name string) []string {
		for _, x := range h.status()["members"].([]any) {
			m := x.(map[string]any)
			if m["name"] == name {
				var out []string
				for _, r := range m["roles"].([]any) {
					out = append(out, r.(string))
				}
				return out
			}
		}
		return nil
	}
	if _, err := h.handle("roles", "backup", "ap-office"); err != nil {
		t.Fatal(err)
	}
	if got := roles("ap-office"); !slices.Equal(got, []string{"backup"}) {
		t.Fatalf("ap-office roles %q, want backup", got)
	}
	if r, err := h.handle("roles", "backup", "ap-office"); err != nil || !strings.Contains(r.Message, "nothing changed") {
		t.Fatalf("the same role again: %+v %v", r, err)
	}
	if _, err := h.handle("roles", "sender", "ap-office"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.handle("roles", "none", "ap-office"); err != nil {
		t.Fatal(err)
	}
	if got := roles("ap-office"); len(got) != 0 {
		t.Fatalf("ap-office roles %q after none", got)
	}
	if _, err := h.handle("roles", "none", "gateway"); err == nil || !strings.Contains(err.Error(), "primary admin") {
		t.Fatalf("none on the primary: %v", err)
	}
	if _, err := h.handle("remove", "ap-foo"); err == nil || err.Error() != "no such member: ap-foo" {
		t.Fatalf("remove of an unknown member: %v", err)
	}
	if _, err := h.handle("remove", "gateway"); err == nil {
		t.Fatal("the router removed itself")
	}
	if _, err := h.handle("remove", "Gateway"); err == nil || err.Error() != errArgs.Error() {
		t.Fatalf("remove with an invalid name: %v", err)
	}
	epochBefore, _ := os.ReadFile(filepath.Join(f.dir, node.FileEpoch))
	if _, err := h.handle("remove", "ap-office"); err != nil {
		t.Fatal(err)
	}
	if roles("ap-office") != nil {
		t.Fatal("ap-office is still a member")
	}
	if epochAfter, _ := os.ReadFile(filepath.Join(f.dir, node.FileEpoch)); bytes.Equal(epochBefore, epochAfter) {
		t.Fatal("the removal did not replace the group key")
	}
}

// TestRosterEdits: each edit leaves a roster that passes Check, with the
// roles the admin list implies.
func TestRosterEdits(t *testing.T) {
	mk := func() (roster.Roster, ids.MemberID, ids.MemberID, ids.MemberID) {
		var r roster.Roster
		var idsOf []ids.MemberID
		for i, name := range []string{"gw", "ap-1", "ap-2"} {
			id, _ := identity.Generate()
			idsOf = append(idsOf, id.ID)
			m := roster.Member{ID: id.ID, Name: name, SignPub: id.Sign.Public().(ed25519.PublicKey), RecvPub: id.Recv.PublicKey().Bytes()}
			if i == 0 {
				m.Roles = []roster.Role{roster.RolePrimary}
			}
			r.Members = append(r.Members, m)
		}
		pub, _, _ := ed25519.GenerateKey(rand.Reader)
		r.Version, r.Site, r.RecoveryPub, r.Admins = 1, "home", pub, []ids.MemberID{idsOf[0]}
		return r, idsOf[0], idsOf[1], idsOf[2]
	}
	check := func(r roster.Roster, step string) {
		t.Helper()
		if err := r.Check(); err != nil {
			t.Fatalf("%s: %v", step, err)
		}
	}
	r, gw, ap1, ap2 := mk()
	if err := setRole(&r, "backup", "ap-1"); err != nil {
		t.Fatal(err)
	}
	check(r, "backup")
	if err := setRole(&r, "primary", "ap-2"); err == nil {
		t.Fatal("a primary beside a backup that is someone else")
	}
	if err := setRole(&r, "backup", "ap-2"); err != nil || !slices.Equal(r.Admins, []ids.MemberID{gw, ap2}) {
		t.Fatalf("a new backup replaces the old: %v %v", err, r.Admins)
	}
	check(r, "replace backup")
	if err := setRole(&r, "primary", "ap-2"); err != nil || !slices.Equal(r.Admins, []ids.MemberID{ap2, gw}) {
		t.Fatalf("the backup made primary: %v %v", err, r.Admins)
	}
	check(r, "swap")
	if err := setRole(&r, "none", "gw"); err != nil || !slices.Equal(r.Admins, []ids.MemberID{ap2}) {
		t.Fatalf("none on the backup: %v %v", err, r.Admins)
	}
	check(r, "none")
	if err := setRole(&r, "primary", "ap-1"); err != nil || !slices.Equal(r.Admins, []ids.MemberID{ap1, ap2}) {
		t.Fatalf("a member made primary keeps the old primary as backup: %v %v", err, r.Admins)
	}
	check(r, "primary")
	if err := setRole(&r, "boss", "ap-1"); err == nil {
		t.Fatal("an unknown role")
	}
	if err := setRole(&r, "sender", "nobody"); err == nil || err.Error() != "no such member: nobody" {
		t.Fatalf("an unknown member: %v", err)
	}

	r, gw, ap1, _ = mk()
	_ = setRole(&r, "backup", "ap-1")
	if err := takeOver(&r, gw); err == nil {
		t.Fatal("the primary took over")
	}
	if err := takeOver(&r, ap1); err != nil || !r.Takeover || r.Replaced != gw || !slices.Equal(r.Admins, []ids.MemberID{ap1, gw}) {
		t.Fatalf("takeover: %v %+v", err, r)
	}
	check(r, "takeover")
	if err := confirmTakeover(&r, gw); err == nil {
		t.Fatal("the replaced primary confirmed the takeover")
	}
	if err := confirmTakeover(&r, ap1); err != nil || !r.OwnerConfirmed {
		t.Fatalf("confirm: %v", err)
	}
	check(r, "confirm")
	if err := confirmTakeover(&r, ap1); !errors.Is(err, errUnchanged) {
		t.Fatalf("a second confirm: %v", err)
	}

	r, _, _, ap2 = mk()
	_ = setRole(&r, "backup", "ap-1")
	if err := recoverAdmin(&r, ap2); err != nil || !slices.Equal(r.Admins, []ids.MemberID{ap2}) || r.Takeover {
		t.Fatalf("recover: %v %+v", err, r)
	}
	check(r, "recover")

	r, gw, _, _ = mk()
	var sender bool
	if err := removeMember(&r, gw, "gw", &sender); err == nil {
		t.Fatal("a router removed itself")
	}
	r.Members[1].Roles = []roster.Role{roster.RoleSender}
	if err := removeMember(&r, gw, "ap-1", &sender); err != nil || !sender || len(r.Members) != 2 {
		t.Fatalf("remove a sender: %v %v", err, sender)
	}
	check(r, "remove")
}

// TestReadSandbox: the flags come from proc/self/status, the jail from the
// files a jail leaves out, and an unreadable status is unknown, not off.
func TestReadSandbox(t *testing.T) {
	write := func(root, rel, text string) {
		p := filepath.Join(root, rel)
		_ = os.MkdirAll(filepath.Dir(p), 0o700)
		if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	jailed := t.TempDir()
	write(jailed, "proc/self/status", "Name:\trollcalld\nNoNewPrivs:\t1\nSeccomp:\t2\nSeccomp_filters:\t1\n")
	write(jailed, "etc/openwrt_release", "DISTRIB_RELEASE='25.12.0'\n")
	if s, known := ReadSandbox(jailed); !known || s != (node.SandboxStatus{State: "enforced", NoNewPrivs: true, Seccomp: true, Jail: true}) {
		t.Fatalf("in the jail: %+v %v", s, known)
	}
	host := t.TempDir()
	write(host, "proc/self/status", "NoNewPrivs:\t0\nSeccomp:\t0\n")
	write(host, "etc/openwrt_release", "x")
	write(host, "etc/shadow", "root:*:0:0:99999:7:::\n")
	if s, known := ReadSandbox(host); !known || s.State != "off" || s.Jail {
		t.Fatalf("on the host: %+v %v", s, known)
	}
	noProc := t.TempDir()
	write(noProc, "etc/openwrt_release", "x")
	if s, known := ReadSandbox(noProc); known || s.State != "partial" || !s.Jail {
		t.Fatalf("a jail without /proc: %+v %v", s, known)
	}
	if s, known := ReadSandbox(t.TempDir()); known || s.State != "off" {
		t.Fatalf("off OpenWrt: %+v %v", s, known)
	}
}

func TestTelegramStates(t *testing.T) {
	sender := node.Status{Self: &node.SelfStatus{Roles: []string{"sender"}}, Telegram: node.TelegramStatus{State: "bot_blocked"}}
	plain := node.Status{Self: &node.SelfStatus{Roles: []string{}}, Telegram: node.TelegramStatus{State: "not_sender"}}
	for _, tc := range []struct {
		s          node.Status
		configured bool
		token      string
		chat       int64
		want       string
	}{
		{plain, true, canary, 1, "not_sender"},
		{sender, false, canary, 1, "not_sender"},
		{sender, true, "", 0, "not_configured"},
		{sender, true, canary, 0, "not_bound"},
		{sender, true, canary, 1, "bot_blocked"},
	} {
		if got := telegramState(tc.s, tc.configured, tc.token, tc.chat); got != tc.want {
			t.Errorf("%+v: %s, want %s", tc, got, tc.want)
		}
	}
}

func TestIfaceEvents(t *testing.T) {
	for _, tc := range []struct {
		action, iface string
		want          events.Type
	}{
		{"ifdown", "wan", events.WanDown}, {"ifup", "wan", events.WanUp}, {"ifdown", "wwan", events.WanDown},
		{"ifup", "wan6", events.WanUp}, {"ifdown", "lan", ""}, {"ifupdate", "wan", ""},
	} {
		if got, _ := ifaceEvent(tc.action, tc.iface); got != tc.want {
			t.Errorf("%s %s: %q, want %q", tc.action, tc.iface, got, tc.want)
		}
	}
	h := start(t, newFixture(t, false, false).dir, nil)
	for _, args := range [][]string{{"iface", "ifdown"}, {"iface", "IFDOWN", "wan"}, {"iface", "ifdown", "-wan"},
		{"iface", "ifdown", "wan;reboot"}, {"uplink"}, {"going-down", "now"}, {"bogus"}} {
		if _, err := h.d.Handle("notify", args, 0); err == nil {
			t.Errorf("notify %q was accepted", args)
		}
	}
	if _, err := h.handle("notify", "iface", "ifdown", "wan"); err != nil {
		t.Fatal(err)
	}
	h.run(40 * time.Second)
	if !strings.Contains(fmt.Sprint(h.status()["incidents"]), "WAN went down") {
		t.Fatalf("no WAN incident: %v", h.status()["incidents"])
	}
}

func TestPickBootstrap(t *testing.T) {
	p := func(s ...string) []netip.Addr {
		var out []netip.Addr
		for _, x := range s {
			out = append(out, netip.MustParseAddr(x))
		}
		return out
	}
	for _, tc := range []struct {
		in   []netip.Addr
		want string
	}{
		{p("fe80::1", "2001:db8::1", "192.168.1.1"), "192.168.1.1"},
		{p("fe80::1", "2001:db8::1"), "2001:db8::1"},
		{p("::ffff:10.0.0.1"), "10.0.0.1"},
		{p("fe80::1", "127.0.0.1"), ""},
	} {
		got, ok := pickBootstrap(tc.in)
		if (tc.want == "") == ok || (ok && got.String() != tc.want) {
			t.Errorf("%v: %v %v, want %q", tc.in, got, ok, tc.want)
		}
	}
}

func TestInternetProbe(t *testing.T) {
	var mu sync.Mutex
	var tcp, icmp []string
	fail := errors.New("no answer")
	up := map[string]bool{}
	tcpFn := func(_ context.Context, a string) error {
		mu.Lock()
		defer mu.Unlock()
		tcp = append(tcp, a)
		if up[a] {
			return nil
		}
		return fail
	}
	icmpFn := func(_ context.Context, a string) error {
		mu.Lock()
		defer mu.Unlock()
		icmp = append(icmp, a)
		return fail
	}
	if err := InternetProbe(nil, false, tcpFn, icmpFn)(context.Background()); err == nil {
		t.Fatal("every default target failed, yet the probe passed")
	}
	mu.Lock()
	slices.Sort(tcp)
	mu.Unlock()
	if !slices.Equal(tcp, DefaultProbeTargets) {
		t.Fatalf("default targets %q", tcp)
	}
	// With every target failing, the probe waits for all of them: an IPv4
	// literal went to ICMP, the host name to TCP.
	tcp, icmp = nil, nil
	if err := InternetProbe([]string{"9.9.9.9", "dns.google:443"}, true, tcpFn, icmpFn)(context.Background()); err == nil {
		t.Fatal("every target failed, yet the probe passed")
	}
	mu.Lock()
	if !slices.Equal(icmp, []string{"9.9.9.9"}) || !slices.Equal(tcp, []string{"dns.google:443"}) {
		t.Fatalf("icmp went to %q, tcp to %q", icmp, tcp)
	}
	up["dns.google:443"] = true
	mu.Unlock()
	if err := InternetProbe([]string{"9.9.9.9", "dns.google:443"}, true, tcpFn, icmpFn)(context.Background()); err != nil {
		t.Fatalf("one target answered: %v", err)
	}
}

type oneSwitch struct{ done bool }

func (s *oneSwitch) Tick() (bool, string, string) {
	if s.done {
		return false, "", ""
	}
	s.done = true
	return true, "wan", "wwan"
}

// TestHostStampsStartTime: an internet loss is stamped with its first
// failed probe, not with the probe that decided it; a default route that
// moved makes the topology hint second_uplink.
func TestHostStampsStartTime(t *testing.T) {
	h := start(t, newFixture(t, false, false).dir, nil)
	host := &Host{D: h.d, Probe: &probe.Prober{Probe: func(context.Context) error { return errors.New("down") }}}
	var first time.Time
	for el := 0; el < 60; el++ {
		h.clk.advance(time.Second)
		h.d.Step()
		now := h.clk.Now()
		if first.IsZero() {
			first = now
		}
		host.Tick(now)
	}
	incs := h.status()["incidents"].([]any)
	if len(incs) == 0 {
		t.Fatal("no incident for the internet loss")
	}
	inc := incs[0].(map[string]any)
	if !strings.Contains(fmt.Sprint(inc["text"]), "internet lost") || inc["time"] != first.Format(time.RFC3339) {
		t.Fatalf("incident %v, want internet lost at %s", inc, first.Format(time.RFC3339))
	}
	if h.status()["topology"] != topoNoSecondUplink {
		t.Fatal("topology before any switch")
	}
	(&Host{D: h.d, Routes: &oneSwitch{}}).Tick(h.clk.Now())
	if got := h.status()["topology"]; got != topoSecondUplink {
		t.Fatalf("topology %v after a default-route switch", got)
	}
}

// TestShutdownMarker: a marker of an earlier boot makes this boot planned
// and is consumed; one of this boot stays for the reboot it announced.
func TestShutdownMarker(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := func(b ids.BootID) {
		if err := os.WriteFile(filepath.Join(dir, fileShutdown), []byte(`{"boot":"`+b.String()+`"}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	this := ids.BootID{1, 15: 1}
	marker(this)
	if h := start(t, dir, nil); h.d.planned {
		t.Fatal("a marker of this boot made the start planned")
	}
	if b, _ := os.ReadFile(filepath.Join(dir, fileShutdown)); !bytes.Contains(b, []byte(this.String())) {
		t.Fatal("the marker of this boot was consumed")
	}
	marker(ids.BootID{9, 15: 9})
	if h := start(t, dir, nil); !h.d.planned {
		t.Fatal("a marker of an earlier boot did not make the start planned")
	}
	if h := start(t, dir, nil); h.d.planned {
		t.Fatal("the marker counted twice")
	}
}

// backupFixture writes a group whose primary is another router, never
// online, and this router its backup.
func backupFixture(t *testing.T) fixture {
	t.Helper()
	f := fixture{dir: filepath.Join(t.TempDir(), "state")}
	var err error
	if f.self, err = identity.Generate(); err != nil {
		t.Fatal(err)
	}
	if f.other, err = identity.Generate(); err != nil {
		t.Fatal(err)
	}
	if err := f.self.Save(f.dir); err != nil {
		t.Fatal(err)
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	member := func(id *identity.Identity, name string, role roster.Role) roster.Member {
		return roster.Member{ID: id.ID, Name: name, Roles: []roster.Role{role},
			SignPub: id.Sign.Public().(ed25519.PublicKey), RecvPub: id.Recv.PublicKey().Bytes()}
	}
	r := roster.Roster{Version: 1, Site: "home", RecoveryPub: pub, Admins: []ids.MemberID{f.other.ID, f.self.ID},
		Members: []roster.Member{member(f.other, "gateway", roster.RolePrimary), member(f.self, "ap-office", roster.RoleBackup)}}
	signed, err := roster.SignRoster(r, f.other.ID, f.other.Sign, false)
	if err != nil {
		t.Fatal(err)
	}
	secret := make([]byte, epoch.SecretSize)
	rand.Read(secret)
	f.key = epoch.Key{ID: 1 << 2, Secret: secret, NotAfter: tStart.Add(epoch.RotationPeriod)}
	st, err := store.Open(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := node.Bootstrap(st, signed, f.key); err != nil {
		t.Fatal(err)
	}
	return f
}

// TestTakeoverConfirmRotate: on the backup, admin takeover waits for ten
// minutes without the primary, then makes this router the primary,
// provisionally; admin confirm ends the provision; rotate replaces the key.
func TestTakeoverConfirmRotate(t *testing.T) {
	f := backupFixture(t)
	h := start(t, f.dir, nil)
	self := func() map[string]any { return h.status()["self"].(map[string]any) }
	if _, err := h.handle("admin-confirm"); err == nil || !strings.Contains(err.Error(), "no takeover") {
		t.Fatalf("confirm without a takeover: %v", err)
	}
	h.run(time.Minute)
	if _, err := h.handle("admin-takeover"); err == nil || !strings.Contains(err.Error(), "still heard") {
		t.Fatalf("a takeover a minute after the start: %v", err)
	}
	if self()["admin"] != "backup" {
		t.Fatalf("a refused takeover changed the roster: %v", self())
	}
	h.run(10 * time.Minute)
	if _, err := h.handle("admin-takeover"); err != nil {
		t.Fatalf("takeover after ten minutes without the primary: %v", err)
	}
	if s := self(); s["admin"] != "primary" || s["takeover"] != true {
		t.Fatalf("after the takeover: %v", s)
	}
	if r, err := h.handle("admin-takeover"); err != nil || r.Message != "Nothing to change." {
		t.Fatalf("a second takeover: %+v %v", r, err)
	}
	if _, err := h.handle("admin-confirm"); err != nil {
		t.Fatal(err)
	}
	if s := self(); s["admin"] != "primary" || s["takeover"] != false {
		t.Fatalf("after the confirmation: %v", s)
	}
	before, _ := os.ReadFile(filepath.Join(f.dir, node.FileEpoch))
	if _, err := h.handle("rotate"); err != nil {
		t.Fatal(err)
	}
	if after, _ := os.ReadFile(filepath.Join(f.dir, node.FileEpoch)); bytes.Equal(before, after) {
		t.Fatal("rotate did not replace the group key")
	}
}

// TestStatusDiscoveryAndTopology: the interfaces where discovery cannot run
// are listed with the reason, the others not; a peer zone on WireGuard is
// the overlay row of the topology table.
func TestStatusDiscoveryAndTopology(t *testing.T) {
	f := newFixture(t, false, false)
	h := start(t, f.dir, func(o *Options) {
		o.Devices = []string{"br-lan", "wg0"}
		o.Discovery = func() map[string]error {
			return map[string]error{"br-lan": nil, "wg0": errors.New("no IPv6 link-local address")}
		}
	})
	st := h.status()
	if got := fmt.Sprint(st["discovery"]); got != "[map[error:no IPv6 link-local address interface:wg0]]" {
		t.Fatalf("discovery %s", got)
	}
	if st["topology"] != topoOverlaySites {
		t.Fatalf("topology %v with a WireGuard peer zone", st["topology"])
	}
}

// TestSystemClock: the monotonic clock counts from the boot, as
// proc/uptime gives it, and moves on with the process.
func TestSystemClock(t *testing.T) {
	root := t.TempDir()
	_ = os.MkdirAll(filepath.Join(root, "proc"), 0o700)
	if err := os.WriteFile(filepath.Join(root, "proc", "uptime"), []byte("12345.67 54321.00\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := SystemClock(root)
	m := c.Mono()
	if m < 12345*time.Second || m > 12347*time.Second {
		t.Fatalf("Mono %s, want about 12345.67 s", m)
	}
	if time.Sleep(time.Millisecond); c.Mono() <= m {
		t.Fatal("Mono does not move")
	}
	if d := time.Since(c.Now()); d < 0 || d > time.Second {
		t.Fatalf("Now is %s away from the wall clock", d)
	}
	if m := SystemClock(t.TempDir()).Mono(); m > time.Second {
		t.Fatalf("without proc/uptime Mono starts at %s, want 0", m)
	}
}

// flagsOf returns the flags byte of a heartbeat packet (member's layout:
// offset 53 of the heartbeat; ClockTrusted is 4).
func flagsOf(t *testing.T, k epoch.Key, b []byte) byte {
	t.Helper()
	pk, _ := wire.PacketKey(k.Secret)
	_, pt, err := wire.Open(func(uint32) ([]byte, bool) { return pk, true }, b)
	if err != nil || len(pt) < 1+54 || pt[0] != 1 {
		t.Fatalf("not a heartbeat: %v", err)
	}
	return pt[1+53]
}

// TestClockSynced: notify clock-synced marks the clock trusted, which the
// heartbeats say from then on, also from a node started again in this boot.
func TestClockSynced(t *testing.T) {
	f := newFixture(t, false, false)
	h := start(t, f.dir, nil)
	h.run(6 * time.Second)
	if flagsOf(t, f.key, h.net.last())&4 != 0 {
		t.Fatal("the clock is trusted before ntpd said so")
	}
	if r, err := h.handle("notify", "clock-synced"); err != nil || !r.OK {
		t.Fatalf("notify clock-synced: %+v %v", r, err)
	}
	h.run(6 * time.Second)
	if flagsOf(t, f.key, h.net.last())&4 == 0 {
		t.Fatal("the heartbeat does not say the clock is trusted")
	}
	h.d.mu.Lock()
	h.d.rebuild = true
	h.d.mu.Unlock()
	h.run(6 * time.Second)
	if flagsOf(t, f.key, h.net.last())&4 == 0 {
		t.Fatal("a node started again in this boot forgot the synchronised clock")
	}
	if _, err := h.d.Handle("notify", []string{"clock-synced", "now"}, 0); err == nil {
		t.Fatal("notify clock-synced with an argument was accepted")
	}
}
