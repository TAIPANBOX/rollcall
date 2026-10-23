package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/TAIPANBOX/rollcall/cmd/rollcalld/daemon"
	"github.com/TAIPANBOX/rollcall/internal/config"
	"github.com/TAIPANBOX/rollcall/internal/control"
	"github.com/TAIPANBOX/rollcall/internal/identity"
	"github.com/TAIPANBOX/rollcall/internal/ids"
	"github.com/TAIPANBOX/rollcall/internal/node"
	"github.com/TAIPANBOX/rollcall/internal/pairing"
	"github.com/TAIPANBOX/rollcall/internal/wire"
)

// The tests run the CLI against real daemons (cmd/rollcalld/daemon) over a
// fake network: the control socket is replaced by a direct call of the
// daemon's handler, since the socket admits only root.

var tStart = time.Date(2026, 10, 23, 9, 0, 0, 0, time.UTC)

// canary is the fake bot token the tests plant; it must never be printed.
const canary = "CANARY-123:abc"

var recoveryRE = regexp.MustCompile(`[0-9A-HJKMNP-TV-Z]{5}(?:-[0-9A-HJKMNP-TV-Z]{5}){11}`)

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

// hub carries packets between the daemons of a site, synchronously.
type hub struct {
	mu sync.Mutex
	ds map[netip.AddrPort]*daemon.Daemon
}

func (h *hub) get(a netip.AddrPort) *daemon.Daemon {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.ds[a]
}

func (h *hub) set(a netip.AddrPort, d *daemon.Daemon) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if d == nil {
		delete(h.ds, a)
		return
	}
	h.ds[a] = d
}

func (h *hub) others(self netip.AddrPort) []*daemon.Daemon {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []*daemon.Daemon
	for a, d := range h.ds {
		if a != self {
			out = append(out, d)
		}
	}
	return out
}

var errUnreachable = errors.New("unreachable")

// hubNet is one router's node.Net. It keeps the multicast packets it sent.
type hubNet struct {
	h    *hub
	self netip.AddrPort

	mu   sync.Mutex
	sent [][]byte
}

func (n *hubNet) Multicast(b []byte) error {
	n.mu.Lock()
	n.sent = append(n.sent, bytes.Clone(b))
	n.mu.Unlock()
	for _, d := range n.h.others(n.self) {
		d.HandlePacket(n.self, bytes.Clone(b))
	}
	return nil
}

func (n *hubNet) Unicast(to netip.AddrPort, b []byte) error {
	if d := n.h.get(to); d != nil && to != n.self {
		d.HandlePacket(n.self, bytes.Clone(b))
	}
	return nil
}

func (n *hubNet) Stream(to netip.AddrPort, b []byte) ([]byte, error) {
	d := n.h.get(to)
	if d == nil || to == n.self || !d.Authenticate(b) {
		return nil, errUnreachable
	}
	r := d.HandleStream(netip.AddrPortFrom(n.self.Addr(), 40000), bytes.Clone(b))
	if r == nil {
		return nil, errUnreachable
	}
	return r, nil
}

func (n *hubNet) multicasts() [][]byte {
	n.mu.Lock()
	defer n.mu.Unlock()
	return slices.Clone(n.sent)
}

type site struct {
	t   *testing.T
	clk *fakeClock
	hub *hub
	rs  []*router
}

type router struct {
	s    *site
	name string
	dir  string
	addr netip.AddrPort
	net  *hubNet
	boot ids.BootID
	d    *daemon.Daemon
}

func newSite(t *testing.T) *site {
	return &site{t: t, clk: &fakeClock{wall: tStart, mono: 1000 * time.Second},
		hub: &hub{ds: map[netip.AddrPort]*daemon.Daemon{}}}
}

func (s *site) add(name string) *router {
	i := len(s.rs)
	r := &router{s: s, name: name, dir: filepath.Join(s.t.TempDir(), "state"),
		addr: netip.MustParseAddrPort(fmt.Sprintf("192.0.2.%d:7432", i+1)), boot: ids.BootID{byte(i + 1), 15: 1}}
	r.net = &hubNet{h: s.hub, self: r.addr}
	s.rs = append(s.rs, r)
	return r
}

func testConfig() config.Config {
	return config.Config{Site: "Home", PeerZones: []string{"lan"}, Port: 7432,
		Heartbeat: 5 * time.Second, SilentAfter: 30 * time.Second}
}

// start runs rollcalld on r, with what its state directory holds.
func (r *router) start() {
	r.s.t.Helper()
	d, err := daemon.New(daemon.Options{
		StateDir: r.dir, Config: testConfig(), Devices: []string{"br-lan"}, Net: r.net, Clock: r.s.clk,
		Boot: r.boot, Versions: [2]string{"25.12.0", "test"},
		Addrs: func() []netip.Addr { return []netip.Addr{r.addr.Addr()} },
		Logf:  r.s.t.Logf,
	})
	if err != nil {
		r.s.t.Fatalf("%s: daemon: %v", r.name, err)
	}
	r.s.t.Cleanup(d.Close)
	r.d = d
	r.s.hub.set(r.addr, d)
	d.Step()
}

// stop is a power cut: the daemon is gone from the network at once.
func (r *router) stop() {
	r.s.hub.set(r.addr, nil)
	r.d.Close()
	r.d = nil
}

func (s *site) run(dur time.Duration) {
	for el := time.Duration(0); el < dur; el += time.Second {
		s.clk.advance(time.Second)
		for _, r := range s.rs {
			if r.d != nil {
				r.d.Step()
			}
		}
	}
}

// dialRefused is what the control client returns when nobody listens.
var dialRefused = &net.OpError{Op: "dial", Net: "unix", Err: syscall.ECONNREFUSED}

// cli runs a command line on r, as root, with stdin and the environment env.
func (r *router) cli(stdin string, env map[string]string, args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	c := &cli{
		stdin: strings.NewReader(stdin), stdout: &out, stderr: &errb,
		getenv: func(k string) string { return env[k] },
		call: func(_ context.Context, cmd string, a ...string) ([]byte, error) {
			if r.d == nil {
				return nil, dialRefused
			}
			if !slices.Contains(control.Commands(), cmd) {
				return nil, &control.Error{Msg: control.MsgUnknownCommand}
			}
			b, err := r.d.Handle(cmd, a, 0)
			if err != nil {
				return nil, &control.Error{Msg: err.Error()}
			}
			return b, nil
		},
		stateDir: r.dir, configPath: filepath.Join(r.dir, "no-such-config"),
		hostname: func() (string, error) { return r.name, nil },
	}
	code := c.run(args)
	return code, out.String(), errb.String()
}

// must runs a command line that has to succeed and returns its stdout.
func (r *router) must(stdin string, args ...string) string {
	r.s.t.Helper()
	code, out, errs := r.cli(stdin, nil, args...)
	if code != 0 {
		r.s.t.Fatalf("%s: rollcall %s: exit %d\nstdout: %s\nstderr: %s", r.name, strings.Join(args, " "), code, out, errs)
	}
	return out
}

// initGroup runs init on r and returns the recovery code it printed.
func (r *router) initGroup() string {
	r.s.t.Helper()
	out := r.must("", "init")
	codes := recoveryRE.FindAllString(out, -1)
	if len(codes) != 1 {
		r.s.t.Fatalf("init printed %d recovery codes, want 1:\n%s", len(codes), out)
	}
	return codes[0]
}

// join brings r into the group of admin through invite and join.
func (s *site) join(admin, r *router) {
	s.t.Helper()
	var rep reply
	if err := json.Unmarshal([]byte(admin.must("", "invite", "--json", "--address", admin.addr.Addr().String())), &rep); err != nil || rep.JoinCode == "" {
		s.t.Fatalf("invite: %+v %v", rep, err)
	}
	if r.d == nil {
		r.start()
	}
	r.must("", "join", rep.JoinCode)
	s.run(time.Second)
}

// statusOf returns r's status report as JSON values.
func (r *router) statusOf() map[string]any {
	r.s.t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(r.must("", "status", "--json")), &m); err != nil {
		r.s.t.Fatal(err)
	}
	return m
}

func selfAdmin(m map[string]any) any {
	self, _ := m["self"].(map[string]any)
	return self["admin"]
}

func memberRoles(m map[string]any, name string) []string {
	ms, _ := m["members"].([]any)
	for _, x := range ms {
		mm, _ := x.(map[string]any)
		if mm["name"] == name {
			var out []string
			for _, r := range mm["roles"].([]any) {
				out = append(out, r.(string))
			}
			return out
		}
	}
	return nil
}

// heartbeatOf opens a multicast packet of the router whose state is in dir
// and returns the heartbeat in it (STATUS of package member: the flags at
// offset 53, GoingDown is 8).
func heartbeatOf(t *testing.T, dir string, b []byte) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, node.FileEpoch))
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Keys []struct {
			ID     uint32 `json:"id"`
			Secret []byte `json:"secret"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	lookup := func(id uint32) ([]byte, bool) {
		for _, k := range f.Keys {
			if k.ID == id {
				pk, err := wire.PacketKey(k.Secret)
				return pk, err == nil
			}
		}
		return nil, false
	}
	_, pt, err := wire.Open(lookup, b)
	if err != nil || len(pt) < 1+54 || pt[0] != 1 {
		t.Fatalf("not a heartbeat: %v", err)
	}
	return pt[1:]
}

const flagGoingDown = 8

// TestCLIUsage: the usage text names every command in the form the runbook
// and LuCI use, an unknown command is refused, and every exact form in the
// LuCI ACL parses and makes exactly one control call.
func TestCLIUsage(t *testing.T) {
	var out, errb bytes.Buffer
	c := &cli{stdout: &out, stderr: &errb}
	if code := c.run(nil); code != 2 || !strings.Contains(errb.String(), "usage: rollcall") {
		t.Fatalf("no arguments: exit %d, stderr %q", code, errb.String())
	}
	out.Reset()
	if code := c.run([]string{"help"}); code != 0 {
		t.Fatalf("help: exit %d", code)
	}
	for _, want := range []string{
		"rollcall init [--json] [--name <router>] [--site <site>]",
		"rollcall invite [--json] [--sender] [--address <ip>]",
		"rollcall join [--json] [--name <router>] <join code>",
		"rollcall remove [--json] -- <router>",
		"rollcall roles [--json] sender|primary|backup|none -- <router>",
		"rollcall rotate [--json]",
		"rollcall set-token [--json]",
		"TELEGRAM_ROLLCALL_TOKEN",
		"rollcall bind-telegram [--json]",
		"rollcall admin takeover [--json]",
		"rollcall admin confirm [--json]",
		"rollcall admin recover [--json]",
		"standard input",
		"rollcall status [--json]",
		"rollcall notify going-down | clock-synced | iface <action> <interface> | uplink <interface>",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("usage lacks %q", want)
		}
	}
	errb.Reset()
	if code := c.run([]string{"frobnicate"}); code != 2 || !strings.Contains(errb.String(), "unknown command") {
		t.Errorf("unknown command: exit %d, stderr %q", code, errb.String())
	}
	out.Reset()
	if code := c.run([]string{"frobnicate", "--json"}); code != 1 || !strings.HasPrefix(out.String(), `{"ok":false,"error":`) {
		t.Errorf("unknown command with --json: exit %d, stdout %q", code, out.String())
	}
	// A status the daemon refuses comes from a daemon that runs.
	rec := &recorder{err: &control.Error{Msg: control.MsgPermissionDenied}}
	var o, e bytes.Buffer
	if code := rec.cli(&o, &e, nil).run([]string{"status", "--json"}); code != 1 || o.String() != `{"schema":1,"running":true,"error":"permission denied"}`+"\n" {
		t.Errorf("a refused status: exit %d, %q", code, o.String())
	}

	raw, err := os.ReadFile("../../luci-app-rollcall/root/usr/share/rpcd/acl.d/luci-app-rollcall.json")
	if err != nil {
		t.Fatalf("measured nothing: %v", err)
	}
	forms := regexp.MustCompile(`"/usr/bin/rollcall ([^"]+)"`).FindAllStringSubmatch(string(raw), -1)
	if len(forms) < 10 {
		t.Fatalf("measured nothing: %d forms in the ACL", len(forms))
	}
	for _, f := range forms {
		args := strings.Fields(strings.ReplaceAll(f[1], "*", "ap-office"))
		rec := &recorder{}
		var o, e bytes.Buffer
		c := rec.cli(&o, &e, map[string]string{tokenEnv: canary})
		if code := c.run(args); code != 0 || len(rec.calls) != 1 {
			t.Errorf("ACL form %q: exit %d, %d calls, stderr %q", f[1], code, len(rec.calls), e.String())
		}
	}
}

// recorder is a control caller that records each call and answers it.
type recorder struct {
	calls     [][]string
	deadlines []time.Duration
	err       error
}

func (rec *recorder) call(ctx context.Context, cmd string, args ...string) ([]byte, error) {
	rec.calls = append(rec.calls, append([]string{cmd}, args...))
	if dl, ok := ctx.Deadline(); ok {
		rec.deadlines = append(rec.deadlines, time.Until(dl))
	}
	if rec.err != nil {
		return nil, rec.err
	}
	if cmd == "status" {
		return []byte(`{"schema":1,"running":true,"initialised":false}`), nil
	}
	return []byte(`{"ok":true,"message":"Done."}`), nil
}

func (rec *recorder) cli(out, errb *bytes.Buffer, env map[string]string) *cli {
	return &cli{stdin: strings.NewReader(""), stdout: out, stderr: errb, call: rec.call,
		getenv: func(k string) string { return env[k] }, hostname: func() (string, error) { return "gw", nil }}
}

// TestNameArgv: a router name is accepted only as exactly one word after
// "--" that passes the roster's name rule; any other form is refused before
// rollcalld is asked.
func TestNameArgv(t *testing.T) {
	accepted := []struct {
		args []string
		call []string
	}{
		{[]string{"remove", "--json", "--", "ap-office"}, []string{"remove", "ap-office"}},
		{[]string{"remove", "--", "ap-office"}, []string{"remove", "ap-office"}},
		{[]string{"roles", "--json", "sender", "--", "ap-office"}, []string{"roles", "sender", "ap-office"}},
		{[]string{"roles", "backup", "--", "beryl1"}, []string{"roles", "backup", "beryl1"}},
		{[]string{"roles", "--json", "none", "--", "a-1"}, []string{"roles", "none", "a-1"}},
	}
	for _, tc := range accepted {
		rec := &recorder{}
		var o, e bytes.Buffer
		if code := rec.cli(&o, &e, nil).run(tc.args); code != 0 || len(rec.calls) != 1 || !slices.Equal(rec.calls[0], tc.call) {
			t.Errorf("%q: exit %d, calls %q, stderr %q; want the call %q", tc.args, code, rec.calls, e.String(), tc.call)
		}
	}
	refused := [][]string{
		{"remove", "--json", "ap-office"},                     // no "--"
		{"remove", "ap-office"},                               // no "--"
		{"remove", "--json", "--"},                            // no name
		{"remove", "--json", "--", "ap-office", "beryl2"},     // two names
		{"remove", "--json", "--", "ap-office", "--json"},     // an extra argument
		{"remove", "--json", "--", "-rf"},                     // a leading '-'
		{"remove", "--json", "--", "--json"},                  // an option as the name
		{"remove", "--json", "--", "Kitchen"},                 // upper case
		{"remove", "--json", "--", "a;reboot"},                // a shell character
		{"remove", "--json", "--", ""},                        // empty
		{"remove", "--json", "--", strings.Repeat("a", 33)},   // too long
		{"remove", "--json", "--evil", "--", "ap-office"},     // an unknown option
		{"remove", "--json", "extra", "--", "ap-office"},      // a word before "--"
		{"roles", "--json", "--", "ap-office"},                // no role
		{"roles", "--json", "admin", "--", "ap-office"},       // no such role
		{"roles", "--json", "sender", "backup", "--", "ap-1"}, // two roles
		{"roles", "--json", "sender", "--", "ap-office", "x"}, // an extra argument
		{"roles", "--json", "sender", "ap-office"},            // no "--"
		{"rotate", "--json", "now"},                           // an argument where none belongs
		{"rotate", "--json", "--", "ap-office"},               // a name where none belongs
		{"admin", "takeover", "--json", "--", "x"},            // a name where none belongs
		{"invite", "--json", "--address", "fe80::1%br-lan"},   // an address with a zone
		{"invite", "--json", "--address"},                     // an option without its value
	}
	for _, args := range refused {
		rec := &recorder{}
		var o, e bytes.Buffer
		code := rec.cli(&o, &e, nil).run(args)
		if code == 0 || len(rec.calls) != 0 {
			t.Errorf("%q: exit %d, %d calls; want a refusal and no call", args, code, len(rec.calls))
			continue
		}
		if slices.Contains(args, "--json") && !strings.HasPrefix(o.String(), `{"ok":false,"error":`) {
			t.Errorf("%q with --json printed %q, want the failure reply", args, o.String())
		}
	}
}

// TestSetTokenNeverReadsArgv: set-token sends the token from
// TELEGRAM_ROLLCALL_TOKEN, refuses one on the command line without sending
// it, and never prints a token.
func TestSetTokenNeverReadsArgv(t *testing.T) {
	cases := []struct {
		name string
		env  string
		args []string
		call bool
	}{
		{"from the environment", canary, []string{"set-token", "--json"}, true},
		{"on the command line", "", []string{"set-token", "--json", canary}, false},
		{"on the command line beside the environment", "OTHER-1:xyz", []string{"set-token", canary}, false},
		{"after --", canary, []string{"set-token", "--", canary}, false},
		{"not set", "", []string{"set-token", "--json"}, false},
		{"not a token", "not a token; reboot", []string{"set-token", "--json"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := &recorder{}
			var o, e bytes.Buffer
			code := rec.cli(&o, &e, map[string]string{tokenEnv: tc.env}).run(tc.args)
			if strings.Contains(o.String()+e.String(), canary) || strings.Contains(o.String()+e.String(), "reboot") {
				t.Errorf("the output repeats the token: %q %q", o.String(), e.String())
			}
			if !tc.call {
				if code == 0 || len(rec.calls) != 0 {
					t.Fatalf("exit %d, calls %q; want a refusal and no call", code, rec.calls)
				}
				return
			}
			if code != 0 || len(rec.calls) != 1 || !slices.Equal(rec.calls[0], []string{"set-token", tc.env}) {
				t.Fatalf("exit %d, calls %q", code, rec.calls)
			}
		})
	}
}

// TestCommandTimeouts: status has 2 s, every other command 10 s.
func TestCommandTimeouts(t *testing.T) {
	for _, tc := range []struct {
		args  []string
		limit time.Duration
	}{
		{[]string{"status", "--json"}, statusTimeout},
		{[]string{"rotate", "--json"}, callTimeout},
		{[]string{"notify", "going-down"}, callTimeout},
		{[]string{"roles", "sender", "--", "gw"}, callTimeout},
	} {
		rec := &recorder{}
		var o, e bytes.Buffer
		if code := rec.cli(&o, &e, nil).run(tc.args); code != 0 || len(rec.deadlines) != 1 {
			t.Fatalf("%q: exit %d, %d deadlines", tc.args, code, len(rec.deadlines))
		}
		if d := rec.deadlines[0]; d > tc.limit || d < tc.limit-time.Second {
			t.Errorf("%q: the call had %s, want %s", tc.args, d, tc.limit)
		}
	}
	if statusTimeout != 2*time.Second || callTimeout != 10*time.Second {
		t.Errorf("limits %s and %s, want 2 s and 10 s", statusTimeout, callTimeout)
	}
}

// TestInitPrintsRecoveryCodeOnce: init creates the group and prints the
// recovery code once; the state directory keeps only its public key; a
// second init refuses, prints no code and changes nothing; rollcalld starts
// from what init left.
func TestInitPrintsRecoveryCodeOnce(t *testing.T) {
	s := newSite(t)
	a := s.add("gateway")
	code := a.initGroup()
	seed, err := parseRecoveryCode(code)
	if err != nil {
		t.Fatalf("the printed code does not read back: %v", err)
	}
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	rosterBin, err := os.ReadFile(filepath.Join(a.dir, node.FileRoster))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(rosterBin, []byte(base64.StdEncoding.EncodeToString(pub))) {
		t.Fatal("the roster does not name the printed code's key as the recovery key")
	}
	files, _ := os.ReadDir(a.dir)
	for _, f := range files {
		b, _ := os.ReadFile(filepath.Join(a.dir, f.Name()))
		for _, form := range [][]byte{seed, []byte(code), []byte(hex.EncodeToString(seed)), []byte(base64.StdEncoding.EncodeToString(seed))} {
			if bytes.Contains(b, form) {
				t.Errorf("%s holds the recovery seed", f.Name())
			}
		}
	}

	idBefore, _ := os.ReadFile(filepath.Join(a.dir, "identity.json"))
	c2, out, errs := a.cli("", nil, "init")
	if c2 != 1 || !strings.Contains(errs, "belongs to a group already") {
		t.Fatalf("second init: exit %d, stderr %q", c2, errs)
	}
	if recoveryRE.MatchString(out + errs) {
		t.Fatal("the second init printed a recovery code")
	}
	idAfter, _ := os.ReadFile(filepath.Join(a.dir, "identity.json"))
	rosterAfter, _ := os.ReadFile(filepath.Join(a.dir, node.FileRoster))
	if !bytes.Equal(idBefore, idAfter) || !bytes.Equal(rosterBin, rosterAfter) {
		t.Fatal("the second init changed the identity or the roster")
	}

	a.start()
	st := a.statusOf()
	if st["initialised"] != true || selfAdmin(st) != "primary" || !slices.Equal(memberRoles(st, "gateway"), []string{"primary"}) {
		t.Fatalf("status after init: %v", st)
	}
}

// TestInitKeepsAnExistingIdentity: init saves an identity only when there
// is none; one that is there is used as it is, and one it cannot read is
// never replaced.
func TestInitKeepsAnExistingIdentity(t *testing.T) {
	s := newSite(t)
	a := s.add("gateway")
	id, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := id.Save(a.dir); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(a.dir, "identity.json"))
	a.initGroup()
	after, _ := os.ReadFile(filepath.Join(a.dir, "identity.json"))
	if !bytes.Equal(before, after) {
		t.Fatal("init replaced an identity that was there")
	}
	rosterBin, _ := os.ReadFile(filepath.Join(a.dir, node.FileRoster))
	if !bytes.Contains(rosterBin, []byte(id.ID.String())) {
		t.Fatal("the roster does not hold the identity that was there")
	}

	b := s.add("ap-office")
	if err := id.Save(b.dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(b.dir, "identity.json")
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	before, _ = os.ReadFile(path)
	if code, out, errs := b.cli("", nil, "init"); code != 1 || recoveryRE.MatchString(out) {
		t.Fatalf("init over an unreadable identity: exit %d, %q %q", code, out, errs)
	}
	after, _ = os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("init replaced an identity it could not read")
	}
	if _, err := os.Stat(filepath.Join(b.dir, node.FileRoster)); err == nil {
		t.Fatal("init wrote a roster beside an identity it could not read")
	}
}

// TestNotifyGoingDownReachesNode: notify going-down makes the node send a
// heartbeat that says so at once, records the shutdown marker, and the
// other router counts the reboot that follows as planned.
func TestNotifyGoingDownReachesNode(t *testing.T) {
	s := newSite(t)
	a, b := s.add("gateway"), s.add("ap-office")
	a.initGroup()
	a.start()
	s.run(5 * time.Second)
	s.join(a, b)
	s.run(20 * time.Second)

	sent := a.net.multicasts()
	if len(sent) == 0 || heartbeatOf(t, a.dir, sent[len(sent)-1])[53]&flagGoingDown != 0 {
		t.Fatal("no heartbeat before the notice, or one that says going down already")
	}
	a.must("", "notify", "going-down")
	now := a.net.multicasts()
	if len(now) != len(sent)+1 {
		t.Fatalf("%d heartbeats sent by the notice, want 1 at once", len(now)-len(sent))
	}
	if heartbeatOf(t, a.dir, now[len(sent)])[53]&flagGoingDown == 0 {
		t.Fatal("the heartbeat sent at the notice does not say going down")
	}
	marker, err := os.ReadFile(filepath.Join(a.dir, "shutdown.json"))
	if err != nil || !bytes.Contains(marker, []byte(a.boot.String())) {
		t.Fatalf("shutdown marker %q, %v; want this boot", marker, err)
	}

	a.stop()
	s.run(40 * time.Second)
	a.boot = ids.BootID{0xa2, 15: 2}
	a.start()
	s.run(90 * time.Second)
	if !incidentWith(b.statusOf(), "gateway rebooted as planned") {
		t.Fatalf("ap-office did not report a planned reboot of gateway: %v", b.statusOf()["incidents"])
	}
}

func incidentWith(st map[string]any, sub string) bool {
	incs, _ := st["incidents"].([]any)
	for _, x := range incs {
		if m, _ := x.(map[string]any); strings.Contains(fmt.Sprint(m["text"]), sub) {
			return true
		}
	}
	return false
}

// TestAdminRecoverWithCode: with the code init printed, an ordinary member
// signs a roster that makes it the primary admin, which the group adopts;
// a code of another group, a typo and a code on the command line fail and
// change nothing.
func TestAdminRecoverWithCode(t *testing.T) {
	s := newSite(t)
	a, b := s.add("gateway"), s.add("ap-office")
	code := a.initGroup()
	a.start()
	s.run(5 * time.Second)
	s.join(a, b)
	s.run(10 * time.Second)
	if selfAdmin(b.statusOf()) != nil {
		t.Fatal("ap-office is an admin before the recovery")
	}

	other := formatRecoveryCode(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	if c, _, errs := b.cli(other+"\n", nil, "admin", "recover"); c != 1 || !strings.Contains(errs, "does not belong to this group") {
		t.Fatalf("a code of another group: exit %d, stderr %q", c, errs)
	}
	typo := []byte(code)
	typo[7] = map[bool]byte{true: 'A', false: 'B'}[typo[7] != 'A']
	if c, _, errs := b.cli(string(typo)+"\n", nil, "admin", "recover"); c != 1 || !strings.Contains(errs, "typo") {
		t.Fatalf("a code with a typo: exit %d, stderr %q", c, errs)
	}
	if c, _, _ := b.cli("", nil, "admin", "recover", code); c == 0 {
		t.Fatal("admin recover took the code from the command line")
	}
	if selfAdmin(b.statusOf()) != nil {
		t.Fatal("a failed recovery changed the roster")
	}

	out := b.must(strings.ToLower(code)+"\n", "admin", "recover", "--json")
	if !strings.HasPrefix(out, `{"ok":true,"message":`) || strings.Contains(out, code) {
		t.Fatalf("recover --json: %q", out)
	}
	st := b.statusOf()
	if selfAdmin(st) != "primary" || !slices.Contains(memberRoles(st, "ap-office"), "primary") {
		t.Fatalf("ap-office after the recovery: %v", st["self"])
	}
	s.run(30 * time.Second)
	if st := a.statusOf(); !slices.Contains(memberRoles(st, "ap-office"), "primary") || slices.Contains(memberRoles(st, "gateway"), "primary") {
		t.Fatalf("gateway did not adopt the recovered roster: %v", st["members"])
	}
}

// jsonBlocks returns the ```json blocks of STATUS-JSON.md, in order, and the
// one under the heading of the full example.
func jsonBlocks(t *testing.T) (blocks []string, full string) {
	t.Helper()
	raw, err := os.ReadFile("../../luci-app-rollcall/STATUS-JSON.md")
	if err != nil {
		t.Fatalf("measured nothing: %v", err)
	}
	doc := string(raw)
	re := regexp.MustCompile("(?s)```json\n(.*?)```")
	for _, m := range re.FindAllStringSubmatch(doc, -1) {
		blocks = append(blocks, m[1])
	}
	i := strings.Index(doc, "### Example of a full report")
	if i < 0 || len(blocks) < 4 {
		t.Fatal("measured nothing: STATUS-JSON.md has no full example")
	}
	full = re.FindStringSubmatch(doc[i:])[1]
	return blocks, full
}

func decode(t *testing.T, s string) any {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatalf("%v in %s", err, s)
	}
	return v
}

// nullable are the fields STATUS-JSON.md allows to be null.
var nullable = map[string]bool{
	"sender": true, "self.admin": true, "members[].last_seen": true, "members[].last_seen_seconds": true,
	"storage.error": true, "telegram.last_ok": true, "group_key": true,
}

// sameShape compares got with want, the example: the same keys at every
// level, values of the same JSON type, null only where it is allowed.
func sameShape(t *testing.T, path string, want, got any) {
	t.Helper()
	if want == nil || got == nil {
		if want != got && !nullable[path] {
			t.Errorf("%s: %v, want %v", path, got, want)
		}
		return
	}
	switch w := want.(type) {
	case map[string]any:
		g, ok := got.(map[string]any)
		if !ok {
			t.Errorf("%s: %T, want an object", path, got)
			return
		}
		for k := range w {
			if _, ok := g[k]; !ok {
				t.Errorf("%s: field %q missing", path, k)
			}
		}
		for k := range g {
			if _, ok := w[k]; !ok {
				t.Errorf("%s: field %q is not in STATUS-JSON.md", path, k)
			}
		}
		for k := range w {
			p := k
			if path != "" {
				p = path + "." + k
			}
			sameShape(t, p, w[k], g[k])
		}
	case []any:
		g, ok := got.([]any)
		if !ok {
			t.Errorf("%s: %T, want an array", path, got)
			return
		}
		if len(w) > 0 && len(g) == 0 && (path == "members" || path == "incidents") {
			t.Errorf("%s: empty, so its entries were not compared", path)
		}
		if len(w) > 0 && len(g) > 0 {
			for _, x := range g {
				sameShape(t, path+"[]", w[0], x)
			}
		}
	default:
		if fmt.Sprintf("%T", want) != fmt.Sprintf("%T", got) {
			t.Errorf("%s: %T, want %T", path, got, want)
		}
	}
}

// TestStatusJSONMatchesContract is the golden test of status --json and the
// admin replies against luci-app-rollcall/STATUS-JSON.md itself: the report
// without a daemon and before setup is exactly the documented one, a full
// report has exactly the documented fields with their types, and an admin
// command answers in the documented form.
func TestStatusJSONMatchesContract(t *testing.T) {
	blocks, full := jsonBlocks(t)
	s := newSite(t)
	a, b := s.add("gateway"), s.add("ap-office")

	c, out, _ := a.cli("", nil, "status", "--json")
	if want := decode(t, blocks[0]); c != 1 || !jsonEqual(decode(t, out), want) {
		t.Errorf("daemon not running: exit %d, %s; want %s", c, out, blocks[0])
	}
	a.start()
	c, out, _ = a.cli("", nil, "status", "--json")
	if want := decode(t, blocks[1]); c != 0 || !jsonEqual(decode(t, out), want) {
		t.Errorf("not set up: exit %d, %s; want %s", c, out, blocks[1])
	}

	// A group of one with nothing to report yet still writes every field.
	a.stop()
	a.initGroup()
	a.start()
	var fresh, example map[string]any
	_ = json.Unmarshal([]byte(a.must("", "status", "--json")), &fresh)
	_ = json.Unmarshal([]byte(full), &example)
	for k := range example {
		if _, ok := fresh[k]; !ok {
			t.Errorf("a new group's report lacks %q", k)
		}
	}
	if len(fresh) != len(example) {
		t.Errorf("a new group's report has %d fields, the example %d", len(fresh), len(example))
	}
	s.run(5 * time.Second)
	s.join(a, b)
	s.run(40 * time.Second)
	out = a.must("", "status", "--json")
	if strings.Count(out, "\n") != 1 || !strings.HasSuffix(out, "}\n") {
		t.Errorf("status --json printed more than one object: %q", out)
	}
	sameShape(t, "", decode(t, full), decode(t, out))

	var inv map[string]any
	_ = json.Unmarshal([]byte(a.must("", "invite", "--json")), &inv)
	if len(inv) != 3 || inv["ok"] != true || inv["message"] != "Join window open for 10 minutes." || inv["join_code"] == "" {
		t.Errorf("invite --json: %v", inv)
	}
	c, out, _ = a.cli("", nil, "remove", "--json", "--", "ap-foo")
	if want := decode(t, `{"ok": false, "error": "no such member: ap-foo"}`); c != 1 || !jsonEqual(decode(t, out), want) {
		t.Errorf("remove of an unknown member: exit %d, %s", c, out)
	}
	if !strings.Contains(strings.Join(blocks, ""), `"error": "no such member: ap-foo"`) {
		t.Error("STATUS-JSON.md no longer shows the failure reply compared above")
	}
}

func jsonEqual(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}

// TestRecoveryCode: a code reads back to its seed, forgiving case, white
// space and look-alike letters; a change of any one symbol is a typo; the
// errors never repeat the text.
func TestRecoveryCode(t *testing.T) {
	seed := bytes.Repeat([]byte{0x5a}, ed25519.SeedSize)
	for i := range seed {
		seed[i] ^= byte(i * 37)
	}
	code := formatRecoveryCode(seed)
	if !recoveryRE.MatchString(code) || len(code) != 71 {
		t.Fatalf("code %q has the wrong form", code)
	}
	for _, form := range []string{code, strings.ToLower(code), " " + strings.ReplaceAll(code, "-", " ") + "\n",
		strings.ReplaceAll(strings.ReplaceAll(code, "0", "O"), "1", "l")} {
		got, err := parseRecoveryCode(form)
		if err != nil || !bytes.Equal(got, seed) {
			t.Fatalf("%q: %x, %v", form, got, err)
		}
	}
	syms := []byte(strings.ReplaceAll(code, "-", ""))
	for i := range syms {
		for _, r := range []byte(crockford) {
			if r == syms[i] {
				continue
			}
			bad := slices.Clone(syms)
			bad[i] = r
			_, err := parseRecoveryCode(string(bad))
			if !errors.Is(err, errRecoveryTypo) {
				t.Fatalf("symbol %d changed to %c: %v, want a typo", i, r, err)
			}
			if err != nil && strings.Contains(err.Error(), string(bad)) {
				t.Fatal("the error repeats the code")
			}
		}
	}
	for _, bad := range []string{"", code[:len(code)-1], code + "0", strings.Replace(code, "-", "U", 1)} {
		if _, err := parseRecoveryCode(bad); !errors.Is(err, errRecoveryTypo) {
			t.Errorf("%q: %v, want a typo", bad, err)
		}
	}
}

// TestControlPathsAgree: the CLI and the daemon name the control socket of
// packaging/README.md.
func TestControlPathsAgree(t *testing.T) {
	readme, err := os.ReadFile("../../packaging/README.md")
	if err != nil {
		t.Fatalf("measured nothing: %v", err)
	}
	daemonSrc, err := os.ReadFile("../rollcalld/main.go")
	if err != nil {
		t.Fatalf("measured nothing: %v", err)
	}
	for _, c := range []struct{ name, value string }{{"ControlDirPath", ControlDirPath}, {"ControlSocketPath", ControlSocketPath}} {
		if !strings.Contains(string(readme), fmt.Sprintf("`%s` = `%s`", c.name, c.value)) {
			t.Errorf("packaging/README.md does not give %s = %s", c.name, c.value)
		}
		if !regexp.MustCompile(c.name + `\s*=\s*"` + regexp.QuoteMeta(c.value) + `"`).Match(daemonSrc) {
			t.Errorf("cmd/rollcalld does not give %s = %s", c.name, c.value)
		}
	}
}

// TestStatusText: without --json, status prints a few lines for a person.
func TestStatusText(t *testing.T) {
	s := newSite(t)
	a := s.add("gateway")
	a.start()
	if out := a.must("", "status"); !strings.Contains(out, "this router is not set up") {
		t.Fatalf("before init: %q", out)
	}
	a.stop()
	a.initGroup()
	a.start()
	out := a.must("", "status")
	for _, want := range []string{"Site Home, this router gateway.", "Members:", "gateway", "primary", "Sender: none can reach Telegram", "Sandbox: off"} {
		if !strings.Contains(out, want) {
			t.Errorf("status lacks %q:\n%s", want, out)
		}
	}
}

// TestStatusTextShowsFlood: the text form of status says when the router is
// under a flood, and says nothing of one otherwise.
func TestStatusTextShowsFlood(t *testing.T) {
	for _, flood := range []bool{false, true} {
		report := fullReport(t, func(m map[string]any) { m["under_flood"] = flood })
		b, _ := json.Marshal(report)
		var out, errb bytes.Buffer
		c := &cli{stdout: &out, stderr: &errb, call: func(context.Context, string, ...string) ([]byte, error) { return b, nil }}
		if code := c.run([]string{"status"}); code != 0 {
			t.Fatalf("status: exit %d, %q", code, errb.String())
		}
		if got := strings.Contains(out.String(), "Under a flood:"); got != flood {
			t.Errorf("under_flood %v: the text says a flood %v:\n%s", flood, got, out.String())
		}
	}
}

// TestInitSiteName: the roster's site is --site, else the site option when
// it is a valid name, else home; an invalid --site is refused.
func TestInitSiteName(t *testing.T) {
	for _, tc := range []struct {
		option, flag, want string
	}{
		{"office-2", "", "office-2"},
		{"Home", "", "home"},
		{"", "", "home"},
		{"office-2", "cabin", "cabin"},
	} {
		s := newSite(t)
		a := s.add("gateway")
		if err := os.MkdirAll(a.dir, 0o700); err != nil {
			t.Fatal(err)
		}
		conf := "config rollcall 'main'\n"
		if tc.option != "" {
			conf += "\toption site '" + tc.option + "'\n"
		}
		cfgPath := filepath.Join(filepath.Dir(a.dir), "rollcall")
		if err := os.WriteFile(cfgPath, []byte(conf), 0o600); err != nil {
			t.Fatal(err)
		}
		var out, errb bytes.Buffer
		c := &cli{stdout: &out, stderr: &errb, stateDir: a.dir, configPath: cfgPath,
			hostname: func() (string, error) { return "gateway", nil }}
		args := []string{"init"}
		if tc.flag != "" {
			args = append(args, "--site", tc.flag)
		}
		if code := c.run(args); code != 0 || !strings.Contains(out.String(), "Group "+tc.want+" created") {
			t.Errorf("%+v: exit %d, %q %q", tc, code, out.String(), errb.String())
		}
	}
	var out, errb bytes.Buffer
	c := &cli{stdout: &out, stderr: &errb, stateDir: t.TempDir(), hostname: func() (string, error) { return "gateway", nil }}
	if code := c.run([]string{"init", "--site", "My Home"}); code != 2 {
		t.Errorf("an invalid --site: exit %d", code)
	}
	if code := c.run([]string{"init", "--name", "Gateway"}); code != 2 {
		t.Errorf("an invalid --name: exit %d", code)
	}
	c.hostname = func() (string, error) { return "OpenWrt", nil }
	if code := c.run([]string{"init"}); code != 2 || !strings.Contains(errb.String(), "give one with --name") {
		t.Errorf("an invalid hostname: exit %d, %q", code, errb.String())
	}
}

// TestNotifyForms: the notices of the init script and hotplug, and nothing
// else, reach rollcalld.
func TestNotifyForms(t *testing.T) {
	for _, tc := range []struct {
		args []string
		call []string
	}{
		{[]string{"notify", "going-down"}, []string{"notify", "going-down"}},
		{[]string{"notify", "clock-synced"}, []string{"notify", "clock-synced"}},
		{[]string{"notify", "iface", "ifdown", "wan"}, []string{"notify", "iface", "ifdown", "wan"}},
		{[]string{"notify", "uplink", "wwan"}, []string{"notify", "uplink", "wwan"}},
		{[]string{"notify", "clock-synced", "--json"}, []string{"notify", "clock-synced"}},
	} {
		rec := &recorder{}
		var o, e bytes.Buffer
		if code := rec.cli(&o, &e, nil).run(tc.args); code != 0 || len(rec.calls) != 1 || !slices.Equal(rec.calls[0], tc.call) {
			t.Errorf("%q: exit %d, calls %q", tc.args, code, rec.calls)
		}
	}
	for _, args := range [][]string{
		{"notify"}, {"notify", "clock-synced", "now"}, {"notify", "clock"}, {"notify", "going-down", "--", "x"},
		{"notify", "iface", "ifdown"}, {"notify", "uplink"}, {"notify", "--evil", "clock-synced"},
	} {
		rec := &recorder{}
		var o, e bytes.Buffer
		if code := rec.cli(&o, &e, nil).run(args); code == 0 || len(rec.calls) != 0 {
			t.Errorf("%q: exit %d, %d calls; want a refusal and no call", args, code, len(rec.calls))
		}
	}
}

// TestRunbookCommandsParse: every rollcall command in the lab runbook, in
// its ssh lines and in its inline commands, is one this CLI accepts, so no
// step fails on its syntax on a router.
func TestRunbookCommandsParse(t *testing.T) {
	raw, err := os.ReadFile("../../docs/lab/runbook.md")
	if err != nil {
		t.Fatalf("measured nothing: %v", err)
	}
	admin, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	var inv pairing.Inviter
	code, err := inv.Open(tStart, netip.MustParseAddrPort("192.0.2.1:7432"), admin)
	if err != nil {
		t.Fatal(err)
	}
	doc := strings.NewReplacer("<join code>", code.String(),
		"<an address of flint2 that beryl1 reaches>", "192.0.2.1").Replace(string(raw))
	verbs := `(?:status|init|invite|join|remove|roles|rotate|set-token|bind-telegram|admin|notify|help|version)`
	inSSH := regexp.MustCompile(`(?:'|&& )rollcall (` + verbs + `\b[^'&|"]*)`)
	inline := regexp.MustCompile("`rollcall (" + verbs + "\\b[^`]*)`")
	var cmds []string
	for _, line := range strings.Split(doc, "\n") {
		if strings.Contains(line, "tailscale ssh") {
			for _, m := range inSSH.FindAllStringSubmatch(line, -1) {
				cmds = append(cmds, m[1])
			}
		}
		for _, m := range inline.FindAllStringSubmatch(line, -1) {
			cmds = append(cmds, m[1])
		}
	}
	if len(cmds) < 15 {
		t.Fatalf("measured nothing: %d commands found in the runbook", len(cmds))
	}
	for _, c := range cmds {
		rec := &recorder{}
		var o, e bytes.Buffer
		cl := rec.cli(&o, &e, map[string]string{tokenEnv: canary})
		cl.stdin = strings.NewReader(formatRecoveryCode(bytes.Repeat([]byte{1}, 32)))
		cl.stateDir = filepath.Join(t.TempDir(), "state")
		cl.configPath = filepath.Join(t.TempDir(), "none")
		if code := cl.run(strings.Fields(c)); code != 0 {
			t.Errorf("runbook command %q: exit %d, %s", "rollcall "+c, code, strings.TrimSpace(e.String()))
		}
	}
}
