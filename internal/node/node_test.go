package node

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/epoch"
	"github.com/TAIPANBOX/rollcall/internal/events"
	"github.com/TAIPANBOX/rollcall/internal/history"
	"github.com/TAIPANBOX/rollcall/internal/identity"
	"github.com/TAIPANBOX/rollcall/internal/ids"
	"github.com/TAIPANBOX/rollcall/internal/member"
	"github.com/TAIPANBOX/rollcall/internal/roster"
	"github.com/TAIPANBOX/rollcall/internal/store"
	"github.com/TAIPANBOX/rollcall/internal/wire"
)

// tStart is the wall clock when a test group starts.
var tStart = time.Date(2026, 10, 23, 9, 0, 0, 0, time.UTC)

const sec = time.Second

// canary is the fake bot token the tests plant; it must never leave.
const canary = "CANARY-123:abc"

// fakeClock is one clock for a whole group: wall and monotonic move together.
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

// hub carries the packets of a group between its nodes, synchronously.
type hub struct {
	mu    sync.Mutex
	nodes map[netip.AddrPort]*Node
	cut   map[[2]netip.AddrPort]bool
}

func (h *hub) node(to netip.AddrPort) *Node {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.nodes[to]
}

func (h *hub) blocked(a, b netip.AddrPort) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.cut[[2]netip.AddrPort{a, b}] || h.cut[[2]netip.AddrPort{b, a}]
}

// fakeNet is one node's Net. It counts every call.
type fakeNet struct {
	h    *hub
	self netip.AddrPort

	mu      sync.Mutex
	calls   int
	streams []netip.AddrPort
	unis    []netip.AddrPort
}

func (f *fakeNet) count(to netip.AddrPort, stream bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if stream {
		f.streams = append(f.streams, to)
	} else if to.IsValid() {
		f.unis = append(f.unis, to)
	}
}

func (f *fakeNet) Calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *fakeNet) contacted(a netip.AddrPort) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Contains(f.streams, a) || slices.Contains(f.unis, a)
}

func (f *fakeNet) Multicast(b []byte) error {
	f.count(netip.AddrPort{}, false)
	if f.h == nil {
		return nil
	}
	f.h.mu.Lock()
	var to []*Node
	for a, n := range f.h.nodes {
		if a != f.self && !f.h.cut[[2]netip.AddrPort{f.self, a}] && !f.h.cut[[2]netip.AddrPort{a, f.self}] {
			to = append(to, n)
		}
	}
	f.h.mu.Unlock()
	for _, n := range to {
		n.HandlePacket(f.self, bytes.Clone(b))
	}
	return nil
}

func (f *fakeNet) Unicast(to netip.AddrPort, b []byte) error {
	f.count(to, false)
	if f.h == nil {
		return nil
	}
	if n := f.h.node(to); n != nil && !f.h.blocked(f.self, to) {
		n.HandlePacket(f.self, bytes.Clone(b))
	}
	return nil
}

var errUnreachable = errors.New("unreachable")

func (f *fakeNet) Stream(to netip.AddrPort, b []byte) ([]byte, error) {
	f.count(to, true)
	if f.h == nil {
		return nil, errUnreachable
	}
	n := f.h.node(to)
	if n == nil || f.h.blocked(f.self, to) || len(b) > maxFrame {
		return nil, errUnreachable
	}
	if !n.Authenticate(b) {
		return nil, errUnreachable
	}
	// The TCP source port is an ephemeral one.
	from := netip.AddrPortFrom(f.self.Addr(), 40000)
	r := n.HandleStream(from, bytes.Clone(b))
	if r == nil {
		return nil, errUnreachable
	}
	return r, nil
}

// chat is the one chat of a group; every sender's channel writes to it.
type chat struct {
	mu    sync.Mutex
	clk   *fakeClock
	msgs  []chatMsg
	pings map[string][]time.Duration
}

type chatMsg struct {
	by   string
	text string
	at   time.Duration
}

type fakeChannel struct {
	c  *chat
	by string
}

func (f *fakeChannel) Send(_ context.Context, text string) error {
	f.c.mu.Lock()
	defer f.c.mu.Unlock()
	f.c.msgs = append(f.c.msgs, chatMsg{by: f.by, text: text, at: f.c.clk.Mono()})
	return nil
}

func (f *fakeChannel) Ping(_ context.Context) error {
	f.c.mu.Lock()
	defer f.c.mu.Unlock()
	f.c.pings[f.by] = append(f.c.pings[f.by], f.c.clk.Mono())
	return nil
}

// messages returns the texts in the chat that contain sub.
func (c *chat) messages(sub string) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []string
	for _, m := range c.msgs {
		if strings.Contains(m.text, sub) {
			out = append(out, m.text)
		}
	}
	return out
}

func (c *chat) all() []string { return c.messages("") }

// setup says how a test group is made.
type setup struct {
	n       int
	running []bool      // which members get a node; nil for all
	admins  int         // 1 (a primary) or 2 (and a backup)
	senders map[int]int // member index -> priority, for members with the sender role
}

// group is a simulated site.
type group struct {
	t      testing.TB
	clk    *fakeClock
	hub    *hub
	chat   *chat
	ids    []*identity.Identity
	addrs  []netip.AddrPort
	stores []*store.Store
	nets   []*fakeNet
	nodes  []*Node
	cfgs   []Config
	key    epoch.Key
	first  roster.Signed
	rec    ed25519.PrivateKey
}

func bootN(i, seq int) ids.BootID { return ids.BootID{byte(i + 1), byte(seq), 15: 0xb1} }

func newGroup(t testing.TB, s setup) *group {
	t.Helper()
	if s.admins == 0 {
		s.admins = 1
	}
	clk := &fakeClock{wall: tStart, mono: 1000 * sec}
	g := &group{t: t, clk: clk, hub: &hub{nodes: map[netip.AddrPort]*Node{}, cut: map[[2]netip.AddrPort]bool{}},
		chat: &chat{clk: clk, pings: map[string][]time.Duration{}}}
	g.rec = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0xee}, ed25519.SeedSize))
	r := roster.Roster{Version: 1, Site: "home", RecoveryPub: g.rec.Public().(ed25519.PublicKey)}
	for i := 0; i < s.n; i++ {
		id, err := identity.Generate()
		if err != nil {
			t.Fatal(err)
		}
		g.ids = append(g.ids, id)
		g.addrs = append(g.addrs, netip.MustParseAddrPort(fmt.Sprintf("10.0.0.%d:7432", i+1)))
		m := roster.Member{ID: id.ID, Name: fmt.Sprintf("r%02d", i+1),
			SignPub: id.Sign.Public().(ed25519.PublicKey), RecvPub: id.Recv.PublicKey().Bytes()}
		switch {
		case i == 0:
			m.Roles = append(m.Roles, roster.RolePrimary)
		case i < s.admins:
			m.Roles = append(m.Roles, roster.RoleBackup)
		}
		if _, ok := s.senders[i]; ok {
			m.Roles = append(m.Roles, roster.RoleSender)
		}
		r.Members = append(r.Members, m)
		if i < s.admins {
			r.Admins = append(r.Admins, id.ID)
		}
	}
	first, err := roster.SignRoster(r, g.ids[0].ID, g.ids[0].Sign, false)
	if err != nil {
		t.Fatal(err)
	}
	g.first = first
	secret := make([]byte, epoch.SecretSize)
	rand.Read(secret)
	g.key = epoch.Key{ID: 1 << 2, Secret: secret, NotAfter: tStart.Add(epoch.RotationPeriod)}
	g.nodes = make([]*Node, s.n)
	for i := 0; i < s.n; i++ {
		st, err := store.Open(fmt.Sprintf("%s/r%02d", t.TempDir(), i+1))
		if err != nil {
			t.Fatal(err)
		}
		if err := Bootstrap(st, first, g.key); err != nil {
			t.Fatal(err)
		}
		prio, sender := s.senders[i]
		if sender {
			if err := SaveSecrets(st, canary, 42); err != nil {
				t.Fatal(err)
			}
		}
		g.stores = append(g.stores, st)
		g.nets = append(g.nets, &fakeNet{h: g.hub, self: g.addrs[i]})
		g.cfgs = append(g.cfgs, Config{Site: "Home", Heartbeat: 5 * sec, SilentAfter: 30 * sec, Sender: sender,
			Priority: prio, TZ: time.UTC, Boot: bootN(i, 1), BootSeq: 1, Versions: [2]string{"24.10.4", "1.0.0"}})
		if s.running == nil || s.running[i] {
			g.start(i)
		}
	}
	return g
}

// start starts member i's node on its store.
func (g *group) start(i int) *Node {
	g.t.Helper()
	var ch *fakeChannel
	if g.cfgs[i].Sender {
		ch = &fakeChannel{c: g.chat, by: fmt.Sprintf("r%02d", i+1)}
	}
	var dc any = ch
	var n *Node
	var err error
	if ch != nil {
		n, err = New(g.cfgs[i], g.stores[i], g.ids[i], g.nets[i], g.clk, dc.(*fakeChannel))
	} else {
		n, err = New(g.cfgs[i], g.stores[i], g.ids[i], g.nets[i], g.clk, nil)
	}
	if err != nil {
		g.t.Fatalf("New r%02d: %v", i+1, err)
	}
	n.SetClockTrusted(true)
	g.nodes[i] = n
	g.hub.mu.Lock()
	g.hub.nodes[g.addrs[i]] = n
	g.hub.mu.Unlock()
	return n
}

// stop takes member i's node off the network, as a power cut does.
func (g *group) stop(i int) {
	g.hub.mu.Lock()
	delete(g.hub.nodes, g.addrs[i])
	g.hub.mu.Unlock()
	g.nodes[i] = nil
}

// run moves the group d on, one second at a time, ticking every node.
func (g *group) run(d time.Duration) {
	for el := time.Duration(0); el < d; el += sec {
		g.clk.advance(sec)
		for _, n := range g.nodes {
			if n != nil {
				n.Tick()
			}
		}
	}
}

// split cuts every link between the members in a and those in b.
func (g *group) split(a, b []int, cut bool) {
	g.hub.mu.Lock()
	defer g.hub.mu.Unlock()
	for _, i := range a {
		for _, j := range b {
			k := [2]netip.AddrPort{g.addrs[i], g.addrs[j]}
			if cut {
				g.hub.cut[k] = true
			} else {
				delete(g.hub.cut, k)
			}
		}
	}
}

func with[T any](n *Node, f func() T) T {
	n.mu.Lock()
	defer n.mu.Unlock()
	return f()
}

// ownTypes returns the event types in n's own chain, oldest first.
func ownTypes(n *Node) []events.Type {
	return with(n, func() []events.Type {
		var out []events.Type
		for _, e := range n.log.Range(n.id.ID, 1, n.log.Head(n.id.ID).Seq) {
			if b, err := DecodeEvent(e); err == nil {
				out = append(out, b.Type)
			}
		}
		return out
	})
}

func countType(ts []events.Type, t events.Type) int {
	c := 0
	for _, x := range ts {
		if x == t {
			c++
		}
	}
	return c
}

// packetKey returns the packet key of k.
func testPacketKey(t testing.TB, k epoch.Key) []byte {
	t.Helper()
	pk, err := wire.PacketKey(k.Secret)
	if err != nil {
		t.Fatal(err)
	}
	return pk
}

// sealEnvelope returns a packet of type typ from id, sealed under k.
func sealEnvelope(t testing.TB, k epoch.Key, id *identity.Identity, typ msgType, boot ids.BootID, bootSeq, counter uint64, payload []byte) []byte {
	t.Helper()
	msg := encodeEnvelope(envelope{typ: typ, from: id.ID, bootSeq: bootSeq, boot: boot, counter: counter, payload: payload}, k.ID, id.Sign)
	p, err := wire.Seal(testPacketKey(t, k), k.ID, msg)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// heartbeatPlain returns a heartbeat of id, signed, in plaintext form (the
// type byte and the heartbeat), for epoch k.
func heartbeatPlain(t testing.TB, k epoch.Key, id *identity.Identity, name string, boot ids.BootID, counter uint64) []byte {
	t.Helper()
	b, err := member.EncodeHeartbeat(member.Heartbeat{Epoch: k.ID, From: id.ID, BootSeq: 1, Boot: boot, Counter: counter,
		Name: name, Wall: tStart, Mono: sec, ClockTrusted: true}, id)
	if err != nil {
		t.Fatal(err)
	}
	return append([]byte{byte(msgHeartbeat)}, b...)
}

func sealPlain(t testing.TB, k epoch.Key, pt []byte) []byte {
	t.Helper()
	p, err := wire.Seal(testPacketKey(t, k), k.ID, pt)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// TestUnauthenticatedProducesNothing: packets that do not pass AEAD, of any
// shape, make no call on Net, now or at a later Tick, and nothing in them is
// read: no signature is checked, no address learned, nothing planned
// (invariant 2).
func TestUnauthenticatedProducesNothing(t *testing.T) {
	g := newGroup(t, setup{n: 2, running: []bool{true, false}})
	a, b := g.nodes[0], g.ids[1]
	g.run(3 * sec)
	attacker := netip.MustParseAddrPort("192.0.2.66:7432")
	rng := mrand.New(mrand.NewPCG(1, 2))
	fill := func(b []byte) {
		for i := range b {
			b[i] = byte(rng.Uint32())
		}
	}
	before := g.nets[0].Calls()
	hb0 := with(a, func() member.Counters { return a.table.Counters() })

	// Shapes: random bytes; a valid header of the known epoch with random
	// bytes after it; and plaintext a member signed, put after the header
	// without encryption: a heartbeat and an envelope of B's.
	plainHB := heartbeatPlain(t, g.key, b, "r02", bootN(1, 1), 1)
	payload, _ := json.Marshal(digestReq{})
	plainEnv := encodeEnvelope(envelope{typ: msgDigestReq, from: b.ID, bootSeq: 1, boot: bootN(1, 1), counter: 2, payload: payload}, g.key.ID, b.Sign)
	header := func() []byte {
		h := make([]byte, wire.HeaderLen)
		h[0] = wire.Version
		h[2], h[3], h[4], h[5] = byte(g.key.ID>>24), byte(g.key.ID>>16), byte(g.key.ID>>8), byte(g.key.ID)
		fill(h[6:])
		return h
	}
	for i := 0; i < 1000; i++ {
		var p []byte
		switch i % 4 {
		case 0:
			p = make([]byte, rng.IntN(1300))
			fill(p)
		case 1:
			tail := make([]byte, rng.IntN(1100))
			fill(tail)
			p = append(header(), tail...)
		case 2:
			p = append(header(), plainHB...)
			p = append(p, make([]byte, 16)...)
		case 3:
			p = append(header(), plainEnv...)
			p = append(p, make([]byte, 16)...)
		}
		a.HandlePacket(attacker, p)
		if r := a.HandleStream(attacker, p); r != nil {
			t.Fatalf("packet %d (shape %d) got a reply of %d bytes", i, i%4, len(r))
		}
		if a.Authenticate(p) {
			t.Fatalf("packet %d (shape %d) authenticated", i, i%4)
		}
	}
	if got := g.nets[0].Calls(); got != before {
		t.Fatalf("handling 2000 unauthenticated packets made %d calls on Net", got-before)
	}
	with(a, func() any {
		if a.counters.SigChecks != 0 || a.counters.Accepted != 0 {
			t.Errorf("signatures checked %d, messages accepted %d; want 0 and 0", a.counters.SigChecks, a.counters.Accepted)
		}
		if hb := a.table.Counters(); hb.Accepted != hb0.Accepted || hb.Signature != hb0.Signature || hb.Malformed != hb0.Malformed || hb.Unknown != hb0.Unknown {
			t.Errorf("heartbeat counters moved: %+v, were %+v", hb, hb0)
		}
		if len(a.jobs) != 0 {
			t.Errorf("%d exchanges planned", len(a.jobs))
		}
		for id, p := range a.peers {
			if p.addr == attacker {
				t.Errorf("the attacker's address was learned for %s", id)
			}
		}
		if a.counters.Auth+a.counters.Malformed+a.counters.Epoch < 2000 {
			t.Errorf("only %d of 2000 refusals counted", a.counters.Auth+a.counters.Malformed+a.counters.Epoch)
		}
		return nil
	})
	g.run(60 * sec)
	if g.nets[0].contacted(attacker) {
		t.Fatal("a later Tick contacted the attacker's address")
	}
}

// TestCheckOrder: a packet that passes AEAD from a sender outside the roster
// never reaches the signature check, and is counted; a forged packet from a
// member does not move the member's replay window; a replay is refused
// before its signature is checked; a signed body that does not decode is
// counted as schema.
func TestCheckOrder(t *testing.T) {
	g := newGroup(t, setup{n: 2, running: []bool{true, false}})
	a, b := g.nodes[0], g.ids[1]
	g.run(2 * sec)
	stranger, _ := identity.Generate()
	from := netip.MustParseAddrPort("10.0.0.9:7432")
	digest, _ := json.Marshal(digestReq{})
	counters := func() Counters { return with(a, func() Counters { return a.counters }) }

	// Unknown sender, valid AEAD, valid signature of its own: a heartbeat,
	// then an envelope.
	a.HandlePacket(from, sealPlain(t, g.key, heartbeatPlain(t, g.key, stranger, "r09", bootN(9, 1), 1)))
	if hb := with(a, func() member.Counters { return a.table.Counters() }); hb.Unknown != 1 || hb.Signature != 0 || hb.Accepted != 0 {
		t.Fatalf("stranger's heartbeat: unknown %d, signature failures %d, accepted %d; want 1, 0, 0", hb.Unknown, hb.Signature, hb.Accepted)
	}
	if r := a.HandleStream(from, sealEnvelope(t, g.key, stranger, msgDigestReq, bootN(9, 1), 1, 2, digest)); r != nil {
		t.Fatal("a stranger got a reply")
	}
	if c := counters(); c.Unknown != 1 || c.SigChecks != 0 || c.Accepted != 0 {
		t.Fatalf("stranger's envelope: unknown %d, signature checks %d, accepted %d; want 1, 0, 0", c.Unknown, c.SigChecks, c.Accepted)
	}

	// A forgery naming B with a high counter and a bad signature.
	forged := encodeEnvelope(envelope{typ: msgDigestReq, from: b.ID, bootSeq: 1, boot: bootN(1, 1), counter: 500, payload: digest}, g.key.ID, stranger.Sign)
	p, _ := wire.Seal(testPacketKey(t, g.key), g.key.ID, forged)
	if r := a.HandleStream(from, p); r != nil {
		t.Fatal("a forgery got a reply")
	}
	if c := counters(); c.Signature != 1 || c.SigChecks != 1 || c.Accepted != 0 {
		t.Fatalf("forgery: signature failures %d, checks %d, accepted %d; want 1, 1, 0", c.Signature, c.SigChecks, c.Accepted)
	}
	// B's genuine packet with a far lower counter is still accepted: the
	// forgery did not move the window.
	genuine := sealEnvelope(t, g.key, b, msgDigestReq, bootN(1, 1), 1, 5, digest)
	if r := a.HandleStream(from, genuine); r == nil {
		t.Fatalf("B's genuine request after a forgery got no reply (counters %+v)", counters())
	}
	// Its replay is refused at the replay step, before any signature check.
	checks := counters().SigChecks
	if r := a.HandleStream(from, genuine); r != nil {
		t.Fatal("a replay got a reply")
	}
	if c := counters(); c.Replay != 1 || c.SigChecks != checks {
		t.Fatalf("replay: replays %d, signature checks %d -> %d; want 1 and unchanged", c.Replay, checks, c.SigChecks)
	}
	// A validly signed body that does not decode.
	bad := sealEnvelope(t, g.key, b, msgDigestReq, bootN(1, 1), 1, 6, []byte(`{"x":1}`))
	if r := a.HandleStream(from, bad); r != nil {
		t.Fatal("a body that does not decode got a reply")
	}
	if c := counters(); c.Schema != 1 || c.Accepted != 1 {
		t.Fatalf("schema: %d, accepted %d; want 1 and 1", c.Schema, c.Accepted)
	}
}

// TestFailClosedWithoutKeys: without an epoch key (or a roster) the node
// refuses to start, says why, and does nothing at all (invariant 12).
func TestFailClosedWithoutKeys(t *testing.T) {
	g := newGroup(t, setup{n: 2, running: []bool{false, false}})
	for _, tc := range []struct {
		name string
		prep func(st *store.Store)
		want error
	}{
		{"no epoch key", func(st *store.Store) {
			st.WriteFileAtomic(FileRoster, encodeChain([]roster.Signed{g.first}))
		}, ErrNoEpochKey},
		{"empty key list", func(st *store.Store) {
			st.WriteFileAtomic(FileRoster, encodeChain([]roster.Signed{g.first}))
			writeKeys(st, nil, false)
		}, ErrNoEpochKey},
		{"no roster", func(st *store.Store) { writeKeys(st, []epoch.Key{g.key}, false) }, ErrNoRoster},
		{"corrupt epoch file", func(st *store.Store) {
			st.WriteFileAtomic(FileRoster, encodeChain([]roster.Signed{g.first}))
			st.WriteFileAtomic(FileEpoch, []byte(`{"keys":[{"id":4,"secret":"AAAA","not_after":"2026-01-01T00:00:00Z"}],"removed":false}`))
		}, ErrState},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st, err := store.Open(t.TempDir() + "/s")
			if err != nil {
				t.Fatal(err)
			}
			tc.prep(st)
			nt := &fakeNet{self: g.addrs[0]}
			n, err := New(g.cfgs[0], st, g.ids[0], nt, g.clk, &fakeChannel{c: g.chat, by: "x"})
			if !errors.Is(err, tc.want) || n == nil {
				t.Fatalf("New: %v (node %v); want %v and a stopped node", err, n != nil, tc.want)
			}
			s := n.Status()
			if s.State != "stopped" || s.Error != err.Error() || s.Initialised {
				t.Fatalf("Status state %q error %q initialised %v; want stopped, %q, false", s.State, s.Error, s.Initialised, err)
			}
			p := sealPlain(t, g.key, heartbeatPlain(t, g.key, g.ids[1], "r02", bootN(1, 1), 1))
			n.HandlePacket(g.addrs[1], p)
			if n.HandleStream(g.addrs[1], p) != nil || n.Authenticate(p) {
				t.Fatal("a stopped node answered")
			}
			for i := 0; i < 100; i++ {
				g.clk.advance(sec)
				n.Tick()
			}
			if nt.Calls() != 0 || len(g.chat.pings) != 0 {
				t.Fatalf("a stopped node made %d calls on Net and %d pings", nt.Calls(), len(g.chat.pings))
			}
		})
	}
}

// removeC builds a group of three, removes r03 at the primary, and runs on.
func removeC(t *testing.T) (*group, *Node) {
	g := newGroup(t, setup{n: 3, senders: map[int]int{2: 1}})
	g.run(15 * sec)
	if err := g.nodes[0].Remove(g.ids[2].ID); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	c := g.nodes[2]
	g.run(15 * sec)
	return g, c
}

// TestRemovedSelfClearsSecrets: a member that sees a roster without itself
// stops sending and clears its group secrets (security spec 5.6).
func TestRemovedSelfClearsSecrets(t *testing.T) {
	g, c := removeC(t)
	if s := c.Status(); s.State != "removed" || s.Initialised {
		t.Fatalf("removed member's status: state %q initialised %v", s.State, s.Initialised)
	}
	with(c, func() any {
		if c.ring.Lookup(g.key.ID); len(c.keys) != 0 {
			t.Errorf("the removed member still holds %d keys", len(c.keys))
		}
		if _, ok := c.ring.Lookup(g.key.ID); ok {
			t.Error("the removed member's ring still opens the epoch")
		}
		if c.ch != nil || c.secrets.BotToken != "" {
			t.Error("the removed member still holds its channel or token")
		}
		return nil
	})
	b, _ := g.stores[2].ReadFile(FileEpoch)
	var f epochFile
	if json.Unmarshal(b, &f) != nil || len(f.Keys) != 0 || !f.Removed {
		t.Fatalf("stored epoch file after removal: %s", b)
	}
	if b, _ := g.stores[2].ReadFile(FileSecrets); bytes.Contains(b, []byte(canary)) {
		t.Fatal("the stored bot token survived the removal")
	}
	calls := g.nets[2].Calls()
	g.run(30 * sec)
	if g.nets[2].Calls() != calls {
		t.Fatal("the removed member still sends")
	}
	// It stays removed after a restart.
	if _, err := New(g.cfgs[2], g.stores[2], g.ids[2], &fakeNet{}, g.clk, nil); !errors.Is(err, ErrRemoved) {
		t.Fatalf("restart of a removed member: %v, want ErrRemoved", err)
	}
}

// TestRemoveRotatesAndExcludes: after remove, the removed member gets no
// new key, and once the overlap is over its packets fail at the epoch step.
func TestRemoveRotatesAndExcludes(t *testing.T) {
	g, _ := removeC(t)
	a, b := g.nodes[0], g.nodes[1]
	var newID uint32
	with(a, func() any {
		newID = a.current().ID
		if newID != (2<<2)|0 {
			t.Errorf("new epoch ID %d, want %d (sequence 2, primary)", newID, (2<<2)|0)
		}
		if a.deliveries[g.ids[2].ID] != nil {
			t.Error("a delivery to the removed member is planned")
		}
		return nil
	})
	if with(b, func() uint32 { return b.current().ID }) != newID {
		t.Fatal("the remaining member did not install the new key")
	}
	if with(g.nodes[2], func() bool { _, ok := g.nodes[2].ring.Lookup(newID); return ok }) {
		t.Fatal("the removed member holds the new key")
	}
	// Within the overlap its packets open but name no member.
	hb := heartbeatPlain(t, g.key, g.ids[2], "r03", bootN(9, 1), 1000)
	unknown := with(a, func() uint64 { return a.table.Counters().Unknown })
	a.HandlePacket(g.addrs[2], sealPlain(t, g.key, hb))
	if with(a, func() uint64 { return a.table.Counters().Unknown }) != unknown+1 {
		t.Fatal("within the overlap, the removed member's packet was not refused as unknown")
	}
	g.run(60 * sec)
	for _, n := range []*Node{a, b} {
		ep := with(n, func() uint64 { return n.counters.Epoch })
		n.HandlePacket(g.addrs[2], sealPlain(t, g.key, heartbeatPlain(t, g.key, g.ids[2], "r03", bootN(9, 1), 1001)))
		if with(n, func() uint64 { return n.counters.Epoch }) != ep+1 {
			t.Fatal("after the overlap, the removed member's packet did not fail at the epoch step")
		}
	}
	for _, n := range []*Node{a, b} {
		for _, m := range n.Status().Members {
			if m.State != "up" {
				t.Fatalf("after the rotation %s is %s", m.Name, m.State)
			}
		}
	}
}

// TestRosterChangeAnnouncedOnce: every roster change is announced exactly
// once to the chat, by the group, also when the sender fails over after
// the announcement (invariant 16).
func TestRosterChangeAnnouncedOnce(t *testing.T) {
	g := newGroup(t, setup{n: 4, senders: map[int]int{0: 2, 1: 1}})
	g.run(20 * sec)
	if err := g.nodes[0].Publish(func(r *roster.Roster) error {
		r.Members[2].Roles = append(r.Members[2].Roles, roster.RoleSender)
		return nil
	}); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	g.run(20 * sec)
	if err := g.nodes[0].Remove(g.ids[3].ID); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	g.run(30 * sec)
	// The sender goes away; the next one must not announce again.
	g.split([]int{0}, []int{1, 2, 3}, true)
	g.run(120 * sec)
	t.Logf("chat:\n%s", strings.Join(g.chat.all(), "\n"))
	roles, removed := g.chat.messages("r03 roles changed (by r01)"), g.chat.messages("r04 removed (by r01)")
	if len(roles) != 1 || len(removed) != 1 {
		t.Fatalf("announcements: %d of the role change, %d of the removal; want 1 and 1. Chat:\n%s",
			len(roles), len(removed), strings.Join(g.chat.all(), "\n"))
	}
	if n := len(g.chat.messages("the group changed")); n != 2 {
		t.Fatalf("%d roster messages, want 2. Chat:\n%s", n, strings.Join(g.chat.all(), "\n"))
	}
	for _, m := range g.chat.all() {
		if strings.Contains(m, "joined") || strings.Contains(m, "left the group") {
			t.Fatalf("a roster change announced a second time as %q", m)
		}
	}
	if len(g.chat.messages("r01 stopped answering")) != 1 {
		t.Fatalf("the failover did not reach the chat:\n%s", strings.Join(g.chat.all(), "\n"))
	}
}

// TestReservedTypesIgnored: checkpoint, cp_sig and objection are checked
// like any packet and then ignored in v1.
func TestReservedTypesIgnored(t *testing.T) {
	g := newGroup(t, setup{n: 2, running: []bool{true, false}})
	a, b := g.nodes[0], g.ids[1]
	g.run(2 * sec)
	digest := with(a, func() ids.Hash { return a.log.Digest() })
	calls := g.nets[0].Calls()
	counter := uint64(10)
	for _, typ := range []msgType{msgCheckpoint, msgCPSig, msgObjection} {
		counter++
		a.HandlePacket(g.addrs[1], sealEnvelope(t, g.key, b, typ, bootN(1, 1), 1, counter, []byte(`{"height":1}`)))
		counter++
		if r := a.HandleStream(g.addrs[1], sealEnvelope(t, g.key, b, typ, bootN(1, 1), 1, counter, []byte("opaque"))); r != nil {
			t.Fatalf("type %d got a reply", typ)
		}
	}
	counter++
	a.HandlePacket(g.addrs[1], sealEnvelope(t, g.key, b, msgType(200), bootN(1, 1), 1, counter, nil))
	with(a, func() any {
		if a.counters.Ignored != 6 || a.counters.Malformed != 1 {
			t.Errorf("ignored %d, malformed %d; want 6 and 1", a.counters.Ignored, a.counters.Malformed)
		}
		if len(a.jobs) != 0 || a.log.Digest() != digest || a.cur().Version != 1 {
			t.Error("a reserved type changed the node's state")
		}
		return nil
	})
	if g.nets[0].Calls() != calls {
		t.Fatal("a reserved type made a call on Net")
	}
}

// TestCatchUpOnDigestMismatch: a peer whose heartbeat digest differs gets
// the missing range of entries over Stream.
func TestCatchUpOnDigestMismatch(t *testing.T) {
	g := newGroup(t, setup{n: 2})
	a, b := g.nodes[0], g.nodes[1]
	g.run(10 * sec)
	g.split([]int{0}, []int{1}, true)
	for _, typ := range []events.Type{events.WanDown, events.WanUp, events.InternetLost, events.InternetRestored} {
		a.LocalEvent(events.Event{Type: typ})
		g.run(2 * sec)
	}
	aHead := with(a, func() history.Head { return a.log.Head(a.id.ID) })
	if bHead := with(b, func() history.Head { return b.log.Head(a.id.ID) }); bHead.Seq >= aHead.Seq {
		t.Fatalf("before healing B already holds A's chain to %d of %d", bHead.Seq, aHead.Seq)
	}
	streams := len(g.nets[1].streams)
	g.split([]int{0}, []int{1}, false)
	g.run(15 * sec)
	if got := with(b, func() history.Head { return b.log.Head(a.id.ID) }); got != with(a, func() history.Head { return a.log.Head(a.id.ID) }) {
		t.Fatalf("B holds A's chain to %d, A is at %d", got.Seq, aHead.Seq)
	}
	if with(a, func() ids.Hash { return a.log.Digest() }) != with(b, func() ids.Hash { return b.log.Digest() }) {
		t.Fatal("digests still differ after catch-up")
	}
	if !slices.Contains(g.nets[1].streams[streams:], g.addrs[0]) {
		t.Fatal("B did not fetch over Stream from A")
	}
	if countType(ownTypes(a), events.InternetLost) != 1 {
		t.Fatal("A's own chain does not hold its event once")
	}
}

// TestEpochRotatesAfter30Days: the acting admin rotates when the key's 30
// days are over, every member installs the new key, and the old one stops
// working 60 s after each switch.
func TestEpochRotatesAfter30Days(t *testing.T) {
	g := newGroup(t, setup{n: 3, admins: 2})
	g.run(15 * sec)
	// The clock reaches NotAfter - 20 s; ten seconds later nothing has
	// rotated yet.
	g.clk.advance(epoch.RotationPeriod - 15*sec - 20*sec)
	g.run(10 * sec)
	for i, n := range g.nodes {
		if id := with(n, func() uint32 { return n.current().ID }); id != g.key.ID {
			t.Fatalf("r%02d rotated before NotAfter: %d", i+1, id)
		}
	}
	g.run(15 * sec)
	want := uint32(2<<2 | 0)
	for i, n := range g.nodes {
		if id := with(n, func() uint32 { return n.current().ID }); id != want {
			t.Fatalf("r%02d is on epoch %d, want %d", i+1, id, want)
		}
		if _, ok := n.ring.Lookup(g.key.ID); !ok {
			t.Fatalf("r%02d no longer accepts the old epoch within the overlap", i+1)
		}
	}
	g.run(epoch.Overlap)
	for i, n := range g.nodes {
		if _, ok := n.ring.Lookup(g.key.ID); ok {
			t.Fatalf("r%02d still accepts the old epoch after the overlap", i+1)
		}
	}
	g.run(30 * sec)
	for _, n := range g.nodes {
		for _, m := range n.Status().Members {
			if m.State != "up" {
				t.Fatalf("after the rotation %s is %s", m.Name, m.State)
			}
		}
	}
}

// TestUnderFloodRaised: a burst of AEAD failures raises one UnderFlood,
// and authenticated heartbeats from the same source address still count.
func TestUnderFloodRaised(t *testing.T) {
	g := newGroup(t, setup{n: 2})
	a := g.nodes[0]
	g.run(10 * sec)
	garbage := func() {
		for i := 0; i < 2*floodBurst; i++ {
			p := sealPlain(t, g.key, []byte("not a packet"))
			p[len(p)-1] ^= 1
			a.HandlePacket(g.addrs[1], p)
		}
	}
	accepted := with(a, func() uint64 { return a.table.Counters().Accepted })
	garbage()
	g.run(6 * sec)
	garbage()
	g.run(6 * sec)
	if n := countType(ownTypes(a), events.UnderFlood); n != 1 {
		t.Fatalf("%d UnderFlood events, want 1", n)
	}
	if with(a, func() uint64 { return a.table.Counters().Accepted }) <= accepted {
		t.Fatal("B's heartbeats from the flooded address no longer count")
	}
	if s := a.Status(); s.Members[1].State != "up" {
		t.Fatalf("B is %s during the flood", s.Members[1].State)
	}
}

// TestNoAutomaticExpulsion: a fork proof marks the member suspicious and
// raises an alarm; the roster is unchanged.
func TestNoAutomaticExpulsion(t *testing.T) {
	g := newGroup(t, setup{n: 3, running: []bool{true, true, false}, senders: map[int]int{0: 1}})
	a, b := g.nodes[0], g.nodes[1]
	c := g.ids[2]
	g.run(10 * sec)
	e1, err := NewBoot(c, history.Head{}, BootBody{Boot: Boot{ID: bootN(2, 1), Seq: 1}, Version: "24.10.4"})
	if err != nil {
		t.Fatal(err)
	}
	e2, err := NewBoot(c, history.Head{}, BootBody{Boot: Boot{ID: bootN(2, 1), Seq: 1}, Version: "24.10.5"})
	if err != nil {
		t.Fatal(err)
	}
	with(a, func() bool { return a.appendLocked(e1, a.stamp()) })
	with(b, func() bool { return b.appendLocked(e2, b.stamp()) })
	g.run(60 * sec)
	for _, n := range []*Node{a, b} {
		if len(with(n, func() []history.ForkProof { return n.log.Forks() })) != 1 {
			t.Fatal("the fork was not proven")
		}
		s := n.Status()
		if s.Version != 1 || len(s.Members) != 3 || s.Members[2].State != "suspicious" {
			t.Fatalf("after the fork: roster version %d, %d members, r03 %s; want 1, 3, suspicious", s.Version, len(s.Members), s.Members[2].State)
		}
		if countType(ownTypes(n), events.Fork) != 1 {
			t.Fatal("no alarm in the own chain")
		}
	}
	t.Logf("chat:\n%s", strings.Join(g.chat.all(), "\n"))
	if len(g.chat.messages("r03 showed different histories")) != 1 {
		t.Fatalf("the alarm did not reach the chat once:\n%s", strings.Join(g.chat.all(), "\n"))
	}
}

// TestPingCadence: a member with the sender role checks the channel every
// 30 s and does nothing else with it while nothing happens.
func TestPingCadence(t *testing.T) {
	g := newGroup(t, setup{n: 2, senders: map[int]int{0: 1}})
	g.run(5 * time.Minute)
	pings := g.chat.pings["r01"]
	if len(pings) != 10 {
		t.Fatalf("%d pings in 5 min of ticks, want 10", len(pings))
	}
	for i := 1; i < len(pings); i++ {
		if d := pings[i] - pings[i-1]; d != pingEvery {
			t.Fatalf("pings %d and %d are %v apart, want %v", i-1, i, d, pingEvery)
		}
	}
	if len(g.chat.pings["r02"]) != 0 {
		t.Fatal("a member without the sender role pinged")
	}
	if m := g.chat.all(); len(m) != 0 {
		t.Fatalf("messages without an incident: %q", m)
	}
}

// TestDroppedBranchAnnounced: after a split in which both sides changed the
// roster, every member adopts the branch its primary started (even though
// that branch's tip is signed by a member made backup on it), and the chat
// gets exactly one message listing the undone changes with their signers.
func TestDroppedBranchAnnounced(t *testing.T) {
	g := newGroup(t, setup{n: 4, admins: 2, senders: map[int]int{0: 2, 3: 1}})
	g.run(15 * sec)
	g.split([]int{0, 2}, []int{1, 3}, true)
	g.run(40 * sec)
	// The primary's side: r03 becomes the backup, then signs a change itself.
	if err := g.nodes[0].Publish(func(r *roster.Roster) error {
		r.Admins = []ids.MemberID{g.ids[0].ID, g.ids[2].ID}
		r.Members[1].Roles = slices.DeleteFunc(r.Members[1].Roles, func(x roster.Role) bool { return x == roster.RoleBackup })
		r.Members[2].Roles = append(r.Members[2].Roles, roster.RoleBackup)
		return nil
	}); err != nil {
		t.Fatalf("primary's change: %v", err)
	}
	g.run(10 * sec)
	if err := g.nodes[2].Publish(func(r *roster.Roster) error {
		r.Members[2].Roles = append(r.Members[2].Roles, roster.RoleSender)
		return nil
	}); err != nil {
		t.Fatalf("new backup's change: %v", err)
	}
	// The backup's side: it gives itself the sender role.
	if err := g.nodes[1].Publish(func(r *roster.Roster) error {
		r.Members[1].Roles = append(r.Members[1].Roles, roster.RoleSender)
		return nil
	}); err != nil {
		t.Fatalf("backup's change: %v", err)
	}
	g.run(10 * sec)
	tip := with(g.nodes[2], func() ids.Hash { return g.nodes[2].curHash })
	g.split([]int{0, 2}, []int{1, 3}, false)
	g.run(90 * sec)
	for i, n := range g.nodes {
		if h := with(n, func() ids.Hash { return n.curHash }); h != tip {
			t.Fatalf("r%02d holds roster %s, want the primary's branch %s", i+1, h, tip)
		}
	}
	t.Logf("chat:\n%s", strings.Join(g.chat.all(), "\n"))
	undone := g.chat.messages("these changes were undone")
	if len(undone) != 1 || !strings.Contains(undone[0], "r02 roles changed (by r02)") {
		t.Fatalf("undone announcements: %q; want one naming r02's change by r02. Chat:\n%s", undone, strings.Join(g.chat.all(), "\n"))
	}
}

// TestOwnChainCaughtUpFirst: a router restarted from a store that lost its
// last entries takes them back from its peers before it writes, so it does
// not fork its own chain.
func TestOwnChainCaughtUpFirst(t *testing.T) {
	g := newGroup(t, setup{n: 2})
	a := g.nodes[0]
	g.run(5 * sec)
	a.LocalEvent(events.Event{Type: events.WanDown})
	g.run(5 * sec)
	a.LocalEvent(events.Event{Type: events.WanUp})
	g.run(10 * sec)
	held := with(g.nodes[1], func() history.Head { return g.nodes[1].log.Head(g.ids[0].ID) })
	stored := len(readStored(t, g.stores[0], g.ids[0].ID))
	if uint64(stored) >= held.Seq {
		t.Fatalf("the store holds %d entries, the peer %d: nothing was lost", stored, held.Seq)
	}
	// A power cut: the last entries are lost with the RAM.
	g.stop(0)
	g.cfgs[0].Boot, g.cfgs[0].BootSeq = bootN(0, 2), 2
	a = g.start(0)
	if with(a, func() uint64 { return a.log.Head(a.id.ID).Seq }) != uint64(stored) {
		t.Fatal("the restart did not start from the store")
	}
	g.run(20 * sec)
	if fs := with(g.nodes[1], func() []history.ForkProof { return g.nodes[1].log.Forks() }); len(fs) != 0 {
		t.Fatalf("the restarted router forked its own chain at seq %d", fs[0].A.Seq)
	}
	boot := with(a, func() BootBody { return a.rec.boot })
	if boot.Boot.Seq != 2 {
		t.Fatalf("boot record of this boot not written: %+v", boot)
	}
	var at uint64
	with(a, func() any {
		for _, e := range a.log.Range(a.id.ID, 1, a.log.Head(a.id.ID).Seq) {
			if b, err := DecodeBoot(e); err == nil && b.Boot.Seq == 2 {
				at = e.Seq
			}
		}
		return nil
	})
	if at <= held.Seq {
		t.Fatalf("the new boot record is at seq %d, at or below the %d the peer held", at, held.Seq)
	}
}

func readStored(t testing.TB, st *store.Store, o ids.MemberID) []history.Entry {
	b, err := st.ReadFile(filePrefix + o.String() + ".json")
	if err != nil {
		return nil
	}
	var es []history.Entry
	if err := json.Unmarshal(b, &es); err != nil {
		t.Fatal(err)
	}
	return es
}

// TestViewsUniqueIDs: the election gets every roster member once.
func TestViewsUniqueIDs(t *testing.T) {
	g := newGroup(t, setup{n: 4, senders: map[int]int{0: 1, 2: 1}})
	g.run(20 * sec)
	for _, n := range g.nodes {
		vs := with(n, func() []roster.Member { return n.cur().Members })
		views := with(n, func() []ids.MemberID {
			var out []ids.MemberID
			for _, v := range n.views() {
				out = append(out, v.ID)
			}
			return out
		})
		seen := map[ids.MemberID]bool{}
		for _, id := range views {
			if seen[id] {
				t.Fatalf("view lists %s twice", id)
			}
			seen[id] = true
		}
		if len(views) != len(vs) {
			t.Fatalf("%d views for %d members", len(views), len(vs))
		}
	}
}

// TestStatusShape: the report has the fields of STATUS-JSON.md and never
// the token.
func TestStatusShape(t *testing.T) {
	g := newGroup(t, setup{n: 2, senders: map[int]int{0: 1}})
	g.run(40 * sec)
	b, err := json.Marshal(g.nodes[0].Status())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte(canary)) {
		t.Fatal("the token is in the status")
	}
	var m map[string]any
	json.Unmarshal(b, &m)
	for _, k := range []string{"schema", "running", "initialised", "generated", "site", "self", "members", "sender",
		"discovery", "storage", "telegram", "group_key", "backup_warning"} {
		if _, ok := m[k]; !ok {
			t.Errorf("status has no %q: %s", k, b)
		}
	}
	if m["schema"] != float64(1) || m["sender"] != "r01" {
		t.Errorf("schema %v sender %v: %s", m["schema"], m["sender"], b)
	}
	if tg := m["telegram"].(map[string]any); tg["state"] != "ok" {
		t.Errorf("telegram %v", tg)
	}
}

// TestBootSeqRestoredBeforeFirstHeartbeat: a router restored from an older
// backup starts below the boot sequence number its peers remember; it asks
// them before its first heartbeat and continues above it, so it is not
// locked out (security spec 5.3).
func TestBootSeqRestoredBeforeFirstHeartbeat(t *testing.T) {
	g := newGroup(t, setup{n: 2, running: []bool{false, true}})
	dir := t.TempDir() + "/id"
	for i := 0; i < 3; i++ {
		if _, err := identity.NextBootSeq(dir); err != nil {
			t.Fatal(err)
		}
	}
	g.cfgs[0].IdentityDir, g.cfgs[0].BootSeq, g.cfgs[0].Boot = dir, 3, bootN(0, 3)
	g.start(0)
	g.run(20 * sec)
	b := g.nodes[1]
	heardSeq := func() uint64 {
		return with(b, func() uint64 {
			if p := b.peers[g.ids[0].ID]; p != nil && p.heard {
				return p.hb.BootSeq
			}
			return 0
		})
	}
	if heardSeq() != 3 {
		t.Fatalf("B heard boot %d of A, want 3", heardSeq())
	}
	// A power cut, and the identity directory comes back from a backup
	// made when the stored number was 1.
	g.stop(0)
	old := t.TempDir() + "/id"
	identity.NextBootSeq(old)
	seq, _ := identity.NextBootSeq(old)
	g.cfgs[0].IdentityDir, g.cfgs[0].BootSeq, g.cfgs[0].Boot = old, seq, bootN(0, 4)
	a := g.start(0)
	g.run(20 * sec)
	if got := heardSeq(); got != 4 {
		t.Fatalf("B hears A in boot %d, want 4 (above the 3 it remembered)", got)
	}
	if got := with(a, func() uint64 { return a.table.BootSeq() }); got != 4 {
		t.Fatalf("A sends with boot %d, want 4", got)
	}
	if boot := with(a, func() BootBody { return a.rec.boot }); boot.Boot.Seq != 4 {
		t.Fatalf("A's boot record names boot %d, want 4", boot.Boot.Seq)
	}
}
