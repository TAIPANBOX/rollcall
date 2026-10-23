package node

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/epoch"
	"github.com/TAIPANBOX/rollcall/internal/identity"
	"github.com/TAIPANBOX/rollcall/internal/ids"
	"github.com/TAIPANBOX/rollcall/internal/pairing"
	"github.com/TAIPANBOX/rollcall/internal/roster"
	"github.com/TAIPANBOX/rollcall/internal/store"
)

// The fakes of this file are named apart from node_test.go's.

// secCanary is the fake bot token of this file.
const secCanary = "CANARY-456:def"

type secClock struct {
	mu   sync.Mutex
	wall time.Time
	mono time.Duration
}

func (c *secClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.wall
}

func (c *secClock) Mono() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.mono
}

func (c *secClock) step(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.wall, c.mono = c.wall.Add(d), c.mono+d
}

// secNet hands a TCP request to one node, the admin.
type secNet struct{ to *Node }

func (s *secNet) Multicast([]byte) error               { return nil }
func (s *secNet) Unicast(netip.AddrPort, []byte) error { return nil }
func (s *secNet) Stream(_ netip.AddrPort, b []byte) ([]byte, error) {
	if s.to == nil || !s.to.Authenticate(b) {
		return nil, errors.New("unreachable")
	}
	r := s.to.HandleStream(netip.MustParseAddrPort("192.0.2.9:40000"), b)
	if r == nil {
		return nil, errors.New("no answer")
	}
	return r, nil
}

type secChannel struct {
	mu    sync.Mutex
	pings int
}

func (c *secChannel) Send(context.Context, string) error { return nil }
func (c *secChannel) Ping(context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pings++
	return nil
}

func (c *secChannel) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.pings
}

// secretsNode starts a group of one whose member has the sender role when
// sender is set, configured to send, with no channel.
func secretsNode(t *testing.T, sender bool) (*Node, *store.Store, *secClock) {
	t.Helper()
	id, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	m := roster.Member{ID: id.ID, Name: "gateway", Roles: []roster.Role{roster.RolePrimary},
		SignPub: id.Sign.Public().(ed25519.PublicKey), RecvPub: id.Recv.PublicKey().Bytes()}
	if sender {
		m.Roles = append(m.Roles, roster.RoleSender)
	}
	r := roster.Roster{Version: 1, Site: "home", RecoveryPub: pub, Admins: []ids.MemberID{id.ID}, Members: []roster.Member{m}}
	signed, err := roster.SignRoster(r, id.ID, id.Sign, false)
	if err != nil {
		t.Fatal(err)
	}
	wall := time.Date(2026, 10, 23, 9, 0, 0, 0, time.UTC)
	secret := make([]byte, epoch.SecretSize)
	rand.Read(secret)
	st, err := store.Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	if err := Bootstrap(st, signed, epoch.Key{ID: 1 << 2, Secret: secret, NotAfter: wall.Add(epoch.RotationPeriod)}); err != nil {
		t.Fatal(err)
	}
	clk := &secClock{wall: wall, mono: 1000 * time.Second}
	n, err := New(Config{Site: "Home", Sender: true, BootSeq: 1, Boot: ids.BootID{1, 15: 1}}, st, id, &secNet{}, clk, nil)
	if err != nil {
		t.Fatal(err)
	}
	return n, st, clk
}

// TestSetSecrets: a running sender takes a new bot token, chat ID and
// channel without a restart: it stores them, pings the new channel at the
// next Tick, redacts the new token, and hands it to a router that joins as a
// sender. A router without the sender role, a malformed token and a stopped
// node are refused, and nothing is stored.
func TestSetSecrets(t *testing.T) {
	n, st, clk := secretsNode(t, true)
	n.Tick()
	if s := n.Status(); s.Telegram.State != "not_configured" {
		t.Fatalf("before: telegram %q", s.Telegram.State)
	}
	ch := &secChannel{}
	if err := n.SetSecrets(pairing.Secrets{BotToken: secCanary, ChatID: 42}, ch); err != nil {
		t.Fatal(err)
	}
	if b, err := st.ReadFile(FileSecrets); err != nil || !bytes.Contains(b, []byte(secCanary)) || !bytes.Contains(b, []byte("42")) {
		t.Fatalf("stored secrets %q, %v", b, err)
	}
	clk.step(time.Second)
	n.Tick()
	if ch.count() != 1 {
		t.Fatalf("%d pings of the new channel at the next Tick, want 1", ch.count())
	}
	if s := n.Status(); s.Telegram.State != "ok" {
		t.Fatalf("after: telegram %q", s.Telegram.State)
	}
	if got := n.redacted(Status{Error: "x " + secCanary}).Error; bytes.Contains([]byte(got), []byte(secCanary)) {
		t.Fatal("the new token is not redacted")
	}
	// A channel that replaces one just pinged is pinged at the next Tick
	// too, not 30 s later.
	ch2 := &secChannel{}
	if err := n.SetSecrets(pairing.Secrets{BotToken: secCanary, ChatID: 43}, ch2); err != nil {
		t.Fatal(err)
	}
	clk.step(time.Second)
	n.Tick()
	if ch2.count() != 1 {
		t.Fatalf("%d pings of the replacing channel at the next Tick, want 1", ch2.count())
	}

	// A router that joins as a sender gets the token set while running.
	code, err := n.Invite(netip.MustParseAddrPort("192.0.2.1:7432"), true)
	if err != nil {
		t.Fatal(err)
	}
	joiner, _ := identity.Generate()
	st2, _ := store.Open(filepath.Join(t.TempDir(), "joiner"))
	if err := Join(st2, &secNet{to: n}, code, joiner, "ap-office"); err != nil {
		t.Fatalf("join: %v", err)
	}
	if b, _ := st2.ReadFile(FileSecrets); !bytes.Contains(b, []byte(secCanary)) {
		t.Fatal("the new sender did not get the token set while running")
	}

	// Clearing them stores nothing secret and stops the channel.
	if err := n.SetSecrets(pairing.Secrets{}, nil); err != nil {
		t.Fatal(err)
	}
	if b, _ := st.ReadFile(FileSecrets); bytes.Contains(b, []byte(secCanary)) {
		t.Fatal("cleared secrets still stored")
	}

	if err := n.SetSecrets(pairing.Secrets{BotToken: "not a token"}, ch); !errors.Is(err, ErrArgument) {
		t.Fatalf("a malformed token: %v", err)
	}
	plain, st3, _ := secretsNode(t, false)
	if err := plain.SetSecrets(pairing.Secrets{BotToken: secCanary, ChatID: 42}, ch); !errors.Is(err, ErrNotSender) {
		t.Fatalf("a router without the sender role: %v", err)
	}
	if _, err := st3.ReadFile(FileSecrets); err == nil {
		t.Fatal("a router without the sender role stored a token")
	}
	stopped, _ := New(Config{}, st3, nil, &secNet{}, &secClock{}, nil)
	if err := stopped.SetSecrets(pairing.Secrets{BotToken: secCanary}, ch); err == nil {
		t.Fatal("a stopped node took secrets")
	}
}
