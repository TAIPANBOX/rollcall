package node

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/TAIPANBOX/rollcall/internal/epoch"
	"github.com/TAIPANBOX/rollcall/internal/identity"
	"github.com/TAIPANBOX/rollcall/internal/ids"
	"github.com/TAIPANBOX/rollcall/internal/roster"
	"github.com/TAIPANBOX/rollcall/internal/store"
)

// boundKey returns a fresh key bound to b with sequence number seq and
// authority a, its ID the one IDOf gives.
func boundKey(b epoch.Binding, seq uint16, a uint8) epoch.Key {
	secret := make([]byte, epoch.SecretSize)
	rand.Read(secret)
	return epoch.Key{ID: epoch.IDOf(b, seq, a), Secret: secret, NotAfter: tStart.Add(epoch.RotationPeriod), Roster: b, Seq: seq, Authority: a}
}

// handDeliver seals k to n, signed by from, and hands it to n in its two
// parts, as serveEpoch does; it returns n's answer to the last part.
func handDeliver(t testing.TB, n *Node, from *identity.Identity, k epoch.Key) (epochAck, bool) {
	t.Helper()
	blob, err := epoch.Seal(k, n.id.Recv.PublicKey(), n.id.ID, from.ID, from.Sign)
	if err != nil {
		t.Fatal(err)
	}
	half := (len(blob) + 1) / deliveryParts
	type answer struct {
		ack epochAck
		ok  bool
	}
	a := with(n, func() answer {
		now := n.stamp()
		if ack, ok := n.partIn(from.ID, 0, k.ID, blob[:half], now); !ok || ack != ackPart {
			t.Fatalf("first part: %v %v, want ackPart", ack, ok)
		}
		ack, ok := n.partIn(from.ID, 1, k.ID, blob[half:], now)
		return answer{ack, ok}
	})
	return a.ack, a.ok
}

// TestDeliveredKeyChecks (A1): a member takes a delivered key only when it
// fits its roster, the admin who signed it holds the place the key
// carries, and its ID is the one its binding gives; of two keys bound to
// its roster it keeps the newer; a key bound to a roster it does not hold
// waits, pending, and one bound to a roster that lost a member since is
// refused.
func TestDeliveredKeyChecks(t *testing.T) {
	g := newGroup(t, setup{n: 4, admins: 2, running: []bool{true, true, true, false}})
	g.run(15 * sec)
	p, b, m := g.ids[0], g.ids[1], g.nodes[2]
	head := with(m, func() epoch.Binding { return m.binding() })
	cur := func() epoch.Key { return currentKey(m) }

	k2 := boundKey(head, 2, 1)
	if ack, ok := handDeliver(t, m, b, k2); !ok || ack != ackInstalled || cur().ID != k2.ID {
		t.Fatalf("the backup's key at sequence 2: %v %v, current %d; want installed", ack, ok, cur().ID)
	}
	if ack, ok := handDeliver(t, m, b, boundKey(head, 1, 1)); !ok || ack != ackHeld || cur().ID != k2.ID {
		t.Fatalf("an older key bound to the roster: %v %v; want held, the current key kept", ack, ok)
	}
	if _, ok := handDeliver(t, m, b, boundKey(head, 3, 0)); ok || cur().ID != k2.ID {
		t.Fatal("a key that claims the primary's place, signed by the backup, was taken")
	}
	wrongID := boundKey(head, 3, 1)
	wrongID.ID ^= 0x10
	if _, ok := handDeliver(t, m, b, wrongID); ok || cur().ID != k2.ID {
		t.Fatal("a key whose ID is not its binding's was taken")
	}
	k3 := boundKey(head, 2, 0)
	if ack, ok := handDeliver(t, m, p, k3); !ok || ack != ackInstalled || cur().ID != k3.ID {
		t.Fatalf("the primary's key at the backup's sequence: %v %v; want installed, the primary's before the backup's", ack, ok)
	}

	var other ids.Hash
	rand.Read(other[:])
	ahead := boundKey(epoch.Binding{Version: head.Version + 1, Hash: other}, 1, 0)
	if _, ok := handDeliver(t, m, p, ahead); ok || cur().ID != k3.ID {
		t.Fatal("a key bound to a roster the member does not hold was taken")
	}
	if !with(m, func() bool { _, ok := m.pending[p.ID]; return ok }) {
		t.Fatal("the key bound to a roster the member does not hold is not kept pending")
	}
	if _, ok := m.ring.Lookup(ahead.ID); ok {
		t.Fatal("the Ring accepts a pending key")
	}
	// A key bound to the next roster, which the member takes as soon as it
	// takes that roster, without waiting for the delivery again.
	next, err := roster.SignRoster(func() roster.Roster {
		r := cloneRoster(rosterOfNode(m))
		r.Version, r.Prev = head.Version+1, head.Hash
		r.Members[2].Roles = append(r.Members[2].Roles, roster.RoleSender)
		return r
	}(), p.ID, p.Sign, false)
	if err != nil {
		t.Fatal(err)
	}
	k4 := boundKey(epoch.Binding{Version: head.Version + 1, Hash: next.Hash()}, 1, 0)
	if _, ok := handDeliver(t, m, p, k4); ok || cur().ID != k3.ID {
		t.Fatal("a key bound to the next roster was taken before that roster")
	}
	if !with(m, func() bool {
		return m.extendLocked(len(m.chain)-1, []roster.Signed{next}, nil, m.stamp())
	}) {
		t.Fatal("r03 did not take the next roster")
	}
	if cur().ID != k4.ID {
		t.Fatal("the pending key bound to the roster just taken was not installed with it")
	}

	// In a group where the primary removes r04, keys bound to the roster
	// before no longer fit.
	g = newGroup(t, setup{n: 4, admins: 2, running: []bool{true, true, true, false}})
	g.run(15 * sec)
	p, m = g.ids[0], g.nodes[2]
	head = with(m, func() epoch.Binding { return m.binding() })
	if err := g.nodes[0].Remove(g.ids[3].ID); err != nil {
		t.Fatal(err)
	}
	g.run(15 * sec)
	if got := currentKey(m).Roster; got.Version != head.Version+1 {
		t.Fatalf("r03 is on a key bound to version %d after the removal, want %d", got.Version, head.Version+1)
	}
	if ack, ok := handDeliver(t, m, p, boundKey(head, 5, 0)); !ok || ack != ackHeld || currentKey(m).Roster.Version != head.Version+1 {
		t.Fatalf("a key bound to the roster before the removal: %v %v; want refused as held", ack, ok)
	}
}

// TestStoredKeysCarryBinding (A1): the stored key file is format 2 and
// binds every key to its roster; a file without the binding is refused and
// the router stops, and Bootstrap binds an unbound key to its roster and
// refuses one bound to another.
func TestStoredKeysCarryBinding(t *testing.T) {
	g := newGroup(t, setup{n: 2, running: []bool{false, false}})
	b, err := g.stores[0].ReadFile(FileEpoch)
	if err != nil {
		t.Fatal(err)
	}
	var f epochFile
	if err := json.Unmarshal(b, &f); err != nil || f.Format != 2 || len(f.Keys) != 1 {
		t.Fatalf("stored key file: %s", b)
	}
	if k := f.Keys[0]; k.RosterVersion != 1 || k.RosterHash != g.first.Hash() || k.Seq != 1 || k.Authority != 0 {
		t.Fatalf("the bootstrap key is bound to version %d, seq %d, authority %d; want the first roster, 1, 0", k.RosterVersion, k.Seq, k.Authority)
	}

	// A file of the format before the binding: the router does not start.
	old := []byte(`{"keys":[{"id":4,"secret":"` + "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=" + `","not_after":"2026-11-22T09:00:00Z"}],"removed":false}`)
	if err := g.stores[1].WriteFileAtomic(FileEpoch, old); err != nil {
		t.Fatal(err)
	}
	if _, err := New(g.cfgs[1], g.stores[1], g.ids[1], &fakeNet{}, g.clk, nil); !errors.Is(err, ErrState) || !strings.Contains(err.Error(), "format 0, want 2") {
		t.Fatalf("New with a key file without bindings: %v, want ErrState naming the format", err)
	}

	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	wrong := g.key
	wrong.Secret = bytes.Clone(g.key.Secret)
	wrong.Roster, wrong.Seq = epoch.Binding{Version: 2, Hash: g.first.Hash()}, 1
	if err := Bootstrap(st, g.first, wrong); !errors.Is(err, ErrArgument) {
		t.Fatalf("Bootstrap with a key bound to another roster: %v, want ErrArgument", err)
	}
}
