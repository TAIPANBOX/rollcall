package node

import (
	"bytes"
	"testing"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/epoch"
	"github.com/TAIPANBOX/rollcall/internal/roster"
)

// heldSecrets returns copies of the epoch secrets node n holds.
func heldSecrets(n *Node) [][]byte {
	return with(n, func() [][]byte {
		var out [][]byte
		for _, k := range n.keys {
			out = append(out, bytes.Clone(k.Secret))
		}
		return out
	})
}

// currentKey returns a copy of node n's current epoch key.
func currentKey(n *Node) epoch.Key {
	return with(n, func() epoch.Key {
		k := n.current()
		k.Secret = bytes.Clone(k.Secret)
		return k
	})
}

// onKeyOf fails the test for every node of idx whose current key is one of
// the secrets in held, which the router who must not read the group holds.
func onKeyOf(t *testing.T, g *group, idx []int, held [][]byte, who string) {
	t.Helper()
	for _, i := range idx {
		k := currentKey(g.nodes[i])
		for _, s := range held {
			if bytes.Equal(k.Secret, s) {
				t.Errorf("r%02d is on epoch %d, a key %s holds", i+1, k.ID, who)
			}
		}
	}
}

// sameKey fails the test unless the nodes of idx are on one key.
func sameKey(t *testing.T, g *group, idx []int) {
	t.Helper()
	first := currentKey(g.nodes[idx[0]])
	for _, i := range idx[1:] {
		if k := currentKey(g.nodes[i]); !bytes.Equal(k.Secret, first.Secret) {
			t.Errorf("r%02d is on epoch %d, r%02d on %d: the group is not on one key", i+1, k.ID, idx[0]+1, first.ID)
		}
	}
}

// TestNearCapKeyThenRemoval (A1, attack a): a compromised backup installs
// a key at the highest sequence number its rotation still allows, and the
// owner then removes it on the primary. The primary rotates at once, and
// the remaining members end on a fresh key the removed backup does not
// hold: the sequence it exhausted belongs to the roster it was removed
// from.
func TestNearCapKeyThenRemoval(t *testing.T) {
	g := newGroup(t, setup{n: 4, admins: 2})
	g.run(15 * sec)
	b := g.nodes[1]
	capRotate(t, b)
	g.run(15 * sec)
	sameKey(t, g, []int{0, 1, 2, 3})
	if err := g.nodes[0].Rotate(); err == nil {
		t.Error("the primary rotated past the last sequence number of the roster version")
	}
	removed := heldSecrets(b)
	if err := g.nodes[0].Remove(g.ids[1].ID); err != nil {
		t.Errorf("Remove of the backup: %v", err)
	}
	g.run(30 * sec)
	onKeyOf(t, g, []int{0, 2, 3}, removed, "the removed backup")
	sameKey(t, g, []int{0, 2, 3})
}

// TestSplitRemovalOutranksBackupKey (A1, attack b): the group splits, the
// primary removes M on its side and rotates, the backup rotates on the
// other side and delivers its key to M. Once the split heals within the
// overlap, every member of the primary's roster ends on the primary's key,
// which M never held: the backup's key is bound to the roster before the
// removal and is refused, whatever its order.
func TestSplitRemovalOutranksBackupKey(t *testing.T) {
	g := newGroup(t, setup{n: 4, admins: 2})
	g.run(15 * sec)
	g.split([]int{0, 2}, []int{1, 3}, true)
	g.run(5 * sec)
	if err := g.nodes[0].Remove(g.ids[3].ID); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	g.run(2 * sec)
	if err := g.nodes[1].Rotate(); err != nil {
		t.Fatalf("the backup's rotation: %v", err)
	}
	g.run(5 * sec)
	m := heldSecrets(g.nodes[3])
	g.split([]int{0, 2}, []int{1, 3}, false)
	g.run(2 * time.Minute)
	onKeyOf(t, g, []int{0, 1, 2}, m, "the removed M")
	sameKey(t, g, []int{0, 1, 2})
	if r := rosterOfNode(g.nodes[1]); len(r.Members) != 3 {
		t.Errorf("the backup did not take the roster without M: %d members", len(r.Members))
	}
	// No admin goes on delivering a key that no longer fits its roster.
	for _, i := range []int{0, 1} {
		n := g.nodes[i]
		with(n, func() any {
			for id, d := range n.deliveries {
				if !n.fits(d.key.Roster) {
					t.Errorf("r%02d still delivers epoch %d, bound to roster %d, to %s", i+1, d.key.ID, d.key.Roster.Version, id)
				}
			}
			return nil
		})
	}
}

// TestKeyBoundToAnotherRosterRefused (A1): during a split the backup
// changes the roster on its side, once and then twice, and rotates under
// its own roster; the primary removes M on the other side. After the heal
// the primary's branch wins, and no member of it takes the backup's keys,
// bound to a roster of the same version that lost, or to a later version
// of the losing branch; the backup itself moves to the primary's roster
// and key.
func TestKeyBoundToAnotherRosterRefused(t *testing.T) {
	for _, changes := range []int{1, 2} {
		g := newGroup(t, setup{n: 4, admins: 2})
		g.run(15 * sec)
		g.split([]int{0, 2}, []int{1, 3}, true)
		g.run(5 * sec)
		if err := g.nodes[0].Remove(g.ids[3].ID); err != nil {
			t.Fatalf("Remove: %v", err)
		}
		b := g.nodes[1]
		for c := 0; c < changes; c++ {
			if err := b.Publish(func(r *roster.Roster) error {
				r.Members[3].Roles = append(r.Members[3].Roles[:0:0], roster.RoleSender)
				if c > 0 {
					r.Members[2].Roles = append(r.Members[2].Roles[:0:0], roster.RoleSender)
				}
				return nil
			}); err != nil {
				t.Fatalf("the backup's roster change %d: %v", c+1, err)
			}
		}
		if currentKey(b).ID == g.key.ID {
			// A roster change that rotates nothing: the backup rotates
			// under it.
			if err := b.Rotate(); err != nil {
				t.Fatalf("the backup's rotation: %v", err)
			}
		}
		g.run(5 * sec)
		backup := heldSecrets(b)[len(heldSecrets(b))-1:]
		g.split([]int{0, 2}, []int{1, 3}, false)
		g.run(2 * time.Minute)
		// The backup rotated once during the split, so it still reads the
		// primary's delivery, sealed under the key before the split, and
		// moves to the primary's key with the primary's roster.
		onKeyOf(t, g, []int{0, 1, 2}, backup, "the backup's losing branch")
		sameKey(t, g, []int{0, 1, 2})
		for _, i := range []int{1, 2} {
			if r := rosterOfNode(g.nodes[i]); len(r.Members) != 3 {
				t.Errorf("%d changes: r%02d is not on the primary's roster: %d members", changes, i+1, len(r.Members))
			}
		}
	}
}

// TestOverlapAfterBoundRotation (A1): after a rotation the previous key
// is still accepted for epoch.Overlap and refused after.
func TestOverlapAfterBoundRotation(t *testing.T) {
	g := newGroup(t, setup{n: 3, running: []bool{true, true, false}})
	g.run(15 * sec)
	a := g.nodes[0]
	if err := a.Rotate(); err != nil {
		t.Fatal(err)
	}
	g.run(30 * sec)
	beat := func(counter uint64) uint64 {
		before := with(a, func() uint64 { return a.counters.Epoch })
		a.HandlePacket(g.addrs[2], sealPlain(t, g.key, heartbeatPlain(t, g.key, g.ids[2], "r03", bootN(2, 1), counter)))
		return with(a, func() uint64 { return a.counters.Epoch }) - before
	}
	if beat(1) != 0 {
		t.Fatal("30 s after the rotation a packet under the previous key failed at the epoch step")
	}
	g.run(31 * sec)
	if beat(2) != 1 {
		t.Fatal("61 s after the rotation a packet under the previous key did not fail at the epoch step")
	}
}
