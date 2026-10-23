package node

import (
	"slices"
	"testing"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/roster"
)

// TestRecoveryRemovalOnMemberRotates (A1): the recovery key removes a
// member, signed on an ordinary member that cannot rotate itself. The
// acting admin, whose key no longer fits the roster without that member,
// rotates when it takes the roster, and the removed member does not hold
// the key the group ends on.
func TestRecoveryRemovalOnMemberRotates(t *testing.T) {
	g := newGroup(t, setup{n: 4, admins: 2})
	g.run(15 * sec)
	removed := heldSecrets(g.nodes[3])
	gone := g.ids[3].ID
	_ = g.nodes[2].PublishRecovery(func(r *roster.Roster) error {
		r.Members = slices.DeleteFunc(r.Members, func(m roster.Member) bool { return m.ID == gone })
		return nil
	}, g.rec)
	g.run(30 * sec)
	for i := 0; i < 3; i++ {
		if r := rosterOfNode(g.nodes[i]); len(r.Members) != 3 {
			t.Fatalf("r%02d did not take the recovery roster: the case did not happen", i+1)
		}
	}
	onKeyOf(t, g, []int{0, 1, 2}, removed, "the removed r04")
	sameKey(t, g, []int{0, 1, 2})
}

// TestMemberBackAfterOverlapGetsKey (A1): a member cut off for longer than
// the overlap, while the primary removed another member and rotated,
// takes the new key when it is back: the delivery is sealed under the key
// it last spoke, and its acknowledgement of each part is read under that
// key too, though the primary's Ring no longer takes it; the roster the
// key is bound to it fetches with that key.
func TestMemberBackAfterOverlapGetsKey(t *testing.T) {
	g := newGroup(t, setup{n: 4})
	g.run(15 * sec)
	g.split([]int{2}, []int{0, 1, 3}, true)
	g.run(5 * sec)
	if err := g.nodes[0].Remove(g.ids[3].ID); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	removed := heldSecrets(g.nodes[3])
	g.run(2 * time.Minute)
	g.split([]int{2}, []int{0, 1, 3}, false)
	g.run(time.Minute)
	if r := rosterOfNode(g.nodes[2]); len(r.Members) != 3 {
		t.Errorf("r03 did not take the roster without r04: %d members", len(r.Members))
	}
	onKeyOf(t, g, []int{0, 1, 2}, removed, "the removed r04")
	sameKey(t, g, []int{0, 1, 2})
	for _, m := range g.nodes[0].Status().Members {
		if m.Name == "r03" && m.State != "up" {
			t.Fatalf("r01 sees r03 %s after it came back", m.State)
		}
	}
}
