package node

import (
	"bytes"
	"testing"

	"github.com/TAIPANBOX/rollcall/internal/identity"
	"github.com/TAIPANBOX/rollcall/internal/roster"
)

// nextRoster signs, as id, the roster after prev (signed as prevS) that
// edit makes.
func nextRoster(t testing.TB, prev roster.Roster, prevS roster.Signed, id *identity.Identity, edit func(r *roster.Roster)) (roster.Signed, roster.Roster) {
	t.Helper()
	r := cloneRoster(prev)
	r.Version, r.Prev = prev.Version+1, prevS.Hash()
	if edit != nil {
		edit(&r)
	}
	s, err := roster.SignRoster(r, id.ID, id.Sign, false)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Verify(&prevS)
	if err != nil {
		t.Fatalf("the fixture roster %d does not verify: %v", r.Version, err)
	}
	return s, got
}

// TestPreferJudgesVersionByTheTips (A2): two branches started with the same
// authority are told apart by the version of their tips, as spec 6.1
// says. The first rosters of both are always version common+1, so a
// version taken from them never decides; the branch that went further
// wins even when its first roster has the higher hash.
func TestPreferJudgesVersionByTheTips(t *testing.T) {
	g := newGroup(t, setup{n: 3, running: []bool{false, false, false}})
	p := g.ids[0]
	common, err := g.first.Verify(nil)
	if err != nil {
		t.Fatal(err)
	}
	rename := func(site string) func(r *roster.Roster) { return func(r *roster.Roster) { r.Site = site } }

	// Two first rosters after common; the one with the lower hash is the
	// short branch's only roster, so that a choice made on the first rosters
	// alone would keep it, and the long branch grows from the other. Taking
	// the order as it falls, rather than searching for a lower hash, keeps
	// the test deterministic whatever the fixture's random keys.
	as, a := nextRoster(t, common, g.first, p, rename("first-a"))
	bs, b := nextRoster(t, common, g.first, p, rename("first-b"))
	ha, hb := as.Hash(), bs.Hash()
	if bytes.Compare(ha[:], hb[:]) > 0 {
		as, a, bs, b = bs, b, as, a
	}
	short, rShort := []roster.Signed{as}, []roster.Roster{a}
	x2s, x2 := nextRoster(t, b, bs, p, rename("long-2"))
	x3s, x3 := nextRoster(t, x2, x2s, p, rename("long-3"))
	long := []roster.Signed{bs, x2s, x3s}
	rLong := []roster.Roster{b, x2, x3}

	if !preferTheirs(long, short, rLong, rShort, common) {
		t.Error("theirs at version 4 lost to ours at version 2, both started by the primary")
	}
	if preferTheirs(short, long, rShort, rLong, common) {
		t.Error("theirs at version 2 won over ours at version 4, both started by the primary")
	}
}
