package node

import (
	"bytes"
	"fmt"
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

	x1s, x1 := nextRoster(t, common, g.first, p, rename("long-1"))
	x2s, x2 := nextRoster(t, x1, x1s, p, rename("long-2"))
	x3s, x3 := nextRoster(t, x2, x2s, p, rename("long-3"))
	long := []roster.Signed{x1s, x2s, x3s}
	rLong := []roster.Roster{x1, x2, x3}

	// The short branch's only roster gets the lower hash, so that a choice
	// made on the first rosters alone would keep it.
	var short []roster.Signed
	var rShort []roster.Roster
	hx := x1s.Hash()
	for k := 0; k < 64 && short == nil; k++ {
		s, r := nextRoster(t, common, g.first, p, rename(fmt.Sprintf("short-%d", k)))
		if hs := s.Hash(); bytes.Compare(hs[:], hx[:]) < 0 {
			short, rShort = []roster.Signed{s}, []roster.Roster{r}
		}
	}
	if short == nil {
		t.Fatal("no short branch with the lower hash in 64 tries")
	}

	if !preferTheirs(long, short, rLong, rShort, common) {
		t.Error("theirs at version 4 lost to ours at version 2, both started by the primary")
	}
	if preferTheirs(short, long, rShort, rLong, common) {
		t.Error("theirs at version 2 won over ours at version 4, both started by the primary")
	}
}
