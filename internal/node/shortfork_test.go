package node

import (
	"testing"

	"github.com/TAIPANBOX/rollcall/internal/events"
	"github.com/TAIPANBOX/rollcall/internal/history"
)

// TestForkInShorterBranchFound (D16): a router holds a longer branch of a
// member's chain than the member shows it; the member's own, shorter chain
// differs at a sequence number both hold. Comparing heads finds that: the
// router fetches the member's entry at the lower head and holds the fork
// proof.
func TestForkInShorterBranchFound(t *testing.T) {
	g := newGroup(t, setup{n: 3, running: []bool{false, true, true}})
	c := g.ids[2]
	g.run(10 * sec) // r03 writes its boot record, seq 1
	g.stop(2)
	a := g.start(0)
	g.split([]int{0}, []int{1}, true)
	var bs []EventBody
	for range 8 { // longer than r03's own chain will be
		bs = append(bs, EventBody{Subject: c.ID, Type: events.WanDown, At: AtOf(g.clk.stampNow())})
	}
	inject(a, forge(t, c, history.Head{}, bs...)...)
	g.reboot(2)
	g.run(30 * sec)
	if fs := with(a, func() []history.ForkProof { return a.log.Forks() }); len(fs) != 1 || fs[0].A.Origin != c.ID {
		t.Fatalf("r01 holds fork proofs %v; want one against r03", fs)
	}
	if st := stateOf(a.Status(), "r03"); st != "suspicious" {
		t.Fatalf("r01 sees r03 %q, want suspicious", st)
	}
}
