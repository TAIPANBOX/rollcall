package node

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/events"
	"github.com/TAIPANBOX/rollcall/internal/history"
)

// alarmIDs returns the IDs of the alarm incidents n holds, sorted.
func alarmIDs(n *Node) []string {
	return with(n, func() []string {
		var out []string
		for _, r := range n.inc.recent {
			if slices.Contains(r.inc.Events, events.Fork) {
				out = append(out, r.inc.ID)
			}
		}
		slices.Sort(out)
		return out
	})
}

// TestOneForkAlarmPerMember (D2): two routers find different fork proofs of
// one member; both raise the same alarm incident, so whichever sends it,
// the chat gets it once.
func TestOneForkAlarmPerMember(t *testing.T) {
	g := newGroup(t, setup{n: 3, running: []bool{true, true, false}, senders: map[int]int{0: 1}})
	a, b := g.nodes[0], g.nodes[1]
	c := g.ids[2]
	g.split([]int{0}, []int{1}, true)
	g.run(5 * sec)
	now := AtOf(g.clk.stampNow())
	x := forge(t, c, history.Head{}, EventBody{Subject: c.ID, Type: events.WanDown, At: now}, EventBody{Subject: c.ID, Type: events.WanUp, At: now})
	y := forge(t, c, history.Head{Seq: 1, Hash: x[0].Hash()}, EventBody{Subject: c.ID, Type: events.WanDown, At: shift(now, sec)})
	z := forge(t, c, history.Head{}, EventBody{Subject: c.ID, Type: events.UplinkSwitched, At: now})
	inject(a, x...)
	inject(a, z...) // r01's proof: seq 1
	inject(b, x[0], y[0])
	g.split([]int{0}, []int{1}, false)
	g.run(30 * sec)
	ia, ib := alarmIDs(a), alarmIDs(b)
	if len(ia) != 1 || !slices.Equal(ia, ib) {
		t.Fatalf("r01 raised alarms %v, r02 %v; want the same one alarm about r03", ia, ib)
	}
}

// TestForkedWitnessNotCounted (D2): once a member is proven to show
// different histories, its events are left out of the incidents still to
// be made: routers that saw its different faces make the same incidents.
func TestForkedWitnessNotCounted(t *testing.T) {
	g := newGroup(t, setup{n: 3, running: []bool{true, true, false}, senders: map[int]int{0: 1}})
	a := g.nodes[0]
	c := g.ids[2]
	g.run(5 * sec)
	now := AtOf(g.clk.stampNow())
	x := forge(t, c, history.Head{}, EventBody{Subject: g.ids[1].ID, Type: events.MemberSilent, At: now})
	z := forge(t, c, history.Head{}, EventBody{Subject: c.ID, Type: events.UplinkSwitched, At: now})
	inject(a, x...)
	inject(a, z...)
	g.run(time.Minute)
	t.Logf("chat:\n%s", strings.Join(g.chat.all(), "\n"))
	if m := g.chat.messages("r02 stopped answering"); len(m) != 0 {
		t.Fatalf("an event of a member proven to show different histories reached the chat: %q", m)
	}
}
