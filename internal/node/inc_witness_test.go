package node

import (
	"testing"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/events"
	"github.com/TAIPANBOX/rollcall/internal/history"
	"github.com/TAIPANBOX/rollcall/internal/identity"
	"github.com/TAIPANBOX/rollcall/internal/ids"
)

// statementsAbout counts n's own witness statements about entries of origin.
func statementsAbout(n *Node, origin ids.MemberID) int {
	return with(n, func() int {
		c := 0
		for _, e := range n.log.Range(n.id.ID, 1, n.log.Head(n.id.ID).Seq) {
			if w, err := history.DecodeWitness(e); err == nil && e.Kind == history.KindWitness {
				for _, o := range n.log.Range(origin, 1, n.log.Head(origin).Seq) {
					if o.Hash() == w.Ref {
						c++
					}
				}
			}
		}
		return c
	})
}

// eventFlood injects into n, every gap, an internet loss of origin's own, each
// an event n states a view on, count times; it returns the chain's head.
func eventFlood(t *testing.T, g *group, n *Node, origin *identity.Identity, head history.Head, count int, gap time.Duration) history.Head {
	t.Helper()
	for i := 0; i < count; i++ {
		e := forge(t, origin, head, EventBody{Subject: origin.ID, Type: events.InternetLost, At: AtOf(g.clk.stampNow())})[0]
		head = history.Head{Seq: e.Seq, Hash: e.Hash()}
		inject(n, e)
		if gap > 0 {
			g.run(gap)
		}
	}
	return head
}

// TestWitnessStatementsBounded (N4): a compromised member writes an event
// every second that the others state a view on. Each statement rewrites the
// stating router's own chain on flash, so a router states its view on at
// most witnessBurst of one origin's events at once and one more each
// witnessEvery; the rest are dropped and counted.
func TestWitnessStatementsBounded(t *testing.T) {
	g := newGroup(t, setup{n: 3, running: []bool{true, true, false}})
	a, liar := g.nodes[0], g.ids[2]
	g.run(40 * sec)
	const dur = 3 * time.Minute
	eventFlood(t, g, a, liar, history.Head{}, int(dur/sec), sec)
	made := statementsAbout(a, liar.ID)
	// The events come at 0 s to 179 s: the burst, then one at 60 s and one
	// at 120 s.
	if want := witnessBurst + 2; made != want {
		t.Fatalf("r01 stated %d views on one origin's %d events in %s, want %d", made, int(dur/sec), dur, want)
	}
	if d := a.Status().WitnessesDropped; d == 0 || int(d)+made != int(dur/sec) {
		t.Fatalf("Status.WitnessesDropped = %d with %d made of %d events, want the rest", d, made, int(dur/sec))
	}
}

// TestWitnessBurstAllowed (N4): an honest member that records many events
// at once (a whole site went silent, then came back) gets a view stated on
// each of them, up to witnessBurst, and not one more.
func TestWitnessBurstAllowed(t *testing.T) {
	g := newGroup(t, setup{n: 3, running: []bool{true, true, false}})
	a, other := g.nodes[0], g.ids[2]
	g.run(40 * sec)
	eventFlood(t, g, a, other, history.Head{}, witnessBurst+1, 0)
	if made := statementsAbout(a, other.ID); made != witnessBurst {
		t.Fatalf("r01 stated %d views on a burst of %d events, want %d: all but the one over the burst", made, witnessBurst+1, witnessBurst)
	}
}
