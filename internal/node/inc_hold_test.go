package node

import (
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/events"
	"github.com/TAIPANBOX/rollcall/internal/history"
)

// TestEndFloodHoldsOneIncidentBriefly (N2): a member goes down, and a
// compromised member writes a return of it every few seconds, each one that
// will never join the silence. The sender holds that silence back for a
// bounded time only, and never holds anything else: another router's
// internet loss, queued meanwhile, goes out at once, and the silence after
// it, while the flood still goes on. The loss is recorded 20 s after the
// cut, so that, waiting the 30 s of a link change, it is queued while the
// silence is held.
func TestEndFloodHoldsOneIncidentBriefly(t *testing.T) {
	g := newGroup(t, setup{n: 4, running: []bool{true, true, true, false}, senders: map[int]int{0: 1}})
	w, x, liar := g.nodes[0], g.ids[1].ID, g.ids[3]
	g.run(40 * sec)
	g.stop(1)
	g.run(20 * sec)
	g.nodes[2].LocalEvent(events.Event{Type: events.InternetLost})
	g.run(12 * sec) // the silence of r02 is recorded, not settled yet
	head := history.Head{}
	for i := 0; i < 30; i++ {
		at := AtOf(g.clk.stampNow())
		at.Wall = at.Wall.Add(-48 * time.Hour) // never joins the silence, never told itself
		e := forge(t, liar, head, EventBody{Subject: x, Type: events.MemberBack, At: at})[0]
		head = history.Head{Seq: e.Seq, Hash: e.Hash()}
		inject(w, e)
		g.run(3 * sec)
	}
	ms := g.chat.all()
	t.Logf("chat:\n%s", strings.Join(ms, "\n"))
	silence, loss := -1, -1
	for i, m := range ms {
		switch {
		case strings.Contains(m, "r02 stopped answering"):
			silence = i
		case strings.Contains(m, "internet lost") && strings.Contains(m, "Seen by r03"):
			loss = i
		}
	}
	if silence < 0 || loss < 0 {
		t.Fatalf("while the flood goes on the chat holds r02's silence at %d and r03's internet loss at %d; want both: a flood of returns held the sender", silence, loss)
	}
	if loss > silence {
		t.Fatalf("r03's internet loss went out after r02's held silence: the hold stopped every incident, not one")
	}
}
