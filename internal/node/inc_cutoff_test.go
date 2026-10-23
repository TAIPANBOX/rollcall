package node

import (
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/events"
	"github.com/TAIPANBOX/rollcall/internal/history"
)

// TestCutOffNeedsTheSubjectsView (N1): in a group of three, a compromised
// member records the witness silent and says nothing of the subject, which
// really went down. The witness's record of the subject's silence is the
// truth, not a cut-off router's view: the subject, down, never recorded the
// witness silent. The chat tells the outage.
func TestCutOffNeedsTheSubjectsView(t *testing.T) {
	g := newGroup(t, setup{n: 3, running: []bool{true, true, false}, senders: map[int]int{0: 1}})
	w, liar := g.nodes[0], g.ids[2]
	g.run(40 * sec)
	g.stop(1) // the subject goes down
	inject(w, forge(t, liar, history.Head{},
		EventBody{Subject: w.id.ID, Type: events.MemberSilent, Last: Boot{ID: bootN(0, 1), Seq: 1}, At: AtOf(g.clk.stampNow())})...)
	g.run(time.Minute)
	t.Logf("chat:\n%s", strings.Join(g.chat.all(), "\n"))
	if n := len(g.chat.messages("r02 stopped answering")); n != 1 {
		t.Fatalf("%d messages tell r02's silence, want 1: a third member's word dropped a true outage", n)
	}
}
