package node

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/clock"
	"github.com/TAIPANBOX/rollcall/internal/deliver"
	"github.com/TAIPANBOX/rollcall/internal/events"
)

// TestQueueOverflowTold (Q1): when more incidents wait than the queue holds,
// the chat is told, with the site's name, before the incidents themselves,
// and the status keeps the count of those dropped.
func TestQueueOverflowTold(t *testing.T) {
	g := newGroup(t, setup{n: 1, senders: map[int]int{0: 1}})
	a := g.nodes[0]
	g.run(40 * sec)
	g.chat.setDown(true)
	with(a, func() any {
		now := a.stamp()
		for i := 1; i <= deliver.MaxQueued+2; i++ {
			at := clock.Stamp{Wall: now.Wall.Add(time.Duration(i) * time.Millisecond), Trusted: true}
			a.queue.Add(events.Incident{ID: fmt.Sprintf("%016x", i), Start: at, End: at, Events: []events.Type{events.UplinkSwitched}}, now.Wall)
		}
		return nil
	})
	g.chat.setDown(false)
	g.run(40 * sec)
	ms := g.chat.all()
	if len(ms) == 0 || !strings.HasPrefix(ms[0], "Home: incidents were dropped: more than 1000 were waiting to be sent.") {
		t.Fatalf("the first message is %q, want the notice that incidents were dropped", ms[:min(len(ms), 2)])
	}
	if n := len(g.chat.messages("incidents were dropped")); n != 1 {
		t.Fatalf("%d notices, want 1", n)
	}
	if d := a.Status().Dropped; d != 2 {
		t.Fatalf("Status.Dropped = %d, want 2", d)
	}
}
