package node

import (
	"testing"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/events"
	"github.com/TAIPANBOX/rollcall/internal/history"
)

// TestOwnEntriesDurableBeforeSent (D6): an own entry is on flash before any
// peer can learn of it, so a router that loses power and hears first a peer
// that does not hold its last entries writes its boot record after them, not
// over them: its own chain never forks.
func TestOwnEntriesDurableBeforeSent(t *testing.T) {
	g := newGroup(t, setup{n: 3})
	g.run(70 * sec)
	a := g.nodes[0]
	a.LocalEvent(events.Event{Type: events.WanDown})
	g.run(10 * sec) // flushed with it: the next flush is a minute away
	g.split([]int{2}, []int{0, 1}, true)
	a.LocalEvent(events.Event{Type: events.WanUp})
	head := with(a, func() history.Head { return a.log.Head(a.id.ID) })
	stored := readStored(t, g.stores[0], g.ids[0].ID)
	if len(stored) == 0 || stored[len(stored)-1].Hash() != head.Hash {
		t.Fatalf("the own entry at seq %d is not on flash before it can be sent (the store holds %d entries)", head.Seq, len(stored))
	}
	g.run(5 * sec)
	if held := with(g.nodes[1], func() history.Head { return g.nodes[1].log.Head(g.ids[0].ID) }); held != head {
		t.Fatalf("r02 holds r01's head %d, want %d", held.Seq, head.Seq)
	}
	// A power cut; on return r01 reaches only r03, which never saw its last
	// entry.
	g.stop(0)
	g.split([]int{0}, []int{1}, true)
	g.split([]int{2}, []int{0}, false)
	g.run(5 * time.Second)
	g.reboot(0)
	g.run(20 * sec)
	g.split([]int{0, 1, 2}, []int{0, 1, 2}, false)
	g.run(30 * sec)
	for i, n := range g.nodes {
		if fs := with(n, func() []history.ForkProof { return n.log.Forks() }); len(fs) != 0 {
			t.Fatalf("r%02d holds a fork proof against r%02d's chain at seq %d", i+1, 1, fs[0].A.Seq)
		}
	}
	for i := 1; i < 3; i++ {
		if st := stateOf(g.nodes[i].Status(), "r01"); st != "up" {
			t.Fatalf("r%02d sees r01 %q, want up", i+1, st)
		}
	}
}

// stateOf returns the state st reports for the member called name.
func stateOf(st Status, name string) string {
	for _, m := range st.Members {
		if m.Name == name {
			return m.State
		}
	}
	return ""
}
