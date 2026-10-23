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

// TestCorrectionsThenUpdates (D6): one reconciliation corrects two absences
// and the first changes what was told. Its update is signed after every
// correction Reconcile chained, not between them, so the router never signs
// two entries at one sequence number of its own chain.
func TestCorrectionsThenUpdates(t *testing.T) {
	g := newGroup(t, setup{n: 4, running: []bool{true, true, true, false}, senders: map[int]int{0: 1}})
	g.run(40 * sec)
	g.stop(2)
	g.run(40 * sec)
	g.reboot(2)
	g.run(40 * sec)
	c, liar := g.ids[2].ID, g.ids[3]
	now := AtOf(g.clk.stampNow())
	b1, b2 := Boot{ID: bootN(2, 1), Seq: 1}, Boot{ID: bootN(2, 2), Seq: 2}
	inject(g.nodes[0], forge(t, liar, history.Head{},
		EventBody{Subject: c, Type: events.RebootUnplanned, Last: b1, Back: b1, At: shift(now, -20*sec)},
		EventBody{Subject: c, Type: events.RebootPlanned, Last: b2, Back: b2, At: shift(now, -10*sec)},
	)...)
	g.run(time.Minute)
	for i, n := range g.nodes[:3] {
		if fs := with(n, func() []history.ForkProof { return n.log.Forks() }); len(fs) != 0 {
			t.Fatalf("r%02d holds a fork proof against r%02d's own chain at seq %d", i+1, 3, fs[0].A.Seq)
		}
	}
	if us := updateEvents(g.nodes[2]); len(us) != 2 {
		t.Fatalf("r03 recorded %d updates, want one per corrected absence", len(us))
	}
}

// TestShutdownFlushes (clean shutdown): GoingDown and Stop write at once
// what the node keeps on flash at most once a minute otherwise: the other
// members' chains, the state file with the incidents and the peers, and
// the alive file.
func TestShutdownFlushes(t *testing.T) {
	for _, how := range []string{"going down", "stop"} {
		t.Run(how, func(t *testing.T) {
			g := newGroup(t, setup{n: 2})
			g.run(70 * sec)
			g.nodes[1].LocalEvent(events.Event{Type: events.WanDown})
			g.run(5 * sec)
			a := g.nodes[0]
			held := with(a, func() history.Head { return a.log.Head(g.ids[1].ID) })
			if es := readStored(t, g.stores[0], g.ids[1].ID); len(es) > 0 && es[len(es)-1].Hash() == held.Hash {
				t.Fatal("r02's last entry is on r01's flash already: the case did not happen")
			}
			g.clk.advance(sec)
			if how == "stop" {
				if err := a.Stop(); err != nil {
					t.Fatal(err)
				}
			} else {
				a.GoingDown()
			}
			es := readStored(t, g.stores[0], g.ids[1].ID)
			if len(es) == 0 || es[len(es)-1].Hash() != held.Hash {
				t.Fatalf("after %s r01's flash holds %d entries of r02, not its last one", how, len(es))
			}
			b, err := g.stores[0].ReadFile(fileState)
			if err != nil {
				t.Fatalf("no state file after %s: %v", how, err)
			}
			var f stateFile
			if err := decodeJSON(b, &f, maxStateFile); err != nil || f.Heads[g.ids[1].ID] != held.Seq || len(f.Peers) != 1 {
				t.Fatalf("state file after %s: heads %v, %d peers, %v; want r02's head %d and r02", how, f.Heads, len(f.Peers), err, held.Seq)
			}
			alive, ok := g.readAlive(0)
			if !ok || !alive.At.Wall.Equal(g.clk.Now()) {
				t.Fatalf("alive file after %s: %+v, want written now", how, alive)
			}
		})
	}
}
