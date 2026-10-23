package node

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/history"
	"github.com/TAIPANBOX/rollcall/internal/identity"
	"github.com/TAIPANBOX/rollcall/internal/ids"
)

// bulk returns n entries of id's chain after head, with small bodies that
// no part of the node reads as an event.
func bulk(t testing.TB, id *identity.Identity, head history.Head, n int) []history.Entry {
	t.Helper()
	out := make([]history.Entry, 0, n)
	for i := 0; i < n; i++ {
		e, err := history.NewEntry(id, head, history.KindEvent, json.RawMessage(fmt.Sprintf(`{"n":%d}`, i)))
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, e)
		head = history.Head{Seq: e.Seq, Hash: e.Hash()}
	}
	return out
}

// pastBounds is more entries than a log keeps of one origin.
const pastBounds = history.DefaultMaxEntries + 20

// TestOwnChainPastBoundsReloaded (B2): a router whose own chain is longer
// than the log keeps restarts and goes on with its chain from where it
// was: it reads its file, which starts past seq 1, and its next entry
// follows its head, so its peer finds no fork.
func TestOwnChainPastBoundsReloaded(t *testing.T) {
	g := newGroup(t, setup{n: 2})
	g.run(10 * sec)
	a, b := g.nodes[0], g.nodes[1]
	self := g.ids[0]
	head := with(a, func() history.Head { return a.log.Head(self.ID) })
	if head.Seq == 0 {
		t.Fatal("r01 has no own entry after 10 s: the case did not happen")
	}
	es := bulk(t, self, head, pastBounds)
	inject(a, es...)
	inject(b, es...)
	if err := with(a, func() error { return a.writeChainLocked(self.ID) }); err != nil {
		t.Fatal(err)
	}
	last := es[len(es)-1].Seq
	if p := with(a, func() uint64 { return a.log.Pruned(self.ID).Seq }); p == 0 {
		t.Fatal("r01 kept its whole chain: the case did not happen")
	}

	g.stop(0)
	g.run(5 * sec)
	a = g.reboot(0)
	if h := with(a, func() history.Head { return a.log.Head(self.ID) }); h.Seq != last {
		t.Errorf("after the restart r01 holds its own chain up to %d, want %d", h.Seq, last)
	}
	g.run(90 * sec)
	ha := with(a, func() history.Head { return a.log.Head(self.ID) })
	if ha.Seq <= last {
		t.Errorf("r01's own chain is at %d after the restart, want past %d", ha.Seq, last)
	}
	if fs := with(b, func() []history.ForkProof { return b.log.Forks() }); len(fs) != 0 {
		t.Fatalf("r02 holds %d fork proofs after r01's restart, want none", len(fs))
	}
	if hb := with(b, func() history.Head { return b.log.Head(self.ID) }); hb != ha {
		t.Errorf("r02 holds r01's chain up to %d, r01 is at %d", hb.Seq, ha.Seq)
	}
}

// TestNewMemberReceivesChainPastBounds (B2): a member that holds nothing of
// an origin whose chain is longer than its peers keep takes it from the
// base its peer offers, the peer's Pruned, and holds the rest of it.
func TestNewMemberReceivesChainPastBounds(t *testing.T) {
	g := newGroup(t, setup{n: 3, running: []bool{true, false, false}})
	a := g.nodes[0]
	origin := g.ids[2]
	es := bulk(t, origin, history.Head{}, pastBounds)
	inject(a, es...)
	pruned := with(a, func() history.Head { return a.log.Pruned(origin.ID) })
	if pruned.Seq == 0 {
		t.Fatal("r01 kept the whole chain: the case did not happen")
	}
	b := g.start(1)
	g.run(time.Minute)
	if h := with(b, func() history.Head { return b.log.Head(origin.ID) }); h.Seq != es[len(es)-1].Seq {
		t.Fatalf("the new member holds r03's chain up to %d, want %d", h.Seq, es[len(es)-1].Seq)
	}
	if p := with(b, func() history.Head { return b.log.Pruned(origin.ID) }); p != pruned {
		t.Errorf("the new member's base for r03 is %d, want the peer's %d", p.Seq, pruned.Seq)
	}
}

// fetchesPlanned returns the fetch jobs n has planned for origin: the peer
// asked and the first seq asked for.
func fetchesPlanned(t testing.TB, n *Node, origin ids.MemberID) map[ids.MemberID]uint64 {
	t.Helper()
	out := map[ids.MemberID]uint64{}
	for _, j := range n.jobs {
		if j.typ != msgFetch {
			continue
		}
		var req fetchReq
		if err := json.Unmarshal(j.payload, &req); err != nil {
			t.Fatal(err)
		}
		if req.Origin == origin {
			out[j.to] = req.From
		}
	}
	return out
}

// TestLowestBaseTaken (B2): two peers offer bases for an origin the node
// holds nothing of; the one that kept less offers the higher base. The
// node waits one round for the offers and fetches from the lowest base,
// so a peer cannot hide an origin's older, unpruned entries from it by
// answering first. It never starts the chain on the higher base.
func TestLowestBaseTaken(t *testing.T) {
	g := newGroup(t, setup{n: 4, running: []bool{true, false, false, false}})
	a := g.nodes[0]
	origin, honest, partial := g.ids[2].ID, g.ids[1].ID, g.ids[3].ID
	es := bulk(t, g.ids[2], history.Head{}, pastBounds)
	last := es[len(es)-1]
	with(a, func() any {
		now := a.stamp()
		a.headsIn(partial, headsMsg{Heads: []headMsg{{Origin: origin, Seq: last.Seq, Hash: last.Hash(), Pruned: 400}}}, now)
		return nil
	})
	if f := with(a, func() map[ids.MemberID]uint64 { return fetchesPlanned(t, a, origin) }); len(f) != 0 {
		t.Fatalf("a fetch from the first base offered was planned at once: %v", f)
	}
	g.clk.advance(sec)
	with(a, func() any {
		now := a.stamp()
		a.headsIn(honest, headsMsg{Heads: []headMsg{{Origin: origin, Seq: last.Seq, Hash: last.Hash(), Pruned: 20}}}, now)
		return nil
	})
	g.clk.advance(retryEvery)
	with(a, func() any {
		now := a.stamp()
		a.headsIn(partial, headsMsg{Heads: []headMsg{{Origin: origin, Seq: last.Seq, Hash: last.Hash(), Pruned: 400}}}, now)
		return nil
	})
	f := with(a, func() map[ids.MemberID]uint64 { return fetchesPlanned(t, a, origin) })
	if len(f) != 1 || f[honest] != 21 {
		t.Fatalf("fetches planned for the origin: %v, want one from the peer with the lowest base, from 21", f)
	}
	// Entries from the higher base, fetched before the lower one came, do
	// not start the chain.
	with(a, func() any {
		a.entriesIn(partial, origin, 401, last.Seq, es[400:], a.stamp())
		return nil
	})
	if p := with(a, func() history.Head { return a.log.Pruned(origin) }); p.Seq != 0 {
		t.Fatalf("the chain started at the higher base %d", p.Seq)
	}
}
