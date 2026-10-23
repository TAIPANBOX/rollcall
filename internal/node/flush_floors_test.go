package node

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/TAIPANBOX/rollcall/internal/ids"
	"github.com/TAIPANBOX/rollcall/internal/store"
)

// storedFloors returns the counters the peer state file of member i holds,
// by peer.
func (g *group) storedFloors(i int) map[ids.MemberID]uint64 {
	g.t.Helper()
	b, err := g.stores[i].ReadFile("peer-state.json")
	if err != nil {
		g.t.Fatalf("r%02d's peer state: %v", i+1, err)
	}
	var f struct {
		Peers []struct {
			ID      ids.MemberID `json:"id"`
			Counter uint64       `json:"counter"`
		} `json:"peers"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		g.t.Fatal(err)
	}
	out := map[ids.MemberID]uint64{}
	for _, p := range f.Peers {
		out[p.ID] = p.Counter
	}
	return out
}

// heardCounters returns the counter of the last heartbeat n accepted from
// each peer.
func heardCounters(n *Node) map[ids.MemberID]uint64 {
	return with(n, func() map[ids.MemberID]uint64 {
		out := map[ids.MemberID]uint64{}
		for id, p := range n.peers {
			if p.heard {
				out[id] = p.hb.Counter
			}
		}
		return out
	})
}

// TestStopLeavesPeerFloors (N5): Stop and GoingDown write the peer state
// file, the replay floors, with everything else the node keeps; written only
// once a minute, it lagged up to a minute of the peers' packets behind, and a
// restart would take a recording of them again.
func TestStopLeavesPeerFloors(t *testing.T) {
	for _, how := range []string{"Stop", "GoingDown"} {
		t.Run(how, func(t *testing.T) {
			g := newGroup(t, setup{n: 3})
			g.run(85 * sec) // written at the first tick and a minute later
			n := g.nodes[0]
			if how == "Stop" {
				if err := n.Stop(); err != nil {
					t.Fatalf("Stop: %v", err)
				}
			} else {
				n.GoingDown()
			}
			heard, stored := heardCounters(n), g.storedFloors(0)
			if len(heard) != 2 {
				t.Fatalf("heard %d peers, want 2", len(heard))
			}
			for id, c := range heard {
				if stored[id] < c {
					t.Errorf("after %s the file holds counter %d of %s, below the %d of its last heartbeat", how, stored[id], id, c)
				}
			}
		})
	}
}

// TestStopReportsFloorsNotWritten (N5): when the peer state file cannot be
// written, Stop says so, though everything else reached flash.
func TestStopReportsFloorsNotWritten(t *testing.T) {
	g := newGroup(t, setup{n: 2, running: []bool{false, true}})
	dir := filepath.Join(t.TempDir(), "r01")
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := Bootstrap(st, g.first, g.key); err != nil {
		t.Fatal(err)
	}
	g.stores[0] = st
	n := g.start(0)
	g.run(20 * sec)
	if err := os.Remove(filepath.Join(dir, "peer-state.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "peer-state.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := n.Stop(); err == nil {
		t.Fatal("Stop reported no error though the peer state file could not be written")
	}
	if _, err := st.ReadFile("state.json"); err != nil {
		t.Fatalf("the state file was not written: %v", err)
	}
}
