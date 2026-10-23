package node

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/events"
	"github.com/TAIPANBOX/rollcall/internal/history"
	"github.com/TAIPANBOX/rollcall/internal/ids"
)

// statePeers returns what member i's state file on flash says of its peers:
// silent or not, by peer; a peer it does not name is missing.
func (g *group) statePeers(i int) map[ids.MemberID]bool {
	g.t.Helper()
	b, err := g.stores[i].ReadFile(fileState)
	if err != nil {
		g.t.Fatalf("r%02d's state file: %v", i+1, err)
	}
	var f stateFile
	if err := json.Unmarshal(b, &f); err != nil {
		g.t.Fatal(err)
	}
	out := map[ids.MemberID]bool{}
	for _, p := range f.Peers {
		out[p.ID] = p.Silent
	}
	return out
}

// silences counts n's own records of x's silence.
func silences(n *Node, x ids.MemberID) int {
	c := 0
	for _, e := range ownEntries(n, history.KindEvent) {
		if b, err := DecodeEvent(e); err == nil && b.Type == events.MemberSilent && b.Subject == x {
			c++
		}
	}
	return c
}

// TestRestartDoesNotTellASilenceAgain (D14): r03 goes silent and r02
// records it, then r02 restarts (its daemon only, or a reboot) before its
// state file, written at most once a minute, says r03 is silent. Its own
// record of the silence is on flash, so the absence is open in its history:
// from its start it does not record r03 silent again, and the chat hears of
// the silence once. When the file was last written before r02 had heard r03
// at all, r02 recorded it again from its start, and the chat got a second
// "r03 stopped answering" (the first two cases, red before the fix); when
// the file names r03 as heard, the history was consulted already (the
// third).
func TestRestartDoesNotTellASilenceAgain(t *testing.T) {
	for _, c := range []struct {
		name   string
		up     time.Duration // how long the group runs before r03 goes
		reboot bool
	}{
		{"file without the peer, daemon restart", 8 * sec, false},
		{"file without the peer, reboot", 8 * sec, true},
		{"file with the peer heard, daemon restart", 65 * sec, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			g := newGroup(t, setup{n: 3, senders: map[int]int{0: 1}})
			g.run(c.up)
			g.stop(2)
			g.run(42 * sec)
			if n := len(g.chat.messages("r03 stopped answering")); n != 1 {
				t.Fatalf("%d silence messages before the restart: the case did not happen", n)
			}
			silent, named := g.statePeers(1)[g.ids[2].ID]
			if silent || named != (c.up > time.Minute) {
				t.Fatalf("r02's state file names r03 %v, silent %v: the case did not happen", named, silent)
			}
			g.stop(1)
			if c.reboot {
				g.reboot(1)
			} else {
				g.cfgs[1].BootSeq = 2
				g.start(1)
			}
			g.run(2 * time.Minute)
			t.Logf("chat:\n%s", strings.Join(g.chat.all(), "\n"))
			if n := len(g.chat.messages("r03 stopped answering")); n != 1 {
				t.Fatalf("%d messages that r03 stopped answering, want 1", n)
			}
			if n := silences(g.nodes[1], g.ids[2].ID); n != 1 {
				t.Fatalf("r02 recorded r03 silent %d times, want once", n)
			}
		})
	}
}

// TestHeardPeerSilentAgainIsRecorded (D14): the rule above is for a peer not
// heard since this start. A peer this node heard after a silence another
// member recorded, and whose return nobody recorded, that goes silent again
// is a new absence: it is recorded.
func TestHeardPeerSilentAgainIsRecorded(t *testing.T) {
	g := newGroup(t, setup{n: 4, running: []bool{true, true, true, false}, senders: map[int]int{0: 1}})
	g.run(20 * sec)
	b, x := g.nodes[1], g.ids[2].ID
	inject(b, forge(t, g.ids[3], history.Head{}, EventBody{Subject: x, Type: events.MemberSilent, At: AtOf(g.clk.stampNow())})...)
	if !with(b, func() bool { return b.openAbsenceLocked(x) }) {
		t.Fatal("r03's absence is not open in r02's history: the case did not happen")
	}
	g.stop(2)
	g.run(45 * sec)
	if n := silences(b, x); n != 1 {
		t.Fatalf("r02 recorded the r03 it heard silent %d times, want once", n)
	}
}

// TestFileSaysSilentWithoutRecord (D14): the state file says a peer was
// silent, and the history no longer holds the record of it (pruned after a
// long absence): from its start the node still does not record it again.
func TestFileSaysSilentWithoutRecord(t *testing.T) {
	g := newGroup(t, setup{n: 2, senders: map[int]int{0: 1}})
	g.run(20 * sec)
	a, x := g.nodes[0], g.ids[1].ID
	if err := a.Stop(); err != nil {
		t.Fatal(err)
	}
	g.stop(0)
	g.stop(1)
	var f stateFile
	b, err := g.stores[0].ReadFile(fileState)
	if err != nil || json.Unmarshal(b, &f) != nil || len(f.Peers) != 1 || f.Peers[0].ID != x {
		t.Fatalf("r01's state file: %s, %v", b, err)
	}
	f.Peers[0].Silent = true
	if b, err = json.Marshal(f); err != nil || g.stores[0].WriteFileAtomic(fileState, b) != nil {
		t.Fatal("writing the state file")
	}
	g.cfgs[0].BootSeq = 2
	a = g.start(0)
	g.run(time.Minute)
	t.Logf("chat:\n%s", strings.Join(g.chat.all(), "\n"))
	if n := silences(a, x); n != 0 || len(g.chat.messages("r02 stopped answering")) != 0 {
		t.Fatalf("r01 recorded r02 silent %d times from its start; chat %q", n, g.chat.all())
	}
}
