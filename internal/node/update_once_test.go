package node

import (
	"slices"
	"strings"
	"testing"

	"github.com/TAIPANBOX/rollcall/internal/events"
	"github.com/TAIPANBOX/rollcall/internal/history"
	"github.com/TAIPANBOX/rollcall/internal/ids"
)

// TestOneUpdatePerAbsence: the claims about one absence of a router reach it
// at different times, so it corrects them in more than one reconciliation,
// each with a correction entry of its own; the chat still gets one update
// for that absence. r03 loses power twice (boots b1, b2, b3), and r04, which
// last heard it in b1, records it silent; r03 corrects that to an unplanned
// reboot from b1 to b3 and sends the update. Then a second claim about the
// same absence comes: another member's silence (sim seed 241, 2026-10-31),
// r04's own guess at the return (seed 698), or the first after a restart of
// r03's daemon. Before the fix each correction sent "r03 rebooted
// unexpectedly, back at ..." again, under another incident ID.
func TestOneUpdatePerAbsence(t *testing.T) {
	b1, b3 := Boot{ID: bootN(2, 1), Seq: 1}, Boot{ID: bootN(2, 3), Seq: 3}
	cases := []struct {
		name    string
		restart bool
		// second returns r04's or r05's next claim about r03.
		second func(g *group, first history.Entry) history.Entry
	}{
		{"another member's silence", false, func(g *group, _ history.Entry) history.Entry {
			return forge(t, g.ids[4], history.Head{},
				EventBody{Subject: g.ids[2].ID, Type: events.MemberSilent, Last: b1, At: AtOf(g.clk.stampNow())})[0]
		}},
		{"the claimant's guess at the return", false, func(g *group, first history.Entry) history.Entry {
			return forge(t, g.ids[3], history.Head{Seq: first.Seq, Hash: first.Hash()},
				EventBody{Subject: g.ids[2].ID, Type: events.RebootPlanned, Last: b1, Back: b3, At: AtOf(g.clk.stampNow())})[0]
		}},
		{"after a restart of the daemon", true, func(g *group, _ history.Entry) history.Entry {
			return forge(t, g.ids[4], history.Head{},
				EventBody{Subject: g.ids[2].ID, Type: events.MemberSilent, Last: b1, At: AtOf(g.clk.stampNow())})[0]
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := newGroup(t, setup{n: 5, running: []bool{true, true, true, false, false}, senders: map[int]int{0: 1}})
			g.run(40 * sec)
			for seq := 2; seq <= 3; seq++ {
				g.stop(2)
				g.run(40 * sec)
				g.cfgs[2].Boot, g.cfgs[2].BootSeq = bootN(2, seq), uint64(seq)
				g.start(2)
				g.run(70 * sec)
			}
			first := forge(t, g.ids[3], history.Head{},
				EventBody{Subject: g.ids[2].ID, Type: events.MemberSilent, Last: b1, At: AtOf(g.clk.stampNow())})[0]
			inject(g.nodes[0], first)
			g.run(60 * sec)
			if n := len(g.chat.messages("r03 rebooted unexpectedly, back at")); n != 1 {
				t.Fatalf("after the first claim the update reached the chat %d times, want 1:\n%s", n, strings.Join(g.chat.all(), "\n"))
			}
			if tc.restart {
				g.stop(2)
				g.start(2)
				g.run(30 * sec)
			}
			second := tc.second(g, first)
			inject(g.nodes[0], second)
			g.run(90 * sec)
			t.Logf("chat:\n%s", strings.Join(g.chat.all(), "\n"))
			var corrected []ids.Hash
			for _, e := range ownEntries(g.nodes[2], history.KindCorrection) {
				if b, err := history.DecodeCorrection(e); err == nil && b.Class == history.ClassRebootUnplanned {
					corrected = append(corrected, b.Refs...)
				}
			}
			for _, c := range []history.Entry{first, second} {
				if !slices.Contains(corrected, c.Hash()) {
					t.Fatalf("r03 did not correct the claim %s: the case did not happen", c.Hash())
				}
			}
			var us []EventBody
			for _, u := range updateEvents(g.nodes[2]) {
				if u.Last == b1 && u.Back == b3 {
					us = append(us, u)
				}
			}
			if len(us) != 1 || us[0].Type != events.RebootUnplanned {
				t.Fatalf("r03's updates for its absence from b1 to b3: %+v; want one reboot_unplanned", us)
			}
			if n := len(g.chat.messages("r03 rebooted unexpectedly, back at")); n != 1 {
				t.Fatalf("the update reached the chat %d times, want 1", n)
			}
		})
	}
}

// TestUpdateWaitingForFlashTells: an update this router recorded and could
// not write to flash yet (Node.writes) tells its absence as a signed one
// does, so a correction of that absence in the meantime sends no second
// one; a waiting record of another class, another absence or another member
// does not.
func TestUpdateWaitingForFlashTells(t *testing.T) {
	g := newGroup(t, setup{n: 2})
	n := g.nodes[0]
	b1, b2, b3 := Boot{ID: bootN(0, 1), Seq: 1}, Boot{ID: bootN(0, 2), Seq: 2}, Boot{ID: bootN(0, 3), Seq: 3}
	c := Correction{Class: history.ClassRebootUnplanned, From: b1, To: b3}
	waiting := func(subject ids.MemberID, typ events.Type, last, back Boot) ownWrite {
		return ownWrite{kind: history.KindEvent, ev: &events.Event{Type: typ, Subject: subject},
			body: EventBody{Subject: subject, Type: typ, Last: last, Back: back}}
	}
	told := func(ws ...ownWrite) bool {
		return with(n, func() bool {
			held := n.writes
			defer func() { n.writes = held }()
			n.writes = append(slices.Clone(held), ws...)
			return n.toldOwnLocked(c)
		})
	}
	if told() {
		t.Fatal("the absence counts as told with no record of it")
	}
	if !told(waiting(n.id.ID, events.RebootUnplanned, b1, b3)) {
		t.Fatal("an update waiting for flash does not tell its absence")
	}
	for _, w := range []ownWrite{
		waiting(n.id.ID, events.RebootPlanned, b1, b3),
		waiting(n.id.ID, events.RebootUnplanned, b2, b3),
		waiting(n.id.ID, events.RebootUnplanned, b1, b2),
		waiting(g.ids[1].ID, events.RebootUnplanned, b1, b3),
	} {
		if told(w) {
			t.Fatalf("a waiting record %+v tells the absence from b1 to b3", w.body)
		}
	}
}
