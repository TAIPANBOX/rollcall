package node

import (
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/events"
	"github.com/TAIPANBOX/rollcall/internal/history"
	"github.com/TAIPANBOX/rollcall/internal/ids"
)

// TestLateRecordInOwnSpanAbsorbed (Q4, seeds 862 and 360): a router comes
// back from a power cut, and its own account of the absence, with the
// moment it began, is told. Then a member's record of its silence arrives
// late, stamped inside that absence but more than the coalescing window
// from the other silences. It is the same absence, which the chat was
// told: it joins nothing and sends nothing.
func TestLateRecordInOwnSpanAbsorbed(t *testing.T) {
	g := newGroup(t, setup{n: 4, running: []bool{true, true, true, false}, senders: map[int]int{0: 1}})
	g.run(40 * sec)
	g.stop(2)
	cut := AtOf(g.clk.stampNow())
	g.run(time.Minute)
	g.reboot(2)
	g.run(90 * sec)
	if n := len(g.chat.messages("r03 rebooted unexpectedly at 09:00")); n != 1 {
		t.Fatalf("%d messages tell r03's reboot from its start: the case did not happen\n%s", n, strings.Join(g.chat.all(), "\n"))
	}
	inject(g.nodes[0], forge(t, g.ids[3], history.Head{},
		EventBody{Subject: g.ids[2].ID, Type: events.MemberSilent, Last: Boot{ID: bootN(2, 1), Seq: 1}, At: shift(cut, 30*sec)})...)
	g.run(time.Minute)
	t.Logf("chat:\n%s", strings.Join(g.chat.all(), "\n"))
	if n := len(g.chat.messages("r03 stopped answering")); n != 1 {
		t.Fatalf("%d messages tell r03's silence, want 1: the late record told the same absence again", n)
	}
}

// holdsOwnReturn reports whether n holds subject's own account of a return.
func holdsOwnReturn(n *Node, subject ids.MemberID) bool {
	return with(n, func() bool {
		for _, r := range n.inc.evs {
			if events.Own(r.ev) && r.ev.Subject == subject {
				return true
			}
		}
		return false
	})
}

// TestStartJoinsOwnAccountWithSilence (Q4, seed 698): a router's silence is
// queued and not sent yet (Telegram is out) when the router comes back; its
// own account of the absence arrives together with a late record of its
// silence, so the incident they make holds a silence and a return. The
// silence queued before is the same absence: it goes out once, in that
// incident, not again on its own.
func TestStartJoinsOwnAccountWithSilence(t *testing.T) {
	g := newGroup(t, setup{n: 4, running: []bool{true, true, true, false}, senders: map[int]int{0: 1}})
	a, x := g.nodes[0], g.ids[1].ID
	g.run(40 * sec)
	g.chat.setDown(true)
	g.stop(1)
	cut := AtOf(g.clk.stampNow())
	g.run(45 * sec)
	g.reboot(1)
	for i := 0; i < 90 && !holdsOwnReturn(a, x); i++ {
		g.run(sec)
	}
	if !holdsOwnReturn(a, x) {
		t.Fatal("r01 never got r02's own account: the case did not happen")
	}
	inject(a, forge(t, g.ids[3], history.Head{},
		EventBody{Subject: x, Type: events.MemberSilent, Last: Boot{ID: bootN(1, 1), Seq: 1}, At: shift(cut, 2*sec)})...)
	g.run(30 * sec)
	g.chat.setDown(false)
	g.run(time.Minute)
	t.Logf("chat:\n%s", strings.Join(g.chat.all(), "\n"))
	if ms := g.chat.messages("r02"); len(ms) != 1 || !strings.Contains(ms[0], "r02 rebooted unexpectedly at 09:00") {
		t.Fatalf("messages about r02 %q; want one that tells its reboot from its start", ms)
	}
}

// TestEarlierSilenceNotJoined (Q4): a silence of a router from long before,
// still unsent, is another absence than the one its own account of a later
// power cut spans: it does not join that incident, and both are told.
func TestEarlierSilenceNotJoined(t *testing.T) {
	g := newGroup(t, setup{n: 4, running: []bool{true, true, true, false}, senders: map[int]int{0: 1}})
	a, x := g.nodes[0], g.ids[1].ID
	g.run(40 * sec)
	g.chat.setDown(true)
	old := AtOf(g.clk.stampNow())
	old.Wall = old.Wall.Add(-30 * time.Minute)
	head := history.Head{}
	e := forge(t, g.ids[3], head, EventBody{Subject: x, Type: events.MemberSilent, Last: Boot{ID: bootN(1, 1), Seq: 1}, At: old})[0]
	inject(a, e)
	g.run(20 * sec)
	// A power cut short of the silence time: only r04's late record tells a
	// silence of it, and it joins the own account's incident.
	g.stop(1)
	cut := AtOf(g.clk.stampNow())
	g.run(15 * sec)
	g.reboot(1)
	for i := 0; i < 90 && !holdsOwnReturn(a, x); i++ {
		g.run(sec)
	}
	if !holdsOwnReturn(a, x) {
		t.Fatal("r01 never got r02's own account: the case did not happen")
	}
	inject(a, forge(t, g.ids[3], history.Head{Seq: e.Seq, Hash: e.Hash()},
		EventBody{Subject: x, Type: events.MemberSilent, Last: Boot{ID: bootN(1, 1), Seq: 1}, At: shift(cut, sec)})...)
	g.run(time.Minute)
	g.chat.setDown(false)
	g.run(time.Minute)
	t.Logf("chat:\n%s", strings.Join(g.chat.all(), "\n"))
	if n := len(g.chat.messages("r02 stopped answering at 08:30")); n != 1 {
		t.Fatalf("%d messages tell r02's silence of 08:30, want 1: it was taken into a later absence", n)
	}
	if n := len(g.chat.messages("r02 rebooted unexpectedly at 09:01")); n != 1 {
		t.Fatalf("%d messages tell r02's reboot, want 1", n)
	}
}

// TestSilenceSoonAfterOwnReturnTold (Q4): a router comes back and goes down
// again seconds after its own account of the first absence. The silence of
// the second absence is stamped after that account: it is a new absence,
// and the chat tells it.
func TestSilenceSoonAfterOwnReturnTold(t *testing.T) {
	g := newGroup(t, setup{n: 3, senders: map[int]int{0: 1}})
	g.run(40 * sec)
	g.stop(2)
	g.run(time.Minute)
	c := g.reboot(2)
	for i := 0; i < 90 && len(ownReturns(c)) == 0; i++ {
		g.run(sec)
	}
	if len(ownReturns(c)) == 0 {
		t.Fatal("r03 recorded no account of its return: the case did not happen")
	}
	g.run(3 * sec)
	g.stop(2)
	g.run(2 * time.Minute)
	t.Logf("chat:\n%s", strings.Join(g.chat.all(), "\n"))
	if n := len(g.chat.messages("r03 stopped answering")); n != 2 {
		t.Fatalf("%d messages tell r03's silences, want 2: the second absence was taken for the first", n)
	}
}
