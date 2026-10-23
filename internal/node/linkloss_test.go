package node

import (
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/events"
	"github.com/TAIPANBOX/rollcall/internal/history"
)

// TestLinkLossOneMessage (D1, D9): a mesh node that stays up loses its link
// to the others for two minutes. The chat gets its silence and then one
// message for the link loss: no update from the node about the silence
// claims it corrects (the group's own message tells the link loss), and
// nothing from what the cut-off node saw of the others.
func TestLinkLossOneMessage(t *testing.T) {
	g := newGroup(t, setup{n: 3, senders: map[int]int{0: 1}})
	g.run(40 * sec)
	g.split([]int{2}, []int{0, 1}, true)
	g.run(2 * time.Minute)
	g.split([]int{2}, []int{0, 1}, false)
	g.run(3 * time.Minute)
	t.Logf("chat:\n%s", strings.Join(g.chat.all(), "\n"))
	if us := updateEvents(g.nodes[2]); len(us) != 0 {
		t.Errorf("r03 recorded updates %+v; the group's own message tells the link loss", us)
	}
	ms := g.chat.all()
	if len(ms) != 2 || !strings.Contains(ms[0], "r03 stopped answering at 09:00") || !strings.Contains(ms[1], "r03 lost contact 09:00 to 09:02 but stayed up") {
		t.Fatalf("chat %q; want r03's silence, then its link loss with its span", ms)
	}
}

// TestSilenceCorrectedWithoutUpdate (D1): a router that stayed up corrects
// a claim that it went silent, but records no update: the claimant's record
// of its return in the same boot tells the link loss, and an update would
// say it a second time, from the claim's moment.
func TestSilenceCorrectedWithoutUpdate(t *testing.T) {
	g := newGroup(t, setup{n: 4, running: []bool{true, true, true, false}, senders: map[int]int{0: 1}})
	g.run(40 * sec)
	c, liar := g.ids[2].ID, g.ids[3]
	now := AtOf(g.clk.stampNow())
	inject(g.nodes[0], forge(t, liar, history.Head{},
		EventBody{Subject: c, Type: events.MemberSilent, Last: Boot{ID: bootN(2, 1), Seq: 1}, At: shift(now, -50*sec)})...)
	g.run(60 * sec)
	t.Logf("chat:\n%s", strings.Join(g.chat.all(), "\n"))
	corrected := false
	for _, e := range ownEntries(g.nodes[2], history.KindCorrection) {
		if b, err := history.DecodeCorrection(e); err == nil && b.Class == history.ClassLinkLost {
			corrected = true
		}
	}
	if !corrected {
		t.Fatal("r03 did not correct the silence claim: the case did not happen")
	}
	if us := updateEvents(g.nodes[2]); len(us) != 0 {
		t.Fatalf("r03 recorded updates %+v for a corrected silence", us)
	}
}

// TestLateWitnessAbsorbed (D2): a member's record of an absence the chat was
// told already arrives late (its router was away meanwhile). It joins
// nothing and sends nothing: another message for the same silence would be
// a duplicate under another incident ID.
func TestLateWitnessAbsorbed(t *testing.T) {
	g := newGroup(t, setup{n: 4, running: []bool{true, true, true, false}, senders: map[int]int{0: 1}})
	g.run(40 * sec)
	g.stop(2)
	g.run(time.Minute)
	if n := len(g.chat.messages("r03 stopped answering")); n != 1 {
		t.Fatalf("%d messages tell r03's silence before the late record, want 1", n)
	}
	seen := eventOfType(t, g.nodes[0], events.MemberSilent, g.ids[2].ID)
	b, err := DecodeEvent(seen)
	if err != nil {
		t.Fatal(err)
	}
	inject(g.nodes[0], forge(t, g.ids[3], history.Head{},
		EventBody{Subject: g.ids[2].ID, Type: events.MemberSilent, Last: b.Last, At: shift(b.At, 2*sec)})...)
	g.run(time.Minute)
	t.Logf("chat:\n%s", strings.Join(g.chat.all(), "\n"))
	if n := len(g.chat.messages("r03 stopped answering")); n != 1 {
		t.Fatalf("%d messages tell r03's silence, want 1: the late record told it again", n)
	}
}
