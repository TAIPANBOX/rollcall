package node

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/deliver"
	"github.com/TAIPANBOX/rollcall/internal/events"
	"github.com/TAIPANBOX/rollcall/internal/history"
	"github.com/TAIPANBOX/rollcall/internal/identity"
	"github.com/TAIPANBOX/rollcall/internal/ids"
)

// otherSendersAck returns, as entries of sender's chain after head, its
// record of x's silence at at, and its acknowledgement of the incident it
// made of that record and of told, which another member recorded.
func otherSendersAck(t *testing.T, n *Node, sender *identity.Identity, head history.Head, x EventBody, told history.Entry) []history.Entry {
	t.Helper()
	own := forge(t, sender, head, x)[0]
	tb, err := DecodeEvent(told)
	if err != nil {
		t.Fatal(err)
	}
	incs := events.Coalesce([]events.Event{eventOf(told, tb), eventOf(own, x)}, events.DefaultWindow)
	if len(incs) != 1 {
		t.Fatalf("the other sender's records make %d incidents, want 1", len(incs))
	}
	body, err := deliver.AckBodyRefs(incs[0].ID, incs[0].Refs)
	if err != nil {
		t.Fatal(err)
	}
	ack, err := history.NewEntry(sender, history.Head{Seq: own.Seq, Hash: own.Hash()}, history.KindEvent, body)
	if err != nil {
		t.Fatal(err)
	}
	return []history.Entry{own, ack}
}

// TestAckNamesWhatItTold (Q4, seeds 553 and 706): two senders made the
// same silence into incidents of different events (a record reached one in
// time and the other late, or an equivocator showed each a different
// face), so their IDs differ. The one that sent its own records the events
// it told in its acknowledgement; the other, which holds a twin of every
// event of its own incident, sees the absence was told and sends nothing.
func TestAckNamesWhatItTold(t *testing.T) {
	g := newGroup(t, setup{n: 4, running: []bool{true, true, false, false}, senders: map[int]int{0: 2, 2: 1}})
	a, x := g.nodes[0], g.ids[1].ID
	g.run(40 * sec)
	g.chat.setDown(true)
	g.stop(1)
	cut := AtOf(g.clk.stampNow())
	last := Boot{ID: bootN(1, 1), Seq: 1}
	g.run(25 * sec)
	inject(a, forge(t, g.ids[3], history.Head{}, EventBody{Subject: x, Type: events.MemberSilent, Last: last, At: shift(cut, sec)})...)
	g.run(20 * sec)
	if n := with(a, func() int {
		for _, r := range a.inc.recent {
			if slices.Contains(r.inc.Members, x.String()) && !a.deliveredLocked(r.inc.ID) {
				return len(r.events)
			}
		}
		return 0
	}); n != 2 {
		t.Fatalf("r01's unsent incident of r02's silence holds %d events, want its own record and r04's: the case did not happen", n)
	}
	mine := eventOfType(t, a, events.MemberSilent, x)
	inject(a, otherSendersAck(t, a, g.ids[2], history.Head{}, EventBody{Subject: x, Type: events.MemberSilent, Last: last, At: shift(cut, 2*sec)}, mine)...)
	g.chat.setDown(false)
	g.run(time.Minute)
	t.Logf("chat:\n%s", strings.Join(g.chat.all(), "\n"))
	if n := len(g.chat.messages("r02 stopped answering")); n != 0 {
		t.Fatalf("r01 told r02's silence %d times after r03 had told it", n)
	}
	if st := a.Status(); st.Queued != 0 {
		t.Fatalf("r01 still queues %d incidents", st.Queued)
	}
}

// TestAckBeforeOwnIncident (Q4, seed 553): the other sender's
// acknowledgement reaches this router before it made its own incident of
// the same silence (it was catching up after a restart): the incident it
// makes is told already and is not queued.
func TestAckBeforeOwnIncident(t *testing.T) {
	g := newGroup(t, setup{n: 4, running: []bool{true, true, false, false}, senders: map[int]int{0: 2, 2: 1}})
	a, x := g.nodes[0], g.ids[1].ID
	g.run(40 * sec)
	g.chat.setDown(true)
	g.stop(1)
	cut := AtOf(g.clk.stampNow())
	last := Boot{ID: bootN(1, 1), Seq: 1}
	g.run(25 * sec)
	inject(a, forge(t, g.ids[3], history.Head{}, EventBody{Subject: x, Type: events.MemberSilent, Last: last, At: shift(cut, sec)})...)
	recorded := func() bool {
		return slices.ContainsFunc(ownEntries(a, history.KindEvent), func(e history.Entry) bool {
			b, err := DecodeEvent(e)
			return err == nil && b.Type == events.MemberSilent && b.Subject == x
		})
	}
	for i := 0; i < 15 && !recorded(); i++ {
		g.run(sec)
	}
	mine := eventOfType(t, a, events.MemberSilent, x)
	inject(a, otherSendersAck(t, a, g.ids[2], history.Head{}, EventBody{Subject: x, Type: events.MemberSilent, Last: last, At: shift(cut, 2*sec)}, mine)...)
	if held := with(a, func() bool {
		return slices.ContainsFunc(a.inc.recent, func(r *incRec) bool { return slices.Contains(r.inc.Members, x.String()) })
	}); held {
		t.Fatal("r01 made its incident before the acknowledgement arrived: the case did not happen")
	}
	g.run(20 * sec)
	g.chat.setDown(false)
	g.run(time.Minute)
	t.Logf("chat:\n%s", strings.Join(g.chat.all(), "\n"))
	if n := len(g.chat.messages("r02 stopped answering")); n != 0 {
		t.Fatalf("r01 told r02's silence %d times after r03 had told it", n)
	}
}

// TestAckOfOneMemberStillSendsTheOther (Q4): two routers went down
// together, one incident here; another sender told only one of them. The
// other's silence was not told, so the incident still goes out.
func TestAckOfOneMemberStillSendsTheOther(t *testing.T) {
	g := newGroup(t, setup{n: 4, running: []bool{true, true, true, false}, senders: map[int]int{0: 2, 3: 1}})
	a, x := g.nodes[0], g.ids[1].ID
	g.run(40 * sec)
	g.chat.setDown(true)
	g.stop(1)
	g.stop(2)
	cut := AtOf(g.clk.stampNow())
	g.run(45 * sec)
	mine := eventOfType(t, a, events.MemberSilent, x)
	inject(a, otherSendersAck(t, a, g.ids[3], history.Head{}, EventBody{Subject: x, Type: events.MemberSilent, Last: Boot{ID: bootN(1, 1), Seq: 1}, At: shift(cut, 2*sec)}, mine)...)
	g.chat.setDown(false)
	g.run(time.Minute)
	t.Logf("chat:\n%s", strings.Join(g.chat.all(), "\n"))
	if n := len(g.chat.messages("r03")); n != 1 {
		t.Fatalf("%d messages tell r03's silence, want 1: another member's acknowledgement of r02's alone stood for it", n)
	}
}

// TestOwnAckNamesTheEvents (Q4): the sender's acknowledgement of what it
// sent names the events of that incident.
func TestOwnAckNamesTheEvents(t *testing.T) {
	g := newGroup(t, setup{n: 3, senders: map[int]int{0: 1}})
	a := g.nodes[0]
	g.run(40 * sec)
	g.stop(2)
	g.run(time.Minute)
	var refs []ids.Hash
	id := ""
	for _, e := range ownEntries(a, history.KindEvent) {
		if aid, _, ok := deliver.AckOf(e); ok {
			id, refs = aid, deliver.AckRefs(e)
		}
	}
	want := with(a, func() []ids.Hash {
		if r := a.inc.byID[id]; r != nil {
			return r.inc.Refs
		}
		return nil
	})
	if id == "" || len(want) == 0 || !slices.Equal(refs, want) {
		t.Fatalf("r01's acknowledgement of %q names %v, want the incident's events %v", id, refs, want)
	}
}

// TestAckOfLessStillSends (Q4): an acknowledgement that names a silence
// does not stand for an incident that also tells the return after it: the
// whole absence still goes out.
func TestAckOfLessStillSends(t *testing.T) {
	g := newGroup(t, setup{n: 4, running: []bool{true, true, false, false}, senders: map[int]int{0: 2, 2: 1}})
	a, x := g.nodes[0], g.ids[1].ID
	g.run(40 * sec)
	g.chat.setDown(true)
	g.stop(1)
	cut := AtOf(g.clk.stampNow())
	g.run(45 * sec)
	g.reboot(1)
	g.run(time.Minute)
	mine := eventOfType(t, a, events.MemberSilent, x)
	inject(a, otherSendersAck(t, a, g.ids[2], history.Head{}, EventBody{Subject: x, Type: events.MemberSilent, Last: Boot{ID: bootN(1, 1), Seq: 1}, At: shift(cut, 2*sec)}, mine)...)
	g.chat.setDown(false)
	g.run(time.Minute)
	t.Logf("chat:\n%s", strings.Join(g.chat.all(), "\n"))
	if n := len(g.chat.messages("r02 rebooted unexpectedly at 09:00")); n != 1 {
		t.Fatalf("%d messages tell r02's reboot, want 1: an acknowledgement of its silence alone stood for the whole absence", n)
	}
}
