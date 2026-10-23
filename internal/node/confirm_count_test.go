package node

import (
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/events"
	"github.com/TAIPANBOX/rollcall/internal/history"
	"github.com/TAIPANBOX/rollcall/internal/ids"
)

// TestConfirmedCountsWhoSawIt (L8, lab message 3): a router loses power and
// is back within a minute; both other routers saw it go silent. The chat
// said "confirmed by 0 of 2" on the lab day, when no router's clock was
// trusted (no witness statement is made on an untrusted stamp), and says
// "1 of 2" with trusted clocks (the statements about one record were
// counted, and the router that rebooted, which never states anything about
// itself, was counted among those who could). Both routers that saw it go
// silent confirm it: 2 of 2, whatever the clocks.
func TestConfirmedCountsWhoSawIt(t *testing.T) {
	for _, trusted := range []bool{true, false} {
		t.Run(map[bool]string{true: "trusted clocks", false: "no clock trusted"}[trusted], func(t *testing.T) {
			g := newGroup(t, setup{n: 3, senders: map[int]int{0: 1}})
			for _, n := range g.nodes {
				n.SetClockTrusted(trusted)
			}
			g.run(40 * sec)
			g.stop(2)
			g.run(30 * sec)
			g.reboot(2).SetClockTrusted(trusted)
			g.run(2 * time.Minute)
			t.Logf("chat:\n%s", strings.Join(g.chat.all(), "\n"))
			ms := g.chat.messages("r03 rebooted unexpectedly at 09:00, back after")
			if len(ms) != 1 || len(g.chat.messages("r03")) != 1 {
				t.Fatalf("messages about r03: %q; want one that tells the reboot", g.chat.messages("r03"))
			}
			if !strings.Contains(ms[0], ", confirmed by 2 of 2.") {
				t.Fatalf("%q: want it confirmed by both routers that saw r03 go silent, 2 of 2", ms[0])
			}
			for _, inc := range g.nodes[0].Status().Incidents {
				if strings.Contains(inc.Text, "rebooted") && (inc.ConfirmedBy != 2 || inc.Members != 2) {
					t.Fatalf("the status shows %q confirmed by %d of %d, want the message's 2 of 2", inc.Text, inc.ConfirmedBy, inc.Members)
				}
			}
		})
	}
}

// TestPlannedRebootConfirmed (L8, lab message 4): a router announces its
// shutdown and comes back; both others saw it go: 2 of 2, not 1 of 2.
func TestPlannedRebootConfirmed(t *testing.T) {
	g := newGroup(t, setup{n: 3, senders: map[int]int{0: 1}})
	g.run(40 * sec)
	g.nodes[1].GoingDown()
	g.stop(1)
	g.run(45 * sec)
	g.cfgs[1].Planned = true
	g.reboot(1)
	g.run(2 * time.Minute)
	t.Logf("chat:\n%s", strings.Join(g.chat.all(), "\n"))
	ms := g.chat.messages("r02 rebooted as planned at 09:00, back after")
	if len(ms) != 1 || !strings.Contains(ms[0], ", confirmed by 2 of 2.") {
		t.Fatalf("messages %q; want one planned reboot confirmed by 2 of 2", g.chat.messages("r02"))
	}
}

// TestNoCountWhereNobodyElseCouldSee (L8, lab message 2): a router's own
// internet loss is told with the routers that saw it ("Seen by"), and no
// other router can see it, so "confirmed by 0 of 2" meant nothing: the
// count is left out. So it is where every member was a cause (a site power
// cut): nobody was left to see it.
func TestNoCountWhereNobodyElseCouldSee(t *testing.T) {
	g := newGroup(t, setup{n: 3, senders: map[int]int{0: 1}})
	g.run(40 * sec)
	g.nodes[0].LocalEvent(events.Event{Type: events.InternetLost})
	g.run(3 * time.Minute)
	g.nodes[0].LocalEvent(events.Event{Type: events.InternetRestored})
	g.run(time.Minute)
	for i := range 3 {
		g.stop(i)
	}
	g.clk.advance(2 * time.Minute)
	for i := range 3 {
		g.reboot(i)
	}
	g.run(2 * time.Minute)
	t.Logf("chat:\n%s", strings.Join(g.chat.all(), "\n"))
	if ms := g.chat.messages("internet was down from 09:00 to 09:03 (3 min). Seen by r01."); len(ms) != 1 {
		t.Fatalf("internet messages %q; want one without a count", g.chat.messages("internet"))
	}
	if ms := g.chat.messages("rebooted unexpectedly"); len(ms) != 1 || !strings.Contains(ms[0], "r01") || !strings.Contains(ms[0], "r02") || !strings.Contains(ms[0], "r03") {
		t.Fatalf("the site power cut was not told once, naming all three: %q", ms)
	}
	if ms := g.chat.messages("confirmed by"); len(ms) != 0 {
		t.Fatalf("a count where nobody else could see: %q", ms)
	}
	// The status tells how many saw it, of the whole roster.
	for _, inc := range g.nodes[0].Status().Incidents {
		if want := map[bool]int{true: 1, false: 3}[strings.Contains(inc.Text, "internet")]; inc.ConfirmedBy != want || inc.Members != 3 {
			t.Fatalf("the status shows %q seen by %d of %d, want %d of 3", inc.Text, inc.ConfirmedBy, inc.Members, want)
		}
	}
}

// TestConfirmationsCountRecordsAndStatements (L8): "confirmed by N of M"
// counts, of the members other than the absent one, each that recorded the
// absence itself or whose latest statement about such a record says it saw
// the same; not the absent member, not a member whose latest statement
// disagrees.
func TestConfirmationsCountRecordsAndStatements(t *testing.T) {
	g := newGroup(t, setup{n: 4, running: []bool{true, false, false, false}})
	n, x := g.nodes[0], g.ids[3].ID
	g.run(5 * sec)
	at := AtOf(g.clk.stampNow())
	silent := forge(t, g.ids[1], history.Head{}, EventBody{Subject: x, Type: events.MemberSilent, At: at})[0]
	inject(n, silent)
	ev := eventOf(silent, EventBody{Subject: x, Type: events.MemberSilent, At: at})
	inc := events.Incident{Members: []string{x.String()}, Causes: 1, Events: []events.Type{events.MemberSilent}}
	count := func(evs ...events.Event) (c, o int) {
		with(n, func() any { c, o = n.confirmations(inc, evs); return nil })
		return c, o
	}
	if c, o := count(ev); c != 1 || o != 3 {
		t.Fatalf("one record: %d of %d, want 1 of 3", c, o)
	}
	state := func(id int, head history.Head, agree bool) history.Head {
		w, err := history.NewWitness(g.ids[id], head, silent.Hash(), agree, "")
		if err != nil {
			t.Fatal(err)
		}
		inject(n, w)
		return history.Head{Seq: w.Seq, Hash: w.Hash()}
	}
	h3 := state(2, history.Head{}, true)
	h4 := state(3, history.Head{}, true) // the absent member itself
	if c, o := count(ev); c != 2 || o != 3 {
		t.Fatalf("a record and an agreeing statement: %d of %d, want 2 of 3", c, o)
	}
	state(2, h3, false)
	if c, o := count(ev); c != 1 || o != 3 {
		t.Fatalf("after the statement was taken back: %d of %d, want 1 of 3", c, o)
	}
	gone := ev
	gone.Witness = ids.MemberID{0xee} // a member removed since it recorded
	if c, o := count(gone); c != 0 || o != 3 {
		t.Fatalf("a removed member's record: %d of %d, want 0 of 3", c, o)
	}
	other := ev
	other.Subject = g.ids[2].ID // another member's absence, which this incident does not tell
	if c, o := count(other); c != 0 || o != 3 {
		t.Fatalf("a record of another member's absence: %d of %d, want 0 of 3", c, o)
	}
	// The absent member lost its internet first; another router's internet
	// failed too and it says so: that confirms no absence.
	lost := forge(t, g.ids[3], h4, EventBody{Subject: x, Type: events.InternetLost, At: at})[0]
	inject(n, lost)
	w, err := history.NewWitness(g.ids[1], history.Head{Seq: silent.Seq, Hash: silent.Hash()}, lost.Hash(), true, "")
	if err != nil {
		t.Fatal(err)
	}
	inject(n, w)
	if a := with(n, func() []ids.MemberID { a, _ := history.Confirmations(n.log, lost.Hash(), n.isMember); return a }); len(a) != 1 {
		t.Fatalf("the statement about the internet loss is not in the log: %v", a)
	}
	linkEv := eventOf(lost, EventBody{Subject: x, Type: events.InternetLost, At: at})
	if c, o := count(linkEv); c != 0 || o != 3 {
		t.Fatalf("a statement about the absent member's internet: %d of %d, want 0 of 3", c, o)
	}
	inc.Causes, inc.Events = 0, []events.Type{events.InternetLost}
	if c, o := count(ev); c != 0 || o != 0 {
		t.Fatalf("an internet loss: %d of %d, want no count", c, o)
	}
}
