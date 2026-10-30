package node

import (
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/clock"
	"github.com/TAIPANBOX/rollcall/internal/events"
)

type linkStep struct {
	at  time.Duration // after the group has run 90 s
	who int
	typ events.Type
}

// replayLinks runs a group of three, r01 the sender, through steps, then for
// ten minutes, and returns the chat.
func replayLinks(t *testing.T, steps []linkStep) (*group, []string) {
	t.Helper()
	g := newGroup(t, setup{n: 3, senders: map[int]int{0: 1}})
	g.run(90 * sec)
	var now time.Duration
	for _, s := range steps {
		g.run(s.at - now)
		now = s.at
		g.nodes[s.who].LocalEvent(events.Event{Type: s.typ})
	}
	g.run(10 * time.Minute)
	return g, g.chat.all()
}

// TestOverlappingWanLossesBothClose: two routers lose their WAN at moments
// 88 s apart and get it back 2 s apart. Each restore ends its own router's
// loss: the chat tells the outage from the first loss to the last return,
// and no loss is left open to be closed by the next WAN event, hours later.
// Replays flint2 and beryl2 on 2026-10-29 23:09:28 to 23:13:44 (Marble's
// carrier test): the restores closed only beryl2's loss, flint2's stayed open
// for 11 h 29 min, and the next blip told "WAN was down from 29 Oct 23:09 to
// 30 Oct 10:38".
func TestOverlappingWanLossesBothClose(t *testing.T) {
	D, U := events.WanDown, events.WanUp
	g, msgs := replayLinks(t, []linkStep{
		{0, 0, D}, {12 * sec, 0, D}, {88 * sec, 2, D}, {100 * sec, 2, D}, {254 * sec, 2, U}, {256 * sec, 0, U},
	})
	t.Logf("chat:\n  %s", strings.Join(msgs, "\n  "))
	closing := g.chat.messages("WAN was down")
	if len(closing) != 1 || !strings.Contains(closing[0], "WAN was down from 09:01 to 09:05 (4 min 16 s)") ||
		!strings.Contains(closing[0], "r01") || !strings.Contains(closing[0], "r03") {
		t.Fatalf("closing lines %q; want one, from r01's loss at 09:01 to the last return, naming r01 and r03", closing)
	}
	// A later blip of r01 is told as itself, not as the end of an outage
	// that began before the first one ended.
	g.nodes[0].LocalEvent(events.Event{Type: D})
	g.run(16 * sec)
	g.nodes[0].LocalEvent(events.Event{Type: U})
	g.run(2 * time.Minute)
	if later := g.chat.messages("WAN was down"); len(later) != 2 || !strings.Contains(later[1], "(16 s)") {
		t.Fatalf("after a later 16 s blip of r01: %q; want it told with its own length", later)
	}
	// And so is one of r03: its loss was closed too.
	g.nodes[2].LocalEvent(events.Event{Type: D})
	g.run(20 * sec)
	g.nodes[2].LocalEvent(events.Event{Type: U})
	g.run(2 * time.Minute)
	if later := g.chat.messages("WAN was down"); len(later) != 3 || !strings.Contains(later[2], "(20 s)") {
		t.Fatalf("after a later 20 s blip of r03: %q; want it told with its own length", later)
	}
}

// TestRestoreEndsOnlyItsOwnRoutersLoss: r03 loses its WAN and moves to its
// backup uplink; at the same moment r01, whose WAN was never down, records a
// restore (a WAN set up again after a change). Neither ends r03's loss: r03's
// own restore does, later.
func TestRestoreEndsOnlyItsOwnRoutersLoss(t *testing.T) {
	D, U, S := events.WanDown, events.WanUp, events.UplinkSwitched
	g, msgs := replayLinks(t, []linkStep{{0, 2, D}, {60 * sec, 0, U}, {61 * sec, 2, S}, {180 * sec, 2, U}})
	t.Logf("chat:\n  %s", strings.Join(msgs, "\n  "))
	closing := g.chat.messages("WAN was down")
	if len(closing) != 1 || !strings.Contains(closing[0], "(3 min)") || !strings.Contains(closing[0], "r03") || strings.Contains(closing[0], "r01") {
		t.Fatalf("closing lines %q; want r03's 3 min outage, closed by its own return and not naming r01", closing)
	}
}

// TestOverlappingInternetLossesBothClose: the same for the internet probe,
// which pairs its losses and restores the same way.
func TestOverlappingInternetLossesBothClose(t *testing.T) {
	L, R := events.InternetLost, events.InternetRestored
	g, msgs := replayLinks(t, []linkStep{{0, 1, L}, {88 * sec, 2, L}, {254 * sec, 2, R}, {256 * sec, 1, R}})
	t.Logf("chat:\n  %s", strings.Join(msgs, "\n  "))
	closing := g.chat.messages("internet was down")
	if len(closing) != 1 || !strings.Contains(closing[0], "internet was down from 09:01 to 09:05 (4 min 16 s)") {
		t.Fatalf("closing lines %q; want one from r02's loss at 09:01 to the last return", closing)
	}
}

// TestWanAndInternetBackTogetherBothClose: the sender's WAN goes down; its
// internet probe finds the loss after three failed rounds, 30 s later, and
// dates it 5 s after the WAN went down, so the WAN loss is already an incident
// of its own. When the cable is back, the WAN and the internet come back
// within 2 s, one incident with both restores. It ends the WAN loss as well
// as the internet loss. Replays flint2 on 2026-10-30 10:50:38 to 10:53:55
// (Marble's port down for 3 min): the restores closed only the internet
// loss, and the WAN loss stayed open.
func TestWanAndInternetBackTogetherBothClose(t *testing.T) {
	g := newGroup(t, setup{n: 3, senders: map[int]int{0: 1}})
	g.run(90 * sec)
	a := g.nodes[0]
	a.LocalEvent(events.Event{Type: events.WanDown})
	g.run(5 * sec)
	g.chat.setDown(true)
	g.run(25 * sec)
	lost := with(a, func() clock.Stamp {
		s := a.localStamp(a.stamp())
		s.Wall, s.Mono = s.Wall.Add(-25*sec), s.Mono-25*sec
		return s
	})
	a.LocalEvent(events.Event{Type: events.InternetLost, At: lost})
	g.run(163 * sec)
	g.chat.setDown(false)
	a.LocalEvent(events.Event{Type: events.WanUp})
	g.run(2 * sec)
	a.LocalEvent(events.Event{Type: events.InternetRestored})
	g.run(5 * time.Minute)
	t.Logf("chat:\n  %s", strings.Join(g.chat.all(), "\n  "))
	// The WAN loss was closed: a later blip of r01 is told with its own length.
	a.LocalEvent(events.Event{Type: events.WanDown})
	g.run(16 * sec)
	a.LocalEvent(events.Event{Type: events.WanUp})
	g.run(2 * time.Minute)
	t.Logf("after a later blip:\n  %s", strings.Join(g.chat.all(), "\n  "))
	var blip []string
	for _, m := range g.chat.messages("WAN was down") {
		if strings.Contains(m, "(16 s)") {
			blip = append(blip, m)
		}
	}
	if len(blip) != 1 {
		t.Fatalf("WAN lines %q; want the later 16 s blip told with its own length", g.chat.messages("WAN"))
	}
}
