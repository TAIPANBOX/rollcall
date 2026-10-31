package node

import (
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/clock"
	"github.com/TAIPANBOX/rollcall/internal/events"
	"github.com/TAIPANBOX/rollcall/internal/ids"
)

// TestOlderPiecesOfAFlapDoNotStretchALaterOutage replays what flint2 did on
// the night of 2026-10-30. rc92 had told the WAN flap of lab cell R1.4
// (12:05:01 to 12:06:49, beryl2) in pieces and kept them: among them three
// incidents of a return and the drop after it (12:06:02-05, 12:06:13-15,
// 12:06:23-25), while the return that ended the flap, 12:06:47, lay in
// another piece. rc93 restored them from its state.json and, ten hours later,
// told the end of cell R1.5 (both uplinks down for 2 min 13 s) as "WAN was
// down from 12:06 to 22:09 (10 h 3 min) ... WAN went down 3 times on beryl2,
// 10 h 3 min in all": each of those pieces ends with a drop, and the end of
// R1.5 was merged with them as with an outage that had not ended. Replayed
// here, the merged end counts as delivered with its pieces and is not sent at
// all; either way the pieces were in it. A WAN that drops alone joins them
// the same way, as the records of an outage they still hold (absorbLocked).
func TestOlderPiecesOfAFlapDoNotStretchALaterOutage(t *testing.T) {
	D, U, L, R := events.WanDown, events.WanUp, events.InternetLost, events.InternetRestored
	for _, c := range []struct {
		name  string
		steps []cellStep
		start string
		end   *regexp.Regexp
	}{
		// Lab cell R1.5: r01 and r03 lose their WAN and internet for 2 min 26 s.
		{"both uplinks down", []cellStep{{0, 0, 0, D}, {0, 0, 2, D}, {2, 0, 0, L}, {3, 0, 2, L},
			{136, 0, 0, U}, {137, 0, 2, U}, {145, 0, 0, R}, {146, 0, 2, R}},
			"WAN and internet went down at 10:13", regexp.MustCompile(`were down from 10:13 to 10:15 \(2 min 26 s\)`)},
		// r03's WAN alone, as the flap's own drops were, for 2 min 16 s.
		{"the flapped WAN alone", []cellStep{{0, 0, 2, D}, {136, 0, 2, U}},
			"WAN went down at 10:13", regexp.MustCompile(`WAN was down from 10:13 to 10:15 \(2 min 16 s\)`)},
	} {
		t.Run(c.name, func(t *testing.T) { replayAfterOlderPieces(t, c.steps, c.start, c.end) })
	}
}

// replayAfterOlderPieces plays the flap of R1.4 on r03, puts in its place on
// both senders the pieces rc92 kept of it, and an hour later plays steps; the
// chat must get the start and the end of that outage alone.
func replayAfterOlderPieces(t *testing.T, steps []cellStep, start string, end *regexp.Regexp) {
	t.Helper()
	D, U, L, R := events.WanDown, events.WanUp, events.InternetLost, events.InternetRestored
	g := newGroup(t, setup{n: 3, senders: map[int]int{0: 1, 1: 2}})
	g.run(90 * sec)
	play := func(steps []cellStep) {
		now := 0
		for _, s := range steps {
			g.run(time.Duration(s.at-now) * sec)
			now = s.at
			g.nodes[s.who].LocalEvent(events.Event{Type: s.typ})
		}
		g.run(10 * time.Minute)
	}
	beryl2 := g.ids[2].ID
	senders := g.nodes[:2]
	before := make([]int, len(senders))
	for i, n := range senders {
		before[i] = with(n, func() int { return len(n.inc.recent) })
	}
	play([]cellStep{{0, 0, 2, D}, {2, 0, 2, L}, {61, 0, 2, U}, {64, 0, 2, D}, {72, 0, 2, U}, {74, 0, 2, D},
		{82, 0, 2, U}, {84, 0, 2, D}, {106, 0, 2, U}, {108, 0, 2, R}})
	told := len(g.chat.all())

	// What rc92 kept of the flap on both senders, taken back as
	// restoreIncidentLocked takes it from a state.json: its own incidents
	// replace what this build made of the flap, and the chat was told each
	// of them.
	for i, n := range senders {
		with(n, func() bool {
			var flap []events.Event
			for _, r := range n.inc.evs {
				if r.ev.Witness == beryl2 && linkChange(r.ev.Type) {
					flap = append(flap, r.ev)
				}
			}
			slices.SortFunc(flap, stampOrder)
			if len(flap) != 10 {
				t.Fatalf("the flap left %d link records on r%02d, want 10", len(flap), i+1)
			}
			for _, r := range n.inc.recent[before[i]:] {
				delete(n.inc.byID, r.inc.ID)
			}
			n.inc.recent = slices.Clone(n.inc.recent[:before[i]])
			now := n.stamp()
			piece := func(paired bool, comps []string, evs ...events.Event) string {
				incs := events.Coalesce(evs, 2*time.Minute)
				if len(incs) != 1 {
					t.Fatalf("%d incidents of a piece, want 1", len(incs))
				}
				n.restoreIncidentLocked(incState{Inc: incs[0], Events: evs, Components: comps, Paired: paired}, now)
				n.inc.ackedIDs[incs[0].ID] = true
				return incs[0].ID
			}
			down, lost := piece(true, nil, flap[0]), piece(true, nil, flap[1])
			piece(false, nil, flap[2], flap[3])
			piece(false, nil, flap[4], flap[5])
			piece(false, nil, flap[6], flap[7])
			piece(false, []string{down, lost}, flap[0], flap[1], flap[8], flap[9])
			return true
		})
	}

	g.run(time.Hour)
	play(steps)
	msgs := g.chat.all()[told:]
	t.Logf("chat after the restore:\n  %s", strings.Join(msgs, "\n  "))
	if len(msgs) != 2 {
		t.Fatalf("%d messages for the outage, want 2: its start and its end", len(msgs))
	}
	if !strings.Contains(msgs[0], start) {
		t.Fatalf("the start %q; want %q", msgs[0], start)
	}
	if !end.MatchString(msgs[1]) || strings.Contains(msgs[1], "09:0") || regexp.MustCompile(`\d+ h\b`).MatchString(msgs[1]) {
		t.Fatalf("the end %q; want %s, the outage of 10:13 alone, not stretched back to the flap at 09:01", msgs[1], end)
	}
}

// TestOpenLinksTakeLaterReturns pins what openLinksLocked takes for a later
// return: only a return of the same link, by the same router, stamped after
// the incident's own last record of it, in another kept incident, ends the
// outage the incident holds down.
func TestOpenLinksTakeLaterReturns(t *testing.T) {
	x, y := ids.MemberID{1}, ids.MemberID{2}
	ev := func(typ events.Type, who ids.MemberID, s int) events.Event {
		d := time.Duration(s) * time.Second
		return events.Event{Type: typ, Witness: who, Subject: who, At: clock.Stamp{Wall: tStart.Add(d), Mono: d, Trusted: true}}
	}
	D, U, L, R := events.WanDown, events.WanUp, events.InternetLost, events.InternetRestored
	wan := linkKey{events.WanDown, x}
	for _, c := range []struct {
		name  string
		held  []events.Event // the incident asked about
		other []events.Event // another kept incident
		down  bool
	}{
		{"a later return of the link by the router ends it", []events.Event{ev(U, x, 10), ev(D, x, 13)}, []events.Event{ev(U, x, 40)}, false},
		{"another router's return does not", []events.Event{ev(U, x, 10), ev(D, x, 13)}, []events.Event{ev(U, y, 40)}, true},
		{"the return of another link does not", []events.Event{ev(U, x, 10), ev(D, x, 13)}, []events.Event{ev(R, x, 40)}, true},
		{"an earlier return does not", []events.Event{ev(U, x, 10), ev(D, x, 13)}, []events.Event{ev(U, x, 5)}, true},
		{"a later drop does not", []events.Event{ev(U, x, 10), ev(D, x, 13)}, []events.Event{ev(D, x, 40)}, true},
		{"a return before the incident's last drop does not", []events.Event{ev(D, x, 0), ev(U, x, 10), ev(D, x, 13)}, []events.Event{ev(U, x, 11)}, true},
		{"the router's own last drop counts, not another router's", []events.Event{ev(D, x, 13), ev(D, y, 20)}, []events.Event{ev(U, x, 15)}, false},
		{"no other incident: down", []events.Event{ev(D, x, 0), ev(L, x, 2)}, nil, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			var n Node
			held := &incRec{events: c.held}
			n.inc.recent = []*incRec{held}
			if c.other != nil {
				n.inc.recent = append(n.inc.recent, &incRec{events: c.other})
			}
			if got := n.openLinksLocked(held)[wan]; got != c.down {
				t.Fatalf("WAN of x down = %v, want %v", got, c.down)
			}
		})
	}
}
