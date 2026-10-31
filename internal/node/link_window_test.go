package node

import (
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/clock"
	"github.com/TAIPANBOX/rollcall/internal/deliver"
	"github.com/TAIPANBOX/rollcall/internal/events"
	"github.com/TAIPANBOX/rollcall/internal/ids"
)

// The wire names of the DNS events, written out: a router of an older
// version reads them as strings it does not know.
const (
	dnsLost     events.Type = "dns_lost"
	dnsRestored events.Type = "dns_restored"
)

// cellStep is one record of a lab cell's time line: router who records typ
// at seconds after the start, stamped ago seconds earlier (a probe dates a
// loss at its first failed round, and decides it two rounds later).
type cellStep struct {
	at, ago int
	who     int
	typ     events.Type
}

// replayCell runs a group of three through a lab cell: r01 (flint2) the
// sender, r02 (beryl1) the second sender, r03 (beryl2) without the role, as
// in the lab on 2026-10-30. The steps start once the group has run 90 s, at
// 09:01:30; after them the group runs for ten minutes. It returns the chat.
func replayCell(t *testing.T, steps []cellStep) (*group, []string) {
	t.Helper()
	g := newGroup(t, setup{n: 3, senders: map[int]int{0: 1, 1: 2}})
	g.run(90 * sec)
	start := g.clk.Mono()
	now := 0
	for _, s := range steps {
		g.run(time.Duration(s.at-now) * sec)
		now = s.at
		n := g.nodes[s.who]
		e := events.Event{Type: s.typ}
		if s.ago > 0 {
			ago := time.Duration(s.ago) * sec
			e.At = with(n, func() clock.Stamp {
				st := n.localStamp(n.stamp())
				st.Wall, st.Mono = st.Wall.Add(-ago), st.Mono-ago
				return st
			})
		}
		n.LocalEvent(e)
	}
	g.run(10 * time.Minute)
	msgs := g.chat.all()
	g.chat.mu.Lock()
	var lines []string
	for _, m := range g.chat.msgs {
		lines = append(lines, fmt.Sprintf("+%s %s", m.at-start, m.text))
	}
	g.chat.mu.Unlock()
	t.Logf("chat (%d), each after the first step:\n  %s", len(msgs), strings.Join(lines, "\n  "))
	return g, msgs
}

// firstMessageAfter returns how long after the first record of a replay,
// whose last step was at last seconds, the chat got its first message.
func firstMessageAfter(g *group, last int) time.Duration {
	g.chat.mu.Lock()
	defer g.chat.mu.Unlock()
	if len(g.chat.msgs) == 0 {
		return -1
	}
	return g.chat.msgs[0].at - (g.clk.Mono() - 10*time.Minute - time.Duration(last)*sec)
}

// TestFlappingWanToldAsOneOutage replays lab cell R1.4 (2026-10-30 12:05:01
// to 12:06:50, beryl2): the WAN went down, the internet probe dated its loss
// 2 s later, the WAN came back and went down three more times 2 s each, and
// the internet came back. rc92 sent 6 messages: "WAN went down", "internet
// lost", three times "WAN was down (2 s)" and "internet was down".
func TestFlappingWanToldAsOneOutage(t *testing.T) {
	D, U, L, R := events.WanDown, events.WanUp, events.InternetLost, events.InternetRestored
	_, msgs := replayCell(t, []cellStep{
		{0, 0, 2, D}, {22, 20, 2, L},
		{61, 0, 2, D}, {63, 0, 2, U}, {72, 0, 2, D}, {74, 0, 2, U}, {83, 0, 2, D}, {85, 0, 2, U},
		{109, 0, 2, R},
	})
	if len(msgs) == 0 || len(msgs) > 2 {
		t.Fatalf("%d messages, want at most 2: the start and the end of one outage", len(msgs))
	}
	last := msgs[len(msgs)-1]
	if !strings.Contains(last, "WAN and internet were down from 09:01 to 09:03 (1 min 49 s)") ||
		!strings.Contains(last, "WAN went down 3 times, 1 min 7 s in all") {
		t.Fatalf("the last message %q; want the whole outage, and the WAN's 3 drops with their 1 min 7 s", last)
	}
}

// TestTwoHourUplinkLossTwoMessages replays lab cell O1 (2026-10-30 14:34:13
// to 16:34:34, beryl2): the WAN went down, the internet probe found the loss
// 20 s later and dated it at the WAN loss; two hours later the WAN came back,
// and the internet 11 s after it. rc92 sent 4 messages.
func TestTwoHourUplinkLossTwoMessages(t *testing.T) {
	D, U, L, R := events.WanDown, events.WanUp, events.InternetLost, events.InternetRestored
	g, msgs := replayCell(t, []cellStep{{0, 0, 2, D}, {20, 20, 2, L}, {7210, 0, 2, U}, {7221, 0, 2, R}})
	if len(msgs) != 2 {
		t.Fatalf("%d messages, want 2: the start and the end", len(msgs))
	}
	// The decided price: the internet loss is recorded 20 s after the WAN
	// loss, and the chain waits its 30 s after it.
	if d := firstMessageAfter(g, 7221); d < 0 || d > 60*sec {
		t.Fatalf("the start reached the chat %s after the first record, want within 60 s", d)
	}
	if !strings.Contains(msgs[0], "WAN and internet went down at 09:01") {
		t.Fatalf("first message %q; want the start of the outage naming the WAN and the internet", msgs[0])
	}
	if !strings.Contains(msgs[1], "WAN and internet were down from 09:01 to 11:01 (2 h)") {
		t.Fatalf("second message %q; want the outage of the WAN and the internet with its length", msgs[1])
	}
}

// TestBothUplinksDownTwoMessages replays lab cell R1.5 (2026-10-30 12:11:20
// to 12:13:45): flint2, the sender, and beryl2 lost their WAN at once, their
// internet probes found the losses 22 s later, and both came back 2 min 16 s
// after the cut, the internet 9 s after the WAN. rc92 sent 3 messages.
func TestBothUplinksDownTwoMessages(t *testing.T) {
	D, U, L, R := events.WanDown, events.WanUp, events.InternetLost, events.InternetRestored
	g, msgs := replayCell(t, []cellStep{
		{0, 0, 0, D}, {0, 0, 2, D}, {22, 20, 0, L}, {23, 20, 2, L},
		{136, 0, 0, U}, {137, 0, 2, U}, {145, 0, 0, R}, {146, 0, 2, R},
	})
	if len(msgs) != 2 {
		t.Fatalf("%d messages, want 2: the start and the end", len(msgs))
	}
	if d := firstMessageAfter(g, 146); d < 0 || d > 60*sec {
		t.Fatalf("the start reached the chat %s after the first record, want within 60 s", d)
	}
	for i, want := range []string{"WAN and internet went down at 09:01", "WAN and internet were down from 09:01 to 09:03"} {
		// The witnesses are named in the order of their IDs, which each run
		// draws anew.
		if !strings.Contains(msgs[i], want) || !regexp.MustCompile(`Seen by (r01, r03|r03, r01)\.`).MatchString(msgs[i]) {
			t.Fatalf("message %d %q; want %q, seen by both routers", i+1, msgs[i], want)
		}
	}
}

// TestInternetOnlyLossTwoMessages replays lab cells D3 and D4 (2026-10-30,
// the internet behind one router cut for 5 minutes, its WAN up): the chat
// gets the loss and then the outage with its length, 2 messages, as rc92
// sent.
func TestInternetOnlyLossTwoMessages(t *testing.T) {
	L, R := events.InternetLost, events.InternetRestored
	_, msgs := replayCell(t, []cellStep{{22, 20, 2, L}, {320, 0, 2, R}})
	if len(msgs) != 2 || !strings.Contains(msgs[0], "internet lost at 09:01") ||
		!strings.Contains(msgs[1], "internet was down from 09:01 to 09:06 (5 min 18 s)") {
		t.Fatalf("chat %q; want the loss, then the outage with its length", msgs)
	}
}

// TestDNSCutToldAsItsOwnIncident replays lab cell D2 (2026-10-30 14:03:42 to
// 14:09:01, flint2): the uplink dropped DNS for 5 minutes while the internet
// probe kept reaching 1.1.1.1 and 8.8.8.8. rc92 had no DNS probe and told
// nothing; the DNS probe records the cut, and the chat gets its start and its
// end, neither of them an internet loss.
func TestDNSCutToldAsItsOwnIncident(t *testing.T) {
	_, msgs := replayCell(t, []cellStep{{22, 20, 0, dnsLost}, {321, 0, 0, dnsRestored}})
	if len(msgs) != 2 {
		t.Fatalf("%d messages, want 2: the start and the end of the DNS cut", len(msgs))
	}
	if !strings.Contains(msgs[0], "DNS stopped answering at 09:01") ||
		!strings.Contains(msgs[1], "DNS was down from 09:01 to 09:06 (5 min 19 s)") {
		t.Fatalf("chat %q; want the start of the DNS cut, then its length", msgs)
	}
	for _, m := range msgs {
		if strings.Contains(m, "internet lost") || strings.Contains(m, "internet was down") {
			t.Fatalf("message %q tells an internet loss; only DNS failed", m)
		}
	}
}

// TestLateLossJoinsTheStart: the WAN goes down, and the internet probe, a
// round late, records the loss 35 s afterwards, dated 10 s after the WAN
// loss: within the window of it, but after the WAN loss alone had waited out
// the window. It is not a message of its own: when the start was told
// already, the end tells both links; while the start waits for the chat, the
// start tells both.
func TestLateLossJoinsTheStart(t *testing.T) {
	D, U, L, R := events.WanDown, events.WanUp, events.InternetLost, events.InternetRestored
	t.Run("start told already", func(t *testing.T) {
		_, msgs := replayCell(t, []cellStep{{0, 0, 2, D}, {35, 25, 2, L}, {300, 0, 2, U}, {305, 0, 2, R}})
		if len(msgs) != 2 || !strings.Contains(msgs[0], "WAN went down at 09:01") {
			t.Fatalf("chat %q; want the start of the outage once, then its end", msgs)
		}
		if !strings.Contains(msgs[1], "WAN and internet were down from 09:01 to 09:06") {
			t.Fatalf("second message %q; want the end naming both links", msgs[1])
		}
	})
	t.Run("start waiting out a rate limit", func(t *testing.T) {
		g := newGroup(t, setup{n: 3, senders: map[int]int{0: 1, 1: 2}})
		g.run(90 * sec)
		g.chat.mu.Lock()
		g.chat.limited, g.chat.limitWait = 1, 30*sec
		g.chat.mu.Unlock()
		c := g.nodes[2]
		c.LocalEvent(events.Event{Type: D})
		g.run(35 * sec) // the start is made and its first send refused
		c.LocalEvent(events.Event{Type: L, At: with(c, func() clock.Stamp {
			st := c.localStamp(c.stamp())
			st.Wall, st.Mono = st.Wall.Add(-25*sec), st.Mono-25*sec
			return st
		})})
		g.run(2 * time.Minute)
		msgs := g.chat.all()
		t.Logf("chat (%d):\n  %s", len(msgs), strings.Join(msgs, "\n  "))
		if len(msgs) != 1 || !strings.Contains(msgs[0], "WAN and internet went down at 09:01") {
			t.Fatalf("chat %q; want one start naming both links: the start waits for the late loss", msgs)
		}
	})
	t.Run("start not sent yet", func(t *testing.T) {
		g := newGroup(t, setup{n: 3, senders: map[int]int{0: 1, 1: 2}})
		g.run(90 * sec)
		g.chat.setDown(true)
		c := g.nodes[2]
		c.LocalEvent(events.Event{Type: D})
		g.run(35 * sec)
		c.LocalEvent(events.Event{Type: L, At: with(c, func() clock.Stamp {
			st := c.localStamp(c.stamp())
			st.Wall, st.Mono = st.Wall.Add(-25*sec), st.Mono-25*sec
			return st
		})})
		g.run(2 * time.Minute)
		g.chat.setDown(false)
		g.run(2 * time.Minute)
		msgs := g.chat.all()
		t.Logf("chat (%d):\n  %s", len(msgs), strings.Join(msgs, "\n  "))
		if len(msgs) != 1 || !strings.Contains(msgs[0], "WAN and internet went down at 09:01") {
			t.Fatalf("chat %q; want one start naming both links", msgs)
		}
	})
}

// TestStartsEndedTogetherOneMessage: while the chat is out, two routers lose
// their WAN a minute apart and get it back together. The return ends both
// starts, and neither of them is sent on its own: the chat gets one message,
// from the first loss to the last return. Also when the end is held for a
// late record of r03 (an internet loss dated 20 s before its WAN loss) as the
// chat comes back: the second start is not sent meanwhile.
func TestStartsEndedTogetherOneMessage(t *testing.T) {
	for _, late := range []bool{false, true} {
		t.Run(map[bool]string{false: "end alone", true: "end held for a late record"}[late], func(t *testing.T) {
			g := newGroup(t, setup{n: 3, senders: map[int]int{0: 1}})
			g.run(90 * sec)
			g.chat.setDown(true)
			c := g.nodes[2]
			g.nodes[0].LocalEvent(events.Event{Type: events.WanDown})
			g.run(60 * sec)
			c.LocalEvent(events.Event{Type: events.WanDown})
			g.run(60 * sec)
			g.nodes[0].LocalEvent(events.Event{Type: events.WanUp})
			c.LocalEvent(events.Event{Type: events.WanUp})
			if late {
				g.run(10 * sec)
				c.LocalEvent(events.Event{Type: events.InternetLost, At: with(c, func() clock.Stamp {
					st := c.localStamp(c.stamp())
					st.Wall, st.Mono = st.Wall.Add(-90*sec), st.Mono-90*sec
					return st
				})})
				g.run(20 * sec)
			} else {
				g.run(2 * time.Minute)
			}
			g.chat.setDown(false)
			g.run(2 * time.Minute)
			msgs := g.chat.all()
			t.Logf("chat (%d):\n  %s", len(msgs), strings.Join(msgs, "\n  "))
			if len(msgs) != 1 || !strings.Contains(msgs[0], "WAN was down from 09:01 to 09:03 (2 min)") {
				t.Fatalf("chat %q; want one message, the outage from the first loss to the return", msgs)
			}
		})
	}
}

// TestLossAfterTheEndIsNews: a WAN blip of 5 s is told; the internet probe
// then records a loss dated within the blip, late. The chat was told the WAN
// is back, so the loss is news, not a part of what was told: it goes out,
// and its end after it.
func TestLossAfterTheEndIsNews(t *testing.T) {
	D, U, L, R := events.WanDown, events.WanUp, events.InternetLost, events.InternetRestored
	_, msgs := replayCell(t, []cellStep{{0, 0, 2, D}, {5, 0, 2, U}, {50, 47, 2, L}, {120, 0, 2, R}})
	if len(msgs) != 3 || !strings.Contains(msgs[0], "WAN was down from 09:01 to 09:01 (5 s)") ||
		!strings.Contains(msgs[1], "internet lost at 09:01") || !strings.Contains(msgs[2], "internet was down from 09:01 to 09:03") {
		t.Fatalf("chat %q; want the blip, then the internet loss and its end", msgs)
	}
}

// TestFlapEndsTheOpenLoss: the WAN goes down and the start is told; a
// minute later the WAN drops twice more, 2 s each, and stays up. Its last
// record is a return, so the outage the chat was told began ends there, from
// its first loss; a later blip is told with its own length. In lab cell R1.4
// the first loss stayed open, since every later return came with a loss of
// its own.
func TestFlapEndsTheOpenLoss(t *testing.T) {
	D, U := events.WanDown, events.WanUp
	g, msgs := replayCell(t, []cellStep{{0, 0, 2, D}, {61, 0, 2, D}, {63, 0, 2, U}, {72, 0, 2, D}, {74, 0, 2, U}})
	if len(msgs) != 2 || !strings.Contains(msgs[0], "WAN went down at 09:01") ||
		!strings.Contains(msgs[1], "WAN was down from 09:01 to 09:02 (1 min 14 s). WAN went down 2 times, 1 min 5 s in all") {
		t.Fatalf("chat %q; want the start, then the whole outage from the first loss with its 2 drops", msgs)
	}
	c := g.nodes[2]
	c.LocalEvent(events.Event{Type: D})
	g.run(16 * sec)
	c.LocalEvent(events.Event{Type: U})
	g.run(2 * time.Minute)
	if later := g.chat.messages("WAN was down"); len(later) != 2 || !strings.Contains(later[1], "(16 s)") {
		t.Fatalf("after a later 16 s blip: %q; want it told with its own length", later)
	}
}

// TestEndlessFlapToldWhileItFlaps: beryl2's WAN goes down for 5 s and up for
// 5 s, again and again, for 10 minutes, with its internet loss dated as in
// lab cell R1.4; then the WAN stays up and the internet comes back. Every
// record chains to the one before it, so the chain never waits out its 30 s:
// at bb22451 the chat heard nothing for those 10 minutes and then one line,
// "WAN went down 61 times". The chain is told once it has waited at most
// maxLinkHold after its first record, and its end tells the whole outage:
// two messages. Also when only the WAN flaps, and the first message found it
// up for a moment.
func TestEndlessFlapToldWhileItFlaps(t *testing.T) {
	D, U, L, R := events.WanDown, events.WanUp, events.InternetLost, events.InternetRestored
	for _, c := range []struct {
		name     string
		internet bool
		last     int // the last drop starts here; the WAN is back 5 s later for good
		want     string
	}{
		{"with the internet lost", true, 600, "WAN and internet were down from 09:01 to 09:11 (10 min 15 s). WAN went down 61 times, 5 min 5 s in all"},
		{"the WAN alone", false, 600, "WAN was down from 09:01 to 09:11 (10 min 5 s). WAN went down 61 times, 5 min 5 s in all"},
		// The last return is taken in at a ceiling (600 s) and nothing
		// follows it: the chain is ended once it is quiet.
		{"the WAN alone, its last drop taken at a ceiling", false, 590, "WAN was down from 09:01 to 09:11 (9 min 55 s). WAN went down 60 times, 5 min in all"},
	} {
		t.Run(c.name, func(t *testing.T) {
			steps := []cellStep{{0, 0, 2, D}}
			for s := 5; s < c.last; s += 10 {
				steps = append(steps, cellStep{s, 0, 2, U}, cellStep{s + 5, 0, 2, D})
				if s == 15 && c.internet {
					steps = append(steps, cellStep{22, 20, 2, L})
				}
			}
			steps = append(steps, cellStep{c.last + 5, 0, 2, U})
			if c.internet {
				steps = append(steps, cellStep{c.last + 15, 0, 2, R})
			}
			last := steps[len(steps)-1].at
			g, msgs := replayCell(t, steps)
			if d := firstMessageAfter(g, last); d < 0 || d > 90*sec {
				t.Fatalf("the first message came %s after the first record, want within 90 s: the chat was silent while the WAN flapped", d)
			}
			if len(msgs) != 2 {
				t.Fatalf("%d messages, want 2: the flapping told within 90 s, and the whole outage at its end", len(msgs))
			}
			// While it flaps, the message says so; it does not read as over.
			if !strings.Contains(msgs[0], "WAN keeps dropping since 09:01: down 6 times so far") || strings.Contains(msgs[0], "was down from") {
				t.Fatalf("the first message %q; want the WAN told as one that keeps dropping, not as one that was down", msgs[0])
			}
			if !strings.Contains(msgs[1], c.want) {
				t.Fatalf("the last message %q; want %q", msgs[1], c.want)
			}
		})
	}
}

// TestShortFlapCutByTheCeilingIsEnded: the WAN drops four times in 35 s and
// stays up. The ceiling tells it at 60 s, still dropping as far as it can
// know, before its chain is quiet at 65 s; nothing follows, and its end is
// told even so: the chat's last word is not that it keeps dropping.
func TestShortFlapCutByTheCeilingIsEnded(t *testing.T) {
	D, U := events.WanDown, events.WanUp
	_, msgs := replayCell(t, []cellStep{{0, 0, 2, D}, {5, 0, 2, U}, {10, 0, 2, D}, {15, 0, 2, U},
		{20, 0, 2, D}, {25, 0, 2, U}, {30, 0, 2, D}, {35, 0, 2, U}})
	if len(msgs) != 2 || !strings.Contains(msgs[0], "WAN keeps dropping since 09:01: down 4 times so far, 20 s in all") ||
		!strings.Contains(msgs[1], "WAN was down from 09:01 to 09:02 (35 s). WAN went down 4 times, 20 s in all") {
		t.Fatalf("chat %q; want the flapping, then its end", msgs)
	}
}

// TestCompactLinks: a chain of 61 drops is kept as its first and last
// records with the middle drops counted, and the message reads the same
// counts, first loss, last return and last record from what is kept.
func TestCompactLinks(t *testing.T) {
	w := ids.MemberID{3}
	at := func(s int) clock.Stamp {
		return clock.Stamp{Wall: tStart.Add(time.Duration(s) * sec), Mono: time.Duration(s) * sec, Trusted: true, Boot: bootN(2, 1)}
	}
	ev := func(n, s int, typ events.Type) events.Event {
		return events.Event{Type: typ, Subject: w, Witness: w, At: at(s), Ref: ids.Hash{byte(n), byte(n >> 8), 31: 1}}
	}
	var evs []events.Event
	n := 0
	for s := 0; s < 610; s += 10 {
		evs = append(evs, ev(n, s, events.WanDown), ev(n+1, s+5, events.WanUp))
		n += 2
	}
	evs = append(evs, ev(n, 2, events.InternetLost), ev(n+1, 615, events.InternetRestored))
	kept, elided := compactLinks(evs, maxLinkEvents)
	if len(kept) > 8 || len(elided) != 1 || elided[0].Drops != 59 || elided[0].Gone != 59*5*sec {
		t.Fatalf("kept %d events, elided %+v; want the first and last drops kept, 59 counted", len(kept), elided)
	}
	if got, want := deliver.LinksOf(kept, elided...), deliver.LinksOf(evs); !reflect.DeepEqual(got, want) {
		t.Fatalf("summary of what is kept %+v\nwant %+v", got, want)
	}
	if !reflect.DeepEqual(linkEnds(kept), linkEnds(evs)) {
		t.Fatal("the last records changed")
	}
	if k, e := compactLinks(evs[:10], maxLinkEvents); len(k) != 10 || e != nil {
		t.Fatal("a short chain was compacted")
	}
}

// TestCappedChainKeptAcrossARestart: midway through an endless flap, what
// the node writes to flash keeps the capped incident with the drops it no
// longer holds, and the strict decoder reads them back.
func TestCappedChainKeptAcrossARestart(t *testing.T) {
	g := newGroup(t, setup{n: 3, senders: map[int]int{0: 1, 1: 2}})
	g.run(90 * sec)
	c := g.nodes[2]
	for s := 0; s < 480; s += 10 {
		c.LocalEvent(events.Event{Type: events.WanDown})
		g.run(5 * sec)
		c.LocalEvent(events.Event{Type: events.WanUp})
		g.run(5 * sec)
	}
	a := g.nodes[0]
	b, err := json.Marshal(with(a, func() stateFile { return a.stateLocked() }))
	if err != nil {
		t.Fatal(err)
	}
	var f stateFile
	if err := decodeJSON(b, &f, maxStateFile); err != nil {
		t.Fatalf("the state file does not read back: %v", err)
	}
	for _, s := range f.Recent {
		if s.Capped && len(s.Elided) == 1 && s.Elided[0].Drops > 0 && len(s.Events) <= maxLinkEvents+2 {
			return
		}
	}
	t.Fatalf("no capped incident with elided drops among %d kept, %d bytes", len(f.Recent), len(b))
}

// TestEndAfterAFlappingStartIsTold: the WAN drops, comes back for 5 s and
// drops again, and stays down; the start is told with its two drops. When the
// WAN comes back minutes later, its end is told: the acknowledgement of the
// start named a WAN loss and a WAN return already, yet it told the start, not
// the whole outage the end merges.
func TestEndAfterAFlappingStartIsTold(t *testing.T) {
	D, U := events.WanDown, events.WanUp
	_, msgs := replayCell(t, []cellStep{{0, 0, 2, D}, {5, 0, 2, U}, {10, 0, 2, D}, {300, 0, 2, U}})
	if len(msgs) != 2 || !strings.Contains(msgs[0], "WAN went down at 09:01. WAN went down 2 times") ||
		!strings.Contains(msgs[1], "WAN was down from 09:01 to 09:06 (5 min). WAN went down 2 times, 4 min 55 s in all") {
		t.Fatalf("chat %q; want the start with its 2 drops, then the whole outage", msgs)
	}
}

// TestLateLossesPastTheCeilingOneStart replays lab cell V-R1.5-rc94
// (2026-10-31 02:40:50 to 02:43:03, rc94): flint2 and beryl2 lost their WAN
// at once; flint2's internet probe recorded its loss about 20 s later, dated
// at the cut, and beryl2's about 30 s after the cut, dated 10 s after it. The
// last record settled past the ceiling, so the start was made by it, and 3 s
// later the chain went quiet with both links still down and nothing joined:
// rc94 told the start a second time, "WAN and internet went down at 02:40"
// at 02:41:55 and 02:41:58. A quiet chain whose links are all still down,
// with nothing recorded since its message, has nothing new to tell: the
// return ends it.
func TestLateLossesPastTheCeilingOneStart(t *testing.T) {
	D, U, L, R := events.WanDown, events.WanUp, events.InternetLost, events.InternetRestored
	g, msgs := replayCell(t, []cellStep{{0, 0, 2, D}, {0, 0, 0, D}, {20, 20, 0, L}, {31, 20, 2, L},
		{136, 0, 0, U}, {137, 0, 0, R}, {143, 0, 2, U}, {150, 0, 2, R}})
	if len(msgs) != 2 {
		t.Fatalf("%d messages, want 2: the start and the end", len(msgs))
	}
	if d := firstMessageAfter(g, 150); d < 0 || d > 65*sec {
		t.Fatalf("the start reached the chat %s after the first record, want within the ceiling", d)
	}
	if !strings.Contains(msgs[0], "WAN and internet went down at 09:01") ||
		!strings.Contains(msgs[1], "WAN and internet were down from 09:01 to 09:04 (2 min 30 s)") {
		t.Fatalf("chat %q; want the start, then the outage with its length", msgs)
	}
}

// TestEndOfAFlapThatStayedDownIsTold: beryl2's WAN goes down for 5 s and up
// for 5 s, then stays down, and comes back at 300 s. The ceiling tells the
// flapping, and the return ends the outage with every drop; the chain that went
// quiet with the WAN down tells nothing between them. Its last drop joins the
// capped incident either when it went quiet on its own (90 s) or at a ceiling
// (110 s), and the end merges the capped incident, whose acknowledgement names
// a WAN loss and a WAN return: it is the acknowledgement of a part of the end,
// and does not count the end told. At 98a14b1 the chat never heard that the
// WAN came back (a replay of the forge night campaign, 2026-10-31; not seen on
// a router); at 8473828 it heard the WAN down with its drops between the
// flapping and the end, as in lab cell V3 (TestFlapIntoOutageTwoMessages).
func TestEndOfAFlapThatStayedDownIsTold(t *testing.T) {
	D, U := events.WanDown, events.WanUp
	for _, c := range []struct {
		name string
		flap int // the WAN goes down here and stays down until 300 s
		last string
	}{
		{"its last drop taken when the chain went quiet", 90,
			"WAN was down from 09:01 to 09:06 (5 min). WAN went down 10 times, 4 min 15 s in all"},
		{"its last drops joined at a ceiling", 110,
			"WAN was down from 09:01 to 09:06 (5 min). WAN went down 12 times, 4 min 5 s in all"},
	} {
		t.Run(c.name, func(t *testing.T) {
			var steps []cellStep
			for s := 0; s < c.flap; s += 10 {
				steps = append(steps, cellStep{s, 0, 2, D}, cellStep{s + 5, 0, 2, U})
			}
			steps = append(steps, cellStep{c.flap, 0, 2, D}, cellStep{300, 0, 2, U})
			_, msgs := replayCell(t, steps)
			if len(msgs) != 2 || !strings.Contains(msgs[0], "WAN keeps dropping since 09:01: down 6 times so far") {
				t.Fatalf("chat %q; want the flapping, then the end of the outage", msgs)
			}
			if !strings.Contains(msgs[1], c.last) {
				t.Fatalf("the last message %q; want %q, from the first loss to the return", msgs[1], c.last)
			}
		})
	}
}

// TestChainGoneDownKeepsAnotherRoutersEnd: beryl1's WAN goes down and its
// start is told; beryl2's WAN flaps from 15 s and is told by the ceiling, then
// stays down from 80 s, and beryl1's WAN comes back 2 s later. The two records
// are one incident (the 10 s window), which continues beryl2's chain with its
// WAN down and also ends beryl1's outage: it does not join the chain silently,
// as a drop of beryl2 alone does, or beryl1's return would go untold and
// beryl2's return would be told as one without a start. The chat gets what it
// got before: beryl1 back with beryl2 still down, then beryl2's outage.
func TestChainGoneDownKeepsAnotherRoutersEnd(t *testing.T) {
	D, U := events.WanDown, events.WanUp
	steps := []cellStep{{0, 0, 1, D}}
	for s := 15; s < 70; s += 10 {
		steps = append(steps, cellStep{s, 0, 2, D}, cellStep{s + 5, 0, 2, U})
	}
	steps = append(steps, cellStep{80, 0, 2, D}, cellStep{82, 0, 1, U}, cellStep{300, 0, 2, U})
	_, msgs := replayCell(t, steps)
	if len(msgs) != 4 || !strings.Contains(msgs[2], "WAN came back at 09:02 on r02, still down on r03") ||
		!strings.Contains(msgs[3], "WAN was down from 09:01 to 09:06 (5 min)") {
		t.Fatalf("chat %q; want beryl1's start, beryl2's flapping, beryl1 back with beryl2 still down, then beryl2's outage", msgs)
	}
}

// TestFlapIntoOutageTwoMessages replays lab cell V3 on rc96 (2026-10-31
// 04:39:30 to 04:45:00, beryl2), with the records flint2 kept: the WAN was
// cut and restored every 5 s nine times, and 5 s after the last restore cut
// for 3.5 min. netifd reported 9 drops and 3 returns of the flap, and the
// internet probe a loss and a return within it, then a loss dated 7 s after
// the last drop and recorded 20 s later. The ceiling told the flapping at
// 04:40:36; at 04:42:10 that late loss, quiet, merged with the capped chain
// and told "WAN and internet went down at 04:39. WAN went down 4 times.
// Internet went down 2 times", as a message of its own; the return told the
// outage at 04:45:33. Three messages for one outage: the chain went quiet
// with every link down, and what it recorded after its message is the
// return's to tell.
func TestFlapIntoOutageTwoMessages(t *testing.T) {
	D, U, L, R := events.WanDown, events.WanUp, events.InternetLost, events.InternetRestored
	_, msgs := replayCell(t, []cellStep{
		{0, 0, 2, D}, {10, 0, 2, U}, {11, 0, 2, D}, {21, 0, 2, D}, {22, 21, 2, L}, {30, 0, 2, U},
		{32, 0, 2, D}, {43, 0, 2, D}, {64, 0, 2, D}, {74, 0, 2, D}, {84, 0, 2, D}, {96, 0, 2, U},
		{97, 0, 2, R}, {100, 0, 2, D}, {127, 20, 2, L}, {322, 0, 2, U}, {329, 0, 2, R},
	})
	if len(msgs) != 2 {
		t.Fatalf("%d messages, want 2: the flapping, then the end of the outage", len(msgs))
	}
	if !strings.Contains(msgs[0], "keeps dropping") {
		t.Fatalf("the first message %q; want the WAN told as one that keeps dropping", msgs[0])
	}
	// The lab's end read 5 min 16 s for the WAN; whole seconds make it 15.
	want := "WAN and internet were down from 09:01 to 09:06 (5 min 29 s). WAN went down 4 times, 5 min 15 s in all. Internet went down 2 times, 5 min 18 s in all"
	if !strings.Contains(msgs[1], want) {
		t.Fatalf("the last message %q; want %q, every drop counted", msgs[1], want)
	}
}

// TestPartOfTakesPartsOfParts pins what partOfLocked takes for a part of an
// incident: what it merged, what those merged in turn, and nothing else; that
// only the acknowledgement of such a part is kept from telling the merged
// incident, while one of the same outage under another ID, as a member that
// merged it otherwise makes, still tells it; and that it ends on parts that
// name each other, as a damaged state file may hold.
func TestPartOfTakesPartsOfParts(t *testing.T) {
	var n Node
	n.inc.init()
	keep := func(id string, parts ...string) *incRec {
		r := &incRec{inc: events.Incident{ID: id}, components: parts}
		n.inc.byID[id] = r
		return r
	}
	keep("capped")
	keep("down", "capped", "piece")
	end := keep("end", "down", "return")
	for _, c := range []struct {
		id   string
		part bool
	}{{"down", true}, {"return", true}, {"capped", true}, {"piece", true}, {"end", false}, {"other", false}} {
		if got := n.partOfLocked(end, c.id); got != c.part {
			t.Errorf("%s a part of the end: %v, want %v", c.id, got, c.part)
		}
	}
	w := ids.MemberID{3}
	var refs []ids.Hash
	for i, typ := range []events.Type{events.WanDown, events.WanUp} {
		e := events.Event{Type: typ, Subject: w, Witness: w, Ref: ids.Hash{byte(i + 1)}}
		n.inc.evs[e.Ref] = &evRec{ev: e}
		end.events, refs = append(end.events, e), append(refs, e.Ref)
	}
	for _, c := range []struct {
		id   string
		told bool
	}{{"capped", false}, {"piece", false}, {"down", false}, {"another", true}} {
		if got := n.coveredLocked(end, ackNote{id: c.id, refs: refs}); got != c.told {
			t.Errorf("the acknowledgement of %s tells the end: %v, want %v", c.id, got, c.told)
		}
	}
	if n.partOfLocked(n.inc.byID["capped"], "end") {
		t.Error("an incident with no parts has a part")
	}
	a := keep("a", "b")
	keep("b", "a")
	done := make(chan bool, 1)
	go func() { done <- n.partOfLocked(a, "other") }()
	select {
	case got := <-done:
		if got {
			t.Error("parts that name each other made another incident a part")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("partOfLocked did not end on parts that name each other")
	}
}

// TestFlapUpWithTheInternetStillDownIsTold: beryl2's WAN flaps with its
// internet lost, as in lab cell R1.4, then stays up while the internet stays
// down until 400 s. The chain goes quiet with the WAN back for good: that is an
// end the chat is told, the WAN's drops and the internet still lost, as it is
// told of an outage that did not flap; then the internet's return ends the
// outage. So when the WAN's last return settles on its own, after the ceiling,
// and pairs with the chain, and when a ceiling takes it and the chain is ended
// once quiet (endChainsLocked). Only a return that a later drop of its router's
// WAN overtook is no end (endedLinks).
func TestFlapUpWithTheInternetStillDownIsTold(t *testing.T) {
	D, U, L, R := events.WanDown, events.WanUp, events.InternetLost, events.InternetRestored
	for _, c := range []struct {
		name       string
		up         int // the WAN's last return, for good
		mid, whole string
	}{
		{"its last return settling on its own", 60,
			"WAN was down from 09:01 to 09:02 (1 min); internet lost at 09:01. WAN went down 6 times, 30 s in all",
			"WAN and internet were down from 09:01 to 09:08 (6 min 40 s). WAN went down 6 times, 30 s in all"},
		{"its last return taken at a ceiling", 110,
			"WAN was down from 09:01 to 09:03 (1 min 50 s); internet lost at 09:01. WAN went down 11 times, 55 s in all",
			"WAN and internet were down from 09:01 to 09:08 (6 min 40 s). WAN went down 11 times, 55 s in all"},
	} {
		t.Run(c.name, func(t *testing.T) {
			steps := []cellStep{{0, 0, 2, D}, {5, 0, 2, U}, {10, 0, 2, D}, {15, 0, 2, U}, {22, 20, 2, L}}
			for s := 25; s < c.up; s += 10 {
				steps = append(steps, cellStep{s, 0, 2, D}, cellStep{s + 5, 0, 2, U})
			}
			steps = append(steps, cellStep{400, 0, 2, R})
			_, msgs := replayCell(t, steps)
			if len(msgs) != 3 || !strings.Contains(msgs[0], "keeps dropping") || !strings.Contains(msgs[1], c.mid) ||
				!strings.Contains(msgs[2], c.whole) {
				t.Fatalf("chat %q; want the flapping, the WAN back with the internet still lost, then the outage", msgs)
			}
		})
	}
}

// TestOverrunReturnInAQuietTailIsNoEnd: beryl2's WAN flaps with its internet
// lost; past the ceiling the WAN comes back for 3 s and the internet with it,
// then the WAN goes down for good, and the internet probe's loss comes 31 s
// later, after those records settled. As this member saw them, they bring the
// internet back, but the WAN's drop overtook that return: they join the capped
// chain and tell nothing (endedLinks), and the return at 300 s ends the
// outage. Judged by the last records alone, they were told as "WAN went down"
// between the flapping and the end, the late loss joining that message. The
// sender in the replay of lab cell V3 saw the same, past a ceiling instead.
func TestOverrunReturnInAQuietTailIsNoEnd(t *testing.T) {
	D, U, L, R := events.WanDown, events.WanUp, events.InternetLost, events.InternetRestored
	steps := []cellStep{{0, 0, 2, D}, {21, 20, 2, L}}
	for s := 5; s < 80; s += 10 {
		steps = append(steps, cellStep{s, 0, 2, U}, cellStep{s + 5, 0, 2, D})
	}
	steps = append(steps, cellStep{85, 0, 2, U}, cellStep{86, 0, 2, R}, cellStep{88, 0, 2, D},
		cellStep{119, 30, 2, L}, cellStep{300, 0, 2, U}, cellStep{310, 0, 2, R})
	slices.SortStableFunc(steps, func(a, b cellStep) int { return a.at - b.at })
	_, msgs := replayCell(t, steps)
	if len(msgs) != 2 || !strings.Contains(msgs[0], "keeps dropping") ||
		!strings.Contains(msgs[1], "WAN and internet were down from 09:01 to 09:06 (5 min 10 s)") {
		t.Fatalf("chat %q; want the flapping, then the end of the outage", msgs)
	}
}

// TestEndedLinks: a link's return counts as an end unless its router's WAN
// went down after it; the WAN's own records, a return after the WAN went
// down, and another router's WAN are taken as they are.
func TestEndedLinks(t *testing.T) {
	a, b := ids.MemberID{1}, ids.MemberID{2}
	n := 0
	ev := func(who ids.MemberID, s int, typ events.Type) events.Event {
		n++
		return events.Event{Type: typ, Witness: who, Subject: who, Ref: ids.Hash{byte(n)},
			At: clock.Stamp{Wall: tStart.Add(time.Duration(s) * sec), Mono: time.Duration(s) * sec, Trusted: true}}
	}
	D, U, L, R := events.WanDown, events.WanUp, events.InternetLost, events.InternetRestored
	for _, c := range []struct {
		name string
		evs  []events.Event
		want map[linkKey]bool // down
	}{
		{"the internet back before the WAN dropped", []events.Event{ev(a, 0, D), ev(a, 1, L), ev(a, 10, U), ev(a, 12, R), ev(a, 14, D)},
			map[linkKey]bool{{D, a}: true, {L, a}: true}},
		{"the internet back after the WAN dropped", []events.Event{ev(a, 0, D), ev(a, 1, L), ev(a, 20, R)},
			map[linkKey]bool{{D, a}: true, {L, a}: false}},
		{"the internet back with the WAN up", []events.Event{ev(a, 0, D), ev(a, 1, L), ev(a, 10, U), ev(a, 12, R)},
			map[linkKey]bool{{D, a}: false, {L, a}: false}},
		{"the internet back before a WAN drop that ended", []events.Event{ev(a, 0, L), ev(a, 5, R), ev(a, 8, D), ev(a, 10, U)},
			map[linkKey]bool{{D, a}: false, {L, a}: false}},
		{"DNS back before the WAN dropped", []events.Event{ev(a, 0, dnsLost), ev(a, 5, dnsRestored), ev(a, 8, D)},
			map[linkKey]bool{{D, a}: true, {dnsLost, a}: true}},
		{"another router's WAN dropped", []events.Event{ev(a, 1, L), ev(a, 12, R), ev(b, 0, L), ev(b, 5, R), ev(b, 14, D)},
			map[linkKey]bool{{L, a}: false, {L, b}: true, {D, b}: true}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := endedLinks(c.evs); !reflect.DeepEqual(got, c.want) {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
}

// TestFlapTailKeepsAnotherRoutersEnd: beryl1's internet is lost and told;
// beryl2's WAN flaps and is told by the ceiling, then stays down at 140 s, and
// within 4 s beryl1's internet comes back and beryl1's WAN goes down. The
// three records are one incident, which brings no link back once beryl1's WAN
// drop overtakes its internet's return (endedLinks), and continues beryl2's
// chain: yet it ends beryl1's internet outage, which another kept incident
// holds, so it does not join the chain silently (chainStaysDownLocked). The
// chat is told beryl1's internet outage with its length, as before.
func TestFlapTailKeepsAnotherRoutersEnd(t *testing.T) {
	D, U, L, R := events.WanDown, events.WanUp, events.InternetLost, events.InternetRestored
	steps := []cellStep{{22, 20, 1, L}}
	for s := 70; s < 130; s += 10 {
		steps = append(steps, cellStep{s, 0, 2, D}, cellStep{s + 5, 0, 2, U})
	}
	steps = append(steps, cellStep{140, 0, 2, D}, cellStep{142, 0, 1, R}, cellStep{144, 0, 1, D},
		cellStep{300, 0, 2, U}, cellStep{310, 0, 1, U}, cellStep{340, 0, 1, R})
	_, msgs := replayCell(t, steps)
	if !slices.ContainsFunc(msgs, func(m string) bool {
		return strings.Contains(m, "internet was down from 09:01 to 09:03 (2 min 20 s)")
	}) {
		t.Fatalf("chat %q; want beryl1's internet outage told with its length", msgs)
	}
}
