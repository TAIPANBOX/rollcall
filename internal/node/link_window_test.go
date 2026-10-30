package node

import (
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
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
