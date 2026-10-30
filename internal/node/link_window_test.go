package node

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/clock"
	"github.com/TAIPANBOX/rollcall/internal/events"
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
	_, msgs := replayCell(t, []cellStep{{0, 0, 2, D}, {20, 20, 2, L}, {7210, 0, 2, U}, {7221, 0, 2, R}})
	if len(msgs) != 2 {
		t.Fatalf("%d messages, want 2: the start and the end", len(msgs))
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
	_, msgs := replayCell(t, []cellStep{
		{0, 0, 0, D}, {0, 0, 2, D}, {22, 20, 0, L}, {23, 20, 2, L},
		{136, 0, 0, U}, {137, 0, 2, U}, {145, 0, 0, R}, {146, 0, 2, R},
	})
	if len(msgs) != 2 {
		t.Fatalf("%d messages, want 2: the start and the end", len(msgs))
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
