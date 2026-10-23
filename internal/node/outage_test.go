package node

import (
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/events"
)

// TestOutageOneMessage (D5): a router alone loses its internet; when it is
// back, the router can reach Telegram again before the restore has settled.
// Both ends of the outage are known before anything is sent, so the chat
// gets one message with the outage and its length, not "internet lost"
// followed by "internet was down".
func TestOutageOneMessage(t *testing.T) {
	g := newGroup(t, setup{n: 1, senders: map[int]int{0: 1}})
	a := g.nodes[0]
	g.run(90 * sec)
	g.chat.setDown(true)
	a.LocalEvent(events.Event{Type: events.InternetLost})
	g.run(5 * time.Minute)
	g.chat.setDown(false)
	g.run(31 * sec) // a ping reached Telegram meanwhile
	a.LocalEvent(events.Event{Type: events.InternetRestored})
	g.run(2 * time.Minute)
	t.Logf("chat:\n%s", strings.Join(g.chat.all(), "\n"))
	ms := g.chat.messages("internet")
	if len(ms) != 1 || !strings.Contains(ms[0], "internet was down from 09:01 to 09:07 (5 min") {
		t.Fatalf("messages about the internet %q; want one that tells the outage with its length", ms)
	}
}

// TestReturnKnownBeforeSendingOneMessage (D5): a router goes silent while
// nobody reaches Telegram, and comes back before Telegram does: the silence
// and the return are one message.
func TestReturnKnownBeforeSendingOneMessage(t *testing.T) {
	g := newGroup(t, setup{n: 3, senders: map[int]int{0: 1}})
	g.run(40 * sec)
	g.chat.setDown(true)
	g.stop(2)
	g.run(2 * time.Minute)
	g.reboot(2)
	g.run(10 * sec)
	g.chat.setDown(false)
	g.run(2 * time.Minute)
	t.Logf("chat:\n%s", strings.Join(g.chat.all(), "\n"))
	if ms := g.chat.messages("r03"); len(ms) != 1 || !strings.Contains(ms[0], "r03 rebooted unexpectedly at 09:00, back after 2 min") {
		t.Fatalf("messages about r03 %q; want one that tells the reboot with its length", ms)
	}
}

// TestSilenceReportedSoon (D8): a router loses power; the chat tells its
// silence within 45 s of the cut: detection at 30 s, then no more than the
// 10 s coalescing window for the other routers' records to join.
func TestSilenceReportedSoon(t *testing.T) {
	g := newGroup(t, setup{n: 3, senders: map[int]int{0: 1}})
	g.run(90 * sec)
	g.stop(2)
	cut := g.clk.Mono()
	g.run(time.Minute)
	g.chat.mu.Lock()
	defer g.chat.mu.Unlock()
	for _, m := range g.chat.msgs {
		if strings.Contains(m.text, "r03 stopped answering") {
			if d := m.at - cut; d > 45*sec {
				t.Fatalf("the silence reached the chat %s after the cut, want within 45 s", d)
			}
			return
		}
	}
	t.Fatal("the silence never reached the chat")
}

// TestRestartDuringOutageOneMessage (D5): the whole site loses its internet;
// meanwhile one router restarts and, its internet still gone, records the
// loss again. That is the same outage: the chat gets one message for it,
// from its start to its end.
func TestRestartDuringOutageOneMessage(t *testing.T) {
	g := newGroup(t, setup{n: 3, senders: map[int]int{0: 1}})
	g.run(60 * sec)
	g.chat.setDown(true)
	for _, n := range g.nodes {
		n.LocalEvent(events.Event{Type: events.InternetLost})
	}
	g.run(2 * time.Minute)
	g.stop(2)
	g.run(time.Minute)
	c := g.reboot(2)
	g.run(30 * sec)
	c.LocalEvent(events.Event{Type: events.InternetLost})
	g.run(2 * time.Minute)
	g.chat.setDown(false)
	g.run(31 * sec)
	for _, n := range g.nodes {
		n.LocalEvent(events.Event{Type: events.InternetRestored})
	}
	g.run(2 * time.Minute)
	t.Logf("chat:\n%s", strings.Join(g.chat.all(), "\n"))
	ms := g.chat.messages("internet")
	if len(ms) != 1 || !strings.Contains(ms[0], "internet was down from 09:01 to 09:07") {
		t.Fatalf("messages about the internet %q; want one, from the start of the outage to its end", ms)
	}
}

// TestEndKnownWhileRateLimited (D5): another router loses its internet; the
// sender's first try to tell it is refused (rate limited), and the restore
// is recorded before the next try. The sender holds the loss back until
// the restore joins it: one message with the whole outage.
func TestEndKnownWhileRateLimited(t *testing.T) {
	g := newGroup(t, setup{n: 2, senders: map[int]int{0: 1}})
	g.run(90 * sec)
	g.chat.mu.Lock()
	g.chat.limited, g.chat.limitWait = 1, 30*sec
	g.chat.mu.Unlock()
	b := g.nodes[1]
	b.LocalEvent(events.Event{Type: events.InternetLost})
	g.run(35 * sec)
	b.LocalEvent(events.Event{Type: events.InternetRestored})
	g.run(time.Minute)
	t.Logf("chat:\n%s", strings.Join(g.chat.all(), "\n"))
	if ms := g.chat.messages("internet"); len(ms) != 1 || !strings.Contains(ms[0], "internet was down") {
		t.Fatalf("messages about the internet %q; want one with the whole outage", ms)
	}
}
