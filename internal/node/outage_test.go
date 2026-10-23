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
