package node

import (
	"strings"
	"testing"
	"time"
)

// heldThenDown leaves r01, the sender of a group of two, holding r02's
// silence undelivered (Telegram is out), and then takes r01 down.
func heldThenDown(t *testing.T) *group {
	t.Helper()
	g := newGroup(t, setup{n: 2, senders: map[int]int{0: 1}})
	g.run(40 * sec)
	g.chat.setDown(true)
	g.stop(1)
	g.run(2 * time.Minute)
	if q := g.nodes[0].Status().Queued; q == 0 {
		t.Fatal("nothing queued while Telegram was out: the case did not happen")
	}
	g.stop(0)
	return g
}

// keptSilence reports whether n keeps an incident that tells r02's silence.
func keptSilence(n *Node) bool {
	for _, inc := range n.Status().Incidents {
		if strings.Contains(inc.Text, "r02 stopped answering at 09:00") {
			return true
		}
	}
	return false
}

// TestStaleIncidentNotSentAfterRestart (N3): a sender that held an incident
// undelivered comes back two days later. The incident stays kept but is
// not news any more: the chat does not get it.
func TestStaleIncidentNotSentAfterRestart(t *testing.T) {
	g := heldThenDown(t)
	g.clk.advance(48 * time.Hour)
	a := g.reboot(0)
	g.chat.setDown(false)
	g.run(2 * time.Minute)
	t.Logf("chat:\n%s", strings.Join(g.chat.all(), "\n"))
	if n := len(g.chat.messages("r02 stopped answering")); n != 0 {
		t.Fatalf("%d messages tell a silence of two days ago after the restart, want none", n)
	}
	if !keptSilence(a) {
		t.Fatal("the old incident is not kept after the restart")
	}
}

// TestStaleJudgedOnceTheClockIsTrusted (N3): the sender comes back two days
// later on a clock it does not trust yet, so it cannot tell the incident's
// age; it queues nothing until the clock is trusted, and then sees that the
// incident is too old.
func TestStaleJudgedOnceTheClockIsTrusted(t *testing.T) {
	g := heldThenDown(t)
	g.clk.advance(48 * time.Hour)
	a := g.reboot(0)
	a.SetClockTrusted(false)
	g.chat.setDown(false)
	g.run(30 * sec)
	a.SetClockTrusted(true)
	g.run(2 * time.Minute)
	t.Logf("chat:\n%s", strings.Join(g.chat.all(), "\n"))
	if n := len(g.chat.messages("r02 stopped answering")); n != 0 {
		t.Fatalf("%d messages tell a silence of two days ago, want none", n)
	}
}

// TestMergedStartNotSentAfterRestart (N3): a silence and the return that
// ends it were merged into one incident while Telegram was out, and the
// sender restarts before it could send it. After the restart the merged
// incident tells the absence once; the silence it merged is not queued
// again on its own.
func TestMergedStartNotSentAfterRestart(t *testing.T) {
	g := newGroup(t, setup{n: 3, senders: map[int]int{0: 1}})
	g.run(40 * sec)
	g.chat.setDown(true)
	g.stop(2)
	g.run(time.Minute)
	g.reboot(2)
	g.run(time.Minute)
	g.stop(0)
	a := g.reboot(0)
	g.run(sec)
	if q := a.Status().Queued; q != 1 {
		t.Fatalf("after the restart r01 queues %d incidents, want 1: the merged one, not the silence it tells", q)
	}
	g.chat.setDown(false)
	g.run(2 * time.Minute)
	t.Logf("chat:\n%s", strings.Join(g.chat.all(), "\n"))
	if ms := g.chat.messages("r03"); len(ms) != 1 || !strings.Contains(ms[0], "r03 rebooted unexpectedly at 09:00") {
		t.Fatalf("messages about r03 %q; want one that tells its reboot from its start", ms)
	}
}

// TestRestoredQueuedWithoutTrustedClock (N3): the sender comes back soon,
// on a clock it never comes to trust and with no peer to learn one from.
// Its incident's age cannot be judged, and it reaches the chat after
// restoreJudge.
func TestRestoredQueuedWithoutTrustedClock(t *testing.T) {
	g := heldThenDown(t)
	a := g.reboot(0)
	a.SetClockTrusted(false)
	g.chat.setDown(false)
	g.run(restoreJudge - 10*sec)
	if n := len(g.chat.messages("r02 stopped answering")); n != 0 {
		t.Fatalf("the restored incident went out before its age could be judged or restoreJudge passed (%d messages)", n)
	}
	g.run(time.Minute)
	t.Logf("chat:\n%s", strings.Join(g.chat.all(), "\n"))
	if n := len(g.chat.messages("r02 stopped answering at 09:00")); n != 1 {
		t.Fatalf("%d messages tell r02's silence after restoreJudge, want 1", n)
	}
}
