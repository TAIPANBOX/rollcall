package node

import (
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/history"
)

// TestUndeliveredSurvivesRestart (D19): an incident queued while Telegram
// was out and not yet sent when the sender restarts is queued again from
// what the store holds, and reaches the chat once Telegram is back.
func TestUndeliveredSurvivesRestart(t *testing.T) {
	g := newGroup(t, setup{n: 2, senders: map[int]int{0: 1}})
	g.run(40 * sec)
	g.chat.setDown(true)
	g.stop(1)
	g.run(2 * time.Minute)
	if q := g.nodes[0].Status().Queued; q == 0 {
		t.Fatal("nothing queued while Telegram was out: the case did not happen")
	}
	g.stop(0)
	g.reboot(0)
	g.chat.setDown(false)
	g.run(2 * time.Minute)
	t.Logf("chat:\n%s", strings.Join(g.chat.all(), "\n"))
	if n := len(g.chat.messages("r02 stopped answering at 09:00")); n != 1 {
		t.Fatalf("%d messages tell r02's silence, want 1: what was queued before the restart was lost", n)
	}
}

// TestAlarmSurvivesRestart (D7): a fork proof found less than a minute
// before a power cut is on flash at once, and its alarm, not yet delivered,
// is queued again after the restart: the router's own alarm record, read
// back, does not count as delivered.
func TestAlarmSurvivesRestart(t *testing.T) {
	g := newGroup(t, setup{n: 3, running: []bool{true, true, false}, senders: map[int]int{0: 1}})
	a, b := g.nodes[0], g.nodes[1]
	c := g.ids[2]
	g.run(10 * sec)
	g.chat.setDown(true)
	e1, _ := NewBoot(c, history.Head{}, BootBody{Boot: Boot{ID: bootN(2, 1), Seq: 1}, Version: "24.10.4"})
	e2, _ := NewBoot(c, history.Head{}, BootBody{Boot: Boot{ID: bootN(2, 1), Seq: 1}, Version: "24.10.5"})
	inject(a, e1)
	inject(b, e2)
	g.run(10 * sec)
	if len(alarms(a, "fork")) != 1 {
		t.Fatal("r01 did not find the fork: the case did not happen")
	}
	if _, err := g.stores[0].ReadFile(fileForks); err != nil {
		t.Fatalf("the fork proof is not on flash once found: %v", err)
	}
	g.stop(0)
	a = g.reboot(0)
	if fs := with(a, func() []history.ForkProof { return a.log.Forks() }); len(fs) != 1 {
		t.Fatalf("after the restart r01 holds %d fork proofs, want the one it found: a peer that asks cannot check its alarm", len(fs))
	}
	g.chat.setDown(false)
	g.run(time.Minute)
	t.Logf("chat:\n%s", strings.Join(g.chat.all(), "\n"))
	if n := len(g.chat.messages("r03 showed different histories")); n != 1 {
		t.Fatalf("%d fork alarms in the chat, want 1", n)
	}
	if st := stateOf(g.nodes[0].Status(), "r03"); st != "suspicious" {
		t.Fatalf("after the restart r01 sees r03 %q, want suspicious", st)
	}
}
