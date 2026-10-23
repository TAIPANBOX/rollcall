package node

import (
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/events"
	"github.com/TAIPANBOX/rollcall/internal/history"
)

// TestGoingDownReachesEveryPeer (D18): the announcement of a planned
// shutdown goes to every peer by unicast too, three times, so one lost
// heartbeat does not turn a planned reboot into an unexpected one.
func TestGoingDownReachesEveryPeer(t *testing.T) {
	g := newGroup(t, setup{n: 3})
	g.run(20 * sec)
	before := map[int]int{}
	count := func(i int) int {
		f := g.nets[0]
		f.mu.Lock()
		defer f.mu.Unlock()
		c := 0
		for _, a := range f.unis {
			if a == g.addrs[i] {
				c++
			}
		}
		return c
	}
	for _, i := range []int{1, 2} {
		before[i] = count(i)
	}
	g.nodes[0].GoingDown()
	for _, i := range []int{1, 2} {
		if got := count(i) - before[i]; got < 3 {
			t.Errorf("r%02d got the announcement by unicast %d times, want 3", i+1, got)
		}
	}
}

// TestOwnBootAccountWins (D18): a peer guessed an unplanned reboot (it
// missed the announcement); the router's own account, which says the reboot
// was planned, arrives later than the coalescing settle. The return waits
// for it, and the chat gets one message, as planned.
func TestOwnBootAccountWins(t *testing.T) {
	g := newGroup(t, setup{n: 4, running: []bool{true, true, false, false}, senders: map[int]int{0: 1}})
	g.run(40 * sec)
	x, guesser := g.ids[2], g.ids[3]
	now := AtOf(g.clk.stampNow())
	b1, b2 := Boot{ID: bootN(2, 1), Seq: 1}, Boot{ID: bootN(2, 2), Seq: 2}
	inject(g.nodes[0], forge(t, guesser, history.Head{},
		EventBody{Subject: x.ID, Type: events.RebootUnplanned, Last: b1, Back: b2, At: now})...)
	g.run(settle + 10*sec)
	boot, err := NewBoot(x, history.Head{}, BootBody{Boot: b2, Version: "24.10.4", Planned: true})
	if err != nil {
		t.Fatal(err)
	}
	own := forge(t, x, history.Head{Seq: boot.Seq, Hash: boot.Hash()},
		EventBody{Subject: x.ID, Type: events.RebootPlanned, Last: b1, Back: b2, At: shift(now, sec), Since: shift(now, -time.Minute)})
	inject(g.nodes[0], append([]history.Entry{boot}, own...)...)
	g.run(time.Minute)
	t.Logf("chat:\n%s", strings.Join(g.chat.all(), "\n"))
	ms := g.chat.messages("rebooted")
	if len(ms) != 1 || !strings.Contains(ms[0], "r03 rebooted as planned") {
		t.Fatalf("reboot messages %q; want one, as planned", ms)
	}
}

// TestLateGuessAbsorbed (D18): another member's guess at a return arrives
// after the member's own account of that return was told; it names the
// same boot, so it is the same return, and it sends nothing more.
func TestLateGuessAbsorbed(t *testing.T) {
	g := newGroup(t, setup{n: 4, running: []bool{true, true, false, false}, senders: map[int]int{0: 1}})
	g.run(40 * sec)
	x, guesser := g.ids[2], g.ids[3]
	now := AtOf(g.clk.stampNow())
	b1, b2 := Boot{ID: bootN(2, 1), Seq: 1}, Boot{ID: bootN(2, 2), Seq: 2}
	boot, err := NewBoot(x, history.Head{}, BootBody{Boot: b2, Version: "24.10.4", Planned: true})
	if err != nil {
		t.Fatal(err)
	}
	own := forge(t, x, history.Head{Seq: boot.Seq, Hash: boot.Hash()},
		EventBody{Subject: x.ID, Type: events.RebootPlanned, Last: b1, Back: b2, At: now, Since: shift(now, -time.Minute)})
	inject(g.nodes[0], append([]history.Entry{boot}, own...)...)
	g.run(time.Minute)
	if ms := g.chat.messages("rebooted"); len(ms) != 1 {
		t.Fatalf("reboot messages %q before the late guess, want 1", ms)
	}
	inject(g.nodes[0], forge(t, guesser, history.Head{},
		EventBody{Subject: x.ID, Type: events.RebootUnplanned, Last: b1, Back: b2, At: shift(now, 2*time.Minute)})...)
	g.run(time.Minute)
	t.Logf("chat:\n%s", strings.Join(g.chat.all(), "\n"))
	if ms := g.chat.messages("rebooted"); len(ms) != 1 {
		t.Fatalf("reboot messages %q; the late guess told the return again", ms)
	}
}
