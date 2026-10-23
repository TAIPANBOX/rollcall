package node

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/clock"
	"github.com/TAIPANBOX/rollcall/internal/events"
	"github.com/TAIPANBOX/rollcall/internal/history"
	"github.com/TAIPANBOX/rollcall/internal/identity"
)

// reboot starts member i again after a power cut, in a new boot.
func (g *group) reboot(i int) *Node {
	g.t.Helper()
	g.cfgs[i].Boot, g.cfgs[i].BootSeq = bootN(i, 2), 2
	return g.start(i)
}

// ownReturns returns n's own events about itself of a return type.
func ownReturns(n *Node) []EventBody {
	var out []EventBody
	for _, e := range ownEntries(n, history.KindEvent) {
		b, err := DecodeEvent(e)
		if err != nil || b.Subject != n.id.ID || b.Detail["update"] != "" {
			continue
		}
		switch b.Type {
		case events.RebootUnplanned, events.RebootPlanned, events.Upgraded:
			out = append(out, b)
		}
	}
	return out
}

// TestOwnUnplannedRebootReported: a router alone in its group loses power
// and comes back; nobody saw it go, yet the chat gets one message that it
// rebooted unexpectedly, with the length of the absence, approximate since
// the router knows its last moment up only from its state on flash.
func TestOwnUnplannedRebootReported(t *testing.T) {
	g := newGroup(t, setup{n: 1, senders: map[int]int{0: 1}})
	g.run(40 * sec)
	g.stop(0)
	g.clk.advance(2 * time.Minute)
	g.reboot(0)
	g.run(time.Minute)
	t.Logf("chat:\n%s", strings.Join(g.chat.all(), "\n"))
	got := g.chat.messages("r01 rebooted unexpectedly at 09:00, back after 2 min")
	if len(got) != 1 || len(g.chat.messages("rebooted")) != 1 {
		t.Fatalf("reboot messages %q; want one that tells the absence with its length", g.chat.messages("rebooted"))
	}
	if !strings.Contains(got[0], "Times are approximate") {
		t.Fatalf("%q does not say its times are approximate", got[0])
	}
}

// TestSitePowerCutOneIncident: every router of a site loses power at once
// and comes back seconds apart, the last one more than the coalescing
// window after the first; no router saw another go. The chat gets exactly
// one message naming all three, with approximate times, and no silence.
func TestSitePowerCutOneIncident(t *testing.T) {
	g := newGroup(t, setup{n: 3, senders: map[int]int{0: 1}})
	g.run(40 * sec)
	for i := range 3 {
		g.stop(i)
	}
	g.clk.advance(2 * time.Minute)
	g.reboot(0)
	g.run(8 * sec)
	g.reboot(1)
	g.run(12 * sec)
	g.reboot(2)
	g.run(time.Minute)
	t.Logf("chat:\n%s", strings.Join(g.chat.all(), "\n"))
	got := g.chat.messages("rebooted")
	if len(got) != 1 {
		t.Fatalf("%d reboot messages %q, want exactly 1", len(got), got)
	}
	m := got[0]
	for _, w := range []string{"r01", "r02", "r03", "rebooted unexpectedly at 09:00, back after 3 min", "Times are approximate"} {
		if !strings.Contains(m, w) {
			t.Fatalf("%q does not contain %q", m, w)
		}
	}
	if s := g.chat.messages("stopped answering"); len(s) != 0 {
		t.Fatalf("silences nobody saw reached the chat: %q", s)
	}
}

// TestDaemonRestartNoEvent: the daemon restarts within one boot (same boot
// ID, a new boot sequence number): the router records nothing about itself
// and the chat gets nothing.
func TestDaemonRestartNoEvent(t *testing.T) {
	g := newGroup(t, setup{n: 2, senders: map[int]int{0: 1}})
	g.run(40 * sec)
	g.stop(1)
	g.run(3 * sec)
	g.cfgs[1].BootSeq = 2 // the same boot ID: only the daemon restarted
	g.start(1)
	g.run(time.Minute)
	t.Logf("chat:\n%s", strings.Join(g.chat.all(), "\n"))
	if rs := ownReturns(g.nodes[1]); len(rs) != 0 {
		t.Fatalf("a daemon restart recorded %+v", rs)
	}
	if m := g.chat.messages("rebooted"); len(m) != 0 {
		t.Fatalf("a daemon restart reached the chat: %q", m)
	}
}

// TestUpgradeOwnEvent: a router comes back with a new OpenWrt version: it
// records that it upgraded, with both versions, and the chat says so.
func TestUpgradeOwnEvent(t *testing.T) {
	g := newGroup(t, setup{n: 1, senders: map[int]int{0: 1}})
	g.run(40 * sec)
	g.stop(0)
	g.clk.advance(3 * time.Minute)
	g.cfgs[0].Versions[0] = "24.10.5"
	g.reboot(0)
	g.run(time.Minute)
	t.Logf("chat:\n%s", strings.Join(g.chat.all(), "\n"))
	rs := ownReturns(g.nodes[0])
	if len(rs) != 1 || rs[0].Type != events.Upgraded || rs[0].Detail["from"] != "24.10.4" || rs[0].Detail["to"] != "24.10.5" {
		t.Fatalf("own returns %+v; want one upgraded 24.10.4 -> 24.10.5", rs)
	}
	if n := len(g.chat.messages("r01 upgraded 24.10.4 -> 24.10.5 at 09:00, back after 3 min")); n != 1 || len(g.chat.messages("upgraded")) != 1 {
		t.Fatalf("upgrade messages %q; want one with both versions and the length", g.chat.messages("upgraded"))
	}
}

// TestOwnAndPeerViewMerge: a router announces its shutdown but the
// announcement is lost, so its peers see it go silent and guess an
// unplanned reboot when it comes back; the router itself knows it was
// planned. Its own record and the peers' records of the absence are one
// incident, the chat gets one return message that tells the router's own
// classification, and no update follows.
func TestOwnAndPeerViewMerge(t *testing.T) {
	g := newGroup(t, setup{n: 3, senders: map[int]int{0: 1}})
	g.run(40 * sec)
	g.split([]int{2}, []int{0, 1}, true)
	g.nodes[2].GoingDown()
	g.stop(2)
	g.split([]int{2}, []int{0, 1}, false)
	g.run(2 * time.Minute)
	g.cfgs[2].Planned = true
	c := g.reboot(2)
	g.run(time.Minute)
	t.Logf("chat:\n%s", strings.Join(g.chat.all(), "\n"))
	if n := len(g.chat.messages("r03 stopped answering at 09:00")); n != 1 {
		t.Fatalf("%d silence messages, want 1", n)
	}
	back := g.chat.messages("rebooted")
	if len(back) != 1 || !strings.Contains(back[0], "r03 rebooted as planned at 09:00, back after 2 min") {
		t.Fatalf("return messages %q; want one that tells the planned reboot from its start", back)
	}
	if us := updateEvents(c); len(us) != 0 {
		t.Fatalf("r03 recorded updates %+v though its own record told the class", us)
	}
	self := g.ids[2].ID
	for i, n := range g.nodes {
		ok := with(n, func() bool {
			for _, r := range n.inc.recent {
				own := slices.ContainsFunc(r.events, func(e events.Event) bool { return events.Own(e) && e.Subject == self })
				peer := slices.ContainsFunc(r.events, func(e events.Event) bool {
					return e.Subject == self && e.Witness != self && e.Type == events.RebootUnplanned
				})
				if own {
					return peer
				}
			}
			return false
		})
		if !ok {
			t.Fatalf("r%02d holds no incident with both r03's own record and a peer's guess", i+1)
		}
	}
}

// TestStartOnlyFromSubject: a member says when its own absence began; a
// start on another member's record of it is not read.
func TestStartOnlyFromSubject(t *testing.T) {
	a, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	b, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	at := AtOf(clock.Stamp{Wall: tStart, Mono: time.Minute, Trusted: true, Boot: bootN(0, 2)})
	since := AtOf(clock.Stamp{Wall: tStart.Add(-time.Minute), Mono: time.Hour, Boot: bootN(0, 1)})
	body := EventBody{Subject: a.ID, Type: events.RebootUnplanned, At: at, Since: since}
	theirs := forge(t, b, history.Head{}, body)[0]
	mine := forge(t, a, history.Head{}, body)[0]
	if ev := eventOf(theirs, body); ev.Since != (clock.Stamp{}) {
		t.Fatalf("another member's start was read: %+v", ev.Since)
	}
	if ev := eventOf(mine, body); ev.Since != since.Stamp() || !events.Own(ev) {
		t.Fatalf("the member's own start %+v, want %+v", ev.Since, since.Stamp())
	}
}

// readAlive returns the alive file of member i, and whether there is one.
func (g *group) readAlive(i int) (aliveFile, bool) {
	g.t.Helper()
	b, err := g.stores[i].ReadFile(fileAlive)
	if err != nil {
		return aliveFile{}, false
	}
	var a aliveFile
	if err := decodeJSON(b, &a, 1024); err != nil {
		g.t.Fatalf("alive file %s: %v", b, err)
	}
	return a, true
}

// TestAliveFileCadence: the alive file is written at most once a minute,
// only once this boot's record is in the chain, and at once when the router
// announces its shutdown, after which it stays as written.
func TestAliveFileCadence(t *testing.T) {
	t.Run("once a minute, then at the announcement", func(t *testing.T) {
		g := newGroup(t, setup{n: 2})
		g.run(3 * sec) // the boot record lands in the second second's catch-up
		first, ok := g.readAlive(0)
		if !ok || first.Boot != (Boot{ID: bootN(0, 1), Seq: 1}) || first.Down || first.Version != "24.10.4" {
			t.Fatalf("alive file after the first catch-up: %+v, %v", first, ok)
		}
		g.run(50 * sec)
		if a, _ := g.readAlive(0); a != first {
			t.Fatalf("written again within a minute: %+v, then %+v", first, a)
		}
		g.run(15 * sec)
		second, _ := g.readAlive(0)
		if d := second.At.Wall.Sub(first.At.Wall); d < time.Minute || d > time.Minute+2*sec {
			t.Fatalf("the second write came %v after the first, want a minute", d)
		}
		g.clk.advance(7 * sec)
		g.nodes[0].GoingDown()
		down, _ := g.readAlive(0)
		if !down.Down || !down.At.Wall.Equal(g.clk.Now()) {
			t.Fatalf("at the announcement: %+v, want down at %v", down, g.clk.Now())
		}
		g.run(2 * time.Minute)
		if a, _ := g.readAlive(0); a != down {
			t.Fatalf("changed after the announcement: %+v", a)
		}
	})
	t.Run("not before this boot's record", func(t *testing.T) {
		g := newGroup(t, setup{n: 2, running: []bool{true, false}})
		g.run(50 * sec)
		if a, ok := g.readAlive(0); ok {
			t.Fatalf("an alive file before the own chain was caught up: %+v", a)
		}
		g.run(15 * sec)
		if _, ok := g.readAlive(0); !ok {
			t.Fatal("no alive file once the wait for the own chain was over")
		}
	})
}

// TestRestartBeforeCatchUpStillReports: a router comes back from a power
// cut, and its daemon restarts before the router could catch up its own
// chain; the next run still finds the boot before and records the reboot.
func TestRestartBeforeCatchUpStillReports(t *testing.T) {
	g := newGroup(t, setup{n: 2, senders: map[int]int{0: 1}})
	g.run(70 * sec)
	g.stop(1)
	g.run(40 * sec)
	g.split([]int{1}, []int{0}, true)
	g.reboot(1)
	g.run(10 * sec)
	g.stop(1)
	g.cfgs[1].BootSeq = 3 // the same boot: only the daemon restarted
	g.start(1)
	g.split([]int{1}, []int{0}, false)
	g.run(time.Minute)
	t.Logf("chat:\n%s", strings.Join(g.chat.all(), "\n"))
	rs := ownReturns(g.nodes[1])
	if len(rs) != 1 || rs[0].Type != events.RebootUnplanned || rs[0].Last.ID != bootN(1, 1) || rs[0].Back != (Boot{ID: bootN(1, 2), Seq: 3}) {
		t.Fatalf("own returns %+v; want one unplanned reboot from boot 1 into boot 2", rs)
	}
	if n := len(g.chat.messages("rebooted")); n != 1 {
		t.Fatalf("%d reboot messages, want 1", n)
	}
}
