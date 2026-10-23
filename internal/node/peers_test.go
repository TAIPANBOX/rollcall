package node

import (
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/events"
	"github.com/TAIPANBOX/rollcall/internal/history"
)

// TestRestartRemembersAwayPeer (D14): the daemon of a router restarts while
// a peer is away. It still knows the peer from its store: it does not report
// the absence a second time from its own start, and when the peer comes back
// in a new boot it records a reboot, not a bare return.
func TestRestartRemembersAwayPeer(t *testing.T) {
	g := newGroup(t, setup{n: 3, senders: map[int]int{0: 1}})
	g.run(40 * sec)
	g.stop(2)
	g.run(2 * time.Minute)
	g.stop(0)
	g.cfgs[0].BootSeq = 2 // the same boot: only the daemon restarted
	a := g.start(0)
	g.run(time.Minute)
	g.reboot(2)
	g.run(time.Minute)
	t.Logf("chat:\n%s", strings.Join(g.chat.all(), "\n"))
	if n := len(g.chat.messages("r03 stopped answering")); n != 1 {
		t.Fatalf("%d messages tell r03's silence, want 1", n)
	}
	var got []events.Type
	for _, e := range ownEntries(a, history.KindEvent) {
		if b, err := DecodeEvent(e); err == nil && b.Subject == g.ids[2].ID && b.Type != events.MemberSilent && absence(b.Type) {
			got = append(got, b.Type)
		}
	}
	if len(got) != 1 || got[0] != events.RebootUnplanned {
		t.Fatalf("r01 recorded r03's return as %v, want one reboot_unplanned", got)
	}
}
