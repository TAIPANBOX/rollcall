package node

import (
	"testing"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/clock"
	"github.com/TAIPANBOX/rollcall/internal/events"
)

// TestUntrustedStartCorrected (design 4.4): with its own clock untrusted, a
// router records an event whose start the caller gave (the internet lost
// since the first failed probe) on the clock a trusted peer taught it, and
// still marks it approximate.
func TestUntrustedStartCorrected(t *testing.T) {
	g := newGroup(t, setup{n: 2})
	a := g.nodes[0]
	a.SetClockTrusted(false)
	g.run(20 * sec)
	now, mono := g.clk.Now(), g.clk.Mono()
	a.LocalEvent(events.Event{Type: events.InternetLost,
		At: clock.Stamp{Wall: now.Add(-365 * 24 * time.Hour), Mono: mono - 5*sec, Boot: bootN(0, 1)}})
	e := eventOfType(t, a, events.InternetLost, a.id.ID)
	b, err := DecodeEvent(e)
	if err != nil {
		t.Fatal(err)
	}
	if want := now.Add(-5 * sec); !b.At.Wall.Equal(want) || b.At.Trusted {
		t.Fatalf("start recorded at %v (trusted %v); want %v on the peer's clock, untrusted", b.At.Wall, b.At.Trusted, want)
	}
}
