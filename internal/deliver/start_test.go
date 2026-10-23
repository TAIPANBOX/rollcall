package deliver

import (
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/clock"
	"github.com/TAIPANBOX/rollcall/internal/events"
	"github.com/TAIPANBOX/rollcall/internal/ids"
)

// ownReturn returns a router's own account of its unplanned reboot, back at
// 14:05 local time; since, when not zero, is when its absence began.
func ownReturn(since clock.Stamp) events.Event {
	w := time.Date(2026, 10, 22, 13, 5, 0, 0, time.UTC)
	return events.Event{Type: events.RebootUnplanned, Subject: gwID, Witness: gwID,
		At:    clock.Stamp{Wall: w, Mono: time.Minute, Trusted: true, Boot: ids.BootID{2}},
		Since: since, Back: ids.BootID{2}, Ref: ids.Hash{7}}
}

// TestRenderStartFromOwnAccount (Q2): an incident that holds a router's own
// account of its return, with the moment its absence began and no silence,
// is told from that start: Render takes the start Coalesce set from Since.
func TestRenderStartFromOwnAccount(t *testing.T) {
	since := clock.Stamp{Wall: time.Date(2026, 10, 22, 13, 2, 0, 0, time.UTC), Mono: 2 * time.Hour, Trusted: true, Boot: ids.BootID{1}}
	incs := events.Coalesce([]events.Event{ownReturn(since)}, events.DefaultWindow)
	if len(incs) != 1 {
		t.Fatalf("Coalesce gave %d incidents, want 1", len(incs))
	}
	got := Render(incs[0], "Home", cet, Facts{Names: names})
	if want := "Home: gateway rebooted unexpectedly at 14:02, back after 3 min"; !strings.HasPrefix(got, want) {
		t.Errorf("Render = %q, want it to begin %q", got, want)
	}
}

// TestRenderStartUnknownWithoutSince (Q2): an own account that does not say
// when its absence began, and no silence, leaves the start unknown: the
// message tells the return only.
func TestRenderStartUnknownWithoutSince(t *testing.T) {
	incs := events.Coalesce([]events.Event{ownReturn(clock.Stamp{})}, events.DefaultWindow)
	if len(incs) != 1 {
		t.Fatalf("Coalesce gave %d incidents, want 1", len(incs))
	}
	got := Render(incs[0], "Home", cet, Facts{Names: names})
	if want := "Home: gateway rebooted unexpectedly, back at 14:05."; got != want {
		t.Errorf("Render = %q, want %q", got, want)
	}
}
