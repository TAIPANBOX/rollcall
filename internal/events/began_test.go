package events

import (
	"testing"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/clock"
	"github.com/TAIPANBOX/rollcall/internal/ids"
)

// TestBegan (Q2): an incident says it knows when its absence began when it
// holds a silence, or an own account of a return that gives its start; not
// for an own account without a start, nor for link events alone.
func TestBegan(t *testing.T) {
	x, y := ids.MemberID{1}, ids.MemberID{2}
	at := func(boot byte, d time.Duration) clock.Stamp {
		return clock.Stamp{Wall: time.Date(2026, 10, 22, 13, 0, 0, 0, time.UTC).Add(d), Mono: time.Hour + d, Trusted: true, Boot: ids.BootID{boot}}
	}
	own := Event{Type: RebootUnplanned, Subject: x, Witness: x, At: at(2, 3*time.Minute), Back: ids.BootID{2}, Ref: ids.Hash{1}}
	withSince := own
	withSince.Since = at(1, 0)
	cases := []struct {
		name string
		evs  []Event
		want bool
	}{
		{"own account with its start", []Event{withSince}, true},
		{"own account without a start", []Event{own}, false},
		{"a silence", []Event{{Type: MemberSilent, Subject: x, Witness: y, At: at(3, 0), Ref: ids.Hash{2}}}, true},
		{"link events only", []Event{{Type: InternetLost, Subject: y, Witness: y, At: at(3, 0), Ref: ids.Hash{3}}}, false},
	}
	for _, c := range cases {
		incs := Coalesce(c.evs, DefaultWindow)
		if len(incs) != 1 {
			t.Fatalf("%s: %d incidents, want 1", c.name, len(incs))
		}
		if incs[0].Began != c.want {
			t.Errorf("%s: Began = %v, want %v", c.name, incs[0].Began, c.want)
		}
	}
}
