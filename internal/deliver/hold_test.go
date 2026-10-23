package deliver

import (
	"slices"
	"testing"
	"time"
)

// TestHoldPassesOverOnlyTheHeld (N2): an incident held back is not due and
// not sent, the incidents after it are, and it is sent once a later Hold
// leaves it out.
func TestHoldPassesOverOnlyTheHeld(t *testing.T) {
	q := NewQueue()
	ch := &fakeChannel{}
	held, other := incident(1, t0), incident(2, t0.Add(time.Second))
	q.Add(held, t0)
	q.Add(other, t0)
	q.Hold([]string{held.ID})
	if got := idsOf(q.Due(a, a, t0)); !slices.Equal(got, []string{other.ID}) {
		t.Fatalf("Due with %s held = %v, want only %s", held.ID, got, other.ID)
	}
	if id, err := deliver(t, q, ch, a, a, t0); id != other.ID || err != nil {
		t.Fatalf("Deliver with %s held = %q, %v; want %s, the one not held", held.ID, id, err, other.ID)
	}
	if id, _ := deliver(t, q, ch, a, a, t0.Add(2*Spacing)); id != "" {
		t.Fatalf("Deliver sent %q while it was held", id)
	}
	q.Hold(nil)
	if id, err := deliver(t, q, ch, a, a, t0.Add(4*Spacing)); id != held.ID || err != nil {
		t.Fatalf("Deliver once nothing is held = %q, %v; want %s", id, err, held.ID)
	}
}
