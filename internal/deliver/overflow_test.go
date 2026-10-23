package deliver

import (
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/events"
)

// fill queues MaxQueued incidents and then over more, which are refused.
func fill(t *testing.T, q *Queue, over int, now time.Time) {
	t.Helper()
	for i := 1; i <= MaxQueued+over; i++ {
		if added := q.Add(incident(i, t0.Add(time.Duration(i)*time.Second)), now); added != (i <= MaxQueued) {
			t.Fatalf("Add %d = %v", i, added)
		}
	}
}

// renderAll renders like the node does: the overflow notice through Render.
func renderAll(inc events.Incident) string {
	if len(inc.Events) == 1 && inc.Events[0] == QueueFull {
		return Render(inc, "Home", time.UTC, Facts{})
	}
	return text(inc)
}

// TestOverflowToldOnce (Q1): when the queue is full and drops incidents,
// the sender tells the chat once, before anything else, and keeps the
// count; more drops within the hour tell nothing more, and drops after it
// tell it once again.
func TestOverflowToldOnce(t *testing.T) {
	q := NewQueue()
	ch := &fakeChannel{}
	fill(t, q, 3, t0)
	deliverAt := func(now time.Time) string {
		t.Helper()
		id, err := q.Deliver(t.Context(), ch, a, a, now, renderAll)
		if err != nil {
			t.Fatalf("Deliver: %v", err)
		}
		return id
	}
	deliverAt(t0)
	_, sent := ch.count()
	if len(sent) != 1 || !strings.Contains(sent[0], "Home: incidents were dropped") {
		t.Fatalf("the first message after the overflow is %q, want the notice that incidents were dropped", sent)
	}
	if st := q.Status(); st.Dropped != 3 {
		t.Errorf("Status.Dropped = %d, want 3", st.Dropped)
	}
	notices := func() int {
		_, sent := ch.count()
		return countPrefix(sent, "Home: incidents were dropped")
	}
	// No drop since the notice: incidents only, also an hour later.
	deliverAt(t0.Add(2 * Spacing))
	deliverAt(t0.Add(OverflowEvery + time.Minute))
	if n := notices(); n != 1 {
		t.Fatalf("%d notices without a drop since the first, want 1", n)
	}
	// Drops more than an hour after the notice are told once more, and
	// drops just after that tell nothing more within the hour.
	// refill fills the queue again and has n more Adds refused.
	refill := func(now time.Time, n int) {
		for i, refused := 0, 0; refused < n; i++ {
			if !q.Add(incident(7000+int(now.Sub(t0)/time.Second)*10+i, t0), now) {
				refused++
			}
		}
	}
	later := t0.Add(OverflowEvery + 2*time.Minute)
	refill(later, 2)
	deliverAt(later.Add(2 * Spacing))
	if n := notices(); n != 2 {
		t.Fatalf("%d notices after drops an hour later, want 2", n)
	}
	for i := 1; i <= 5; i++ {
		at := later.Add(time.Duration(i) * time.Minute)
		refill(at, 1)
		deliverAt(at.Add(2 * Spacing))
	}
	if n := notices(); n != 2 {
		t.Fatalf("%d notices after more drops within the hour, want 2", n)
	}
}

// TestOverflowNotToldWithoutDrop (Q1): a full queue that refused nothing
// tells nothing.
func TestOverflowNotToldWithoutDrop(t *testing.T) {
	q := NewQueue()
	ch := &fakeChannel{}
	fill(t, q, 0, t0)
	if _, err := q.Deliver(t.Context(), ch, a, a, t0, renderAll); err != nil {
		t.Fatal(err)
	}
	if _, sent := ch.count(); len(sent) != 1 || strings.Contains(sent[0], "dropped") {
		t.Fatalf("sent %q, want the oldest incident and no notice", sent)
	}
}

func countPrefix(ss []string, p string) int {
	n := 0
	for _, s := range ss {
		if strings.HasPrefix(s, p) {
			n++
		}
	}
	return n
}
