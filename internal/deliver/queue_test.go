package deliver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/clock"
	"github.com/TAIPANBOX/rollcall/internal/events"
	"github.com/TAIPANBOX/rollcall/internal/history"
	"github.com/TAIPANBOX/rollcall/internal/ids"
)

// t0 is the start of every queue fixture.
var t0 = time.Date(2026, 10, 22, 14, 0, 0, 0, time.UTC)

// a, b and c are three members; a ranks first as a sender in the fixtures.
var (
	a = member(0x0a)
	b = member(0x0b)
	c = member(0x0c)
)

// incident returns an incident whose ID is n as 16 hex digits, which started
// at start.
func incident(n int, start time.Time) events.Incident {
	return events.Incident{
		ID:      fmt.Sprintf("%016x", n),
		Start:   clock.Stamp{Wall: start, Trusted: true},
		End:     clock.Stamp{Wall: start, Trusted: true},
		Members: []string{kitchen},
		Causes:  1,
		Events:  []events.Type{events.MemberSilent},
	}
}

func text(inc events.Incident) string { return "about " + inc.ID }

// fakeChannel records what it is given and answers with errs in turn, then
// with nil.
type fakeChannel struct {
	mu    sync.Mutex
	errs  []error
	calls int
	sent  []string // texts whose Send returned nil
	hold  chan struct{}
	in    chan struct{}
}

func (f *fakeChannel) Send(ctx context.Context, text string) error {
	f.mu.Lock()
	f.calls++
	var err error
	if len(f.errs) > 0 {
		err, f.errs = f.errs[0], f.errs[1:]
	}
	hold, in := f.hold, f.in
	f.mu.Unlock()
	if in != nil {
		in <- struct{}{}
	}
	if hold != nil {
		<-hold
	}
	if err == nil {
		f.mu.Lock()
		f.sent = append(f.sent, text)
		f.mu.Unlock()
	}
	return err
}

func (f *fakeChannel) Ping(context.Context) error { return nil }

func (f *fakeChannel) count() (calls int, sent []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls, slices.Clone(f.sent)
}

// deliver runs q.Deliver with the fixtures' context and text.
func deliver(t *testing.T, q *Queue, ch Channel, self, sender ids.MemberID, now time.Time) (string, error) {
	t.Helper()
	return q.Deliver(context.Background(), ch, self, sender, now, text)
}

func idsOf(incs []events.Incident) []string {
	var out []string
	for _, i := range incs {
		out = append(out, i.ID)
	}
	return out
}

func TestOnlySenderSends(t *testing.T) {
	qa, qb, qc := NewQueue(), NewQueue(), NewQueue()
	chA, chB, chC := &fakeChannel{}, &fakeChannel{}, &fakeChannel{}
	inc := incident(1, t0)
	for _, q := range []*Queue{qa, qb, qc} {
		if !q.Add(inc, t0) {
			t.Fatal("Add refused a new incident")
		}
	}
	if got := idsOf(qa.Due(a, a, t0)); !slices.Equal(got, []string{inc.ID}) {
		t.Errorf("sender: Due = %v, want [%s]", got, inc.ID)
	}
	if got := qb.Due(b, a, t0); len(got) != 0 {
		t.Errorf("not the sender: Due = %v, want none", idsOf(got))
	}
	// A minute of ticks: the sender sends once, the others never, however
	// long the incident waits for them.
	for d := time.Duration(0); d <= time.Minute; d += 500 * time.Millisecond {
		if _, err := deliver(t, qa, chA, a, a, t0.Add(d)); err != nil {
			t.Fatalf("sender: Deliver: %v", err)
		}
		for _, m := range []struct {
			q    *Queue
			ch   *fakeChannel
			self ids.MemberID
		}{{qb, chB, b}, {qc, chC, c}} {
			if id, err := deliver(t, m.q, m.ch, m.self, a, t0.Add(d)); id != "" || err != nil {
				t.Fatalf("not the sender at +%v: Deliver = %q, %v", d, id, err)
			}
		}
	}
	if calls, sent := chA.count(); calls != 1 || len(sent) != 1 {
		t.Errorf("sender: %d calls, %d sent; want 1 and 1", calls, len(sent))
	}
	for _, ch := range []*fakeChannel{chB, chC} {
		if calls, _ := ch.count(); calls != 0 {
			t.Errorf("a member that is not the sender called Send %d times", calls)
		}
	}
	if got := qb.Status().Queued; got != 1 {
		t.Errorf("not the sender: Queued = %d, want 1 (kept until acknowledged)", got)
	}
}

func TestNobodySendsWithoutSender(t *testing.T) {
	q := NewQueue()
	ch := &fakeChannel{}
	q.Add(incident(1, t0), t0)
	var none ids.MemberID
	for d := time.Duration(0); d <= time.Minute; d += time.Second {
		if got := q.Due(a, none, t0.Add(d)); len(got) != 0 {
			t.Fatalf("no sender: Due = %v", idsOf(got))
		}
		if id, _ := deliver(t, q, ch, a, none, t0.Add(d)); id != "" {
			t.Fatalf("no sender: Deliver sent %q", id)
		}
		// A zero self is never the sender, not even of a zero sender.
		if got := q.Due(none, none, t0.Add(d)); len(got) != 0 {
			t.Fatalf("zero self: Due = %v", idsOf(got))
		}
	}
	if calls, _ := ch.count(); calls != 0 {
		t.Errorf("Send called %d times", calls)
	}
}

func TestGraceTakeover(t *testing.T) {
	if Grace != 15*time.Second {
		t.Fatalf("Grace = %v, want 15s (design 4.5)", Grace)
	}
	q := NewQueue()
	ch := &fakeChannel{}
	old := incident(1, t0)
	q.Add(old, t0)
	// a is the sender until b's view holds it silent at t0+5s.
	for d := time.Duration(0); d < 5*time.Second; d += time.Second {
		if got := q.Due(b, a, t0.Add(d)); len(got) != 0 {
			t.Fatalf("a still the sender: Due = %v", idsOf(got))
		}
	}
	// From t0+5s b is the sender. The incident reached b while a was the
	// sender, so b sends it only once it has stayed unacknowledged for 15 s.
	if got := q.Due(b, b, t0.Add(5*time.Second)); len(got) != 0 {
		t.Errorf("takeover, unacknowledged 5 s: Due = %v, want none", idsOf(got))
	}
	// An incident that reaches b after it became the sender is b's at once.
	fresh := incident(2, t0.Add(6*time.Second))
	q.Add(fresh, t0.Add(6*time.Second))
	if got := idsOf(q.Due(b, b, t0.Add(6*time.Second))); !slices.Equal(got, []string{fresh.ID}) {
		t.Errorf("incident after the takeover: Due = %v, want [%s]", got, fresh.ID)
	}
	if got := idsOf(q.Due(b, b, t0.Add(15*time.Second-time.Nanosecond))); !slices.Equal(got, []string{fresh.ID}) {
		t.Errorf("unacknowledged 15 s - 1 ns: Due = %v, want [%s]", got, fresh.ID)
	}
	if got := idsOf(q.Due(b, b, t0.Add(15*time.Second))); !slices.Equal(got, []string{old.ID, fresh.ID}) {
		t.Errorf("unacknowledged 15 s: Due = %v, want [%s %s]", got, old.ID, fresh.ID)
	}
	// c, which sees b as the sender, waits for b.
	qc := NewQueue()
	qc.Add(old, t0)
	if got := qc.Due(c, b, t0.Add(time.Hour)); len(got) != 0 {
		t.Errorf("third member: Due = %v, want none", idsOf(got))
	}
	// b delivers both, oldest first, one per second.
	if id, err := deliver(t, q, ch, b, b, t0.Add(15*time.Second)); id != old.ID || err != nil {
		t.Errorf("Deliver = %q, %v; want %q", id, err, old.ID)
	}
	if id, err := deliver(t, q, ch, b, b, t0.Add(16*time.Second)); id != fresh.ID || err != nil {
		t.Errorf("Deliver = %q, %v; want %q", id, err, fresh.ID)
	}
}

// TestTakeoverAgainAfterLosingTheRole: a member that stops being the sender
// and becomes it again treats what it received meanwhile as inherited.
func TestTakeoverAgainAfterLosingTheRole(t *testing.T) {
	q := NewQueue()
	q.Due(b, b, t0) // b has been the sender since t0
	q.Due(b, a, t0.Add(10*time.Second))
	q.Add(incident(1, t0.Add(20*time.Second)), t0.Add(20*time.Second))
	if got := q.Due(b, b, t0.Add(30*time.Second)); len(got) != 0 {
		t.Errorf("sender again after a gap, incident 10 s old: Due = %v, want none", idsOf(got))
	}
	if got := q.Due(b, b, t0.Add(35*time.Second)); len(got) != 1 {
		t.Errorf("incident 15 s old: Due = %v, want it", idsOf(got))
	}
}

func TestAckStopsOthers(t *testing.T) {
	q := NewQueue()
	ch := &fakeChannel{}
	inc := incident(1, t0)
	q.Add(inc, t0)
	q.Due(b, a, t0)
	// a sends and its acknowledgement reaches b through the history.
	q.Ack(inc.ID, a)
	if got := q.Status().Queued; got != 0 {
		t.Errorf("after the ack: Queued = %d, want 0", got)
	}
	// a goes silent; b becomes the sender and has nothing to send.
	for d := 5 * time.Second; d <= time.Minute; d += time.Second {
		if got := q.Due(b, b, t0.Add(d)); len(got) != 0 {
			t.Fatalf("after the ack: Due = %v", idsOf(got))
		}
		if id, _ := deliver(t, q, ch, b, b, t0.Add(d)); id != "" {
			t.Fatalf("after the ack: Deliver sent %q", id)
		}
	}
	// The incident coalesced again later is not queued again.
	if q.Add(inc, t0.Add(2*time.Minute)) {
		t.Error("Add queued an acknowledged incident again")
	}
	// An ack that arrives before its incident keeps the incident out.
	early := incident(2, t0)
	q.Ack(early.ID, a)
	if q.Add(early, t0) {
		t.Error("Add queued an incident acknowledged before it arrived")
	}
	if calls, _ := ch.count(); calls != 0 {
		t.Errorf("Send called %d times", calls)
	}
}

func TestAckOnlyFromAMember(t *testing.T) {
	q := NewQueue()
	inc := incident(1, t0)
	q.Add(inc, t0)
	q.Ack(inc.ID, ids.MemberID{})
	if got := q.Status().Queued; got != 1 {
		t.Errorf("ack by the zero ID: Queued = %d, want 1", got)
	}
	for _, bad := range []string{"", "0", "00000000000000001", strings.ToUpper("000000000000000a"), "000000000000000g", " 000000000000001"} {
		q.Ack(bad, a)
	}
	if got := q.Status().Queued; got != 1 {
		t.Errorf("acks of malformed IDs: Queued = %d, want 1", got)
	}
	// Malformed and anonymous acks take no room: they cannot push a real
	// ack out of what the queue remembers.
	q.Ack("0000000000000002", b)
	for i := 0; i < MaxDone; i++ {
		q.Ack(fmt.Sprintf("bad-%d", i), b)
		q.Ack(fmt.Sprintf("%016x", 1<<40+i), ids.MemberID{})
	}
	if q.Add(incident(2, t0), t0) {
		t.Error("malformed or anonymous acks pushed out a real one")
	}
}

func TestAddDeduplicates(t *testing.T) {
	q := NewQueue()
	ch := &fakeChannel{}
	inc := incident(1, t0)
	if !q.Add(inc, t0) {
		t.Fatal("Add refused a new incident")
	}
	for i := 0; i < 3; i++ {
		if q.Add(inc, t0.Add(time.Duration(i)*time.Second)) {
			t.Errorf("Add %d of the same ID queued it again", i+2)
		}
	}
	if got := q.Status().Queued; got != 1 {
		t.Errorf("Queued = %d, want 1", got)
	}
	for d := time.Duration(0); d < 10*time.Second; d += time.Second {
		deliver(t, q, ch, a, a, t0.Add(d))
	}
	// Coalesced again after it was sent: not queued, not sent again.
	if q.Add(inc, t0.Add(20*time.Second)) {
		t.Error("Add queued an incident this member already sent")
	}
	deliver(t, q, ch, a, a, t0.Add(30*time.Second))
	if _, sent := ch.count(); len(sent) != 1 {
		t.Errorf("sent %d times, want 1", len(sent))
	}
}

func TestAddRefusesMalformedID(t *testing.T) {
	q := NewQueue()
	for _, id := range []string{"", "0123456789abcde", "0123456789abcdef0", "0123456789ABCDEF", "0123456789abcdeg", "0123456789abcde\n"} {
		inc := incident(1, t0)
		inc.ID = id
		if q.Add(inc, t0) {
			t.Errorf("Add accepted ID %q", id)
		}
	}
	if got := q.Status().Queued; got != 0 {
		t.Errorf("Queued = %d, want 0", got)
	}
}

func TestDueOldestFirst(t *testing.T) {
	q := NewQueue()
	ch := &fakeChannel{}
	// Added in another order than they happened; two start together and
	// go by ID.
	q.Add(incident(3, t0.Add(2*time.Minute)), t0)
	q.Add(incident(9, t0.Add(time.Minute)), t0)
	q.Add(incident(1, t0.Add(3*time.Minute)), t0)
	q.Add(incident(4, t0.Add(time.Minute)), t0)
	q.Add(incident(2, t0), t0)
	want := []string{"0000000000000002", "0000000000000004", "0000000000000009", "0000000000000003", "0000000000000001"}
	if got := idsOf(q.Due(a, a, t0)); !slices.Equal(got, want) {
		t.Errorf("Due = %v, want %v", got, want)
	}
	for d := time.Duration(0); d < 10*time.Second; d += time.Second {
		deliver(t, q, ch, a, a, t0.Add(d))
	}
	_, sent := ch.count()
	var got []string
	for _, s := range sent {
		got = append(got, strings.Fields(s)[1])
	}
	if !slices.Equal(got, want) {
		t.Errorf("sent %v, want %v", got, want)
	}
}

func TestAtMostOnePerSecond(t *testing.T) {
	if Spacing != time.Second {
		t.Fatalf("Spacing = %v, want 1s", Spacing)
	}
	q := NewQueue()
	ch := &fakeChannel{}
	for i := 1; i <= 5; i++ {
		q.Add(incident(i, t0), t0)
	}
	var at []time.Duration
	for d := time.Duration(0); d <= 10*time.Second; d += 100 * time.Millisecond {
		for k := 0; k < 3; k++ { // several ticks at one moment
			if id, err := deliver(t, q, ch, a, a, t0.Add(d)); err != nil {
				t.Fatalf("Deliver: %v", err)
			} else if id != "" {
				at = append(at, d)
			}
		}
	}
	want := []time.Duration{0, time.Second, 2 * time.Second, 3 * time.Second, 4 * time.Second}
	if !slices.Equal(at, want) {
		t.Errorf("sent at %v, want %v", at, want)
	}
	// The spacing holds right at its edge.
	q2 := NewQueue()
	ch2 := &fakeChannel{}
	q2.Add(incident(1, t0), t0)
	q2.Add(incident(2, t0), t0)
	deliver(t, q2, ch2, a, a, t0)
	if id, _ := deliver(t, q2, ch2, a, a, t0.Add(time.Second-time.Nanosecond)); id != "" {
		t.Errorf("1 s - 1 ns after a send: Deliver sent %q", id)
	}
	if id, _ := deliver(t, q2, ch2, a, a, t0.Add(time.Second)); id == "" {
		t.Error("1 s after a send: Deliver sent nothing")
	}
}

func TestBlockedBotKeepsQueue(t *testing.T) {
	if BlockedRetry != 5*time.Minute {
		t.Fatalf("BlockedRetry = %v, want 5m", BlockedRetry)
	}
	q := NewQueue()
	ch := &fakeChannel{errs: []error{ErrBlocked}} // 403, then 200
	inc := incident(1, t0)
	q.Add(inc, t0)
	id, err := deliver(t, q, ch, a, a, t0)
	if id != "" || !errors.Is(err, ErrBlocked) {
		t.Fatalf("Deliver = %q, %v; want \"\", ErrBlocked", id, err)
	}
	st := q.Status()
	if st.Problem != "bot blocked" || st.Queued != 1 {
		t.Errorf("Status = %+v, want Problem \"bot blocked\" and Queued 1", st)
	}
	// The owner unblocks the bot at some point; nothing is tried before the
	// five minutes are up.
	for d := time.Second; d < 5*time.Minute; d += time.Second {
		if id, err := deliver(t, q, ch, a, a, t0.Add(d)); id != "" || err != nil {
			t.Fatalf("blocked, +%v: Deliver = %q, %v", d, id, err)
		}
	}
	if calls, _ := ch.count(); calls != 1 {
		t.Fatalf("Send called %d times while blocked, want 1", calls)
	}
	if id, err := deliver(t, q, ch, a, a, t0.Add(5*time.Minute)); id != inc.ID || err != nil {
		t.Fatalf("after 5 min: Deliver = %q, %v; want %q", id, err, inc.ID)
	}
	if st := q.Status(); st.Problem != "" || st.Queued != 0 {
		t.Errorf("after the send: Status = %+v, want no problem and nothing queued", st)
	}
	for d := 5*time.Minute + time.Second; d < 7*time.Minute; d += time.Second {
		deliver(t, q, ch, a, a, t0.Add(d))
	}
	if _, sent := ch.count(); len(sent) != 1 {
		t.Errorf("the incident was sent %d times, want once", len(sent))
	}
}

// TestBlockedUntilASendSucceeds: other failures in between do not end the
// five-minute rhythm; only a successful send does.
func TestBlockedUntilASendSucceeds(t *testing.T) {
	q := NewQueue()
	ch := &fakeChannel{errs: []error{ErrBlocked, ErrTLS, errors.New("timeout"), nil}}
	q.Add(incident(1, t0), t0)
	q.Add(incident(2, t0), t0)
	var tries []time.Duration
	for d := time.Duration(0); d <= 21*time.Minute; d += time.Second {
		before, _ := ch.count()
		deliver(t, q, ch, a, a, t0.Add(d))
		if after, _ := ch.count(); after > before {
			tries = append(tries, d)
		}
	}
	want := []time.Duration{0, 5 * time.Minute, 10 * time.Minute, 15 * time.Minute, 15*time.Minute + time.Second}
	if !slices.Equal(tries, want) {
		t.Errorf("tries at %v, want %v", tries, want)
	}
}

func TestRetryAfterHonoured(t *testing.T) {
	q := NewQueue()
	ch := &fakeChannel{errs: []error{&RateLimitError{RetryAfter: 7 * time.Second}}}
	inc := incident(1, t0)
	q.Add(inc, t0)
	id, err := deliver(t, q, ch, a, a, t0)
	var rl *RateLimitError
	if id != "" || !errors.Is(err, ErrRateLimited) || !errors.As(err, &rl) || rl.RetryAfter != 7*time.Second {
		t.Fatalf("Deliver = %q, %v; want \"\", a RateLimitError of 7s", id, err)
	}
	st := q.Status()
	if st.Problem != "rate limited until 14:00:07" || !st.Until.Equal(t0.Add(7*time.Second)) || st.Queued != 1 {
		t.Errorf("Status = %+v, want rate limited until 14:00:07 with the incident queued", st)
	}
	for d := 100 * time.Millisecond; d < 7*time.Second; d += 100 * time.Millisecond {
		if id, _ := deliver(t, q, ch, a, a, t0.Add(d)); id != "" {
			t.Fatalf("+%v: sent before retry_after", d)
		}
	}
	if id, _ := deliver(t, q, ch, a, a, t0.Add(7*time.Second-time.Nanosecond)); id != "" {
		t.Fatal("7 s - 1 ns: sent before retry_after")
	}
	if id, err := deliver(t, q, ch, a, a, t0.Add(7*time.Second)); id != inc.ID || err != nil {
		t.Errorf("7 s: Deliver = %q, %v; want %q", id, err, inc.ID)
	}
	if st := q.Status(); st.Problem != "" || !st.Until.IsZero() {
		t.Errorf("after the send: Status = %+v, want no problem", st)
	}
}

func TestRetryAfterBounds(t *testing.T) {
	if DefaultRetryAfter != 5*time.Second || MaxRetryAfter != time.Hour {
		t.Fatalf("DefaultRetryAfter = %v, MaxRetryAfter = %v", DefaultRetryAfter, MaxRetryAfter)
	}
	cases := []struct {
		name string
		err  error
		wait time.Duration
	}{
		{"retry_after 0: as if not given", &RateLimitError{}, 5 * time.Second},
		{"negative: as if not given", &RateLimitError{RetryAfter: -time.Hour}, 5 * time.Second},
		{"below the spacing: the spacing", &RateLimitError{RetryAfter: time.Millisecond}, time.Second},
		{"no retry_after given", ErrRateLimited, 5 * time.Second},
		{"wrapped without retry_after", fmt.Errorf("ntfy: %w", ErrRateLimited), 5 * time.Second},
		{"wrapped with retry_after", fmt.Errorf("telegram: %w", &RateLimitError{RetryAfter: 30 * time.Second}), 30 * time.Second},
		{"far too long: an hour", &RateLimitError{RetryAfter: 300 * time.Hour}, time.Hour},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			q := NewQueue()
			ch := &fakeChannel{errs: []error{c.err}}
			q.Add(incident(1, t0), t0)
			deliver(t, q, ch, a, a, t0)
			if st := q.Status(); !st.Until.Equal(t0.Add(c.wait)) {
				t.Errorf("Until = %v, want %v", st.Until, t0.Add(c.wait))
			}
			if id, _ := deliver(t, q, ch, a, a, t0.Add(c.wait-time.Nanosecond)); id != "" {
				t.Errorf("sent %v early", time.Nanosecond)
			}
			if id, _ := deliver(t, q, ch, a, a, t0.Add(c.wait)); id == "" {
				t.Errorf("not sent after %v", c.wait)
			}
		})
	}
}

func TestTLSErrorKeepsQueue(t *testing.T) {
	q := NewQueue()
	ch := &fakeChannel{errs: []error{fmt.Errorf("telegram: %w", ErrTLS)}}
	inc := incident(1, t0)
	q.Add(inc, t0)
	if id, err := deliver(t, q, ch, a, a, t0); id != "" || !errors.Is(err, ErrTLS) {
		t.Fatalf("Deliver = %q, %v; want \"\", ErrTLS", id, err)
	}
	if st := q.Status(); st.Problem != "cannot reach Telegram securely" || st.Queued != 1 {
		t.Errorf("Status = %+v, want \"cannot reach Telegram securely\" with the incident queued", st)
	}
	if id, _ := deliver(t, q, ch, a, a, t0.Add(time.Second)); id != inc.ID {
		t.Errorf("retry: Deliver = %q, want %q", id, inc.ID)
	}
	if _, sent := ch.count(); len(sent) != 1 {
		t.Errorf("sent %d, want 1", len(sent))
	}
}

func TestFailedSendKeepsIncident(t *testing.T) {
	q := NewQueue()
	ch := &fakeChannel{errs: []error{errors.New("connection refused\n\x1b[31mred")}}
	inc := incident(1, t0)
	q.Add(inc, t0)
	if id, err := deliver(t, q, ch, a, a, t0); id != "" || err == nil {
		t.Fatalf("Deliver = %q, %v; want the error", id, err)
	}
	st := q.Status()
	if st.Problem != "send failed: connection refused[31mred" || st.Queued != 1 {
		t.Errorf("Status = %+v, want the last error, cleaned, and the incident queued", st)
	}
	if got := idsOf(q.Due(a, a, t0.Add(time.Second))); !slices.Equal(got, []string{inc.ID}) {
		t.Errorf("after a failed send: Due = %v, want [%s]", got, inc.ID)
	}
	if len(q.Unrecorded()) != 0 {
		t.Error("a failed send asks for an ack entry")
	}
	if id, _ := deliver(t, q, ch, a, a, t0.Add(time.Second)); id != inc.ID {
		t.Errorf("retry: Deliver = %q, want %q", id, inc.ID)
	}
	long := NewQueue()
	long.Add(inc, t0)
	deliver(t, long, &fakeChannel{errs: []error{errors.New(strings.Repeat("e", 1000))}}, a, a, t0)
	if p := long.Status().Problem; p != "send failed: "+strings.Repeat("e", MaxErrorText) {
		t.Errorf("Problem = %q (%d bytes), want the first %d bytes of the error", p, len(p), MaxErrorText)
	}
	// Cut between two characters: a 2-byte character straddles byte 200.
	wide := NewQueue()
	wide.Add(inc, t0)
	deliver(t, wide, &fakeChannel{errs: []error{errors.New(strings.Repeat("e", MaxErrorText-1) + "\u00e9\u00e9")}}, a, a, t0)
	if p := wide.Status().Problem; p != "send failed: "+strings.Repeat("e", MaxErrorText-1) {
		t.Errorf("Problem = %q, want the error cut before the character at byte %d", p, MaxErrorText-1)
	}
}

func TestUnrecordedBounded(t *testing.T) {
	q := NewQueue()
	ch := &fakeChannel{}
	for i := 1; i <= MaxQueued+1; i++ {
		now := t0.Add(time.Duration(i) * time.Second)
		q.Add(incident(i, now), now)
		if id, err := deliver(t, q, ch, a, a, now); id == "" || err != nil {
			t.Fatalf("send %d: Deliver = %q, %v", i, id, err)
		}
	}
	got := q.Unrecorded()
	if len(got) != MaxQueued || got[0] != "0000000000000002" || got[len(got)-1] != fmt.Sprintf("%016x", MaxQueued+1) {
		t.Errorf("Unrecorded holds %d, from %s to %s; want the newest %d", len(got), got[0], got[len(got)-1], MaxQueued)
	}
}

func TestDeliverTagsMessage(t *testing.T) {
	q := NewQueue()
	ch := &fakeChannel{}
	inc := incident(0x1234abcd00000000, t0)
	q.Add(inc, t0)
	deliver(t, q, ch, a, a, t0)
	_, sent := ch.count()
	if want := []string{"about 1234abcd00000000 [1234abcd]"}; !slices.Equal(sent, want) {
		t.Errorf("sent %q, want %q", sent, want)
	}
	// Whatever the renderer returns goes out as one clean line.
	q2 := NewQueue()
	ch2 := &fakeChannel{}
	q2.Add(inc, t0)
	q2.Deliver(context.Background(), ch2, a, a, t0, func(events.Incident) string { return "two\nlines\x1b" })
	if _, sent := ch2.count(); !slices.Equal(sent, []string{"twolines [1234abcd]"}) {
		t.Errorf("sent %q, want the text cleaned", sent)
	}
}

func TestUnrecorded(t *testing.T) {
	q := NewQueue()
	ch := &fakeChannel{}
	one, two := incident(1, t0), incident(2, t0.Add(time.Second))
	q.Add(one, t0)
	q.Add(two, t0)
	if got := q.Unrecorded(); len(got) != 0 {
		t.Errorf("before sending: Unrecorded = %v", got)
	}
	deliver(t, q, ch, a, a, t0)
	deliver(t, q, ch, a, a, t0.Add(time.Second))
	if got := q.Unrecorded(); !slices.Equal(got, []string{one.ID, two.ID}) {
		t.Errorf("Unrecorded = %v, want [%s %s]", got, one.ID, two.ID)
	}
	// Asking again does not clear it: the node clears it by recording.
	if got := q.Unrecorded(); len(got) != 2 {
		t.Errorf("Unrecorded asked twice = %v", got)
	}
	// Another member's ack does not stand for this member's record.
	q.Ack(one.ID, b)
	if got := q.Unrecorded(); len(got) != 2 {
		t.Errorf("after b's ack: Unrecorded = %v, want both", got)
	}
	q.Ack(one.ID, a)
	if got := q.Unrecorded(); !slices.Equal(got, []string{two.ID}) {
		t.Errorf("after a's own ack: Unrecorded = %v, want [%s]", got, two.ID)
	}
}

func TestDeliverRendersOutsideTheLock(t *testing.T) {
	q := NewQueue()
	q.Add(incident(1, t0), t0)
	done := make(chan string, 1)
	go func() {
		id, _ := q.Deliver(context.Background(), &fakeChannel{}, a, a, t0, func(inc events.Incident) string {
			_ = q.Status() // the renderer may look at the queue
			q.Due(a, a, t0)
			return text(inc)
		})
		done <- id
	}()
	select {
	case id := <-done:
		if id == "" {
			t.Error("nothing sent")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Deliver holds its lock while rendering")
	}
}

func TestOneSendInFlight(t *testing.T) {
	q := NewQueue()
	ch := &fakeChannel{hold: make(chan struct{}), in: make(chan struct{})}
	q.Add(incident(1, t0), t0)
	q.Add(incident(2, t0), t0)
	first := make(chan string, 1)
	go func() {
		id, _ := q.Deliver(context.Background(), ch, a, a, t0, text)
		first <- id
	}()
	select { // the first send is in progress
	case <-ch.in:
	case <-time.After(5 * time.Second):
		close(ch.hold)
		t.Fatal("the first Deliver never called Send")
	}
	// Seconds later, still in progress: no second send meanwhile, and the
	// queue answers.
	if id, err := deliver(t, q, ch, a, a, t0.Add(3*time.Second)); id != "" || err != nil {
		t.Errorf("second Deliver during a send = %q, %v; want nothing", id, err)
	}
	if got := q.Status().Queued; got != 2 {
		t.Errorf("during the send: Queued = %d, want 2", got)
	}
	close(ch.hold)
	if id := <-first; id != "0000000000000001" {
		t.Errorf("first Deliver = %q", id)
	}
	ch.mu.Lock()
	ch.in = nil
	ch.mu.Unlock()
	if id, _ := deliver(t, q, ch, a, a, t0.Add(4*time.Second)); id != "0000000000000002" {
		t.Errorf("after the send: Deliver = %q, want the second incident", id)
	}
}

func TestPanicDoesNotWedgeTheQueue(t *testing.T) {
	q := NewQueue()
	q.Add(incident(1, t0), t0)
	func() {
		defer func() {
			if recover() == nil {
				t.Error("the renderer's panic did not reach the caller")
			}
		}()
		q.Deliver(context.Background(), &fakeChannel{}, a, a, t0, func(events.Incident) string { panic("render") })
	}()
	func() {
		defer func() {
			if recover() == nil {
				t.Error("the channel's panic did not reach the caller")
			}
		}()
		q.Deliver(context.Background(), panicChannel{}, a, a, t0.Add(time.Second), text)
	}()
	if got := q.Status().Queued; got != 1 {
		t.Errorf("after the panics: Queued = %d, want 1", got)
	}
	if id, _ := deliver(t, q, &fakeChannel{}, a, a, t0.Add(2*time.Second)); id != "0000000000000001" {
		t.Errorf("after the panics: Deliver = %q, want the incident", id)
	}
}

type panicChannel struct{}

func (panicChannel) Send(context.Context, string) error { panic("send") }
func (panicChannel) Ping(context.Context) error         { return nil }

// TestClockStepsBack: a wall clock that steps backwards never makes a wait
// endless and never lets a send through early. A step back counts as no time
// passing: what was waited before it still counts, and the rest is waited
// after it.
func TestClockStepsBack(t *testing.T) {
	back := t0.Add(-time.Hour)
	q := NewQueue()
	ch := &fakeChannel{errs: []error{&RateLimitError{RetryAfter: 7 * time.Second}}}
	q.Add(incident(1, t0), t0)
	q.Add(incident(2, t0), t0)
	deliver(t, q, ch, a, a, t0)
	if id, _ := deliver(t, q, ch, a, a, back); id != "" {
		t.Error("clock one hour back: sent at once")
	}
	if id, _ := deliver(t, q, ch, a, a, back.Add(7*time.Second-time.Nanosecond)); id != "" {
		t.Error("clock back: sent before retry_after measured again")
	}
	if id, _ := deliver(t, q, ch, a, a, back.Add(7*time.Second)); id == "" {
		t.Error("clock back: stalled after retry_after measured again")
	}
	// The grace too: 1 s of it passed before the step, 14 s are left.
	g := NewQueue()
	g.Due(b, a, t0)
	g.Add(incident(3, t0), t0)
	g.Due(b, b, t0.Add(time.Second))
	if got := g.Due(b, b, back); len(got) != 0 {
		t.Errorf("clock back: Due = %v, want none", idsOf(got))
	}
	if got := g.Due(b, b, back.Add(Grace-time.Second-time.Nanosecond)); len(got) != 0 {
		t.Errorf("clock back, grace not over: Due = %v, want none", idsOf(got))
	}
	if got := g.Due(b, b, back.Add(Grace-time.Second)); len(got) != 1 {
		t.Errorf("clock back, grace over: Due = %v, want the incident", idsOf(got))
	}
	// b stayed the sender across the step, so a new incident is b's at once.
	fresh := incident(5, back)
	g.Add(fresh, back.Add(Grace))
	if got := idsOf(g.Due(b, b, back.Add(Grace))); !slices.Contains(got, fresh.ID) {
		t.Errorf("clock back, a new incident: Due = %v, want it at once", got)
	}
	// A step back while rate limited, 3 s into a 7 s wait: 4 s are left.
	r := NewQueue()
	rc := &fakeChannel{errs: []error{&RateLimitError{RetryAfter: 7 * time.Second}}}
	r.Add(incident(4, t0), t0)
	deliver(t, r, rc, a, a, t0)
	r.Due(a, a, t0.Add(3*time.Second))
	r.Due(a, a, back) // the step is seen here
	if id, _ := deliver(t, r, rc, a, a, back.Add(4*time.Second-time.Nanosecond)); id != "" {
		t.Error("clock back mid-wait: sent early")
	}
	if id, _ := deliver(t, r, rc, a, a, back.Add(4*time.Second)); id == "" {
		t.Error("clock back mid-wait: stalled")
	}
}

func TestDueReturnsCopies(t *testing.T) {
	q := NewQueue()
	inc := incident(1, t0)
	inc.Witnesses = []string{gwHex}
	inc.Refs = []ids.Hash{{1}}
	q.Add(inc, t0)
	inc.Members[0], inc.Events[0], inc.Witnesses[0], inc.Refs[0] = "x", "y", "z", ids.Hash{9}
	got := q.Due(a, a, t0)
	if len(got) != 1 || got[0].Members[0] != kitchen || got[0].Events[0] != events.MemberSilent || got[0].Witnesses[0] != gwHex || got[0].Refs[0] != (ids.Hash{1}) {
		t.Fatalf("the caller's change after Add reached the queue: %+v", got)
	}
	got[0].Members[0], got[0].Events[0], got[0].Witnesses[0], got[0].Refs[0] = "x", "y", "z", ids.Hash{9}
	again := q.Due(a, a, t0)
	if again[0].Members[0] != kitchen || again[0].Events[0] != events.MemberSilent || again[0].Witnesses[0] != gwHex || again[0].Refs[0] != (ids.Hash{1}) {
		t.Fatalf("a change to Due's result reached the queue: %+v", again)
	}
}

func TestQueueBounded(t *testing.T) {
	q := NewQueue()
	for i := 1; i <= MaxQueued+5; i++ {
		added := q.Add(incident(i, t0.Add(time.Duration(i)*time.Second)), t0)
		if added != (i <= MaxQueued) {
			t.Fatalf("Add %d = %v", i, added)
		}
	}
	st := q.Status()
	if st.Queued != MaxQueued || st.Dropped != 5 {
		t.Errorf("Status = %+v, want %d queued and 5 dropped", st, MaxQueued)
	}
	if got := q.Due(a, a, t0); len(got) != MaxQueued || got[0].ID != "0000000000000001" {
		t.Errorf("the queue did not keep the first %d", MaxQueued)
	}
	// A full queue still takes an incident once one leaves it.
	q.Ack("0000000000000001", b)
	if !q.Add(incident(MaxQueued+6, t0), t0) {
		t.Error("Add refused after a slot was freed")
	}
}

func TestDoneBounded(t *testing.T) {
	q := NewQueue()
	for i := 1; i <= MaxDone; i++ {
		q.Ack(fmt.Sprintf("%016x", i), b)
	}
	if q.Add(incident(1, t0), t0) {
		t.Fatal("an acknowledged incident was queued again")
	}
	q.Ack(fmt.Sprintf("%016x", MaxDone+1), b)
	if !q.Add(incident(1, t0), t0) {
		t.Error("the oldest of more than MaxDone acknowledged IDs is still held")
	}
	if q.Add(incident(2, t0), t0) {
		t.Error("the second oldest acknowledged ID was forgotten too")
	}
}

func TestQueueConcurrent(t *testing.T) {
	q := NewQueue()
	ch := &fakeChannel{}
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				now := t0.Add(time.Duration(i) * 50 * time.Millisecond)
				q.Add(incident(g*1000+i, now), now)
				if i%3 == 0 {
					q.Ack(fmt.Sprintf("%016x", g*1000+i-1), b)
				}
				q.Due(a, a, now)
				q.Deliver(context.Background(), ch, a, a, now, text)
				q.Status()
				q.Unrecorded()
			}
		}(g)
	}
	wg.Wait()
	calls, sent := ch.count()
	if calls == 0 || len(sent) != calls {
		t.Errorf("%d calls, %d sent", calls, len(sent))
	}
	seen := map[string]bool{}
	for _, s := range sent {
		if seen[s] {
			t.Errorf("%q sent twice", s)
		}
		seen[s] = true
	}
}

func TestErrors(t *testing.T) {
	for _, err := range []error{ErrBlocked, ErrRateLimited, ErrTLS} {
		if !strings.HasPrefix(err.Error(), "deliver: ") {
			t.Errorf("%q does not name its package", err)
		}
	}
	rl := &RateLimitError{RetryAfter: 7 * time.Second}
	if !errors.Is(rl, ErrRateLimited) || errors.Is(rl, ErrBlocked) {
		t.Error("RateLimitError does not match ErrRateLimited alone")
	}
	if got, want := rl.Error(), "deliver: rate limited: retry after 7s"; got != want {
		t.Errorf("Error = %q, want %q", got, want)
	}
}

func TestAckBodyRoundTrip(t *testing.T) {
	body, err := AckBody("0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != `{"ack":"0123456789abcdef"}` {
		t.Errorf("AckBody = %s", body)
	}
	// It is in the form the history keeps: encoding/json gives it back
	// unchanged.
	again, err := json.Marshal(json.RawMessage(body))
	if err != nil || string(again) != string(body) {
		t.Errorf("a JSON round trip changed the body: %s", again)
	}
	e := history.Entry{Origin: a, Seq: 4, Kind: history.KindEvent, Body: body}
	id, by, ok := AckOf(e)
	if !ok || id != "0123456789abcdef" || by != a {
		t.Errorf("AckOf = %q, %v, %v", id, by, ok)
	}
	for _, bad := range []string{"", "0123456789ABCDEF", "0123456789abcde", "0123456789abcdef0", `0123456789abcde"`} {
		if _, err := AckBody(bad); err == nil {
			t.Errorf("AckBody(%q) accepted", bad)
		}
	}
}

func TestAckOfRefusesOthers(t *testing.T) {
	good := json.RawMessage(`{"ack":"0123456789abcdef"}`)
	cases := []struct {
		name string
		e    history.Entry
	}{
		{"a witness entry", history.Entry{Origin: a, Kind: history.KindWitness, Body: good}},
		{"a correction", history.Entry{Origin: a, Kind: history.KindCorrection, Body: good}},
		{"no origin", history.Entry{Kind: history.KindEvent, Body: good}},
		{"an event record", history.Entry{Origin: a, Kind: history.KindEvent, Body: json.RawMessage(`{"type":"member_silent"}`)}},
		{"spaces", history.Entry{Origin: a, Kind: history.KindEvent, Body: json.RawMessage(`{"ack": "0123456789abcdef"}`)}},
		{"another field", history.Entry{Origin: a, Kind: history.KindEvent, Body: json.RawMessage(`{"ack":"0123456789abcdef","x":1}`)}},
		{"upper case", history.Entry{Origin: a, Kind: history.KindEvent, Body: json.RawMessage(`{"ack":"0123456789ABCDEF"}`)}},
		{"escaped", history.Entry{Origin: a, Kind: history.KindEvent, Body: json.RawMessage(`{"ack":"\u0030123456789abcdef"}`)}},
		{"short", history.Entry{Origin: a, Kind: history.KindEvent, Body: json.RawMessage(`{"ack":"0123456789abcde"}`)}},
		{"not a string", history.Entry{Origin: a, Kind: history.KindEvent, Body: json.RawMessage(`{"ack":1}`)}},
		{"empty", history.Entry{Origin: a, Kind: history.KindEvent}},
	}
	for _, c := range cases {
		if id, _, ok := AckOf(c.e); ok {
			t.Errorf("%s: AckOf = %q, true", c.name, id)
		}
	}
}

// FuzzAckOf: whatever body a peer signs, AckOf either refuses it or returns an
// ID whose body is exactly that body.
func FuzzAckOf(f *testing.F) {
	f.Add([]byte(`{"ack":"0123456789abcdef"}`))
	f.Add([]byte(`{"ack":"0123456789ABCDEF"}`))
	f.Add([]byte(`{"ack":"0123456789abcdef"} `))
	f.Add([]byte(`{"ack":"`))
	f.Add([]byte(`{"ack":"0123456789abcdef","refs":["0100000000000000000000000000000000000000000000000000000000000000"]}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		e := history.Entry{Origin: a, Kind: history.KindEvent, Body: body}
		id, by, ok := AckOf(e)
		if !ok {
			return
		}
		if by != a {
			t.Fatalf("by = %v", by)
		}
		want, err := AckBodyRefs(id, AckRefs(e))
		if err != nil || string(want) != string(body) {
			t.Fatalf("AckOf accepted %q as %q, whose body is %q (%v)", body, id, want, err)
		}
	})
}
