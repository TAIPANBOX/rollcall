package deliver

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/quiet"
)

// call is one Send a quietChannel was given.
type call struct {
	text   string
	silent bool
	ok     bool
}

// quietChannel records every Send with its silent flag and answers with errs
// in turn, then with nil.
type quietChannel struct {
	mu    sync.Mutex
	errs  []error
	calls []call
}

func (f *quietChannel) Send(_ context.Context, text string, silent bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	var err error
	if len(f.errs) > 0 {
		err, f.errs = f.errs[0], f.errs[1:]
	}
	f.calls = append(f.calls, call{text: text, silent: silent, ok: err == nil})
	return err
}

func (f *quietChannel) Ping(context.Context) error { return nil }

func (f *quietChannel) all() []call {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

// TestSilentDecidedWhenSent: whether a message makes a sound is decided when
// it is sent, by the now Deliver is given, not by when its incident began or
// was queued: an incident of 22:58 that could not be sent before 23:00 goes
// out silently, and one of 06:59 sent at 07:00 rings.
func TestSilentDecidedWhenSent(t *testing.T) {
	h, err := quiet.Parse("23:00-07:00")
	if err != nil {
		t.Fatal(err)
	}
	q := NewQueue()
	q.SetQuiet(func(now time.Time) bool { return h.Contains(now, time.UTC) })
	evening := time.Date(2026, 10, 23, 22, 58, 0, 0, time.UTC)
	morning := time.Date(2026, 10, 24, 6, 59, 0, 0, time.UTC)
	ch := &quietChannel{errs: []error{errors.New("no route to host")}}

	q.Add(incident(1, evening), evening)
	if _, err := deliver(t, q, ch, a, a, evening.Add(90*time.Second)); err == nil { // 22:59:30
		t.Fatal("the first attempt was to fail")
	}
	if id, err := deliver(t, q, ch, a, a, evening.Add(2*time.Minute)); err != nil || id == "" { // 23:00:00
		t.Fatalf("the retry at 23:00 sent %q, %v", id, err)
	}
	ch.errs = []error{errors.New("no route to host")}
	q.Add(incident(2, morning), morning)
	if _, err := deliver(t, q, ch, a, a, morning.Add(30*time.Second)); err == nil { // 06:59:30
		t.Fatal("the attempt at 06:59:30 was to fail")
	}
	if id, err := deliver(t, q, ch, a, a, morning.Add(time.Minute)); err != nil || id == "" { // 07:00:00
		t.Fatalf("the retry at 07:00 sent %q, %v", id, err)
	}

	got := ch.all()
	want := []bool{false, true, true, false} // 22:59:30, 23:00:00, 06:59:30, 07:00:00
	if len(got) != len(want) {
		t.Fatalf("%d sends, want %d: %+v", len(got), len(want), got)
	}
	for i, c := range got {
		if c.silent != want[i] {
			t.Errorf("send %d (%q, sent %v): silent %v, want %v", i+1, c.text, c.ok, c.silent, want[i])
		}
	}
}

// TestQuietHoursOnlyTheSound: quiet hours change the sound and nothing else.
// The same incidents, failures and acknowledgements, given to a queue with
// quiet hours at every moment and to one without, are sent at the same
// moments, with the same texts, with the same waits after a rate limit and a
// blocked bot, and leave the same queue; the only difference is that every
// send of the first is silent and none of the second.
func TestQuietHoursOnlyTheSound(t *testing.T) {
	type outcome struct {
		at  time.Duration
		id  string
		err string
	}
	run := func(q *Queue) ([]outcome, []call, Status, []string) {
		ch := &quietChannel{errs: []error{
			&RateLimitError{RetryAfter: 7 * time.Second},
			fmt.Errorf("telegram sendMessage: %w", ErrBlocked),
		}}
		for i := 1; i <= 4; i++ {
			q.Add(incident(i, t0.Add(time.Duration(i)*time.Second)), t0)
		}
		var out []outcome
		for s := time.Duration(0); s <= 6*time.Minute; s += time.Second {
			if s == 3*time.Minute {
				q.Add(incident(5, t0.Add(s)), t0.Add(s))
				q.Ack(fmt.Sprintf("%016x", 4), b) // another sender told incident 4
			}
			id, err := deliver(t, q, ch, a, a, t0.Add(s))
			if id != "" || err != nil {
				e := ""
				if err != nil {
					e = err.Error()
				}
				out = append(out, outcome{at: s, id: id, err: e})
			}
		}
		return out, ch.all(), q.Status(), q.Unrecorded()
	}

	quietQ := NewQueue()
	quietQ.SetQuiet(func(time.Time) bool { return true })
	qOut, qCalls, qStatus, qUnrec := run(quietQ)
	lOut, lCalls, lStatus, lUnrec := run(NewQueue())

	if len(lCalls) < 4 || !slices.ContainsFunc(lOut, func(o outcome) bool { return o.err != "" }) {
		t.Fatalf("the case did not happen: sends %+v", lOut)
	}
	if !slices.Equal(qOut, lOut) {
		t.Errorf("with quiet hours the sends were\n%+v\nwithout\n%+v", qOut, lOut)
	}
	if qStatus != lStatus || !slices.Equal(qUnrec, lUnrec) {
		t.Errorf("with quiet hours the queue is %+v, unrecorded %v; without %+v, %v", qStatus, qUnrec, lStatus, lUnrec)
	}
	if len(qCalls) != len(lCalls) {
		t.Fatalf("%d sends with quiet hours, %d without", len(qCalls), len(lCalls))
	}
	for i := range qCalls {
		if qCalls[i].text != lCalls[i].text || qCalls[i].ok != lCalls[i].ok {
			t.Errorf("send %d: %+v with quiet hours, %+v without", i+1, qCalls[i], lCalls[i])
		}
		if !qCalls[i].silent || lCalls[i].silent {
			t.Errorf("send %d: silent %v with quiet hours and %v without, want true and false", i+1, qCalls[i].silent, lCalls[i].silent)
		}
	}
}
