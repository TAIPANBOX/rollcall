// Package deliver turns incidents into chat messages and delivers them at
// least once through the one member the group elected to send (design 4.5,
// 4.9; security spec 9).
//
// # Who sends
//
// Every member queues every incident it learns of. Only the member that
// elect.Sender names, from the member's own view, sends; the others keep
// the incident until an acknowledgement reaches them through the history.
// When the sender goes silent, the election names the next eligible member,
// and that member sends what the silent sender left unacknowledged, but only
// once each incident has stayed unacknowledged for Grace (15 s), so that an
// acknowledgement still on its way is not overtaken. Precisely: a member that
// is the sender sends an incident at once if it was already the sender when
// the incident reached it (Add), and otherwise once the incident has been
// queued for Grace. A member that stops being the sender and becomes it again
// starts over. Duplicates remain possible after a split or while views differ;
// each message carries the first 8 digits of its incident ID, so a duplicate
// is obvious. At least once is chosen on purpose.
//
// # Acknowledgements
//
// The queue writes no history. After a successful send it lists the incident
// in Unrecorded; the node appends an entry of kind event with the body
// AckBody(id) to its own chain, and every member that reads such an entry from
// its log passes it to Ack (AckOf decodes it). Ack must only be given what a
// verified history entry says: an ack removes an incident from the queue for
// good.
//
// # Pacing
//
// One Queue serves one chat. Deliver makes at most one attempt per Spacing
// (one message per second per chat), oldest incident first, and never two at
// once. A failed attempt keeps its incident queued. After ErrRateLimited it
// waits the channel's retry_after (DefaultRetryAfter if none, at least Spacing,
// at most MaxRetryAfter); after ErrBlocked it tries at most once per
// BlockedRetry until a send succeeds; after ErrTLS, and after any other
// failure, it tries again after Spacing. Status says what stops delivery.
//
// # A full queue
//
// While MaxQueued incidents wait, Add refuses the newest and counts it in
// Status.Dropped. The chat is told too: once Adds were refused, the sender's
// next attempt sends one notice (an incident of type QueueFull, rendered like
// any other) before any incident, and then no other notice for OverflowEvery,
// however many more are refused; refusals after that are told once again. The
// notice is this member's own: it is not queued, not acknowledged and not in
// the history.
//
// # Holding back
//
// The caller may hold back named incidents (Hold): they stay queued and are
// not due, whoever sends, until a later Hold leaves them out. The node holds
// back an incident whose end is about to join it, so both go out as one
// message, and bounds that hold itself. Every other incident stays due.
//
// # Time
//
// Every method takes now from the caller and never reads the clock. A now
// earlier than the latest one seen (a wall clock stepped back) counts as no
// time passing: every wait keeps what it had waited and waits the rest. A
// wall clock that jumps forward ends waits early, by the size of the jump.
// With times from time.Now, which carry Go's monotonic reading, neither
// happens.
package deliver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/clock"
	"github.com/TAIPANBOX/rollcall/internal/events"
	"github.com/TAIPANBOX/rollcall/internal/history"
	"github.com/TAIPANBOX/rollcall/internal/ids"
)

// Channel is where messages go: Telegram, later ntfy. Send delivers one
// plain-text message; Ping checks that the channel answers (Telegram's getMe)
// and sends nothing. A Channel reports the failures the queue acts on with
// the errors of this package, wrapped or not: ErrBlocked, ErrRateLimited (as
// a *RateLimitError when it knows how long to wait) and ErrTLS. Its errors
// never contain a secret, since Status shows them.
type Channel interface {
	Send(ctx context.Context, text string) error
	Ping(ctx context.Context) error
}

var (
	// ErrBlocked reports that the owner blocked the bot (Telegram's 403):
	// nothing reaches the chat until the owner unblocks it.
	ErrBlocked = errors.New("deliver: the bot is blocked in the chat")
	// ErrRateLimited reports that the channel refused the message for now
	// (HTTP 429).
	ErrRateLimited = errors.New("deliver: rate limited")
	// ErrTLS reports a certificate or TLS failure: the channel could not be
	// reached securely, and nothing was sent in clear.
	ErrTLS = errors.New("deliver: no secure connection to the channel")
	// ErrIncidentID reports an incident ID that is not 16 lowercase hex
	// digits.
	ErrIncidentID = errors.New("deliver: an incident ID is 16 lowercase hex digits")
)

// RateLimitError is ErrRateLimited with the wait the channel asked for
// (Telegram's retry_after).
type RateLimitError struct {
	RetryAfter time.Duration
}

// Error says how long to wait.
func (e *RateLimitError) Error() string {
	return fmt.Sprintf("%s: retry after %s", ErrRateLimited, e.RetryAfter)
}

// Unwrap returns ErrRateLimited.
func (e *RateLimitError) Unwrap() error { return ErrRateLimited }

const (
	// Grace is how long an incident a member inherited as the new sender
	// must have stayed unacknowledged before it sends it (design 4.5).
	Grace = 15 * time.Second
	// Spacing is the least time between two attempts: at most one message
	// per second per chat (security spec 9).
	Spacing = time.Second
	// BlockedRetry is the least time between two attempts while the bot is
	// blocked.
	BlockedRetry = 5 * time.Minute
	// DefaultRetryAfter is the wait after ErrRateLimited without a positive
	// RetryAfter.
	DefaultRetryAfter = 5 * time.Second
	// MaxRetryAfter bounds the wait a channel can ask for.
	MaxRetryAfter = time.Hour
	// MaxQueued bounds the incidents waiting; Add refuses more and counts
	// them in Status.Dropped.
	MaxQueued = 1000
	// OverflowEvery is the least time between two notices that the queue
	// refused incidents: one an hour keeps a flood of incidents, which is
	// what fills the queue, from adding a flood of notices.
	OverflowEvery = time.Hour
	// MaxDone bounds the IDs of incidents delivered (by anyone) that the
	// queue remembers, so that one coalesced again is not queued again. The
	// oldest is forgotten first.
	MaxDone = 4096
	// MaxErrorText bounds the bytes of a channel error Status repeats.
	MaxErrorText = 200
)

// problem is what stopped the last attempt.
type problem int

const (
	problemNone problem = iota
	problemBlocked
	problemRateLimited
	problemTLS
	problemOther
)

// item is one queued incident.
type item struct {
	inc   events.Incident
	added time.Time // when it reached this member (Add)
}

// sent is an incident this member sent whose ack it has not yet recorded.
type sent struct {
	id string
	by ids.MemberID
}

// Queue holds a member's undelivered incidents and delivers them, as the
// package doc describes. Make one with NewQueue. It is safe for concurrent
// use.
type Queue struct {
	mu sync.Mutex

	items     []*item // oldest first: by Start.Wall, then by ID
	done      map[string]struct{}
	doneOrder []string // done in the order learnt, to forget the oldest
	dropped   int
	held      map[string]bool // incidents held back (Hold)
	overflow  int             // Adds refused since the last notice
	told      bool            // a notice was sent, at toldAt
	toldAt    time.Time

	seen    bool
	now     time.Time // the latest now seen
	sending bool      // self was the sender at the last call
	since   time.Time // when self became the sender

	tried    bool
	last     time.Time     // when the last attempt started
	wait     time.Duration // the least time from last to the next attempt
	blocked  bool          // ErrBlocked, and no send succeeded since
	problem  problem
	errText  string
	inflight bool

	unrecorded []sent
}

// NewQueue returns an empty queue.
func NewQueue() *Queue {
	return &Queue{done: make(map[string]struct{})}
}

// Add queues inc, which reached this member at now, and reports whether it
// did. It refuses an incident whose ID is malformed, one already queued
// (incident IDs are fixed by the events, so the same ID is the same
// incident), one this member knows was delivered, and any while MaxQueued
// are waiting. The queue keeps a copy.
func (q *Queue) Add(inc events.Incident, now time.Time) bool {
	if !isHex(inc.ID, 16) {
		return false
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	q.observe(now)
	if _, ok := q.done[inc.ID]; ok || q.find(inc.ID) >= 0 {
		return false
	}
	if len(q.items) >= MaxQueued {
		q.dropped++
		q.overflow++
		return false
	}
	it := &item{inc: clone(inc), added: now}
	i, _ := slices.BinarySearchFunc(q.items, it, func(x, y *item) int {
		if c := x.inc.Start.Wall.Compare(y.inc.Start.Wall); c != 0 {
			return c
		}
		return strings.Compare(x.inc.ID, y.inc.ID)
	})
	q.items = slices.Insert(q.items, i, it)
	return true
}

// Ack records that member by acknowledged the incident id: it delivered it.
// The incident leaves the queue for good, and an Add of it later is refused;
// an ack that arrives before its incident keeps the incident out. If by is
// the member that sent it from this queue, it also leaves Unrecorded.
//
// The caller passes only acknowledgements it read from verified history
// entries (AckOf on an entry the Log accepted): an ack from anywhere else
// would let its author suppress a message. A malformed ID and the zero member
// are ignored.
func (q *Queue) Ack(id string, by ids.MemberID) {
	if !isHex(id, 16) || by == (ids.MemberID{}) {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	q.finish(id)
	q.unrecorded = slices.DeleteFunc(q.unrecorded, func(s sent) bool { return s.id == id && s.by == by })
}

// Hold holds back the incidents named in ids, and only them: until the next
// Hold, Due and Deliver pass over them as if they were not due, and every
// other incident is due as before. A nil or empty ids holds nothing back.
func (q *Queue) Hold(ids []string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.held == nil {
		q.held = map[string]bool{}
	}
	clear(q.held)
	for _, id := range ids {
		q.held[id] = true
	}
}

// Due returns copies of the incidents self is to send at now, oldest first,
// as the package doc describes: none unless self is sender, the member the
// election names in self's view (the zero ID for none); otherwise every
// queued incident that reached self while it was already the sender, and
// every other one that has been queued for Grace. It ignores the channel's
// pacing, which Deliver applies.
//
// The queue learns who the sender is from Due and Deliver, so the node calls
// one of them on every tick with the current election result, whoever the
// sender is.
func (q *Queue) Due(self, sender ids.MemberID, now time.Time) []events.Incident {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.observe(now)
	if !q.track(self, sender, now) {
		return nil
	}
	var out []events.Incident
	for _, it := range q.items {
		if q.isDue(it, now) {
			out = append(out, clone(it.inc))
		}
	}
	return out
}

// Deliver sends the oldest incident Due returns through ch, if the pacing
// allows an attempt at now, and returns its ID, or "" if it sent nothing.
// The text is render(incident), cleaned, cut to fit and tagged with the
// incident ID's first 8 digits. render is called without the queue's lock
// held, so it may call the queue.
//
// On success the incident leaves the queue and appears in Unrecorded. On
// failure it stays queued, Deliver returns the channel's error, and the next
// attempt waits as the package doc describes. While an attempt is in
// progress another Deliver sends nothing. A panic in render or ch reaches the
// caller and leaves the queue usable, the incident still queued.
func (q *Queue) Deliver(ctx context.Context, ch Channel, self, sender ids.MemberID, now time.Time, render func(events.Incident) string) (string, error) {
	q.mu.Lock()
	q.observe(now)
	if !q.track(self, sender, now) || q.inflight || q.tried && now.Sub(q.last) < q.wait {
		q.mu.Unlock()
		return "", nil
	}
	var inc events.Incident
	found, notice := false, q.overflow > 0 && (!q.told || now.Sub(q.toldAt) >= OverflowEvery)
	if notice {
		inc, found = noticeOf(now), true
	}
	for _, it := range q.items {
		if !found && q.isDue(it, now) {
			inc, found = clone(it.inc), true
			break
		}
	}
	if !found {
		q.mu.Unlock()
		return "", nil
	}
	q.inflight, q.tried, q.last, q.wait = true, true, now, q.least()
	q.mu.Unlock()

	settled := false
	defer func() {
		if !settled { // render or ch panicked
			q.mu.Lock()
			q.inflight = false
			q.mu.Unlock()
		}
	}()
	err := ch.Send(ctx, tag(render(inc), inc.ID))
	settled = true

	q.mu.Lock()
	defer q.mu.Unlock()
	q.inflight = false
	switch {
	case !notice:
		q.settle(inc.ID, self, err)
	case err == nil:
		q.overflow, q.told, q.toldAt = 0, true, now
		q.settle("", self, nil)
	default:
		q.settle("", self, err)
	}
	if err != nil {
		return "", err
	}
	return inc.ID, nil
}

// noticeOf returns the notice that the queue refused incidents, at now: an
// incident of type QueueFull whose ID is fixed by the moment.
func noticeOf(now time.Time) events.Incident {
	h := sha256.Sum256(fmt.Appendf(nil, "rollcall/v1 queue full\x00%d", now.UnixNano()))
	at := clock.Stamp{Wall: now, Trusted: true}
	return events.Incident{ID: hex.EncodeToString(h[:8]), Start: at, End: at, Events: []events.Type{QueueFull}}
}

// Unrecorded returns the IDs of the incidents this member sent whose
// acknowledgement it has not yet recorded, in the order sent. For each, the
// node appends an entry of kind event with body AckBody(id) to its own chain
// and, once its log holds the entry, passes it to Ack, which removes the ID
// here. Asking does not remove anything.
func (q *Queue) Unrecorded() []string {
	q.mu.Lock()
	defer q.mu.Unlock()
	var out []string
	for _, s := range q.unrecorded {
		out = append(out, s.id)
	}
	return out
}

// Status is the state of a queue, for LuCI and the CLI.
type Status struct {
	Queued  int    // incidents waiting for delivery
	Dropped int    // Adds refused because MaxQueued were waiting
	Problem string // what stopped the last attempt; empty if it succeeded or none was made
	// Until is, while rate limited, the earliest next attempt; zero
	// otherwise. Problem shows it on the clock of the now Deliver was given.
	Until time.Time
}

// Status returns the queue's state. Problem is "bot blocked", "rate limited
// until 15:04:05", "cannot reach Telegram securely", or "send failed: "
// followed by the channel's error, cleaned and cut to MaxErrorText bytes.
func (q *Queue) Status() Status {
	q.mu.Lock()
	defer q.mu.Unlock()
	s := Status{Queued: len(q.items), Dropped: q.dropped}
	switch q.problem {
	case problemBlocked:
		s.Problem = statusBlocked
	case problemRateLimited:
		s.Until = q.last.Add(q.wait)
		s.Problem = fmt.Sprintf(statusRateLimited, s.Until.Format(layoutUntil))
	case problemTLS:
		s.Problem = statusTLS
	case problemOther:
		s.Problem = fmt.Sprintf(statusFailed, q.errText)
	}
	return s
}

// observe moves the queue's idea of now to now. A now before the latest one
// seen shifts every stored moment by the step, so every wait keeps what it
// had waited.
func (q *Queue) observe(now time.Time) {
	if q.seen && now.Before(q.now) {
		step := now.Sub(q.now)
		q.since = q.since.Add(step)
		q.last = q.last.Add(step)
		q.toldAt = q.toldAt.Add(step)
		for _, it := range q.items {
			it.added = it.added.Add(step)
		}
	}
	q.seen, q.now = true, now
}

// track records whether self is the sender at now and reports it.
func (q *Queue) track(self, sender ids.MemberID, now time.Time) bool {
	is := self != (ids.MemberID{}) && sender == self
	if is && !q.sending {
		q.since = now
	}
	q.sending = is
	return is
}

// isDue reports whether the sender sends it at now: it is not held back,
// and it reached the sender while it was the sender, or it has been queued
// for Grace.
func (q *Queue) isDue(it *item, now time.Time) bool {
	if q.held[it.inc.ID] {
		return false
	}
	return !it.added.Before(q.since) || now.Sub(it.added) >= Grace
}

// least is the least wait before any next attempt.
func (q *Queue) least() time.Duration {
	if q.blocked {
		return BlockedRetry
	}
	return Spacing
}

// settle records the outcome of an attempt to send incident id as self.
// The next attempt waits at least q.least(), and longer when rate limited.
func (q *Queue) settle(id string, self ids.MemberID, err error) {
	var wait time.Duration
	var rl *RateLimitError
	switch {
	case err == nil:
		if id != "" { // not the notice of a full queue
			q.finish(id)
			q.unrecorded = append(q.unrecorded, sent{id: id, by: self})
			if len(q.unrecorded) > MaxQueued {
				q.unrecorded = slices.Delete(q.unrecorded, 0, 1)
			}
		}
		q.blocked, q.problem, q.errText = false, problemNone, ""
	case errors.Is(err, ErrBlocked):
		q.blocked, q.problem = true, problemBlocked
	case errors.Is(err, ErrRateLimited):
		wait = DefaultRetryAfter
		if errors.As(err, &rl) && rl.RetryAfter > 0 {
			wait = rl.RetryAfter
		}
		q.problem, wait = problemRateLimited, min(wait, MaxRetryAfter)
	case errors.Is(err, ErrTLS):
		q.problem = problemTLS
	default:
		q.problem, q.errText = problemOther, limit(clean(err.Error()), MaxErrorText)
	}
	q.wait = max(wait, q.least())
}

// finish removes incident id from the queue, if there, and remembers it as
// delivered.
func (q *Queue) finish(id string) {
	if i := q.find(id); i >= 0 {
		q.items = slices.Delete(q.items, i, i+1)
	}
	if _, ok := q.done[id]; ok {
		return
	}
	q.done[id] = struct{}{}
	q.doneOrder = append(q.doneOrder, id)
	if len(q.doneOrder) > MaxDone {
		delete(q.done, q.doneOrder[0])
		q.doneOrder = q.doneOrder[1:]
	}
}

// find returns the index of incident id in the queue, or -1.
func (q *Queue) find(id string) int {
	return slices.IndexFunc(q.items, func(it *item) bool { return it.inc.ID == id })
}

// clone returns inc with its slices copied.
func clone(inc events.Incident) events.Incident {
	inc.Members = slices.Clone(inc.Members)
	inc.Events = slices.Clone(inc.Events)
	inc.Witnesses = slices.Clone(inc.Witnesses)
	inc.Refs = slices.Clone(inc.Refs)
	return inc
}

// limit returns at most the first n bytes of s, cut between two characters.
func limit(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

func utf8RuneStart(b byte) bool { return b&0xC0 != 0x80 }

// The body of an acknowledgement: {"ack":"<incident ID>"}, the one form
// encoding/json writes for it, so it passes the history's body rules.
const (
	ackPrefix = `{"ack":"`
	ackSuffix = `"}`
)

// AckBody returns the body of the history entry, of kind event, that records
// the delivery of incident id: {"ack":"<id>"}.
func AckBody(id string) (json.RawMessage, error) {
	if !isHex(id, 16) {
		return nil, ErrIncidentID
	}
	return json.RawMessage(ackPrefix + id + ackSuffix), nil
}

// AckOf returns the incident ID e acknowledges and the member that did, if e
// is an acknowledgement: an entry of kind event with a non-zero origin whose
// body is exactly what AckBody writes. Any other entry gives false. AckOf does
// not verify e; the caller passes only entries its Log accepted.
func AckOf(e history.Entry) (string, ids.MemberID, bool) {
	b := string(e.Body)
	if e.Kind != history.KindEvent || e.Origin == (ids.MemberID{}) ||
		len(b) != len(ackPrefix)+16+len(ackSuffix) || !strings.HasPrefix(b, ackPrefix) || !strings.HasSuffix(b, ackSuffix) {
		return "", ids.MemberID{}, false
	}
	id := b[len(ackPrefix) : len(ackPrefix)+16]
	if !isHex(id, 16) {
		return "", ids.MemberID{}, false
	}
	return id, e.Origin, true
}
