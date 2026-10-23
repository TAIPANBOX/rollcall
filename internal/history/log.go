package history

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"slices"
	"sync"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/ids"
)

// The bounds of the history (security spec 5.7, design 4.3), per origin: at
// most DefaultMaxEntries entries (NewLog's default for maxPerOrigin) and at
// most DefaultMaxAge of them (for Prune).
const (
	DefaultMaxEntries = 500
	DefaultMaxAge     = 30 * 24 * time.Hour
)

// digestLabel starts the bytes Log.Digest covers.
const digestLabel = "rollcall/v1 history-digest\x00"

var (
	// ErrUnknownOrigin reports an entry whose origin the Log's resolver
	// gives no key for.
	ErrUnknownOrigin = errors.New("history: the entry's origin has no known key")
	// ErrGap reports an entry more than one past the head of its chain.
	ErrGap = errors.New("history: the entry is not the next in its chain; earlier entries are missing")
	// ErrPruned reports an entry at or below the last entry Prune dropped
	// from its chain.
	ErrPruned = errors.New("history: the entry is older than what the log keeps of its chain")
	// ErrFork reports an origin that signed two different entries with the
	// same sequence number. Append returns it as a *ForkError.
	ErrFork = errors.New("history: the origin signed two different entries with the same sequence number")
	// ErrNotFork reports a ForkProof whose entries are not two different
	// entries at one origin and sequence number.
	ErrNotFork = errors.New("history: not a fork proof")
	// ErrStarted reports a StartAt for an origin the log already holds
	// entries of.
	ErrStarted = errors.New("history: the log holds entries of the origin; its chain has started")
)

// Head is the position and hash of the newest entry of a chain. The zero
// Head stands for an empty chain.
type Head struct {
	Seq  uint64   `json:"seq"`
	Hash ids.Hash `json:"hash"`
}

// ForkProof is two different entries signed by one origin with the same
// sequence number: A the one a log held first, B the one that came later.
type ForkProof struct {
	A Entry `json:"a"`
	B Entry `json:"b"`
}

// Verify checks that p proves a fork of the origin whose key is pub: both
// entries verify under pub (Entry.Verify), and they have the same Origin and
// Seq but different hashes (ErrNotFork otherwise).
func (p ForkProof) Verify(pub ed25519.PublicKey) error {
	if err := p.A.Verify(pub); err != nil {
		return fmt.Errorf("fork proof, entry A: %w", err)
	}
	if err := p.B.Verify(pub); err != nil {
		return fmt.Errorf("fork proof, entry B: %w", err)
	}
	if p.A.Origin != p.B.Origin || p.A.Seq != p.B.Seq {
		return fmt.Errorf("%w: entries of origin %s seq %d and origin %s seq %d", ErrNotFork, p.A.Origin, p.A.Seq, p.B.Origin, p.B.Seq)
	}
	if p.A.Hash() == p.B.Hash() {
		return fmt.Errorf("%w: the same entry twice", ErrNotFork)
	}
	return nil
}

func (p ForkProof) clone() ForkProof { return ForkProof{A: p.A.clone(), B: p.B.clone()} }

// ForkError is the error Append returns for a fork. It matches ErrFork and
// carries the proof; the proof is a copy the caller may keep.
type ForkError struct {
	Proof ForkProof
}

// Error names the origin and the sequence number of the fork.
func (e *ForkError) Error() string {
	return fmt.Sprintf("%v: origin %s seq %d", ErrFork, e.Proof.A.Origin, e.Proof.A.Seq)
}

// Unwrap returns ErrFork.
func (e *ForkError) Unwrap() error { return ErrFork }

// stored is one entry a Log holds, with its hash and the time it came.
type stored struct {
	e    Entry
	hash ids.Hash
	at   time.Time
}

// chain is what a Log holds of one origin: entries[i] has Seq
// pruned.Seq+1+i, and the last is the head. Prune never drops the head, so
// a chain in the log is never empty.
type chain struct {
	pruned  Head // the last entry Prune dropped; zero if none
	entries []stored
}

// head returns the newest entry of c, or c.pruned (zero for a new chain)
// when c holds no entries.
func (c *chain) head() Head {
	if len(c.entries) == 0 {
		return c.pruned
	}
	last := c.entries[len(c.entries)-1]
	return Head{Seq: last.e.Seq, Hash: last.hash}
}

// dropOldest drops the k oldest entries of c, never the head, and records
// the last one dropped in c.pruned. Below 1 it does nothing. The dropped
// slots are cleared so their bodies can be collected.
func (c *chain) dropOldest(k int) {
	k = min(k, len(c.entries)-1) // the head stays
	if k <= 0 {
		return
	}
	last := c.entries[k-1]
	c.pruned = Head{Seq: last.e.Seq, Hash: last.hash}
	clear(c.entries[:k])
	c.entries = c.entries[k:]
}

// Log holds the chains of all origins, as the package doc describes. Make one
// with NewLog; a zero Log knows no origin and refuses every entry. A Log must
// not be copied.
type Log struct {
	keyOf  func(ids.MemberID) (ed25519.PublicKey, bool) // set once by NewLog
	max    int                                          // entries held of one origin at most
	mu     sync.Mutex
	chains map[ids.MemberID]*chain
	forks  map[ids.MemberID]ForkProof // the first proof of each forked origin
	bases  map[ids.MemberID]Head      // StartAt's base of each origin the log holds no entry of yet
}

// Append adds e to its origin's chain, or reports why not, as the package
// doc describes. The key is keyOf(e.Origin); an origin keyOf does not know
// gives ErrUnknownOrigin. now is when e was received, from which Prune
// measures its age. A duplicate of an entry held returns nil and changes
// nothing, its time included. A fork returns a *ForkError, and so does every
// later Append for that origin. When an appended entry takes its origin past
// the Log's maxPerOrigin, the oldest entries of that origin are dropped at
// once, as Prune drops them: never the head, and the last one dropped is
// recorded (Pruned).
func (l *Log) Append(e Entry, now time.Time) error {
	pub, known := l.key(e.Origin)
	if !known {
		return fmt.Errorf("%w: origin %s", ErrUnknownOrigin, e.Origin)
	}
	if err := e.Verify(pub); err != nil {
		return err
	}
	h := e.Hash()

	l.mu.Lock()
	defer l.mu.Unlock()
	if p, forked := l.forks[e.Origin]; forked {
		return &ForkError{Proof: p.clone()}
	}
	c := l.chains[e.Origin]
	if c == nil {
		c = &chain{pruned: l.bases[e.Origin]} // the zero Head without StartAt
	}
	head := c.head()
	switch {
	case e.Seq <= c.pruned.Seq:
		return fmt.Errorf("%w: origin %s seq %d; the log keeps seq %d and later", ErrPruned, e.Origin, e.Seq, c.pruned.Seq+1)
	case e.Seq <= head.Seq:
		held := c.entries[e.Seq-c.pruned.Seq-1]
		if held.hash == h {
			return nil
		}
		p := ForkProof{A: held.e.clone(), B: e.clone()}
		if l.forks == nil {
			l.forks = map[ids.MemberID]ForkProof{}
		}
		l.forks[e.Origin] = p
		return &ForkError{Proof: p.clone()}
	case e.Seq-head.Seq != 1:
		return fmt.Errorf("%w: origin %s seq %d after head %d", ErrGap, e.Origin, e.Seq, head.Seq)
	case e.Prev != head.Hash:
		return fmt.Errorf("%w: origin %s seq %d names prev %s, the head is %s", ErrPrev, e.Origin, e.Seq, e.Prev, head.Hash)
	}
	c.entries = append(c.entries, stored{e: e.clone(), hash: h, at: now})
	c.dropOldest(len(c.entries) - l.max) // bound memory now, not at the next Prune
	if l.chains == nil {
		l.chains = map[ids.MemberID]*chain{}
	}
	l.chains[e.Origin] = c
	delete(l.bases, e.Origin) // the chain holds its base now
	return nil
}

// StartAt makes base the start of origin's chain, for a chain whose oldest
// entries are gone: one read back from a file that held only what the log
// kept of it, or fetched from a holder that pruned it. The log then treats
// the entries up to base.Seq as pruned: the first entry Append takes of
// origin is base.Seq+1 with base.Hash as its Prev (ErrPrev for another
// Prev, ErrGap past it), an entry at or below base.Seq is ErrPruned, and
// Pruned reports base. Until that first entry the log holds nothing of
// origin: Head and Range report nothing and the Digest leaves origin out.
//
// The base is not signed: the signature of the entry after it is what
// vouches for it, once Append takes that entry. So a holder passes the
// Prev of the oldest entry it has at hand, Head{Seq: e.Seq-1, Hash:
// e.Prev}, or the Pruned of the log it fetches from, which is the same.
// Without StartAt, Append starts a chain only at Seq 1, and an entry past
// the head of an empty chain is ErrGap: a member that merely missed the
// first entries still fetches them.
//
// StartAt works only while the log holds no entry of origin, and returns
// ErrStarted otherwise, a forked origin included; nothing changes then.
// While the chain is empty it may be called again and the last base counts;
// the zero Head returns origin to the start at Seq 1. It returns
// ErrUnknownOrigin for an origin the resolver does not know, and ErrInvalid
// for a base whose Seq and Hash disagree (a zero Seq goes with a zero Hash
// and only with it) or at the last Seq, after which no entry can follow.
func (l *Log) StartAt(origin ids.MemberID, base Head) error {
	if _, known := l.key(origin); !known {
		return fmt.Errorf("%w: origin %s", ErrUnknownOrigin, origin)
	}
	switch {
	case (base.Seq == 0) != (base.Hash == ids.Hash{}):
		return fmt.Errorf("%w: base seq %d with hash %s", ErrInvalid, base.Seq, base.Hash)
	case base.Seq == math.MaxUint64:
		return fmt.Errorf("%w: a base at the last seq", ErrInvalid)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if c := l.chains[origin]; c != nil {
		return fmt.Errorf("%w: origin %s, head %d", ErrStarted, origin, c.head().Seq)
	}
	if l.bases == nil {
		l.bases = map[ids.MemberID]Head{}
	}
	l.bases[origin] = base
	return nil
}

// NewLog returns an empty Log. keyOf gives the signing key of an origin, from
// the roster, and reports false for an origin it does not know; Append takes
// every entry's key from it and from nowhere else. It is called outside the
// Log's lock, so it may take a lock of its own, and must be safe for
// concurrent use. A nil keyOf knows no origin. maxPerOrigin bounds what the
// Log holds of any one origin (see Append); below 1 it is DefaultMaxEntries.
func NewLog(keyOf func(origin ids.MemberID) (ed25519.PublicKey, bool), maxPerOrigin int) *Log {
	if maxPerOrigin < 1 {
		maxPerOrigin = DefaultMaxEntries
	}
	return &Log{keyOf: keyOf, max: maxPerOrigin}
}

// key returns keyOf(origin), or false if the Log has no resolver.
func (l *Log) key(origin ids.MemberID) (ed25519.PublicKey, bool) {
	if l.keyOf == nil {
		return nil, false
	}
	return l.keyOf(origin)
}

// Head returns the head of origin's chain, or the zero Head if the log holds
// nothing of origin. For a forked origin it is the head of the branch the
// log holds.
func (l *Log) Head(origin ids.MemberID) Head {
	l.mu.Lock()
	defer l.mu.Unlock()
	if c := l.chains[origin]; c != nil {
		return c.head()
	}
	return Head{}
}

// Pruned returns the base of origin's chain: the Seq and Hash of the last
// entry dropped from it (by Prune, or by Append at the Log's bounds), or the
// base StartAt set, or the zero Head if the chain starts at Seq 1. Entries up
// to that Seq are not available; the oldest entry kept has that Hash as its
// Prev. It is the base a log that holds nothing of origin passes to StartAt
// before it takes the rest of the chain from this one.
func (l *Log) Pruned(origin ids.MemberID) Head {
	l.mu.Lock()
	defer l.mu.Unlock()
	if c := l.chains[origin]; c != nil {
		return c.pruned
	}
	return l.bases[origin]
}

// Range returns copies of origin's entries with from <= Seq <= to, oldest
// first, as far as the log holds them. Entries Prune dropped are not
// available and are left out, never made up; nil means none in the range.
func (l *Log) Range(origin ids.MemberID, from, to uint64) []Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	c := l.chains[origin]
	if c == nil {
		return nil
	}
	first := c.pruned.Seq + 1
	from = max(from, first)
	to = min(to, c.head().Seq)
	if from > to {
		return nil
	}
	held := c.entries[from-first : to-first+1]
	out := make([]Entry, len(held))
	for i, s := range held {
		out[i] = s.e.clone()
	}
	return out
}

// Digest returns the digest over the heads of all origins the log holds, as
// the package doc describes.
func (l *Log) Digest() ids.Hash {
	l.mu.Lock()
	defer l.mu.Unlock()
	origins := make([]ids.MemberID, 0, len(l.chains))
	for o := range l.chains {
		origins = append(origins, o)
	}
	slices.SortFunc(origins, func(a, b ids.MemberID) int { return bytes.Compare(a[:], b[:]) })
	h := sha256.New()
	h.Write([]byte(digestLabel))
	for _, o := range origins {
		head := l.chains[o].head()
		if _, forked := l.forks[o]; forked {
			head = Head{Seq: math.MaxUint64}
		}
		h.Write(o[:])
		h.Write(binary.BigEndian.AppendUint64(nil, head.Seq))
		h.Write(head.Hash[:])
	}
	var out ids.Hash
	h.Sum(out[:0])
	return out
}

// Forks returns copies of the fork proofs the log keeps, one per forked
// origin, in ascending order of the origin's MemberID bytes.
func (l *Log) Forks() []ForkProof {
	l.mu.Lock()
	defer l.mu.Unlock()
	origins := make([]ids.MemberID, 0, len(l.forks))
	for o := range l.forks {
		origins = append(origins, o)
	}
	slices.SortFunc(origins, func(a, b ids.MemberID) int { return bytes.Compare(a[:], b[:]) })
	var out []ForkProof
	for _, o := range origins {
		out = append(out, l.forks[o].clone())
	}
	return out
}

// Prune drops, per origin, the oldest entries beyond the limits: all but
// the newest maxEntries, and every entry, from the oldest on, received more
// than maxAge before now (the oldest one received within maxAge, and every
// entry after it, stays). A limit of zero or less is no limit. The head
// always stays, however old and whatever maxEntries is. For every origin it
// drops entries from, it records the last one dropped (Pruned). Fork proofs
// are kept. Append already holds every origin to the Log's maxPerOrigin;
// Prune applies the age limit and any tighter count.
//
// Ages are now.Sub(the time Append was given), which uses the monotonic
// clock when both times carry its reading. An entry received at a time
// after now is not old.
func (l *Log) Prune(maxEntries int, maxAge time.Duration, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, c := range l.chains {
		n := len(c.entries)
		drop := 0
		if maxEntries > 0 && n > maxEntries {
			drop = n - maxEntries
		}
		if maxAge > 0 {
			old := 0
			for old < n && now.Sub(c.entries[old].at) > maxAge {
				old++
			}
			drop = max(drop, old)
		}
		c.dropOldest(drop)
	}
}
