package history

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/ids"
)

func appendAll(t testing.TB, l *Log, es []Entry, at time.Time) {
	t.Helper()
	for _, e := range es {
		if err := l.Append(e, at); err != nil {
			t.Fatalf("Append seq %d: %v", e.Seq, err)
		}
	}
}

// wantDigest is the documented digest over heads, built here on its own.
func wantDigest(heads map[ids.MemberID]Head) ids.Hash {
	origins := make([]ids.MemberID, 0, len(heads))
	for o := range heads {
		origins = append(origins, o)
	}
	slices.SortFunc(origins, func(a, b ids.MemberID) int { return bytes.Compare(a[:], b[:]) })
	h := sha256.New()
	h.Write([]byte(fmtDigestLabel))
	for _, o := range origins {
		h.Write(o[:])
		hd := heads[o]
		h.Write(binary.BigEndian.AppendUint64(nil, hd.Seq))
		h.Write(hd.Hash[:])
	}
	return ids.Hash(h.Sum(nil))
}

// forkedHead is what a forked origin contributes to the digest.
var forkedHead = Head{Seq: math.MaxUint64}

// state is everything a reader of the log can see about some origins.
type state struct {
	Heads  map[ids.MemberID]Head
	Pruned map[ids.MemberID]Head
	Ranges map[ids.MemberID][]Entry
	Forks  []ForkProof
	Digest ids.Hash
}

func stateOf(l *Log, origins ...ids.MemberID) state {
	s := state{Heads: map[ids.MemberID]Head{}, Pruned: map[ids.MemberID]Head{}, Ranges: map[ids.MemberID][]Entry{}}
	for _, o := range origins {
		s.Heads[o] = l.Head(o)
		s.Pruned[o] = l.Pruned(o)
		s.Ranges[o] = l.Range(o, 0, math.MaxUint64)
	}
	s.Forks = l.Forks()
	s.Digest = l.Digest()
	return s
}

func TestChainAppend(t *testing.T) {
	a, b := testMember(1), testMember(2)
	l := testLog()
	if h := l.Head(a.id.ID); h != (Head{}) {
		t.Fatalf("empty log: Head = %+v, want zero", h)
	}
	ea, eb := buildChain(t, a, 5), buildChain(t, b, 3)
	for i := range ea {
		if err := l.Append(ea[i], t0); err != nil {
			t.Fatalf("a seq %d: %v", i+1, err)
		}
		if got := l.Head(a.id.ID); got != headOf(ea[i]) {
			t.Fatalf("after a seq %d: Head = %+v, want %+v", i+1, got, headOf(ea[i]))
		}
		if i < len(eb) {
			if err := l.Append(eb[i], t0); err != nil {
				t.Fatalf("b seq %d: %v", i+1, err)
			}
		}
	}
	if got := l.Range(a.id.ID, 1, 5); !reflect.DeepEqual(got, ea) {
		t.Fatalf("Range(a, 1, 5) = %+v, want the chain", got)
	}
	if got := l.Range(b.id.ID, 1, 3); !reflect.DeepEqual(got, eb) {
		t.Fatalf("Range(b, 1, 3) = %+v, want the chain", got)
	}
	got := l.Range(a.id.ID, 1, 5)
	for i, e := range got {
		want := ids.Hash{}
		if i > 0 {
			want = wantHash(got[i-1])
		}
		if e.Seq != uint64(i+1) || e.Prev != want {
			t.Errorf("entry %d: seq %d prev %s, want seq %d prev %s", i, e.Seq, e.Prev, i+1, want)
		}
	}
	if l.Head(b.id.ID) != headOf(eb[2]) {
		t.Errorf("Head(b) = %+v, want %+v", l.Head(b.id.ID), headOf(eb[2]))
	}

	// A member writes its next entry from the Log's own Head, in any kind.
	for _, kind := range []Kind{KindWitness, KindCorrection, KindBoot, KindCheckpoint, KindObjection, KindEvent} {
		next := mustEntry(t, a, l.Head(a.id.ID), kind, map[string]string{"kind": string(kind)})
		if err := l.Append(next, t0); err != nil {
			t.Fatalf("next entry of kind %q: %v", kind, err)
		}
		if l.Head(a.id.ID) != headOf(next) {
			t.Fatalf("kind %q: Head = %+v, want %+v", kind, l.Head(a.id.ID), headOf(next))
		}
		// Reserved kinds are stored as they came: opaque bodies, unchanged.
		if r := l.Range(a.id.ID, next.Seq, next.Seq); len(r) != 1 || !reflect.DeepEqual(r[0], next) {
			t.Fatalf("kind %q: stored %+v, want %+v", kind, r, next)
		}
	}
	if l.Pruned(a.id.ID) != (Head{}) || len(l.Forks()) != 0 {
		t.Errorf("Pruned %+v, Forks %d; want none", l.Pruned(a.id.ID), len(l.Forks()))
	}
}

func TestRejectsBrokenPrev(t *testing.T) {
	a, b, c := testMember(1), testMember(2), testMember(3)
	es := buildChain(t, a, 3)
	eb := buildChain(t, b, 2)
	l := testLog()
	appendAll(t, l, es[:2], t0)
	before := stateOf(l, a.id.ID, c.id.ID)

	tampered := es[2]
	tampered.Prev[0] ^= 1
	cases := []struct {
		name string
		e    Entry
		want error
	}{
		{"prev of an earlier entry", mustEntry(t, a, Head{Seq: 2, Hash: wantHash(es[0])}, KindEvent, 3), ErrPrev},
		{"prev of nothing held", mustEntry(t, a, Head{Seq: 2, Hash: sha256.Sum256([]byte("nothing"))}, KindEvent, 3), ErrPrev},
		{"prev from another chain", mustEntry(t, a, Head{Seq: 2, Hash: wantHash(eb[1])}, KindEvent, 3), ErrPrev},
		{"first entry with a prev", resign(Entry{Origin: c.id.ID, Seq: 1, Prev: wantHash(es[0]), Kind: KindBoot, Body: []byte(`1`)}, c.key), ErrPrev},
		{"prev changed after signing", tampered, ErrSignature},
	}
	for _, tc := range cases {
		if err := l.Append(tc.e, t0); !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", tc.name, err, tc.want)
		}
		if after := stateOf(l, a.id.ID, c.id.ID); !reflect.DeepEqual(after, before) {
			t.Fatalf("%s: the log changed", tc.name)
		}
	}
	if err := l.Append(es[2], t0); err != nil {
		t.Fatalf("the genuine third entry after the refusals: %v", err)
	}
}

func TestRejectsGap(t *testing.T) {
	a, b := testMember(1), testMember(2)
	es := buildChain(t, a, 5)
	l := testLog()
	appendAll(t, l, es[:2], t0)
	before := stateOf(l, a.id.ID, b.id.ID)
	for _, e := range []Entry{es[3], es[4]} {
		if err := l.Append(e, t0); !errors.Is(err, ErrGap) {
			t.Errorf("seq %d after head 2: err = %v, want %v", e.Seq, err, ErrGap)
		}
	}
	// The origin itself skips a seq and names the head as prev: still a gap.
	skip := mustEntry(t, a, Head{Seq: 3, Hash: wantHash(es[1])}, KindEvent, "skips 3")
	if err := l.Append(skip, t0); !errors.Is(err, ErrGap) {
		t.Errorf("seq 4 naming head 2 as prev: err = %v, want %v", err, ErrGap)
	}
	if err := l.Append(buildChain(t, b, 2)[1], t0); !errors.Is(err, ErrGap) {
		t.Errorf("seq 2 of an origin the log does not hold: err = %v, want %v", err, ErrGap)
	}
	if after := stateOf(l, a.id.ID, b.id.ID); !reflect.DeepEqual(after, before) {
		t.Fatal("a refused entry changed the log")
	}
	appendAll(t, l, es[2:], t0) // the gap filled, in order
	if l.Head(a.id.ID) != headOf(es[4]) {
		t.Fatalf("Head = %+v, want %+v", l.Head(a.id.ID), headOf(es[4]))
	}
}

// TestRejectsForeignSignature: a member cannot write into another member's
// chain, neither as a new entry nor as a second entry at a held position, so
// it cannot frame that member with a fork either. The log knows b's key and
// holds b's chain, so a log that tried any key it knows would accept these.
func TestRejectsForeignSignature(t *testing.T) {
	a, b := testMember(1), testMember(2)
	genuine := buildChain(t, a, 2)

	forgedFirst := resign(Entry{Origin: a.id.ID, Seq: 1, Kind: KindEvent, Body: []byte(`{"n":1}`)}, b.key)
	stolen := genuine[0]
	stolen.Sig = resign(genuine[0], b.key).Sig
	purpose := genuine[0]
	purpose.Sig = ed25519.Sign(a.key, append([]byte("rollcall/v1/roster\x00"), wantMessage(genuine[0])...))

	l := logOf(a, b)
	appendAll(t, l, buildChain(t, b, 2), t0)
	for name, e := range map[string]Entry{
		"entry for a signed by b":         forgedFirst,
		"a's entry re-signed by b":        stolen,
		"a's signature made for a roster": purpose,
	} {
		if err := l.Append(e, t0); !errors.Is(err, ErrSignature) {
			t.Errorf("%s: err = %v, want %v", name, err, ErrSignature)
		}
	}
	if l.Head(a.id.ID) != (Head{}) {
		t.Fatal("a forged entry was stored")
	}

	appendAll(t, l, genuine, t0)
	before := stateOf(l, a.id.ID, b.id.ID)
	forgedNext := resign(Entry{Origin: a.id.ID, Seq: 3, Prev: wantHash(genuine[1]), Kind: KindEvent, Body: []byte(`3`)}, b.key)
	forgedFork := resign(Entry{Origin: a.id.ID, Seq: 2, Prev: wantHash(genuine[0]), Kind: KindEvent, Body: []byte(`"other"`)}, b.key)
	for name, e := range map[string]Entry{"next entry signed by b": forgedNext, "second seq 2 signed by b": forgedFork} {
		err := l.Append(e, t0)
		if !errors.Is(err, ErrSignature) || errors.Is(err, ErrFork) {
			t.Errorf("%s: err = %v, want %v and no fork", name, err, ErrSignature)
		}
	}
	if after := stateOf(l, a.id.ID, b.id.ID); !reflect.DeepEqual(after, before) {
		t.Fatal("a forged entry changed a's chain or raised a fork")
	}
}

// TestUnknownOrigin: an entry from an origin the resolver does not know is
// refused before anything else, and changes nothing; so does every entry
// given to a Log made without a resolver.
func TestUnknownOrigin(t *testing.T) {
	a, b, stranger := testMember(1), testMember(2), testMember(3)
	l := logOf(a, b)
	appendAll(t, l, buildChain(t, a, 2), t0)
	before := stateOf(l, a.id.ID, b.id.ID, stranger.id.ID)
	for name, e := range map[string]Entry{
		"a stranger's own entry":       buildChain(t, stranger, 1)[0],
		"a stranger's entry, bad kind": resign(Entry{Origin: stranger.id.ID, Seq: 1, Kind: "note", Body: []byte(`1`)}, stranger.key),
	} {
		if err := l.Append(e, t0); !errors.Is(err, ErrUnknownOrigin) {
			t.Errorf("%s: err = %v, want %v", name, err, ErrUnknownOrigin)
		}
	}
	if after := stateOf(l, a.id.ID, b.id.ID, stranger.id.ID); !reflect.DeepEqual(after, before) {
		t.Fatal("an entry from an unknown origin changed the log")
	}

	for name, z := range map[string]*Log{"zero Log": {}, "nil resolver": NewLog(nil, 0)} {
		if err := z.Append(buildChain(t, a, 1)[0], t0); !errors.Is(err, ErrUnknownOrigin) {
			t.Errorf("%s: err = %v, want %v", name, err, ErrUnknownOrigin)
		}
		if z.Head(a.id.ID) != (Head{}) || z.Digest() != wantDigest(nil) {
			t.Errorf("%s: stored an entry", name)
		}
	}
}

// TestAppendBounded: Append itself keeps an origin at most at its limit,
// dropping the oldest entries as Prune does and never the head, so memory
// stays bounded between two calls of Prune and the chain still extends.
func TestAppendBounded(t *testing.T) {
	a, b := testMember(1), testMember(2)
	const limit = 5
	es := buildChain(t, a, limit+11)
	l := NewLog(keysOf(a, b), limit)
	appendAll(t, l, buildChain(t, b, 3), t0)
	for i, e := range es[:limit+10] {
		appendAll(t, l, []Entry{e}, t0)
		if got := l.Range(a.id.ID, 0, math.MaxUint64); len(got) > limit || !reflect.DeepEqual(got[len(got)-1], e) {
			t.Fatalf("after seq %d: %d entries held, last %d; want at most %d, the newest last", i+1, len(got), got[len(got)-1].Seq, limit)
		}
	}
	if got := l.Range(a.id.ID, 0, math.MaxUint64); !reflect.DeepEqual(got, es[10:limit+10]) {
		t.Fatalf("held seqs %v, want 11..15", seqs(got))
	}
	if l.Pruned(a.id.ID) != headOf(es[9]) || l.Head(a.id.ID) != headOf(es[limit+9]) {
		t.Fatalf("Pruned %+v Head %+v, want seq 10 and seq 15", l.Pruned(a.id.ID), l.Head(a.id.ID))
	}
	if got := l.Range(b.id.ID, 0, math.MaxUint64); len(got) != 3 {
		t.Fatalf("b holds %d entries, want its 3 untouched", len(got))
	}
	appendAll(t, l, es[limit+10:], t0) // the chain extends past the bound
	if l.Head(a.id.ID) != headOf(es[limit+10]) || len(l.Range(a.id.ID, 0, math.MaxUint64)) != limit {
		t.Fatal("the chain did not extend, or went past the bound")
	}
	if err := l.Append(es[3], t0); !errors.Is(err, ErrPruned) {
		t.Errorf("an entry Append dropped, again: err = %v, want %v", err, ErrPruned)
	}

	// A limit of 1 keeps the head alone; below 1 means DefaultMaxEntries.
	one := NewLog(keysOf(a), 1)
	appendAll(t, one, es[:4], t0)
	if got := one.Range(a.id.ID, 0, math.MaxUint64); !reflect.DeepEqual(got, es[3:4]) || one.Pruned(a.id.ID) != headOf(es[2]) {
		t.Fatalf("limit 1: held seqs %v, pruned %+v; want the head 4 alone, pruned 3", seqs(got), one.Pruned(a.id.ID))
	}
	long := buildChain(t, a, DefaultMaxEntries+3)
	def := NewLog(keysOf(a), 0)
	appendAll(t, def, long, t0)
	if got := def.Range(a.id.ID, 0, math.MaxUint64); len(got) != DefaultMaxEntries || got[0].Seq != 4 {
		t.Fatalf("limit 0: %d entries from seq %d, want %d from seq 4", len(got), got[0].Seq, DefaultMaxEntries)
	}
}

func TestForkDetected(t *testing.T) {
	a, b := testMember(1), testMember(2)
	es := buildChain(t, a, 3)
	alt := mustEntry(t, a, headOf(es[1]), KindEvent, map[string]int{"n": 33}) // another seq 3

	l := testLog()
	appendAll(t, l, es, t0)
	err := l.Append(alt, t0)
	if !errors.Is(err, ErrFork) {
		t.Fatalf("a second seq 3: err = %v, want %v", err, ErrFork)
	}
	var fe *ForkError
	if !errors.As(err, &fe) {
		t.Fatalf("a fork error is %T, want *ForkError", err)
	}
	if !reflect.DeepEqual(fe.Proof, ForkProof{A: es[2], B: alt}) {
		t.Fatalf("proof = %+v, want A the held entry, B the new one", fe.Proof)
	}
	for name, e := range map[string]Entry{"A": fe.Proof.A, "B": fe.Proof.B} {
		if err := e.Verify(a.pub); err != nil {
			t.Errorf("proof entry %s does not verify: %v", name, err)
		}
	}
	if fe.Proof.A.Origin != fe.Proof.B.Origin || fe.Proof.A.Seq != fe.Proof.B.Seq || wantHash(fe.Proof.A) == wantHash(fe.Proof.B) {
		t.Error("the proof is not two different entries at one origin and seq")
	}
	if err := fe.Proof.Verify(a.pub); err != nil {
		t.Errorf("ForkProof.Verify: %v", err)
	}
	if msg := err.Error(); !strings.Contains(msg, a.id.ID.String()) || !strings.Contains(msg, "seq 3") {
		t.Errorf("fork error %q does not name the origin and the seq", msg)
	}
	if l.Head(a.id.ID) != headOf(es[2]) || !reflect.DeepEqual(l.Range(a.id.ID, 1, 3), es) {
		t.Fatal("the fork changed the held chain")
	}
	if got := l.Forks(); !reflect.DeepEqual(got, []ForkProof{{A: es[2], B: alt}}) {
		t.Fatalf("Forks = %+v, want the one proof", got)
	}

	// The origin is untrusted from now on: nothing more from it is taken,
	// and every refusal carries the first proof.
	next := mustEntry(t, a, headOf(es[2]), KindEvent, 4)
	for name, e := range map[string]Entry{"the next entry": next, "a held entry again": es[0], "the fork again": alt} {
		err := l.Append(e, t0)
		if !errors.As(err, &fe) || !reflect.DeepEqual(fe.Proof, ForkProof{A: es[2], B: alt}) {
			t.Errorf("%s from a forked origin: err = %v, want %v with the first proof", name, err, ErrFork)
		}
	}
	if l.Head(a.id.ID) != headOf(es[2]) || len(l.Forks()) != 1 {
		t.Fatal("a forked origin's chain moved, or a second proof was kept")
	}
	// Other origins are not affected.
	eb := buildChain(t, b, 2)
	appendAll(t, l, eb, t0)

	// Every forked origin keeps its own proof; Forks lists them in origin order.
	z := testMember(0) // sorts before a and b
	ez := buildChain(t, z, 1)
	appendAll(t, l, ez, t0)
	altB := mustEntry(t, b, headOf(eb[0]), KindEvent, "b other")
	altZ := mustEntry(t, z, Head{}, KindEvent, "z other")
	for _, e := range []Entry{altB, altZ} {
		if err := l.Append(e, t0); !errors.Is(err, ErrFork) {
			t.Fatalf("fork of origin %s: err = %v, want %v", e.Origin, err, ErrFork)
		}
	}
	wantForks := []ForkProof{{A: ez[0], B: altZ}, {A: es[2], B: alt}, {A: eb[1], B: altB}}
	for i := 0; i < 10; i++ {
		if got := l.Forks(); !reflect.DeepEqual(got, wantForks) {
			t.Fatalf("Forks, call %d: origins %v, want z, a, b", i, forkOrigins(got))
		}
	}

	// A fork at an older position is found the same way.
	l2 := testLog()
	appendAll(t, l2, es, t0)
	alt2 := mustEntry(t, a, headOf(es[0]), KindEvent, map[string]int{"n": 22})
	if err := l2.Append(alt2, t0); !errors.As(err, &fe) || !reflect.DeepEqual(fe.Proof, ForkProof{A: es[1], B: alt2}) {
		t.Errorf("a second seq 2 under head 3: err = %v, want a fork with A = seq 2 held", err)
	}

	// The order of arrival decides which is A.
	l3 := testLog()
	appendAll(t, l3, es[:2], t0)
	appendAll(t, l3, []Entry{alt}, t0)
	if err := l3.Append(es[2], t0); !errors.As(err, &fe) || !reflect.DeepEqual(fe.Proof, ForkProof{A: alt, B: es[2]}) {
		t.Errorf("the other branch held: err = %v, want a fork with A = alt", err)
	}
}

func TestForkProofVerify(t *testing.T) {
	a, b := testMember(1), testMember(2)
	es := buildChain(t, a, 2)
	alt := mustEntry(t, a, headOf(es[0]), KindEvent, "other")
	// An entry claiming b's origin but signed by a: it verifies under a's
	// key, so only the origin rule can refuse the pair.
	claimsB := resign(Entry{Origin: b.id.ID, Seq: 2, Prev: wantHash(es[0]), Kind: KindEvent, Body: []byte(`2`)}, a.key)
	changed := alt
	changed.Body = []byte(`"changed"`)

	cases := []struct {
		name string
		p    ForkProof
		pub  ed25519.PublicKey
		want error
	}{
		{"a fork", ForkProof{A: es[1], B: alt}, a.pub, nil},
		{"the same entry twice", ForkProof{A: es[1], B: es[1]}, a.pub, ErrNotFork},
		{"two positions", ForkProof{A: es[0], B: es[1]}, a.pub, ErrNotFork},
		{"two origins", ForkProof{A: es[1], B: claimsB}, a.pub, ErrNotFork},
		{"B changed", ForkProof{A: es[1], B: changed}, a.pub, ErrSignature},
		{"A changed", ForkProof{A: changed, B: es[1]}, a.pub, ErrSignature},
		{"another key", ForkProof{A: es[1], B: alt}, b.pub, ErrSignature},
		{"no key", ForkProof{A: es[1], B: alt}, nil, ErrKey},
	}
	for _, c := range cases {
		err := c.p.Verify(c.pub)
		if c.want == nil && err != nil || c.want != nil && !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
	}
}

func TestDuplicateIgnored(t *testing.T) {
	a := testMember(1)
	es := buildChain(t, a, 3)
	l := testLog()
	appendAll(t, l, es, t0)
	before := stateOf(l, a.id.ID)
	for _, e := range es {
		cp := e
		cp.Body, cp.Sig = slices.Clone(e.Body), slices.Clone(e.Sig)
		if err := l.Append(cp, t0.Add(29*24*time.Hour)); err != nil {
			t.Errorf("seq %d again: %v, want nil", e.Seq, err)
		}
	}
	if after := stateOf(l, a.id.ID); !reflect.DeepEqual(after, before) {
		t.Fatal("a duplicate changed the log")
	}
	// A duplicate does not renew the entry: its age counts from the first
	// time it was received.
	l.Prune(0, 30*24*time.Hour, t0.Add(30*24*time.Hour+time.Second))
	if got := l.Range(a.id.ID, 1, 3); !reflect.DeepEqual(got, es[2:]) {
		t.Errorf("after pruning at 30 days: %d entries, want only the head", len(got))
	}
}

// TestAppendOnly: nothing changes an entry once it is held. The exported
// method set is pinned, so a new method must come through this test; the
// log shares no memory with its callers; a correction is a new entry; a
// second entry at a held position never replaces the first.
func TestAppendOnly(t *testing.T) {
	methods := func(typ reflect.Type) []string {
		var out []string
		for i := 0; i < typ.NumMethod(); i++ {
			out = append(out, typ.Method(i).Name)
		}
		return out
	}
	if got, want := methods(reflect.TypeOf(&Log{})), []string{"Append", "Digest", "Forks", "Head", "Prune", "Pruned", "Range"}; !slices.Equal(got, want) {
		t.Errorf("*Log methods %v, want %v: a new method must keep the store append-only", got, want)
	}
	for _, typ := range []reflect.Type{reflect.TypeOf(Entry{}), reflect.TypeOf(&Entry{})} {
		if got, want := methods(typ), []string{"Hash", "Verify"}; !slices.Equal(got, want) {
			t.Errorf("%v methods %v, want %v", typ, got, want)
		}
	}

	a := testMember(1)
	es := buildChain(t, a, 2)
	l := testLog()
	in := es[0]
	in.Body, in.Sig = slices.Clone(es[0].Body), slices.Clone(es[0].Sig)
	if err := l.Append(in, t0); err != nil {
		t.Fatal(err)
	}
	in.Body[1], in.Sig[0] = 'X', in.Sig[0]^1 // the caller's copy changes after Append
	if got := l.Range(a.id.ID, 1, 1); !reflect.DeepEqual(got, es[:1]) {
		t.Fatalf("the stored entry changed with the caller's slices: %+v", got)
	}
	out := l.Range(a.id.ID, 1, 1)
	out[0].Body[1], out[0].Sig[0], out[0].Seq = 'X', out[0].Sig[0]^1, 9
	if got := l.Range(a.id.ID, 1, 1); !reflect.DeepEqual(got, es[:1]) {
		t.Fatalf("the stored entry changed with a Range result: %+v", got)
	}
	if l.Head(a.id.ID) != headOf(es[0]) {
		t.Fatal("the head changed with a caller's slices")
	}

	// A correction is a new entry; the event it corrects stays as it was.
	appendAll(t, l, es[1:], t0)
	correction := mustEntry(t, a, headOf(es[1]), KindCorrection,
		map[string]string{"corrects": wantHash(es[1]).String(), "reason": "link lost, no reboot"})
	appendAll(t, l, []Entry{correction}, t0)
	if got := l.Range(a.id.ID, 1, 3); !reflect.DeepEqual(got, []Entry{es[0], es[1], correction}) {
		t.Fatalf("after the correction: %+v", got)
	}

	// A rewritten entry at a held position never replaces the held one.
	rewritten := mustEntry(t, a, headOf(es[0]), KindEvent, map[string]string{"n": "rewritten"})
	err := l.Append(rewritten, t0)
	var fe *ForkError
	if !errors.As(err, &fe) {
		t.Fatalf("a rewritten seq 2: err = %v, want %v", err, ErrFork)
	}
	if got := l.Range(a.id.ID, 2, 2); !reflect.DeepEqual(got, es[1:2]) {
		t.Fatalf("seq 2 after a rewrite: %+v, want the original", got)
	}

	// Proofs share no memory with the log either: the one a fork returns,
	// the one a later refusal returns, and the ones Forks returns.
	fe.Proof.A.Body[1], fe.Proof.B.Sig[0] = 'X', fe.Proof.B.Sig[0]^1
	err = l.Append(es[0], t0)
	if !errors.As(err, &fe) {
		t.Fatalf("an entry from the forked origin: err = %v, want %v", err, ErrFork)
	}
	fe.Proof.B.Body[1], fe.Proof.A.Sig[0] = 'X', fe.Proof.A.Sig[0]^1
	f := l.Forks()
	f[0].A.Sig[0], f[0].B.Body[1] = f[0].A.Sig[0]^1, 'X'
	if got := l.Forks(); !reflect.DeepEqual(got, []ForkProof{{A: es[1], B: rewritten}}) {
		t.Fatalf("a stored proof changed with a caller's copy: %+v", got)
	}
}

func TestDigestChangesWithAnyHead(t *testing.T) {
	ms := []member{testMember(3), testMember(1), testMember(2)} // not in ID order
	chains := map[ids.MemberID][]Entry{}
	for _, m := range ms {
		chains[m.id.ID] = buildChain(t, m, 4)
	}
	l := testLog()
	if got, want := l.Digest(), ids.Hash(sha256.Sum256([]byte(fmtDigestLabel))); got != want {
		t.Fatalf("empty log: Digest = %s, want SHA-256 of the label = %s", got, want)
	}
	heads := map[ids.MemberID]Head{}
	seen := map[ids.Hash]bool{l.Digest(): true}
	for round := 0; round < 4; round++ {
		for _, m := range ms {
			e := chains[m.id.ID][round]
			appendAll(t, l, []Entry{e}, t0)
			heads[m.id.ID] = headOf(e)
			d := l.Digest()
			if seen[d] {
				t.Fatalf("round %d, member %s: the digest did not change", round, m.id.ID)
			}
			seen[d] = true
			if want := wantDigest(heads); d != want {
				t.Fatalf("round %d, member %s: Digest = %s, want %s", round, m.id.ID, d, want)
			}
		}
	}
}

// TestDigestOrder: the digest depends on the heads alone, in MemberID
// order, never on the order of arrival or on what was pruned.
func TestDigestOrder(t *testing.T) {
	var ms []member
	for n := byte(1); n <= 8; n++ {
		ms = append(ms, testMember(n))
	}
	chains := map[ids.MemberID][]Entry{}
	heads := map[ids.MemberID]Head{}
	for _, m := range ms {
		chains[m.id.ID] = buildChain(t, m, 3)
		heads[m.id.ID] = headOf(chains[m.id.ID][2])
	}
	fwd, rev := testLog(), testLog()
	for _, m := range ms {
		appendAll(t, fwd, chains[m.id.ID], t0)
	}
	for i := len(ms) - 1; i >= 0; i-- {
		appendAll(t, rev, chains[ms[i].id.ID], t0)
	}
	want := wantDigest(heads)
	for i := 0; i < 10; i++ {
		if fwd.Digest() != want || rev.Digest() != want {
			t.Fatalf("call %d: digests %s and %s, want %s for both", i, fwd.Digest(), rev.Digest(), want)
		}
	}
	rev.Prune(1, 0, t0)
	if rev.Digest() != want {
		t.Fatal("pruning changed the digest")
	}
}

// TestDigestForked: a forked origin contributes a fixed marker, so two
// peers that hold different branches agree once both know of the fork.
func TestDigestForked(t *testing.T) {
	a, b := testMember(1), testMember(2)
	es, eb := buildChain(t, a, 3), buildChain(t, b, 2)
	alt := mustEntry(t, a, headOf(es[1]), KindEvent, "other")

	p1, p2, unaware := testLog(), testLog(), testLog()
	for _, l := range []*Log{p1, p2, unaware} {
		appendAll(t, l, eb, t0)
		appendAll(t, l, es[:2], t0)
	}
	appendAll(t, p1, es[2:], t0)
	appendAll(t, unaware, es[2:], t0)
	appendAll(t, p2, []Entry{alt}, t0)
	if !errors.Is(p1.Append(alt, t0), ErrFork) || !errors.Is(p2.Append(es[2], t0), ErrFork) {
		t.Fatal("the fork was not found")
	}
	if p1.Head(a.id.ID) == p2.Head(a.id.ID) {
		t.Fatal("the fixture should hold two branches")
	}
	want := wantDigest(map[ids.MemberID]Head{a.id.ID: forkedHead, b.id.ID: headOf(eb[1])})
	if p1.Digest() != want || p2.Digest() != want {
		t.Errorf("forked digests %s and %s, want %s", p1.Digest(), p2.Digest(), want)
	}
	if unaware.Digest() == want {
		t.Error("a peer that does not know of the fork has the same digest")
	}
}

func TestRange(t *testing.T) {
	a, b := testMember(1), testMember(2)
	es := buildChain(t, a, 5)
	l := testLog()
	appendAll(t, l, es, t0)
	cases := []struct {
		from, to uint64
		want     []Entry
	}{
		{1, 5, es}, {0, 5, es}, {2, 4, es[1:4]}, {4, 100, es[3:]}, {3, 3, es[2:3]},
		{5, math.MaxUint64, es[4:]}, {0, math.MaxUint64, es},
		{6, 10, nil}, {4, 2, nil}, {0, 0, nil}, {math.MaxUint64, math.MaxUint64, nil},
	}
	for _, c := range cases {
		if got := l.Range(a.id.ID, c.from, c.to); !reflect.DeepEqual(got, c.want) {
			t.Errorf("Range(%d, %d) = %d entries %+v, want %d", c.from, c.to, len(got), got, len(c.want))
		}
	}
	if got := l.Range(b.id.ID, 0, math.MaxUint64); got != nil {
		t.Errorf("Range of an origin the log does not hold = %+v, want nil", got)
	}
}

func TestPruneBounds(t *testing.T) {
	a, b := testMember(1), testMember(2)
	ea, eb := buildChain(t, a, 10), buildChain(t, b, 3)
	minute := func(i int) time.Time { return t0.Add(time.Duration(i) * time.Minute) }
	l := testLog()
	for i, e := range ea {
		appendAll(t, l, []Entry{e}, minute(i)) // ea[i] received at minute i
	}
	appendAll(t, l, eb, t0)
	digest := l.Digest()

	// By count, per origin.
	l.Prune(4, 0, minute(60))
	if got := l.Range(a.id.ID, 1, 10); !reflect.DeepEqual(got, ea[6:]) {
		t.Fatalf("Prune(4): a keeps seqs %v, want 7..10", seqs(got))
	}
	if got := l.Range(b.id.ID, 1, 3); !reflect.DeepEqual(got, eb) {
		t.Fatalf("Prune(4): b keeps seqs %v, want all 3", seqs(got))
	}
	if l.Pruned(a.id.ID) != headOf(ea[5]) || l.Pruned(b.id.ID) != (Head{}) {
		t.Fatalf("Pruned a %+v b %+v, want a = seq 6, b none", l.Pruned(a.id.ID), l.Pruned(b.id.ID))
	}
	if got := l.Range(a.id.ID, 1, 10); got[0].Prev != l.Pruned(a.id.ID).Hash {
		t.Fatal("the oldest kept entry does not link to the pruned mark")
	}
	if got := l.Range(a.id.ID, 1, 6); got != nil {
		t.Fatalf("Range over pruned seqs = %+v, want nothing", got)
	}
	if l.Digest() != digest || l.Head(a.id.ID) != headOf(ea[9]) {
		t.Fatal("pruning changed the head or the digest")
	}

	// By age: kept are the entries received at most 2 minutes before now.
	l.Prune(0, 2*time.Minute, minute(9))
	if got := l.Range(a.id.ID, 1, 10); !reflect.DeepEqual(got, ea[7:]) {
		t.Fatalf("Prune by age: a keeps seqs %v, want 8..10 (8 is exactly 2 minutes old)", seqs(got))
	}
	if l.Pruned(a.id.ID) != headOf(ea[6]) {
		t.Fatalf("Pruned(a) = %+v, want seq 7", l.Pruned(a.id.ID))
	}
	if got := l.Range(b.id.ID, 1, 3); !reflect.DeepEqual(got, eb[2:]) {
		t.Fatalf("Prune by age: b keeps seqs %v, want only its head", seqs(got))
	}

	// Both limits at once: the one that drops more decides.
	both := testLog()
	for i, e := range ea {
		appendAll(t, both, []Entry{e}, minute(i))
	}
	both.Prune(4, time.Hour, minute(9)) // the count drops 6, the age none
	if got := both.Range(a.id.ID, 1, 10); !reflect.DeepEqual(got, ea[6:]) {
		t.Fatalf("Prune(4, 1h): keeps seqs %v, want 7..10", seqs(got))
	}
	both.Prune(4, 90*time.Second, minute(9)) // the age drops 7 and 8, the count none
	if got := both.Range(a.id.ID, 1, 10); !reflect.DeepEqual(got, ea[8:]) {
		t.Fatalf("Prune(4, 90s): keeps seqs %v, want 9..10", seqs(got))
	}

	// Limits of zero or less are no limits; Prune is idempotent.
	before := stateOf(l, a.id.ID, b.id.ID)
	l.Prune(0, 0, minute(100000))
	l.Prune(-1, -time.Hour, minute(100000))
	l.Prune(3, 2*time.Minute, minute(9))
	if after := stateOf(l, a.id.ID, b.id.ID); !reflect.DeepEqual(after, before) {
		t.Fatal("a no-op prune changed the log")
	}

	// The head stays, however old and however small the limit.
	l.Prune(1, time.Nanosecond, minute(100000))
	if got := l.Range(a.id.ID, 0, math.MaxUint64); !reflect.DeepEqual(got, ea[9:]) {
		t.Fatalf("a keeps seqs %v, want only its head 10", seqs(got))
	}
	if l.Head(a.id.ID) != headOf(ea[9]) || l.Pruned(a.id.ID) != headOf(ea[8]) {
		t.Fatalf("Head %+v Pruned %+v, want 10 and 9", l.Head(a.id.ID), l.Pruned(a.id.ID))
	}

	// The chain grows on from the head; what was pruned is never compared.
	next := mustEntry(t, a, headOf(ea[9]), KindEvent, 11)
	appendAll(t, l, []Entry{next}, minute(100000))
	for _, e := range []Entry{ea[3], ea[8]} {
		if err := l.Append(e, minute(100000)); !errors.Is(err, ErrPruned) {
			t.Errorf("seq %d at or below the pruned mark: err = %v, want %v", e.Seq, err, ErrPruned)
		}
	}
	if err := l.Append(ea[9], minute(100000)); err != nil {
		t.Errorf("a held entry again after pruning: %v, want nil", err)
	}
	alt := mustEntry(t, a, headOf(ea[8]), KindEvent, "other 10")
	if err := l.Append(alt, minute(100000)); !errors.Is(err, ErrFork) {
		t.Errorf("another seq 10, still held: err = %v, want %v", err, ErrFork)
	}
}

func seqs(es []Entry) []uint64 {
	var out []uint64
	for _, e := range es {
		out = append(out, e.Seq)
	}
	return out
}

// TestConcurrentUse runs appends, reads and prunes from many goroutines;
// with -race it checks the locking, and two conflicting entries sent at
// once end as exactly one stored entry and one fork.
func TestConcurrentUse(t *testing.T) {
	shared := testMember(99)
	sharedChain := buildChain(t, shared, 30)
	var ms []member
	chains := map[ids.MemberID][]Entry{}
	for n := byte(1); n <= 8; n++ {
		m := testMember(n)
		ms = append(ms, m)
		chains[m.id.ID] = buildChain(t, m, 30)
	}
	l := testLog()

	// Readers run through both phases below, one goroutine per method, each
	// touching the log only through that method: a method that skips the
	// lock is then unordered with Append's writes, and -race reports it.
	everyone := append(slices.Clone(ms), shared)
	done := make(chan struct{})
	var readers sync.WaitGroup
	loop := func(read func()) {
		readers.Go(func() {
			for {
				select {
				case <-done:
					return
				default:
				}
				read()
			}
		})
	}
	loop(func() {
		for _, m := range everyone {
			_ = l.Head(m.id.ID)
		}
	})
	loop(func() {
		for _, m := range everyone {
			_ = l.Range(m.id.ID, 1, 40)
		}
	})
	loop(func() {
		for _, m := range everyone {
			_ = l.Pruned(m.id.ID)
		}
	})
	loop(func() { _ = l.Digest() })
	loop(func() { _ = l.Forks() })
	loop(func() { l.Prune(1000, 0, t0) }) // drops nothing, reads every chain
	defer func() {
		close(done)
		readers.Wait()
	}()

	var wg sync.WaitGroup
	for _, m := range ms {
		wg.Go(func() {
			for _, e := range chains[m.id.ID] {
				if err := l.Append(e, t0); err != nil {
					t.Errorf("%s seq %d: %v", m.id.ID, e.Seq, err)
				}
			}
			for _, e := range sharedChain {
				if err := l.Append(e, t0); err != nil {
					t.Errorf("shared seq %d: %v", e.Seq, err)
				}
			}
		})
	}
	wg.Wait()
	heads := map[ids.MemberID]Head{shared.id.ID: headOf(sharedChain[29])}
	for _, m := range ms {
		heads[m.id.ID] = headOf(chains[m.id.ID][29])
	}
	if got, want := l.Digest(), wantDigest(heads); got != want {
		t.Fatalf("Digest after concurrent appends = %s, want %s", got, want)
	}

	rivals := []Entry{
		mustEntry(t, shared, headOf(sharedChain[29]), KindEvent, "left"),
		mustEntry(t, shared, headOf(sharedChain[29]), KindEvent, "right"),
	}
	errs := make([]error, len(rivals))
	for i, e := range rivals {
		wg.Go(func() { errs[i] = l.Append(e, t0) })
	}
	wg.Wait()
	stored, forks := 0, 0
	for _, err := range errs {
		switch {
		case err == nil:
			stored++
		case errors.Is(err, ErrFork):
			forks++
		}
	}
	if stored != 1 || forks != 1 {
		t.Fatalf("two rivals at once: %d stored, %d forks (%v), want 1 and 1", stored, forks, errs)
	}
}

func forkOrigins(ps []ForkProof) []ids.MemberID {
	var out []ids.MemberID
	for _, p := range ps {
		out = append(out, p.A.Origin)
	}
	return out
}
