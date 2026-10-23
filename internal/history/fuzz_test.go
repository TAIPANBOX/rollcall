package history

import (
	"encoding/json"
	"errors"
	"maps"
	"reflect"
	"slices"
	"testing"

	"github.com/TAIPANBOX/rollcall/internal/ids"
)

// sentinels are every error Append may return, wrapped or not.
var sentinels = []error{ErrUnknownOrigin, ErrKey, ErrFormat, ErrKind, ErrBody, ErrSignature, ErrPrev, ErrGap, ErrPruned, ErrFork}

// clone returns a copy of l that shares no mutable state with it, so each
// fuzz input starts from the same log without verifying it again. Stored
// entries are never written to, so their slices may be shared.
func (l *Log) clone() *Log {
	l.mu.Lock()
	defer l.mu.Unlock()
	c := &Log{keyOf: l.keyOf, max: l.max, maxBytes: l.maxBytes, chains: map[ids.MemberID]*chain{}, forks: map[ids.MemberID]ForkProof{}}
	for o, ch := range l.chains {
		cp := *ch
		cp.entries = slices.Clone(ch.entries)
		c.chains[o] = &cp
	}
	for o, p := range l.forks {
		c.forks[o] = p
	}
	if l.bases != nil {
		c.bases = maps.Clone(l.bases)
	}
	return c
}

// FuzzAppend feeds arbitrary bytes to Append three ways: as a JSON-encoded
// entry, as the fields of an entry with an arbitrary signature, and as the
// fields of an entry signed with the origin's real key, so that the shape,
// body and chain checks see hostile input past the signature. The log knows
// the key of every test member and nothing else, and holds a chain of 3
// entries of origin A and nothing of origin B.
//
// Nothing may panic. An origin the log does not know, and only such an
// origin, gives ErrUnknownOrigin. An error is always one of the package's sentinels, and
// leaves the log as it was unless it is a fork, which comes with a proof
// that verifies, whose B is the entry given and whose A is the entry held.
// An accepted entry verifies, has a body the documented rules allow, and is
// either a duplicate of a held entry or the new head, linked to the old one.
func FuzzAppend(f *testing.F) {
	a, b := testMember(1), testMember(2)
	es := buildChain(f, a, 3)
	base := testLog()
	appendAll(f, base, es, t0)
	h2, h3 := wantHash(es[1]), wantHash(es[2])

	js, err := json.Marshal(es[1])
	if err != nil {
		f.Fatal(err)
	}
	f.Add(js, uint64(0), []byte(nil), "", []byte(nil), byte(0)) // a duplicate, as JSON
	f.Add([]byte(`{"origin":"`+a.id.ID.String()+`","seq":1}`), uint64(0), []byte(nil), "", []byte(nil), byte(0))
	f.Add([]byte(nil), uint64(4), h3[:], "event", []byte(`{"n":4}`), byte(2))      // the next entry
	f.Add([]byte(nil), uint64(3), h2[:], "event", []byte(`{"n":9}`), byte(2))      // a fork
	f.Add([]byte(nil), uint64(5), h3[:], "event", []byte(`5`), byte(2))            // a gap
	f.Add([]byte(nil), uint64(1), []byte(nil), "boot", []byte(`null`), byte(6))    // B's first entry
	f.Add(es[0].Sig, uint64(1), []byte(nil), "event", []byte(es[0].Body), byte(1)) // a duplicate, field by field
	f.Add([]byte(nil), uint64(4), h3[:], "witness", []byte(`{"a": 1}`), byte(2))   // a body json would rewrite
	f.Add([]byte(nil), uint64(4), h3[:], "note", []byte(`1`), byte(2))             // an unknown kind

	f.Fuzz(func(t *testing.T, raw []byte, seq uint64, prev []byte, kind string, body []byte, mode byte) {
		owner := a
		if mode&4 != 0 {
			owner = b
		}
		var e Entry
		switch mode % 3 {
		case 0:
			if json.Unmarshal(raw, &e) != nil {
				return
			}
		default:
			e = Entry{Origin: owner.id.ID, Seq: seq, Kind: Kind(kind), Body: body, Sig: raw}
			copy(e.Prev[:], prev)
			if mode%3 == 2 {
				e = resign(e, owner.key)
			}
		}
		l := base.clone()
		before := stateOf(l, a.id.ID, b.id.ID)
		oldHead := before.Heads[e.Origin]
		err := l.Append(e, t0)
		after := stateOf(l, a.id.ID, b.id.ID)
		pub, known := testKeys[e.Origin]
		if !known != errors.Is(err, ErrUnknownOrigin) {
			t.Fatalf("origin %s known %v: err = %v", e.Origin, known, err)
		}

		if err != nil {
			known := false
			for _, s := range sentinels {
				known = known || errors.Is(err, s)
			}
			if !known {
				t.Fatalf("Append returned %v, not one of the package's errors", err)
			}
			var fe *ForkError
			if !errors.As(err, &fe) {
				if errors.Is(err, ErrFork) {
					t.Fatalf("ErrFork without a *ForkError: %v", err)
				}
				if !reflect.DeepEqual(after, before) {
					t.Fatalf("a refused entry (%v) changed the log", err)
				}
				return
			}
			if verr := fe.Proof.Verify(pub); verr != nil {
				t.Fatalf("fork proof does not verify: %v", verr)
			}
			if !reflect.DeepEqual(fe.Proof.B, e) {
				t.Fatalf("fork proof B = %+v, want the entry given %+v", fe.Proof.B, e)
			}
			held := before.Ranges[e.Origin]
			if e.Seq == 0 || e.Seq > uint64(len(held)) || !reflect.DeepEqual(fe.Proof.A, held[e.Seq-1]) {
				t.Fatalf("fork proof A = %+v, not the entry held at seq %d", fe.Proof.A, e.Seq)
			}
			if after.Heads[e.Origin] != oldHead || !reflect.DeepEqual(after.Ranges, before.Ranges) {
				t.Fatal("a fork changed a chain")
			}
			return
		}

		if verr := e.Verify(pub); verr != nil {
			t.Fatalf("Append accepted an entry that does not verify: %v", verr)
		}
		if !canonical(e.Body) {
			t.Fatalf("Append accepted the body %q", e.Body)
		}
		switch {
		case e.Seq <= oldHead.Seq:
			held := before.Ranges[e.Origin]
			if e.Seq == 0 || e.Seq > uint64(len(held)) || !reflect.DeepEqual(after, before) || !reflect.DeepEqual(held[e.Seq-1], e) {
				t.Fatalf("seq %d at or below head %d accepted, but not as a duplicate", e.Seq, oldHead.Seq)
			}
		case e.Seq == oldHead.Seq+1 && e.Prev == oldHead.Hash:
			if after.Heads[e.Origin] != headOf(e) {
				t.Fatalf("Head = %+v after appending, want %+v", after.Heads[e.Origin], headOf(e))
			}
		default:
			t.Fatalf("accepted seq %d prev %s on head %+v", e.Seq, e.Prev, oldHead)
		}
	})
}
