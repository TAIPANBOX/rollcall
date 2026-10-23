package history

import (
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"testing"

	"github.com/TAIPANBOX/rollcall/internal/ids"
)

// reload loads saved, one origin's chain as Range gave it, into l the way a
// holder of a bounded chain does: StartAt at the oldest entry's Prev (the
// zero Head for a chain from Seq 1), then every entry in order.
func reload(t testing.TB, l *Log, saved []Entry) {
	t.Helper()
	if len(saved) == 0 {
		return
	}
	first := saved[0]
	if err := l.StartAt(first.Origin, Head{Seq: first.Seq - 1, Hash: first.Prev}); err != nil {
		t.Fatalf("StartAt before seq %d: %v", first.Seq, err)
	}
	appendAll(t, l, saved, t0)
}

// TestCappedChainReloadsAfterRestart: a chain past the per-origin cap,
// written as the node writes it (Range from 1, as JSON) and read back into
// an empty log, comes back whole: the same heads, pruned marks, entries and
// digest, and it grows on from its head. Without StartAt its oldest entry is
// a gap, as for any member that missed the first entries of a chain.
func TestCappedChainReloadsAfterRestart(t *testing.T) {
	a, b := testMember(1), testMember(2)
	l := NewLog(keysOf(a, b), 0)
	appendAll(t, l, buildChain(t, a, DefaultMaxEntries+5), t0)
	appendAll(t, l, buildChain(t, b, 3), t0)

	files := map[ids.MemberID][]byte{}
	for _, o := range []ids.MemberID{a.id.ID, b.id.ID} {
		raw, err := json.Marshal(l.Range(o, 1, l.Head(o).Seq))
		if err != nil {
			t.Fatalf("encode the chain of %s: %v", o, err)
		}
		files[o] = raw
	}

	fresh := NewLog(keysOf(a, b), 0)
	for _, o := range []ids.MemberID{a.id.ID, b.id.ID} {
		var saved []Entry
		if err := json.Unmarshal(files[o], &saved); err != nil {
			t.Fatalf("decode the chain of %s: %v", o, err)
		}
		if o == a.id.ID {
			if saved[0].Seq != 6 {
				t.Fatalf("the saved chain starts at seq %d, want 6 (the log keeps %d)", saved[0].Seq, DefaultMaxEntries)
			}
			if err := fresh.Append(saved[0], t0); !errors.Is(err, ErrGap) {
				t.Fatalf("seq 6 into an empty chain without StartAt: err = %v, want %v", err, ErrGap)
			}
		}
		reload(t, fresh, saved)
	}
	if got, want := stateOf(fresh, a.id.ID, b.id.ID), stateOf(l, a.id.ID, b.id.ID); !reflect.DeepEqual(got, want) {
		t.Fatalf("reloaded log: heads %+v pruned %+v, want heads %+v pruned %+v",
			got.Heads, got.Pruned, want.Heads, want.Pruned)
	}

	next := mustEntry(t, a, fresh.Head(a.id.ID), KindEvent, "after the restart")
	appendAll(t, fresh, []Entry{next}, t0)
	appendAll(t, l, []Entry{next}, t0)
	if fresh.Digest() != l.Digest() || fresh.Head(a.id.ID) != headOf(next) {
		t.Fatal("the reloaded chain does not grow on from its head as the original does")
	}
}

// TestCappedChainReplicatesToEmptyLog: a member with an empty log takes a
// chain its holder pruned: it starts at the base the holder exposes
// (Pruned) and fetches the rest. A holder that pruned nothing exposes the
// zero Head and the chain is fetched from Seq 1.
func TestCappedChainReplicatesToEmptyLog(t *testing.T) {
	a, b := testMember(1), testMember(2)
	holder := NewLog(keysOf(a, b), 0)
	appendAll(t, holder, buildChain(t, a, DefaultMaxEntries+40), t0)
	appendAll(t, holder, buildChain(t, b, 7), t0)

	joiner := NewLog(keysOf(a, b), 0)
	for _, o := range []ids.MemberID{a.id.ID, b.id.ID} {
		base := holder.Pruned(o)
		fetched := holder.Range(o, base.Seq+1, holder.Head(o).Seq)
		if base.Seq > 0 {
			if err := joiner.Append(fetched[0], t0); !errors.Is(err, ErrGap) {
				t.Fatalf("seq %d into an empty chain without StartAt: err = %v, want %v", fetched[0].Seq, err, ErrGap)
			}
		}
		if err := joiner.StartAt(o, base); err != nil {
			t.Fatalf("StartAt(%+v): %v", base, err)
		}
		appendAll(t, joiner, fetched, t0)
	}
	if got, want := stateOf(joiner, a.id.ID, b.id.ID), stateOf(holder, a.id.ID, b.id.ID); !reflect.DeepEqual(got, want) {
		t.Fatalf("replicated log: heads %+v pruned %+v, want heads %+v pruned %+v",
			got.Heads, got.Pruned, want.Heads, want.Pruned)
	}
	if got := joiner.Range(a.id.ID, 0, math.MaxUint64); len(got) != DefaultMaxEntries || got[0].Seq != 41 {
		t.Fatalf("the joiner holds %d entries of a from seq %d, want %d from 41", len(got), got[0].Seq, DefaultMaxEntries)
	}
}

// TestStartAtSetsTheBase: after StartAt the chain takes base.Seq+1 with
// base.Hash as its Prev and nothing else; entries at or below the base are
// ErrPruned, as if pruned, and Pruned reports the base. Until the first entry
// the log holds nothing of the origin: no head, no range, no digest change.
func TestStartAtSetsTheBase(t *testing.T) {
	a, b := testMember(1), testMember(2)
	es := buildChain(t, a, 10)
	base := headOf(es[5]) // seq 6
	l := logOf(a, b)
	empty := l.Digest()
	if err := l.StartAt(a.id.ID, base); err != nil {
		t.Fatalf("StartAt: %v", err)
	}
	if l.Pruned(a.id.ID) != base || l.Head(a.id.ID) != (Head{}) || l.Range(a.id.ID, 0, math.MaxUint64) != nil || l.Digest() != empty {
		t.Fatalf("after StartAt: Pruned %+v Head %+v; want the base and no head, range or digest change", l.Pruned(a.id.ID), l.Head(a.id.ID))
	}
	before := stateOf(l, a.id.ID, b.id.ID)

	other := mustEntry(t, a, Head{Seq: 6, Hash: wantHash(es[4])}, KindEvent, "seq 7 after another seq 6")
	cases := []struct {
		name string
		e    Entry
		want error
	}{
		{"seq 1", es[0], ErrPruned},
		{"seq 6, the base itself", es[5], ErrPruned},
		{"seq 8, past the base", es[7], ErrGap},
		{"seq 7 naming another prev", other, ErrPrev},
	}
	for _, c := range cases {
		if err := l.Append(c.e, t0); !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
	}
	if after := stateOf(l, a.id.ID, b.id.ID); !reflect.DeepEqual(after, before) {
		t.Fatal("a refused entry changed the log")
	}

	appendAll(t, l, es[6:], t0)
	if l.Head(a.id.ID) != headOf(es[9]) || l.Pruned(a.id.ID) != base || !reflect.DeepEqual(l.Range(a.id.ID, 0, math.MaxUint64), es[6:]) {
		t.Fatalf("after seqs 7..10: Head %+v Pruned %+v Range %v", l.Head(a.id.ID), l.Pruned(a.id.ID), seqs(l.Range(a.id.ID, 0, math.MaxUint64)))
	}
	if len(l.bases) != 0 {
		t.Fatalf("the log keeps %d bases of started chains, want none: the chain holds its base", len(l.bases))
	}
	if err := l.Append(es[2], t0); !errors.Is(err, ErrPruned) {
		t.Errorf("seq 3 below the base, after the chain started: err = %v, want %v", err, ErrPruned)
	}
	if err := l.Append(es[8], t0); err != nil {
		t.Errorf("a held entry again: %v, want nil", err)
	}
	alt := mustEntry(t, a, headOf(es[6]), KindEvent, "other 8")
	if err := l.Append(alt, t0); !errors.Is(err, ErrFork) {
		t.Errorf("another seq 8 above the base: err = %v, want %v", err, ErrFork)
	}
}

// TestStartAtOnlyOnAnEmptyChain: StartAt never moves the base of a chain the
// log holds entries of, a forked one included; while the chain is empty the
// last StartAt counts, and the zero Head returns it to Seq 1.
func TestStartAtOnlyOnAnEmptyChain(t *testing.T) {
	a, b := testMember(1), testMember(2)
	es := buildChain(t, a, 4)
	l := logOf(a, b)
	appendAll(t, l, es[:3], t0)
	appendAll(t, l, buildChain(t, b, 2), t0)
	forkOf(t, l, b)
	before := stateOf(l, a.id.ID, b.id.ID)
	for _, o := range []ids.MemberID{a.id.ID, b.id.ID} {
		for _, base := range []Head{{}, headOf(es[0]), headOf(es[2]), {Seq: 40, Hash: wantHash(es[1])}} {
			if err := l.StartAt(o, base); !errors.Is(err, ErrStarted) {
				t.Errorf("StartAt(%s, seq %d) on a held chain: err = %v, want %v", o, base.Seq, err, ErrStarted)
			}
		}
	}
	if after := stateOf(l, a.id.ID, b.id.ID); !reflect.DeepEqual(after, before) {
		t.Fatal("a refused StartAt changed the log")
	}

	e := logOf(a)
	for _, base := range []Head{headOf(es[1]), headOf(es[0])} {
		if err := e.StartAt(a.id.ID, base); err != nil {
			t.Fatalf("StartAt(seq %d) on an empty chain: %v", base.Seq, err)
		}
	}
	if e.Pruned(a.id.ID) != headOf(es[0]) {
		t.Fatalf("Pruned = %+v, want the last base, seq 1", e.Pruned(a.id.ID))
	}
	if err := e.Append(es[2], t0); !errors.Is(err, ErrGap) {
		t.Fatalf("seq 3 after the base moved back to 1: err = %v, want %v", err, ErrGap)
	}
	if err := e.StartAt(a.id.ID, Head{}); err != nil {
		t.Fatalf("StartAt(zero): %v", err)
	}
	if e.Pruned(a.id.ID) != (Head{}) {
		t.Fatalf("Pruned = %+v after StartAt(zero), want none", e.Pruned(a.id.ID))
	}
	appendAll(t, e, es[:1], t0) // seq 1 again
	if err := e.StartAt(a.id.ID, Head{}); !errors.Is(err, ErrStarted) {
		t.Fatalf("StartAt after the first entry: err = %v, want %v", err, ErrStarted)
	}
	if len(e.bases) != 0 {
		t.Fatalf("the log keeps %d bases of started chains, want none", len(e.bases))
	}
}

// TestStartAtRefusesBadArguments: a base whose Seq and Hash disagree, one at
// the last Seq, and an origin the resolver does not know are refused, and
// nothing changes.
func TestStartAtRefusesBadArguments(t *testing.T) {
	a, c := testMember(1), testMember(3)
	h := wantHash(buildChain(t, a, 1)[0])
	l := logOf(a)
	cases := []struct {
		name   string
		origin ids.MemberID
		base   Head
		want   error
	}{
		{"a seq without a hash", a.id.ID, Head{Seq: 3}, ErrInvalid},
		{"a hash without a seq", a.id.ID, Head{Hash: h}, ErrInvalid},
		{"the last seq", a.id.ID, Head{Seq: math.MaxUint64, Hash: h}, ErrInvalid},
		{"an unknown origin", c.id.ID, Head{Seq: 3, Hash: h}, ErrUnknownOrigin},
	}
	for _, tc := range cases {
		if err := l.StartAt(tc.origin, tc.base); !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", tc.name, err, tc.want)
		}
		if l.Pruned(tc.origin) != (Head{}) {
			t.Errorf("%s: Pruned = %+v, want none", tc.name, l.Pruned(tc.origin))
		}
	}
	if err := new(Log).StartAt(a.id.ID, Head{}); !errors.Is(err, ErrUnknownOrigin) {
		t.Errorf("a zero Log: err = %v, want %v", err, ErrUnknownOrigin)
	}
}
