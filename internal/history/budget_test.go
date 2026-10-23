package history

import (
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"

	"github.com/TAIPANBOX/rollcall/internal/ids"
)

// The byte budget, written out here so that a change in the package shows
// as a red test instead of passing on both sides.
const (
	fmtMaxBytes = 256 << 10 // bytes the log holds of one origin, at most
	// fmtEntryFixed is what an entry is charged besides its body, kind and
	// signature: origin 16, seq 8, prev 32 and its hash 32.
	fmtEntryFixed = 16 + 8 + 32 + 32
	// storeFileLimit is internal/store's maxFileSize: the node writes each
	// origin's chain as one file of the store, and the store refuses a file
	// over this size.
	storeFileLimit = 1 << 20
)

// charged is the documented size of e in the byte budget.
func charged(e Entry) int { return len(e.Body) + len(e.Kind) + len(e.Sig) + fmtEntryFixed }

func chargedAll(es []Entry) int {
	n := 0
	for _, e := range es {
		n += charged(e)
	}
	return n
}

// stringBody returns a canonical JSON body of exactly n bytes, n >= 2: a
// string of n-2 letters.
func stringBody(n int) json.RawMessage {
	return json.RawMessage(`"` + strings.Repeat("a", n-2) + `"`)
}

// buildChainAfter returns n entries of m after prev, of the given kind and
// body.
func buildChainAfter(t testing.TB, m member, prev Head, n int, kind Kind, body json.RawMessage) []Entry {
	t.Helper()
	out := make([]Entry, 0, n)
	for range n {
		e := mustEntry(t, m, prev, kind, body)
		out = append(out, e)
		prev = headOf(e)
	}
	return out
}

// TestAppendBoundedByBytes: an origin that writes the largest bodies the
// format allows is held to the byte budget at once, as the count bound
// holds it: the oldest entries go first, no more of them than needed, the
// head stays, and other origins are untouched. Before the budget, one
// compromised member made every holder keep 500 entries of 8 KiB.
func TestAppendBoundedByBytes(t *testing.T) {
	if DefaultMaxBytes != fmtMaxBytes {
		t.Fatalf("DefaultMaxBytes = %d, want %d", DefaultMaxBytes, fmtMaxBytes)
	}
	a, b := testMember(1), testMember(2)
	big := buildChainAfter(t, a, Head{}, 80, KindEvent, stringBody(MaxBodySize))
	l := NewLog(keysOf(a, b), 0)
	appendAll(t, l, buildChain(t, b, 3), t0)
	for i, e := range big {
		appendAll(t, l, []Entry{e}, t0)
		held := l.Range(a.id.ID, 0, math.MaxUint64)
		if got := chargedAll(held); got > fmtMaxBytes {
			t.Fatalf("after seq %d: %d entries of %d bytes held, over the budget of %d", i+1, len(held), got, fmtMaxBytes)
		}
		if held[len(held)-1].Seq != e.Seq {
			t.Fatalf("after seq %d: the head is not the newest entry", i+1)
		}
		if p := l.Pruned(a.id.ID); p.Seq > 0 {
			dropped := big[p.Seq-1]
			if p != headOf(dropped) || held[0].Seq != p.Seq+1 {
				t.Fatalf("after seq %d: Pruned %+v, oldest held %d; want the last dropped entry and the one after it", i+1, p, held[0].Seq)
			}
			if chargedAll(held)+charged(dropped) <= fmtMaxBytes {
				t.Fatalf("after seq %d: seq %d was dropped although it fits in the budget", i+1, dropped.Seq)
			}
		}
	}
	held := l.Range(a.id.ID, 0, math.MaxUint64)
	if len(held) >= len(big) || len(held) < 2 {
		t.Fatalf("%d of %d entries of %d bytes held; want the budget to hold some, not all", len(held), len(big), charged(big[0]))
	}
	t.Logf("budget %d bytes: %d of %d entries with %d-byte bodies held, %d bytes", fmtMaxBytes, len(held), len(big), MaxBodySize, chargedAll(held))
	if got := l.Range(b.id.ID, 0, math.MaxUint64); len(got) != 3 || l.Pruned(b.id.ID) != (Head{}) {
		t.Fatalf("b holds %d entries, pruned %+v; want its 3 untouched", len(got), l.Pruned(b.id.ID))
	}
	if err := l.Append(big[0], t0); !errors.Is(err, ErrPruned) {
		t.Fatalf("an entry the budget dropped, again: err = %v, want %v", err, ErrPruned)
	}

	// Prune keeps the count of bytes held: after it drops entries, the
	// budget makes room for no fewer and no more than it should.
	l.Prune(3, 0, t0)
	next := buildChainAfter(t, a, l.Head(a.id.ID), 40, KindEvent, stringBody(MaxBodySize))
	appendAll(t, l, next, t0)
	if got := l.Range(a.id.ID, 0, math.MaxUint64); len(got) != len(held) || chargedAll(got) > fmtMaxBytes {
		t.Fatalf("after Prune and 40 more: %d entries of %d bytes held, want %d within the budget", len(got), chargedAll(got), len(held))
	}
}

// TestByteBudgetKeepsTheHead: however small the budget, the head stays, as
// it does under every other bound.
func TestByteBudgetKeepsTheHead(t *testing.T) {
	a := testMember(1)
	es := buildChainAfter(t, a, Head{}, 4, KindEvent, stringBody(100))
	l := logOf(a)
	l.maxBytes = charged(es[0]) - 1 // not even one entry fits
	appendAll(t, l, es, t0)
	if got := l.Range(a.id.ID, 0, math.MaxUint64); !reflect.DeepEqual(got, es[3:]) || l.Pruned(a.id.ID) != headOf(es[2]) {
		t.Fatalf("held seqs %v, pruned %+v; want the head 4 alone, pruned 3", seqs(got), l.Pruned(a.id.ID))
	}
	l.maxBytes = 0 // no limit
	more := buildChainAfter(t, a, l.Head(a.id.ID), 3, KindEvent, stringBody(100))
	appendAll(t, l, more, t0)
	if got := l.Range(a.id.ID, 0, math.MaxUint64); len(got) != 4 {
		t.Fatalf("a budget of 0: %d entries held, want 4", len(got))
	}
}

// TestByteBudgetCountsTheWholeEntry: an entry counts for its body, kind and
// signature and the fixed part, no more and no less: a budget of exactly
// three entries holds three, and a byte less holds two.
func TestByteBudgetCountsTheWholeEntry(t *testing.T) {
	a := testMember(1)
	es := buildChainAfter(t, a, Head{}, 6, KindEvent, stringBody(90))
	for _, c := range []struct{ budget, want int }{
		{3 * charged(es[0]), 3},
		{3*charged(es[0]) - 1, 2},
	} {
		l := logOf(a)
		l.maxBytes = c.budget
		appendAll(t, l, es, t0)
		if got := l.Range(a.id.ID, 0, math.MaxUint64); !reflect.DeepEqual(got, es[len(es)-c.want:]) {
			t.Errorf("a budget of %d bytes for entries of %d: held seqs %v, want the newest %d", c.budget, charged(es[0]), seqs(got), c.want)
		}
	}
}

// TestByteBudgetSpareForHonestChains: the budget is above what an honest
// chain of 500 entries needs, so honest chains are bounded by count, not by
// bytes. An event body shaped like the node's (subject, type, last boot,
// stamp, one detail) is 282 bytes; the budget leaves room for 500 entries
// with bodies of up to 362 bytes on average.
func TestByteBudgetSpareForHonestChains(t *testing.T) {
	a := testMember(1)
	hex32, hex64 := strings.Repeat("0123456789abcdef", 2), strings.Repeat("0123456789abcdef", 4)
	event := json.RawMessage(`{"subject":"` + hex32 + `","type":"member_silent","last":{"id":"` + hex32 +
		`","seq":12},"at":{"wall":"2026-10-23T12:34:56.123456789Z","mono":123456789012,"trusted":true,"boot":"` +
		hex32 + `"},"detail":{"version":"24.10.4"}}`)
	witness := json.RawMessage(`{"ref":"` + hex64 + `","agree":true,"note":""}`)
	l := NewLog(keysOf(a), 0)
	prev := Head{}
	var es []Entry
	for i := range DefaultMaxEntries + 20 {
		kind, body := KindEvent, event
		if i%2 == 1 {
			kind, body = KindWitness, witness
		}
		e := mustEntry(t, a, prev, kind, body)
		es = append(es, e)
		prev = headOf(e)
	}
	appendAll(t, l, es, t0)
	held := l.Range(a.id.ID, 0, math.MaxUint64)
	if len(held) != DefaultMaxEntries {
		t.Fatalf("an honest chain keeps %d entries, want %d: the byte budget cut it", len(held), DefaultMaxEntries)
	}
	t.Logf("event body %d bytes, witness body %d bytes; 500 entries hold %d of %d bytes", len(event), len(witness), chargedAll(held), fmtMaxBytes)
	if spare := fmtMaxBytes/DefaultMaxEntries - (len(Kind("correction")) + 64 + fmtEntryFixed); spare != 362 {
		t.Fatalf("the budget leaves %d bytes of body per entry at the count bound, want 362 as documented", spare)
	}
}

// TestByteBudgetFitsTheStoreFile: a full chain at the budget, written as the
// node writes it (json.Marshal of what Range returns, plus the next own
// entry), stays well below the store's file limit. The worst case is the
// most entries the count bound allows, each as large as the budget lets
// them be, with the longest kind and 20-digit seqs: then the per-entry JSON
// overhead (hex IDs and hashes, a base64 signature, field names) is paid
// the most times.
func TestByteBudgetFitsTheStoreFile(t *testing.T) {
	a := testMember(1)
	var huge ids.Hash
	huge[0] = 1
	base := Head{Seq: 10_000_000_000_000_000_000 - 1, Hash: huge} // seqs after it have 20 digits
	perEntry := fmtMaxBytes/DefaultMaxEntries - (len(KindCorrection) + 64 + fmtEntryFixed)
	shapes := []struct {
		name string
		n    int
		body json.RawMessage
	}{
		{"500 entries of the largest body the budget allows", DefaultMaxEntries + 10, stringBody(perEntry)},
		{"entries of the largest body the format allows", DefaultMaxEntries + 10, stringBody(MaxBodySize)},
	}
	worst := 0
	for _, s := range shapes {
		es := buildChainAfter(t, a, base, s.n, KindCorrection, s.body)
		l := logOf(a)
		if err := l.StartAt(a.id.ID, base); err != nil {
			t.Fatal(err)
		}
		appendAll(t, l, es, t0)
		held := l.Range(a.id.ID, 0, math.MaxUint64)
		next := buildChainAfter(t, a, l.Head(a.id.ID), 1, KindCorrection, stringBody(MaxBodySize))
		file, err := json.Marshal(append(held, next...))
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%s: %d entries held, %d bytes charged, file %d bytes with the next own entry", s.name, len(held), chargedAll(held), len(file))
		worst = max(worst, len(file))
	}
	if worst > storeFileLimit/2 {
		t.Fatalf("a full chain writes a file of %d bytes, want at most half the store's limit of %d", worst, storeFileLimit)
	}
}
