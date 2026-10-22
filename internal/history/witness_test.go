package history

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/TAIPANBOX/rollcall/internal/ids"
)

// The statement rules, written out here so that a change in the package
// shows as a red test instead of passing on both sides.
const (
	fmtMaxNote = 200 // bytes of a note, at most
	fmtMaxRefs = 16  // entries one correction refers to, at most
)

// fmtClasses is the closed set of correction classes, in byte order.
var fmtClasses = []string{"link_lost", "member_back", "reboot_planned", "reboot_unplanned", "upgraded"}

// silent is the body of the event the fixtures witness.
var silent = map[string]string{"type": "member_silent", "subject": "gateway"}

// add appends m's next entry of the given kind to l and returns it.
func add(t testing.TB, l *Log, m member, kind Kind, body any) Entry {
	t.Helper()
	e := mustEntry(t, m, l.Head(m.id.ID), kind, body)
	if err := l.Append(e, t0); err != nil {
		t.Fatalf("Append %s seq %d: %v", kind, e.Seq, err)
	}
	return e
}

// witness appends m's statement about ref to l and returns it.
func witness(t testing.TB, l *Log, m member, ref ids.Hash, agree bool, note string) Entry {
	t.Helper()
	e, err := NewWitness(m.id, l.Head(m.id.ID), ref, agree, note)
	if err != nil {
		t.Fatalf("NewWitness: %v", err)
	}
	if err := l.Append(e, t0); err != nil {
		t.Fatalf("Append witness seq %d: %v", e.Seq, err)
	}
	return e
}

// correct appends m's correction of refs to l and returns it.
func correct(t testing.TB, l *Log, m member, refs []ids.Hash, class, note string) Entry {
	t.Helper()
	e, err := NewCorrection(m.id, l.Head(m.id.ID), refs, class, note)
	if err != nil {
		t.Fatalf("NewCorrection: %v", err)
	}
	if err := l.Append(e, t0); err != nil {
		t.Fatalf("Append correction seq %d: %v", e.Seq, err)
	}
	return e
}

// forkOf makes l hold a fork proof against m: m signs a second, different
// entry at the seq of its head, and Append must report the fork.
func forkOf(t testing.TB, l *Log, m member) {
	t.Helper()
	head := l.Head(m.id.ID)
	var prev Head
	if head.Seq > 1 {
		prev = headOf(l.Range(m.id.ID, head.Seq-1, head.Seq-1)[0])
	}
	e := mustEntry(t, m, prev, KindBoot, map[string]string{"fork": "a second entry at the head's seq"})
	if err := l.Append(e, t0); !errors.Is(err, ErrFork) {
		t.Fatalf("a second entry at seq %d: err = %v, want %v", head.Seq, err, ErrFork)
	}
}

// idsOf returns the members' IDs in the order given, nil for none.
func idsOf(ms ...member) []ids.MemberID {
	var out []ids.MemberID
	for _, m := range ms {
		out = append(out, m.id.ID)
	}
	return out
}

// confirmedBy is the count as a message shows it.
func confirmedBy(agree, disagree []ids.MemberID) string {
	return fmt.Sprintf("confirmed by %d of %d", len(agree), len(agree)+len(disagree))
}

// wantConfirmations asks Confirmations about ref several times, because the
// log keeps its chains in a map whose order differs between calls, and
// requires the given lists every time.
func wantConfirmations(t *testing.T, l *Log, ref ids.Hash, agree, disagree []ids.MemberID) {
	t.Helper()
	for i := 0; i < 20; i++ {
		a, d := Confirmations(l, ref)
		if !slices.Equal(a, agree) || !slices.Equal(d, disagree) {
			t.Fatalf("call %d: Confirmations = agree %v, disagree %v; want agree %v, disagree %v", i, a, d, agree, disagree)
		}
	}
}

// wantCorrections asks Corrections about ref several times, for the same
// reason, and requires want every time.
func wantCorrections(t *testing.T, l *Log, ref ids.Hash, want []Entry) {
	t.Helper()
	for i := 0; i < 20; i++ {
		if got := Corrections(l, ref); !reflect.DeepEqual(got, want) {
			t.Fatalf("call %d: Corrections = %d entries %v, want %d %v", i, len(got), seqs(got), len(want), seqs(want))
		}
	}
}

// witnessBody is a witness body in the wire form, built here on its own.
func witnessBody(ref, agree, note string) string {
	return `{"ref":"` + ref + `","agree":` + agree + `,"note":"` + note + `"}`
}

// TestConfirmationCount: the gateway goes silent, the router that saw it
// records the event, and four other routers state what they saw, so a
// message can say "confirmed by 3 of 4". On the way: a member that changed
// its mind counts once, by its latest statement; a member that said the
// same twice counts once; the event's own origin does not confirm itself; a
// member whose chain forked is not counted; malformed statements are
// skipped and the count goes on past them; a statement about another event
// does not count for this one.
func TestConfirmationCount(t *testing.T) {
	origin := testMember(1)
	m2, m3, m4, m5, m6, m7, m8 := testMember(2), testMember(3), testMember(4), testMember(5), testMember(6), testMember(7), testMember(8)
	l := testLog()
	event := add(t, l, origin, KindEvent, silent)
	ref := wantHash(event)
	back := add(t, l, origin, KindEvent, map[string]string{"type": "member_back", "subject": "gateway"})

	witness(t, l, m5, ref, true, "")
	witness(t, l, m5, ref, false, "it answered my probes") // its latest about ref
	witness(t, l, m5, wantHash(back), true, "")            // about the other event
	witness(t, l, m4, ref, true, "")
	witness(t, l, m3, ref, true, "")
	witness(t, l, m3, ref, true, "still silent")                                                               // said twice, counts once
	add(t, l, m2, KindWitness, json.RawMessage(`{"ref":"`+ref.String()+`","agree":false,"note":"","seen":3}`)) // malformed, then more from m2
	witness(t, l, m2, ref, false, "")
	witness(t, l, m2, ref, true, "now I see it too") // changed its mind: the latest counts
	witness(t, l, origin, ref, true, "")             // the event's origin about its own event
	witness(t, l, m6, ref, true, "")
	forkOf(t, l, m6) // m6's chain forked after its statement
	add(t, l, m7, KindWitness, json.RawMessage(witnessBody(ref.String(), "true", strings.Repeat("a", fmtMaxNote+1))))
	add(t, l, m8, KindWitness, json.RawMessage(`{"ref":"`+ref.String()+`","agree":true,"note":"","seen":3}`))

	wantConfirmations(t, l, ref, idsOf(m2, m3, m4), idsOf(m5))
	if got := confirmedBy(Confirmations(l, ref)); got != "confirmed by 3 of 4" {
		t.Fatalf("the message would say %q, want %q", got, "confirmed by 3 of 4")
	}
	wantConfirmations(t, l, wantHash(back), idsOf(m5), nil)
	wantConfirmations(t, l, ids.Hash{1}, nil, nil)
}

// TestWitnessForUnknownRefIsKeptButNotCounted: statements about an event
// the log does not hold yet are appended and kept like any other entry,
// and count from the moment the event arrives.
func TestWitnessForUnknownRefIsKeptButNotCounted(t *testing.T) {
	origin, w1, w2 := testMember(1), testMember(2), testMember(3)
	l := testLog()
	event := mustEntry(t, origin, Head{}, KindEvent, silent) // signed, not yet relayed
	ref := wantHash(event)

	s1 := witness(t, l, w1, ref, true, "")
	s2 := witness(t, l, w2, ref, false, "")
	if got := l.Range(w1.id.ID, 1, 1); !reflect.DeepEqual(got, []Entry{s1}) {
		t.Fatalf("w1's chain = %v, want its statement kept", seqs(got))
	}
	if got := l.Range(w2.id.ID, 1, 1); !reflect.DeepEqual(got, []Entry{s2}) {
		t.Fatalf("w2's chain = %v, want its statement kept", seqs(got))
	}
	wantConfirmations(t, l, ref, nil, nil)

	if err := l.Append(event, t0); err != nil {
		t.Fatal(err)
	}
	wantConfirmations(t, l, ref, idsOf(w1), idsOf(w2))
}

// TestConfirmationsNeedTheEvent: Confirmations counts statements about an
// event the log holds; a statement about an entry of another kind counts for
// nothing, and an event the log pruned has no count any more. A fork of the
// event's own origin does not hide the statements about the event: they name
// the hash of the entry the log holds.
func TestConfirmationsNeedTheEvent(t *testing.T) {
	origin, w2, w3 := testMember(1), testMember(2), testMember(3)

	t.Run("kind", func(t *testing.T) {
		l := testLog()
		event := add(t, l, origin, KindEvent, silent)
		boot := add(t, l, origin, KindBoot, map[string]string{"boot_id": "00ff"})
		corr := correct(t, l, origin, []ids.Hash{wantHash(event)}, "member_back", "")
		s := witness(t, l, w2, wantHash(event), true, "")
		witness(t, l, w2, wantHash(boot), true, "")
		witness(t, l, w2, wantHash(corr), true, "")
		witness(t, l, w3, wantHash(s), true, "")
		wantConfirmations(t, l, wantHash(event), idsOf(w2), nil)
		for name, h := range map[string]ids.Hash{"boot": wantHash(boot), "correction": wantHash(corr), "witness": wantHash(s)} {
			if a, d := Confirmations(l, h); a != nil || d != nil {
				t.Fatalf("statements about a %s entry counted: agree %v, disagree %v", name, a, d)
			}
		}
	})

	t.Run("pruned", func(t *testing.T) {
		l := NewLog(keysOf(origin, w2), 2)
		event := add(t, l, origin, KindEvent, silent)
		witness(t, l, w2, wantHash(event), true, "")
		wantConfirmations(t, l, wantHash(event), idsOf(w2), nil)
		add(t, l, origin, KindEvent, map[string]int{"n": 2})
		add(t, l, origin, KindEvent, map[string]int{"n": 3}) // seq 1 is dropped
		if got := l.Range(origin.id.ID, 1, 1); got != nil {
			t.Fatalf("seq 1 still held: %v", seqs(got))
		}
		wantConfirmations(t, l, wantHash(event), nil, nil)
	})

	t.Run("origin forked", func(t *testing.T) {
		l := testLog()
		event := add(t, l, origin, KindEvent, silent)
		witness(t, l, w2, wantHash(event), true, "")
		witness(t, l, w3, wantHash(event), false, "")
		forkOf(t, l, origin)
		if f := l.Forks(); len(f) != 1 || f[0].A.Origin != origin.id.ID {
			t.Fatalf("Forks = %v, want the origin's", f)
		}
		wantConfirmations(t, l, wantHash(event), idsOf(w2), idsOf(w3))
	})
}

// TestCorrectionDoesNotModifyOriginal: three routers recorded "ap-office
// silent, unplanned reboot"; ap-office shows the same boot ID throughout and
// a lost link (security spec 5.8). It appends one correction referring to
// the three entries. The three entries stay byte for byte as they were, in
// their chains and in their hashes; only ap-office's own chain grows; and
// the correction is found from each entry it refers to.
func TestCorrectionDoesNotModifyOriginal(t *testing.T) {
	ap, gw, a1, a2 := testMember(1), testMember(2), testMember(3), testMember(4)
	others := []ids.MemberID{gw.id.ID, a1.id.ID, a2.id.ID}
	l := testLog()
	claim := map[string]string{"type": "reboot_unplanned", "subject": "ap-office"}
	originals := []Entry{add(t, l, gw, KindEvent, claim), add(t, l, a1, KindEvent, claim), add(t, l, a2, KindEvent, claim)}
	refs := []ids.Hash{wantHash(originals[0]), wantHash(originals[1]), wantHash(originals[2])}
	before := stateOf(l, others...)

	corr := correct(t, l, ap, refs, "link_lost", "same boot ID throughout; the link was down")

	after := stateOf(l, others...)
	if !reflect.DeepEqual(after.Ranges, before.Ranges) || !reflect.DeepEqual(after.Heads, before.Heads) {
		t.Fatal("a correction changed the chains it refers to")
	}
	for i, o := range others {
		got := l.Range(o, 1, 1)
		if len(got) != 1 || !reflect.DeepEqual(got[0], originals[i]) || got[0].Hash() != refs[i] {
			t.Fatalf("entry %d after the correction: %+v, want the original with hash %s", i, got, refs[i])
		}
	}
	if h := l.Head(ap.id.ID); h != headOf(corr) {
		t.Fatalf("ap-office's head = %+v, want its correction %+v", h, headOf(corr))
	}
	if corr.Kind != KindCorrection || corr.Origin != ap.id.ID {
		t.Fatalf("the correction is a %q entry of %s", corr.Kind, corr.Origin)
	}
	b, err := DecodeCorrection(corr)
	want := CorrectionBody{Refs: refs, Class: "link_lost", Note: "same boot ID throughout; the link was down"}
	if err != nil || !reflect.DeepEqual(b, want) {
		t.Fatalf("DecodeCorrection = %+v, %v; want %+v", b, err, want)
	}
	for _, r := range refs {
		wantCorrections(t, l, r, []Entry{corr})
	}
	wantCorrections(t, l, wantHash(corr), nil)
	wantCorrections(t, l, ids.Hash{1}, nil)
}

// TestCorrectionsLookup: Corrections returns every correction that lists the
// entry, in order of origin and then seq, as copies; a correction from a
// forked origin and a malformed one are left out, and the lookup goes on
// past them; a correction that lists other entries only is not returned.
func TestCorrectionsLookup(t *testing.T) {
	ap, gw, a1, a2, a3 := testMember(1), testMember(2), testMember(3), testMember(4), testMember(5)
	l := testLog()
	event := add(t, l, gw, KindEvent, map[string]string{"type": "reboot_unplanned", "subject": "ap-office"})
	other := add(t, l, a1, KindEvent, map[string]string{"type": "member_silent", "subject": "ap-office"})
	ref, ref2 := wantHash(event), wantHash(other)

	// Appended in an order that is not the order of the result.
	c3 := correct(t, l, a1, []ids.Hash{ref}, "reboot_planned", "")
	add(t, l, a1, KindCorrection, json.RawMessage(`{"refs":["`+ref.String()+`"],"class":"exploded","note":""}`))
	c3b := correct(t, l, a1, []ids.Hash{ref2, ref}, "member_back", "")
	c1 := correct(t, l, ap, []ids.Hash{ref}, "link_lost", "")
	correct(t, l, ap, []ids.Hash{ref2}, "link_lost", "") // lists ref2 only
	c1b := correct(t, l, ap, []ids.Hash{ref2, ref}, "upgraded", "25.12.4 -> 25.12.5")
	c2 := correct(t, l, gw, []ids.Hash{ref}, "reboot_unplanned", "my own event, confirmed")
	correct(t, l, a2, []ids.Hash{ref}, "link_lost", "")
	forkOf(t, l, a2) // a2's chain forked: its correction is left out
	add(t, l, a3, KindCorrection, json.RawMessage(`{"refs":["`+ref.String()+`"],"class":"link_lost","note":"","by":"a3"}`))

	want := []Entry{c1, c1b, c2, c3, c3b}
	wantCorrections(t, l, ref, want)
	wantCorrections(t, l, ref2, []Entry{l.Range(ap.id.ID, 2, 2)[0], c1b, c3b})

	got := Corrections(l, ref)
	got[0].Body[1], got[0].Sig[0], got[0].Seq = 'X', got[0].Sig[0]^1, 99
	wantCorrections(t, l, ref, want)
	if r := l.Range(ap.id.ID, 1, 1); !reflect.DeepEqual(r, []Entry{c1}) {
		t.Fatal("a stored correction changed with a caller's copy")
	}
}

// TestNewWitness pins the witness body on the wire and the rules NewWitness
// checks before it signs: a non-zero ref and a note of at most 200 bytes of
// printable UTF-8.
func TestNewWitness(t *testing.T) {
	m := testMember(1)
	ref := ids.Hash{0: 0xab, 31: 0x01}
	e, err := NewWitness(m.id, Head{}, ref, true, "seen <the same> & more")
	if err != nil {
		t.Fatal(err)
	}
	want := witnessBody(ref.String(), "true", "seen \\u003cthe same\\u003e \\u0026 more")
	if string(e.Body) != want {
		t.Fatalf("body %s, want %s", e.Body, want)
	}
	if e.Kind != KindWitness || e.Origin != m.id.ID || e.Seq != 1 || e.Prev != (ids.Hash{}) {
		t.Fatalf("entry %s seq %d prev %s of %s", e.Kind, e.Seq, e.Prev, e.Origin)
	}
	if err := e.Verify(m.pub); err != nil {
		t.Fatal(err)
	}
	if b, err := DecodeWitness(e); err != nil || b != (WitnessBody{Ref: ref, Agree: true, Note: "seen <the same> & more"}) {
		t.Fatalf("DecodeWitness = %+v, %v", b, err)
	}
	next, err := NewWitness(m.id, headOf(e), ref, false, "")
	if err != nil || next.Seq != 2 || next.Prev != wantHash(e) || string(next.Body) != witnessBody(ref.String(), "false", "") {
		t.Fatalf("the next witness: seq %d prev %s body %s, %v", next.Seq, next.Prev, next.Body, err)
	}

	for _, note := range []string{
		"",
		strings.Repeat("a", fmtMaxNote),
		strings.Repeat("\u00e9", fmtMaxNote/2), // 200 bytes in 100 runes
		"ap-office: same boot ID, link down 02:00-02:03 \U0001F642",
		"\u00e0 la carte, \u0436, \u4e2d, \u05d0\u05d1",
	} {
		e, err := NewWitness(m.id, Head{}, ref, true, note)
		if err != nil {
			t.Fatalf("note %q: %v", note, err)
		}
		if b, err := DecodeWitness(e); err != nil || b.Note != note {
			t.Fatalf("note %q decodes as %q, %v", note, b.Note, err)
		}
	}

	refuse := map[string]struct {
		ref  ids.Hash
		note string
	}{
		"all-zero ref":           {ids.Hash{}, ""},
		"201 bytes":              {ref, strings.Repeat("a", fmtMaxNote+1)},
		"201 bytes, multibyte":   {ref, strings.Repeat("\u00e9", fmtMaxNote/2) + "a"},
		"newline":                {ref, "link\ndown"},
		"tab":                    {ref, "link\tdown"},
		"NUL":                    {ref, "link\x00down"},
		"DEL":                    {ref, "link\x7fdown"},
		"C1 control":             {ref, "link\u0085down"},
		"right-to-left override": {ref, "link \u202edown"},
		"zero-width space":       {ref, "link\u200bdown"},
		"byte order mark":        {ref, "\ufefflink"},
		"line separator":         {ref, "link\u2028down"},
		"no-break space":         {ref, "link\u00a0down"},
		"private use":            {ref, "link\ue000"},
		"tag character":          {ref, "link\U000E0041"},
		"invalid UTF-8":          {ref, "link\xffdown"},
		"encoded surrogate":      {ref, "link\xed\xa0\x80"},
	}
	for name, c := range refuse {
		if _, err := NewWitness(m.id, Head{}, c.ref, true, c.note); !errors.Is(err, ErrBody) {
			t.Errorf("%s: err = %v, want %v", name, err, ErrBody)
		}
	}
	if _, err := NewWitness(nil, Head{}, ref, true, ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nil identity: err = %v, want %v", err, ErrInvalid)
	}
}

// TestNewCorrection pins the correction body on the wire, the closed set of
// classes and the rules NewCorrection checks before it signs: 1 to 16 refs,
// none all zero, none twice, a known class and a note as for witnesses.
func TestNewCorrection(t *testing.T) {
	consts := map[string]string{
		ClassLinkLost:        "link_lost",
		ClassMemberBack:      "member_back",
		ClassRebootPlanned:   "reboot_planned",
		ClassRebootUnplanned: "reboot_unplanned",
		ClassUpgraded:        "upgraded",
	}
	for c, want := range consts {
		if c != want {
			t.Errorf("class constant %q, want %q", c, want)
		}
	}
	if len(consts) != len(fmtClasses) {
		t.Fatalf("%d distinct class constants, want %d", len(consts), len(fmtClasses))
	}

	m := testMember(1)
	r1, r2 := ids.Hash{0: 1, 31: 0xee}, ids.Hash{0: 2}
	e, err := NewCorrection(m.id, Head{}, []ids.Hash{r1, r2}, "link_lost", "the link was down & the boot ID stayed")
	if err != nil {
		t.Fatal(err)
	}
	want := `{"refs":["` + r1.String() + `","` + r2.String() + `"],"class":"link_lost","note":"the link was down ` + "\\u0026" + ` the boot ID stayed"}`
	if string(e.Body) != want {
		t.Fatalf("body %s, want %s", e.Body, want)
	}
	if e.Kind != KindCorrection || e.Seq != 1 {
		t.Fatalf("entry %s seq %d", e.Kind, e.Seq)
	}
	if err := e.Verify(m.pub); err != nil {
		t.Fatal(err)
	}

	many := make([]ids.Hash, fmtMaxRefs+1)
	for i := range many {
		many[i] = ids.Hash{0: byte(i + 1)}
	}
	for _, class := range fmtClasses {
		for _, refs := range [][]ids.Hash{many[:1], many[:fmtMaxRefs]} {
			e, err := NewCorrection(m.id, Head{}, refs, class, "")
			if err != nil {
				t.Fatalf("class %s, %d refs: %v", class, len(refs), err)
			}
			if b, err := DecodeCorrection(e); err != nil || !reflect.DeepEqual(b, CorrectionBody{Refs: refs, Class: class}) {
				t.Fatalf("class %s, %d refs: DecodeCorrection = %+v, %v", class, len(refs), b, err)
			}
		}
	}

	refuse := map[string]struct {
		refs  []ids.Hash
		class string
		note  string
	}{
		"no refs":           {nil, "link_lost", ""},
		"empty refs":        {[]ids.Hash{}, "link_lost", ""},
		"17 refs":           {many, "link_lost", ""},
		"all-zero ref":      {[]ids.Hash{r1, {}}, "link_lost", ""},
		"a ref twice":       {[]ids.Hash{r1, r2, r1}, "link_lost", ""},
		"empty class":       {[]ids.Hash{r1}, "", ""},
		"capitals":          {[]ids.Hash{r1}, "Link_lost", ""},
		"trailing space":    {[]ids.Hash{r1}, "link_lost ", ""},
		"hyphen":            {[]ids.Hash{r1}, "link-lost", ""},
		"an event type":     {[]ids.Hash{r1}, "member_silent", ""},
		"internet_lost":     {[]ids.Hash{r1}, "internet_lost", ""},
		"note too long":     {[]ids.Hash{r1}, "link_lost", strings.Repeat("a", fmtMaxNote+1)},
		"control character": {[]ids.Hash{r1}, "link_lost", "a\rb"},
	}
	for name, c := range refuse {
		if _, err := NewCorrection(m.id, Head{}, c.refs, c.class, c.note); !errors.Is(err, ErrBody) {
			t.Errorf("%s: err = %v, want %v", name, err, ErrBody)
		}
	}
}

// TestDecodeStatementsStrict feeds bodies the log would store (one JSON
// value in the form it allows) that are not what NewWitness or
// NewCorrection writes; each is refused with ErrBody, and an entry of
// another kind with ErrInvalid.
func TestDecodeStatementsStrict(t *testing.T) {
	ref := ids.Hash{0: 0xab, 31: 0x01}
	h := ref.String()
	valid := witnessBody(h, "true", "ok")
	if b, err := DecodeWitness(Entry{Kind: KindWitness, Body: json.RawMessage(valid)}); err != nil || b != (WitnessBody{Ref: ref, Agree: true, Note: "ok"}) {
		t.Fatalf("the valid body: %+v, %v", b, err)
	}
	for name, body := range map[string]string{
		"unknown field":       `{"ref":"` + h + `","agree":true,"note":"","x":1}`,
		"no note":             `{"ref":"` + h + `","agree":true}`,
		"no agree":            `{"ref":"` + h + `","note":""}`,
		"no ref":              `{"agree":true,"note":""}`,
		"fields reordered":    `{"agree":true,"ref":"` + h + `","note":""}`,
		"capital hex":         witnessBody(strings.ToUpper(h), "true", ""),
		"short hex":           witnessBody(h[2:], "true", ""),
		"null ref":            `{"ref":null,"agree":true,"note":""}`,
		"all-zero ref":        witnessBody(strings.Repeat("0", 64), "true", ""),
		"agree as a number":   witnessBody(h, "1", ""),
		"agree twice":         `{"ref":"` + h + `","agree":true,"agree":false,"note":""}`,
		"a key in capitals":   `{"Ref":"` + h + `","agree":true,"note":""}`,
		"space":               `{"ref":"` + h + `", "agree":true,"note":""}`,
		"a second value":      valid + `{}`,
		"escaped letter":      witnessBody(h, "true", "\\u0041"),
		"unescaped <":         witnessBody(h, "true", "<"),
		"escaped newline":     witnessBody(h, "true", "a\\nb"),
		"escaped NUL":         witnessBody(h, "true", "\\u0000"),
		"note too long":       witnessBody(h, "true", strings.Repeat("a", fmtMaxNote+1)),
		"note far too long":   witnessBody(h, "true", strings.Repeat("a", 5000)),
		"null":                `null`,
		"array":               `[]`,
		"string":              `"` + h + `"`,
		"empty object":        `{}`,
		"empty":               ``,
		"truncated":           `{"ref":"` + h,
		"a correction's body": `{"refs":["` + h + `"],"class":"link_lost","note":""}`,
	} {
		b, err := DecodeWitness(Entry{Kind: KindWitness, Body: json.RawMessage(body)})
		if !errors.Is(err, ErrBody) || b != (WitnessBody{}) {
			t.Errorf("witness, %s: %+v, err = %v, want %v", name, b, err, ErrBody)
		}
	}

	h2 := ids.Hash{0: 2}.String()
	validC := `{"refs":["` + h + `","` + h2 + `"],"class":"upgraded","note":""}`
	if b, err := DecodeCorrection(Entry{Kind: KindCorrection, Body: json.RawMessage(validC)}); err != nil || len(b.Refs) != 2 {
		t.Fatalf("the valid correction: %+v, %v", b, err)
	}
	refs17 := strings.TrimSuffix(strings.Repeat(`"`+h+`",`, fmtMaxRefs+1), ",")
	for name, body := range map[string]string{
		"unknown field":    `{"refs":["` + h + `"],"class":"upgraded","note":"","x":1}`,
		"null refs":        `{"refs":null,"class":"upgraded","note":""}`,
		"empty refs":       `{"refs":[],"class":"upgraded","note":""}`,
		"refs as a string": `{"refs":"` + h + `","class":"upgraded","note":""}`,
		"17 refs":          `{"refs":[` + refs17 + `],"class":"upgraded","note":""}`,
		"a ref twice":      `{"refs":["` + h + `","` + h + `"],"class":"upgraded","note":""}`,
		"all-zero ref":     `{"refs":["` + strings.Repeat("0", 64) + `"],"class":"upgraded","note":""}`,
		"unknown class":    `{"refs":["` + h + `"],"class":"exploded","note":""}`,
		"class reordered":  `{"class":"upgraded","refs":["` + h + `"],"note":""}`,
		"no class":         `{"refs":["` + h + `"],"note":""}`,
		"note with tab":    `{"refs":["` + h + `"],"class":"upgraded","note":"a\tb"}`,
		"a witness's body": valid,
	} {
		b, err := DecodeCorrection(Entry{Kind: KindCorrection, Body: json.RawMessage(body)})
		if !errors.Is(err, ErrBody) || !reflect.DeepEqual(b, CorrectionBody{}) {
			t.Errorf("correction, %s: %+v, err = %v, want %v", name, b, err, ErrBody)
		}
	}

	for _, k := range []Kind{KindEvent, KindCorrection, KindBoot, KindCheckpoint, KindObjection, "note"} {
		if b, err := DecodeWitness(Entry{Kind: k, Body: json.RawMessage(valid)}); !errors.Is(err, ErrInvalid) || b != (WitnessBody{}) {
			t.Errorf("DecodeWitness of a %q entry: %+v, err = %v, want %v", k, b, err, ErrInvalid)
		}
	}
	for _, k := range []Kind{KindEvent, KindWitness, KindBoot, KindCheckpoint, KindObjection, "note"} {
		if b, err := DecodeCorrection(Entry{Kind: k, Body: json.RawMessage(validC)}); !errors.Is(err, ErrInvalid) || !reflect.DeepEqual(b, CorrectionBody{}) {
			t.Errorf("DecodeCorrection of a %q entry: %+v, err = %v, want %v", k, b, err, ErrInvalid)
		}
	}
}

// TestStatementSizes: the largest statements NewWitness and NewCorrection
// accept (16 refs, the longest class, a 200-byte note that the encoder
// escapes to six bytes a character) fit the decoder's size limit and the
// log's body limit, and decode again.
func TestStatementSizes(t *testing.T) {
	m := testMember(1)
	refs := make([]ids.Hash, fmtMaxRefs)
	for i := range refs {
		refs[i] = ids.Hash{0: 0xff, 1: byte(i)}
	}
	note := strings.Repeat("<", fmtMaxNote)
	c, err := NewCorrection(m.id, Head{}, refs, "reboot_unplanned", note)
	if err != nil {
		t.Fatal(err)
	}
	w, err := NewWitness(m.id, Head{}, refs[0], false, note)
	if err != nil {
		t.Fatal(err)
	}
	if maxStatementBody > fmtMaxBody {
		t.Fatalf("the statement limit %d is above the log's body limit %d", maxStatementBody, fmtMaxBody)
	}
	for _, e := range []Entry{c, w} {
		if len(e.Body) > maxStatementBody {
			t.Fatalf("the largest %s body is %d bytes, above the limit %d", e.Kind, len(e.Body), maxStatementBody)
		}
		t.Logf("largest %s body: %d bytes, limit %d, slack %d", e.Kind, len(e.Body), maxStatementBody, maxStatementBody-len(e.Body))
	}
	if _, err := DecodeCorrection(c); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeWitness(w); err != nil {
		t.Fatal(err)
	}
	over := Entry{Kind: KindWitness, Body: json.RawMessage(witnessBody(refs[0].String(), "true", "") + strings.Repeat(" ", maxStatementBody))}
	if _, err := DecodeWitness(over); !errors.Is(err, ErrBody) {
		t.Fatalf("a body above the limit: err = %v, want %v", err, ErrBody)
	}
}

// TestStatementsConcurrent runs Confirmations and Corrections while other
// goroutines append statements, fork their own chains and prune; under
// -race it shows that both read the log, chains and fork proofs alike, under
// its lock. The final answers are checked too: the members that forked are
// not counted, and their corrections are not returned.
func TestStatementsConcurrent(t *testing.T) {
	origin := testMember(1)
	l := testLog()
	event := add(t, l, origin, KindEvent, silent)
	ref := wantHash(event)
	var writers, readers sync.WaitGroup
	stop := make(chan struct{})
	for _, read := range []func(){
		func() { Confirmations(l, ref) },
		func() { Corrections(l, ref) },
		func() { l.Prune(15, 0, t0) },
	} {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
					read()
				}
			}
		}()
	}
	for n := byte(2); n < 8; n++ {
		m := testMember(n)
		writers.Add(1)
		go func() {
			defer writers.Done()
			var prev Head
			for i := 0; i < 20; i++ {
				var e Entry
				var err error
				if i%2 == 0 {
					e, err = NewWitness(m.id, prev, ref, n%2 == 0, "")
				} else {
					e, err = NewCorrection(m.id, prev, []ids.Hash{ref}, "link_lost", "")
				}
				if err == nil {
					err = l.Append(e, t0)
				}
				if err != nil {
					t.Error(err)
					return
				}
				prev = Head{Seq: e.Seq, Hash: e.Hash()}
			}
		}()
	}
	for n := byte(8); n < 40; n++ { // each agrees and corrects, then forks
		m := testMember(n)
		writers.Add(1)
		go func() {
			defer writers.Done()
			w, err := NewWitness(m.id, Head{}, ref, true, "")
			if err == nil {
				err = l.Append(w, t0)
			}
			var c Entry
			if err == nil {
				c, err = NewCorrection(m.id, headOf(w), []ids.Hash{ref}, "reboot_planned", "")
			}
			if err == nil {
				err = l.Append(c, t0)
			}
			var second Entry
			if err == nil {
				second, err = NewWitness(m.id, Head{}, ref, false, "a second seq 1")
			}
			if err == nil {
				err = l.Append(second, t0)
			}
			if !errors.Is(err, ErrFork) {
				t.Errorf("member %d: err = %v, want %v", n, err, ErrFork)
			}
		}()
	}
	writers.Wait()
	close(stop)
	readers.Wait()
	l.Prune(15, 0, t0) // members 2 to 7 keep seq 6 to 20: 8 corrections each

	if f := l.Forks(); len(f) != 32 {
		t.Fatalf("%d forked origins, want 32", len(f))
	}
	wantConfirmations(t, l, ref, idsOf(testMember(2), testMember(4), testMember(6)), idsOf(testMember(3), testMember(5), testMember(7)))
	got := Corrections(l, ref)
	if len(got) != 6*8 {
		t.Fatalf("%d corrections, want %d", len(got), 6*8)
	}
	for i := 1; i < len(got); i++ { // more than a sort keeps stable for free
		a, b := got[i-1], got[i]
		if c := bytes.Compare(a.Origin[:], b.Origin[:]); c > 0 || c == 0 && a.Seq >= b.Seq {
			t.Fatalf("corrections %d and %d: origin %s seq %d before origin %s seq %d", i-1, i, a.Origin, a.Seq, b.Origin, b.Seq)
		}
	}
}

// FuzzStatementBodies feeds arbitrary bodies to DecodeWitness and
// DecodeCorrection. Nothing may panic; a refusal is ErrBody; and a body
// accepted is exactly the body NewWitness or NewCorrection writes for what
// it decoded to, so the decoders accept nothing the constructors would not
// write.
func FuzzStatementBodies(f *testing.F) {
	m := testMember(1)
	ref := ids.Hash{0: 0xab, 31: 0x01}
	w, err := NewWitness(m.id, Head{}, ref, true, "a <b> & c")
	if err != nil {
		f.Fatal(err)
	}
	c, err := NewCorrection(m.id, Head{}, []ids.Hash{ref, {2}}, "link_lost", "\u00e9")
	if err != nil {
		f.Fatal(err)
	}
	f.Add([]byte(w.Body))
	f.Add([]byte(c.Body))
	f.Add([]byte(`{"ref":null,"agree":true,"note":""}`))
	f.Add([]byte(`{"refs":[],"class":"link_lost","note":""}`))
	f.Add([]byte(witnessBody(ref.String(), "true", "\\u0041")))
	f.Add([]byte(`{"ref":"` + ref.String() + `","agree":true,"agree":false,"note":""}`))

	f.Fuzz(func(t *testing.T, body []byte) {
		if b, err := DecodeWitness(Entry{Kind: KindWitness, Body: body}); err != nil {
			if !errors.Is(err, ErrBody) || b != (WitnessBody{}) {
				t.Fatalf("DecodeWitness refused with %v and %+v", err, b)
			}
		} else {
			e, err := NewWitness(m.id, Head{}, b.Ref, b.Agree, b.Note)
			if err != nil {
				t.Fatalf("DecodeWitness accepted %+v, which NewWitness refuses: %v", b, err)
			}
			if !bytes.Equal(e.Body, body) {
				t.Fatalf("DecodeWitness accepted %q; NewWitness writes %q for it", body, e.Body)
			}
		}
		if b, err := DecodeCorrection(Entry{Kind: KindCorrection, Body: body}); err != nil {
			if !errors.Is(err, ErrBody) || !reflect.DeepEqual(b, CorrectionBody{}) {
				t.Fatalf("DecodeCorrection refused with %v and %+v", err, b)
			}
		} else {
			e, err := NewCorrection(m.id, Head{}, b.Refs, b.Class, b.Note)
			if err != nil {
				t.Fatalf("DecodeCorrection accepted %+v, which NewCorrection refuses: %v", b, err)
			}
			if !bytes.Equal(e.Body, body) {
				t.Fatalf("DecodeCorrection accepted %q; NewCorrection writes %q for it", body, e.Body)
			}
		}
	})
}
