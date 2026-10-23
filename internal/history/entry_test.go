package history

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"math/big"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/TAIPANBOX/rollcall/internal/identity"
	"github.com/TAIPANBOX/rollcall/internal/ids"
	"github.com/TAIPANBOX/rollcall/internal/sig"
)

// The format, written out here so that a change in the package shows as a
// red test instead of passing on both sides.
const (
	fmtSigPrefix   = "rollcall/v1/entry\x00" // what sig.Sign puts before m
	fmtHashLabel   = "rollcall/v1 entry-hash\x00"
	fmtDigestLabel = "rollcall/v1 history-digest\x00"
	fmtMaxBody     = 8 << 10
)

// t0 is the reception time the fixtures start from.
var t0 = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)

// member is one test router with a deterministic key; member n has ID byte
// 0 = n, so members sort by n.
type member struct {
	id  *identity.Identity
	key ed25519.PrivateKey
	pub ed25519.PublicKey
}

func testMember(n byte) member {
	var id ids.MemberID
	id[0], id[15] = n, 0xa5
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{n}, ed25519.SeedSize))
	return member{id: &identity.Identity{ID: id, Sign: key}, key: key, pub: key.Public().(ed25519.PublicKey)}
}

// testKeys holds the public key of testMember(n) for every n.
var testKeys = func() map[ids.MemberID]ed25519.PublicKey {
	keys := map[ids.MemberID]ed25519.PublicKey{}
	for n := 0; n < 256; n++ {
		m := testMember(byte(n))
		keys[m.id.ID] = m.pub
	}
	return keys
}()

// keysOf returns a resolver that knows the given members only.
func keysOf(ms ...member) func(ids.MemberID) (ed25519.PublicKey, bool) {
	keys := map[ids.MemberID]ed25519.PublicKey{}
	for _, m := range ms {
		keys[m.id.ID] = m.pub
	}
	return func(o ids.MemberID) (ed25519.PublicKey, bool) {
		k, ok := keys[o]
		return k, ok
	}
}

// logOf returns an empty log that knows the given members only.
func logOf(ms ...member) *Log { return NewLog(keysOf(ms...), 0) }

// testLog returns an empty log that knows every testMember.
func testLog() *Log {
	return NewLog(func(o ids.MemberID) (ed25519.PublicKey, bool) {
		k, ok := testKeys[o]
		return k, ok
	}, 0)
}

// wantMessage is the documented signed message of e, built here on its own:
// Origin || Seq || Prev || len(Kind) || Kind || len(Body) || Body.
func wantMessage(e Entry) []byte {
	b := append([]byte{}, e.Origin[:]...)
	b = binary.BigEndian.AppendUint64(b, e.Seq)
	b = append(b, e.Prev[:]...)
	b = binary.BigEndian.AppendUint64(b, uint64(len(e.Kind)))
	b = append(b, e.Kind...)
	b = binary.BigEndian.AppendUint64(b, uint64(len(e.Body)))
	return append(b, e.Body...)
}

// wantHash is the documented hash of e, built here on its own.
func wantHash(e Entry) ids.Hash {
	h := sha256.New()
	h.Write([]byte(fmtHashLabel))
	h.Write(wantMessage(e))
	h.Write(binary.BigEndian.AppendUint64(nil, uint64(len(e.Sig))))
	h.Write(e.Sig)
	return ids.Hash(h.Sum(nil))
}

// headOf returns the Head that e makes when it is the newest entry.
func headOf(e Entry) Head { return Head{Seq: e.Seq, Hash: wantHash(e)} }

// resign signs e as it stands with key, so a test can make entries that
// NewEntry refuses to make, or that claim another origin.
func resign(e Entry, key ed25519.PrivateKey) Entry {
	e.Sig = ed25519.Sign(key, append([]byte(fmtSigPrefix), wantMessage(e)...))
	return e
}

func mustEntry(t testing.TB, m member, prev Head, kind Kind, body any) Entry {
	t.Helper()
	e, err := NewEntry(m.id, prev, kind, body)
	if err != nil {
		t.Fatalf("NewEntry(seq %d, %s): %v", prev.Seq+1, kind, err)
	}
	return e
}

// buildChain returns n entries by m, Seq 1 to n, each linked to the one
// before by the hash computed here, with bodies {"n":i}.
func buildChain(t testing.TB, m member, n int) []Entry {
	t.Helper()
	var out []Entry
	var prev Head
	for i := 1; i <= n; i++ {
		e := mustEntry(t, m, prev, KindEvent, map[string]int{"n": i})
		out = append(out, e)
		prev = headOf(e)
	}
	return out
}

// canonical reports, independently of the package, whether b is a body
// the documented rules allow.
func canonical(b []byte) bool {
	if len(b) > fmtMaxBody || !utf8.Valid(b) {
		return false
	}
	var c, esc bytes.Buffer
	if json.Compact(&c, b) != nil {
		return false
	}
	json.HTMLEscape(&esc, c.Bytes())
	return bytes.Equal(esc.Bytes(), b)
}

func TestKindValues(t *testing.T) {
	want := map[Kind]string{
		KindEvent: "event", KindWitness: "witness", KindCorrection: "correction",
		KindBoot: "boot", KindCheckpoint: "checkpoint", KindObjection: "objection",
	}
	for k, s := range want {
		if string(k) != s {
			t.Errorf("kind %q, want the wire value %q", k, s)
		}
	}
	if MaxBodySize != fmtMaxBody {
		t.Errorf("MaxBodySize = %d, want %d", MaxBodySize, fmtMaxBody)
	}
	if DefaultMaxEntries != 500 || DefaultMaxAge != 30*24*time.Hour {
		t.Errorf("defaults %d entries, %v; want 500 entries, 30 days", DefaultMaxEntries, DefaultMaxAge)
	}
}

// TestEntryEncoding pins the signed bytes and the hash to the documented
// constructions, written out byte by byte.
func TestEntryEncoding(t *testing.T) {
	var origin ids.MemberID
	origin[0], origin[15] = 0x01, 0xa5
	var prev ids.Hash
	for i := range prev {
		prev[i] = 0x22
	}
	e := Entry{Origin: origin, Seq: 0x0102030405060708, Prev: prev, Kind: KindBoot, Body: json.RawMessage(`{}`)}
	want := "01" + strings.Repeat("00", 14) + "a5" + // Origin
		"0102030405060708" + // Seq
		strings.Repeat("22", 32) + // Prev
		"0000000000000004" + hex.EncodeToString([]byte("boot")) + // len(Kind), Kind
		"0000000000000002" + "7b7d" // len(Body), Body
	if got := hex.EncodeToString(e.message()); got != want {
		t.Fatalf("signed message\n got %s\nwant %s", got, want)
	}
	if got := hex.EncodeToString(wantMessage(e)); got != want {
		t.Fatalf("the test's own builder disagrees with the written-out bytes: %s", got)
	}

	a := testMember(1)
	e1 := mustEntry(t, a, Head{}, KindEvent, map[string]string{"type": "member_silent", "subject": "ap-office"})
	e2 := mustEntry(t, a, headOf(e1), KindWitness, json.RawMessage(`{"seen":"same"}`))
	for _, e := range []Entry{e1, e2} {
		if !ed25519.Verify(a.pub, append([]byte(fmtSigPrefix), wantMessage(e)...), e.Sig) {
			t.Errorf("seq %d: Sig is not Ed25519 over %q || m", e.Seq, fmtSigPrefix)
		}
		if !sig.Verify(a.pub, "entry", wantMessage(e), e.Sig) {
			t.Errorf("seq %d: Sig is not sig.Sign(key, \"entry\", m)", e.Seq)
		}
		if got, want := e.Hash(), wantHash(e); got != want {
			t.Errorf("seq %d: Hash = %s, want SHA-256(label || m || len(Sig) || Sig) = %s", e.Seq, got, want)
		}
	}
	if e1.Origin != a.id.ID || e1.Seq != 1 || e1.Prev != (ids.Hash{}) || e1.Kind != KindEvent {
		t.Errorf("first entry: origin %s seq %d prev %s kind %q", e1.Origin, e1.Seq, e1.Prev, e1.Kind)
	}
	if got := string(e1.Body); got != `{"subject":"ap-office","type":"member_silent"}` {
		t.Errorf("first body %s, want encoding/json's compact form", got)
	}
	if e2.Seq != 2 || e2.Prev != wantHash(e1) || e2.Kind != KindWitness || string(e2.Body) != `{"seen":"same"}` {
		t.Errorf("second entry: seq %d prev %s kind %q body %s", e2.Seq, e2.Prev, e2.Kind, e2.Body)
	}
}

// TestHashCoversEveryField changes one field at a time: every change gives
// another hash, the signature included, and the length prefixes keep a byte
// from moving across a field boundary unnoticed.
func TestHashCoversEveryField(t *testing.T) {
	a := testMember(1)
	es := buildChain(t, a, 2)
	base := es[1]
	variants := map[string]func(*Entry){
		"origin":         func(e *Entry) { e.Origin[3] ^= 1 },
		"seq":            func(e *Entry) { e.Seq++ },
		"prev":           func(e *Entry) { e.Prev[31] ^= 1 },
		"kind":           func(e *Entry) { e.Kind = KindCorrection },
		"body":           func(e *Entry) { e.Body = json.RawMessage(`{"n":3}`) },
		"signature":      func(e *Entry) { e.Sig = slices.Clone(e.Sig); e.Sig[0] ^= 1 },
		"signature size": func(e *Entry) { e.Sig = e.Sig[:63] },
	}
	seen := map[ids.Hash]string{base.Hash(): "base"}
	for name, change := range variants {
		e := base
		change(&e)
		h := e.Hash()
		if h != wantHash(e) {
			t.Errorf("%s: Hash = %s, want %s", name, h, wantHash(e))
		}
		if other, dup := seen[h]; dup {
			t.Errorf("%s: same hash as %s", name, other)
		}
		seen[h] = name
	}
	if base.Hash() != wantHash(base) || base.Hash() != es[1].Hash() {
		t.Error("Hash changed the entry it was called on")
	}

	// Length prefixes: kind/body and body/signature boundaries.
	k1 := Entry{Kind: "event", Body: []byte(`1`)}
	k2 := Entry{Kind: "even", Body: []byte(`t1`)}
	if k1.Hash() == k2.Hash() {
		t.Error(`kind "event" body "1" hashes like kind "even" body "t1"`)
	}
	s1 := Entry{Kind: "event", Body: []byte(`12`), Sig: []byte{3}}
	s2 := Entry{Kind: "event", Body: []byte(`1`), Sig: []byte{'2', 3}}
	if s1.Hash() == s2.Hash() {
		t.Error("a byte moved from the body to the signature leaves the hash unchanged")
	}
}

// TestEntryVerify checks the shape rules, the body rules and the signature,
// and that each refusal names its cause.
func TestEntryVerify(t *testing.T) {
	a, b := testMember(1), testMember(2)
	es := buildChain(t, a, 2)
	good := es[1]
	if err := good.Verify(a.pub); err != nil {
		t.Fatalf("a genuine entry: %v", err)
	}
	if err := es[0].Verify(a.pub); err != nil {
		t.Fatalf("a genuine first entry: %v", err)
	}

	// re builds a variant of good and signs it with a's key, so only the
	// rule under test can refuse it.
	re := func(change func(*Entry)) Entry {
		e := good
		e.Body = slices.Clone(e.Body)
		change(&e)
		return resign(e, a.key)
	}
	tampered := func(change func(*Entry)) Entry {
		e := good
		e.Body, e.Sig = slices.Clone(e.Body), slices.Clone(e.Sig)
		change(&e)
		return e
	}
	exact := `"` + strings.Repeat("a", fmtMaxBody-2) + `"`

	cases := []struct {
		name string
		e    Entry
		pub  ed25519.PublicKey
		want error
	}{
		{"zero origin", re(func(e *Entry) { e.Origin = ids.MemberID{} }), a.pub, ErrFormat},
		{"seq 0", re(func(e *Entry) { e.Seq = 0 }), a.pub, ErrFormat},
		{"seq 1 with a prev", re(func(e *Entry) { e.Seq = 1 }), a.pub, ErrPrev},
		{"seq 2 without a prev", re(func(e *Entry) { e.Prev = ids.Hash{} }), a.pub, ErrPrev},
		{"unknown kind", re(func(e *Entry) { e.Kind = "note" }), a.pub, ErrKind},
		{"empty kind", re(func(e *Entry) { e.Kind = "" }), a.pub, ErrKind},
		{"kind in capitals", re(func(e *Entry) { e.Kind = "Event" }), a.pub, ErrKind},
		{"kind with NUL", re(func(e *Entry) { e.Kind = "event\x00" }), a.pub, ErrKind},
		{"no signature", tampered(func(e *Entry) { e.Sig = nil }), a.pub, ErrSignature},
		{"short signature", tampered(func(e *Entry) { e.Sig = e.Sig[:63] }), a.pub, ErrSignature},
		{"long signature", tampered(func(e *Entry) { e.Sig = append(e.Sig, 0) }), a.pub, ErrSignature},
		{"empty body", re(func(e *Entry) { e.Body = nil }), a.pub, ErrBody},
		{"body not JSON", re(func(e *Entry) { e.Body = []byte(`{"n":`) }), a.pub, ErrBody},
		{"body two values", re(func(e *Entry) { e.Body = []byte(`1 2`) }), a.pub, ErrBody},
		{"body with a space", re(func(e *Entry) { e.Body = []byte(`{"n": 2}`) }), a.pub, ErrBody},
		{"body with a newline", re(func(e *Entry) { e.Body = []byte("{\"n\":2}\n") }), a.pub, ErrBody},
		{"body with a raw <", re(func(e *Entry) { e.Body = []byte(`"<"`) }), a.pub, ErrBody},
		{"body with a raw >", re(func(e *Entry) { e.Body = []byte(`">"`) }), a.pub, ErrBody},
		{"body with a raw &", re(func(e *Entry) { e.Body = []byte(`"&"`) }), a.pub, ErrBody},
		{"body with a raw U+2028", re(func(e *Entry) { e.Body = []byte("\"\u2028\"") }), a.pub, ErrBody},
		{"body not UTF-8", re(func(e *Entry) { e.Body = []byte("\"\xff\"") }), a.pub, ErrBody},
		{"body one byte too long", re(func(e *Entry) { e.Body = []byte(`"a` + exact[1:]) }), a.pub, ErrBody},
		{"body at the limit", re(func(e *Entry) { e.Body = []byte(exact) }), a.pub, nil},
		{"escaped body", re(func(e *Entry) { e.Body = []byte(`"\u003c\u2028"`) }), a.pub, nil},
		{"origin changed after signing", tampered(func(e *Entry) { e.Origin[5] ^= 1 }), a.pub, ErrSignature},
		{"seq changed after signing", tampered(func(e *Entry) { e.Seq = 3 }), a.pub, ErrSignature},
		{"prev changed after signing", tampered(func(e *Entry) { e.Prev[0] ^= 1 }), a.pub, ErrSignature},
		{"kind changed after signing", tampered(func(e *Entry) { e.Kind = KindWitness }), a.pub, ErrSignature},
		{"body changed after signing", tampered(func(e *Entry) { e.Body = []byte(`{"n":3}`) }), a.pub, ErrSignature},
		{"signature changed", tampered(func(e *Entry) { e.Sig[10] ^= 1 }), a.pub, ErrSignature},
		{"signed as another kind", tampered(func(e *Entry) { e.Sig = sig.Sign(a.key, "roster", wantMessage(*e)) }), a.pub, ErrSignature},
		{"signed without the domain", tampered(func(e *Entry) { e.Sig = ed25519.Sign(a.key, wantMessage(*e)) }), a.pub, ErrSignature},
		{"another member's key", good, b.pub, ErrSignature},
	}
	for _, c := range cases {
		err := c.e.Verify(c.pub)
		if c.want == nil {
			if err != nil {
				t.Errorf("%s: %v, want nil", c.name, err)
			}
			continue
		}
		if !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
	}
	if !(len(exact) == fmtMaxBody && len(`"a`+exact[1:]) == fmtMaxBody+1) {
		t.Fatal("the size fixtures are not at the limit")
	}
}

// TestEntryVerifyKey: a key sig.ValidPublicKey refuses is reported as such,
// before anything else, and never verifies.
func TestEntryVerifyKey(t *testing.T) {
	a := testMember(1)
	e := buildChain(t, a, 1)[0]
	smallOrder := make(ed25519.PublicKey, ed25519.PublicKeySize)
	smallOrder[0] = 1 // y = 1, the identity point
	cases := []struct {
		name string
		pub  ed25519.PublicKey
		want error
	}{
		{"nil key", nil, sig.ErrKeyLength},
		{"short key", a.pub[:31], sig.ErrKeyLength},
		{"long key", append(slices.Clone(a.pub), 0), sig.ErrKeyLength},
		{"small-order key", smallOrder, sig.ErrSmallOrderKey},
	}
	for _, c := range cases {
		err := e.Verify(c.pub)
		if !errors.Is(err, ErrKey) || !errors.Is(err, c.want) {
			t.Errorf("Verify, %s: err = %v, want %v and %v", c.name, err, ErrKey, c.want)
		}
		l := NewLog(func(ids.MemberID) (ed25519.PublicKey, bool) { return c.pub, true }, 0)
		err = l.Append(e, t0)
		if !errors.Is(err, ErrKey) || !errors.Is(err, c.want) {
			t.Errorf("Append, %s: err = %v, want %v and %v", c.name, err, ErrKey, c.want)
		}
		if l.Head(a.id.ID) != (Head{}) {
			t.Errorf("Append, %s: stored the entry", c.name)
		}
	}
	// The key is checked first: a bad key with a bad entry reports the key.
	bad := e
	bad.Kind = "note"
	if err := bad.Verify(nil); !errors.Is(err, ErrKey) {
		t.Errorf("bad key and bad kind: err = %v, want %v", err, ErrKey)
	}
}

func TestNewEntry(t *testing.T) {
	a := testMember(1)
	prev := Head{Seq: 41, Hash: sha256.Sum256([]byte("entry 41"))}
	bodies := []struct {
		in   any
		want string
	}{
		{map[string]int{"b": 2, "a": 1}, `{"a":1,"b":2}`},
		{json.RawMessage("{ \"b\" : [1, 2] }\n"), `{"b":[1,2]}`},
		{"<a & b>\u2028", `"\u003ca \u0026 b\u003e\u2028"`},
		{nil, `null`},
		{struct {
			Subject string `json:"subject"`
			Up      bool   `json:"up"`
		}{"gw", true}, `{"subject":"gw","up":true}`},
		{strings.Repeat("a", fmtMaxBody-2), `"` + strings.Repeat("a", fmtMaxBody-2) + `"`},
	}
	for i, c := range bodies {
		kinds := []Kind{KindEvent, KindWitness, KindCorrection, KindBoot, KindCheckpoint, KindObjection}
		kind := kinds[i%len(kinds)]
		e, err := NewEntry(a.id, prev, kind, c.in)
		if err != nil {
			t.Errorf("body %d: %v", i, err)
			continue
		}
		if string(e.Body) != c.want {
			t.Errorf("body %d: %s, want %s", i, e.Body, c.want)
		}
		if e.Origin != a.id.ID || e.Seq != 42 || e.Prev != prev.Hash || e.Kind != kind {
			t.Errorf("body %d: origin %s seq %d prev %s kind %q", i, e.Origin, e.Seq, e.Prev, e.Kind)
		}
		if err := e.Verify(a.pub); err != nil {
			t.Errorf("body %d: the new entry does not verify: %v", i, err)
		}
		if !canonical(e.Body) {
			t.Errorf("body %d: not canonical", i)
		}
	}
	for _, kind := range []Kind{KindEvent, KindWitness, KindCorrection, KindBoot, KindCheckpoint, KindObjection} {
		if _, err := NewEntry(a.id, Head{}, kind, 1); err != nil {
			t.Errorf("first entry of kind %q: %v", kind, err)
		}
	}
}

func TestNewEntryRejects(t *testing.T) {
	a, b := testMember(1), testMember(2)
	zeroID := &identity.Identity{Sign: a.key}
	shortKey := &identity.Identity{ID: a.id.ID, Sign: a.key[:32]}
	halves := slices.Concat([]byte(a.key[:32]), []byte(b.pub)) // a's seed, b's public half
	mismatched := &identity.Identity{ID: a.id.ID, Sign: ed25519.PrivateKey(halves)}
	smallOrder := slices.Concat([]byte(a.key[:32]), append([]byte{1}, make([]byte, 31)...))
	smallOrderID := &identity.Identity{ID: a.id.ID, Sign: ed25519.PrivateKey(smallOrder)}
	h := sha256.Sum256([]byte("x"))

	cases := []struct {
		name string
		id   *identity.Identity
		prev Head
		kind Kind
		body any
		want error
	}{
		{"nil identity", nil, Head{}, KindEvent, 1, ErrInvalid},
		{"zero member ID", zeroID, Head{}, KindEvent, 1, ErrInvalid},
		{"short key", shortKey, Head{}, KindEvent, 1, ErrInvalid},
		{"key halves that do not match", mismatched, Head{}, KindEvent, 1, ErrSignature},
		{"small-order public half", smallOrderID, Head{}, KindEvent, 1, ErrKey},
		{"unknown kind", a.id, Head{}, "note", 1, ErrKind},
		{"body json cannot encode", a.id, Head{}, KindEvent, make(chan int), ErrBody},
		{"body too long", a.id, Head{}, KindEvent, strings.Repeat("a", fmtMaxBody-1), ErrBody},
		{"raw body not JSON", a.id, Head{}, KindEvent, json.RawMessage(`{`), ErrBody},
		{"raw body not UTF-8", a.id, Head{}, KindEvent, json.RawMessage("\"\xff\""), ErrBody},
		{"prev seq 0 with a hash", a.id, Head{Seq: 0, Hash: h}, KindEvent, 1, ErrInvalid},
		{"prev seq 5 without a hash", a.id, Head{Seq: 5}, KindEvent, 1, ErrInvalid},
		{"prev at the last seq", a.id, Head{Seq: math.MaxUint64, Hash: h}, KindEvent, 1, ErrInvalid},
	}
	for _, c := range cases {
		e, err := NewEntry(c.id, c.prev, c.kind, c.body)
		if !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
		if !reflect.DeepEqual(e, Entry{}) {
			t.Errorf("%s: returned a non-zero entry with the error", c.name)
		}
	}
}

// TestEntryJSONRoundTrip: an entry relayed as JSON through encoding/json
// keeps its exact body bytes, so its hash and signature, even with
// characters encoding/json escapes. A body not in that form is refused
// before it can be stored, so a stored entry never breaks in transit.
func TestEntryJSONRoundTrip(t *testing.T) {
	a := testMember(1)
	e1 := mustEntry(t, a, Head{}, KindEvent, map[string]string{"note": "<gw> & \u2028 \u00e9 \\ \"x\""})
	e2 := mustEntry(t, a, headOf(e1), KindCorrection, json.RawMessage(`{"corrects":1,"why":"\u00e9\/"}`))
	src := testLog()
	for _, e := range []Entry{e1, e2} {
		if err := src.Append(e, t0); err != nil {
			t.Fatalf("Append seq %d: %v", e.Seq, err)
		}
	}
	data, err := json.Marshal(src.Range(a.id.ID, 1, 2))
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var fields []map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatalf("Unmarshal into maps: %v", err)
	}
	var names []string
	for k := range fields[0] {
		names = append(names, k)
	}
	slices.Sort(names)
	if want := []string{"body", "kind", "origin", "prev", "seq", "sig"}; !slices.Equal(names, want) {
		t.Errorf("JSON field names %v, want %v", names, want)
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var back []Entry
	if err := dec.Decode(&back); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !reflect.DeepEqual(back, []Entry{e1, e2}) {
		t.Fatalf("round trip changed the entries:\n got %+v\nwant %+v", back, []Entry{e1, e2})
	}
	dst := testLog()
	for _, e := range back {
		if err := dst.Append(e, t0); err != nil {
			t.Fatalf("Append the relayed seq %d: %v", e.Seq, err)
		}
	}
	if dst.Digest() != src.Digest() || dst.Head(a.id.ID) != headOf(e2) {
		t.Error("the relayed copy does not match the source")
	}

	// A body encoding/json would rewrite is refused, even when well signed.
	spaced := resign(Entry{Origin: a.id.ID, Seq: 1, Kind: KindEvent, Body: []byte(`{"a": "<"}`)}, a.key)
	if err := spaced.Verify(a.pub); !errors.Is(err, ErrBody) {
		t.Errorf("a body encoding/json rewrites: err = %v, want %v", err, ErrBody)
	}
	relayed, _ := json.Marshal(spaced)
	var after Entry
	if err := json.Unmarshal(relayed, &after); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(after.Body, spaced.Body) {
		t.Error("the fixture body survived encoding/json; it does not show the hazard")
	}
}

// reversed returns b in reverse order, in a new slice.
func reversed(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		out[len(b)-1-i] = c
	}
	return out
}

// TestSignatureMalleability: S replaced by S + k*L, with L the order of the
// Ed25519 base point added as little-endian integers, is the same scalar mod
// L. A lax verifier would accept it as a second valid signature over the same
// content, with another entry hash, so a relayer could frame the origin with
// a fork. Go's ed25519.Verify refuses a non-canonical S: none of them
// verifies, and Append neither stores one nor raises a fork.
func TestSignatureMalleability(t *testing.T) {
	a := testMember(1)
	e := buildChain(t, a, 1)[0]
	order, _ := new(big.Int).SetString("27742317777372353535851937790883648493", 10)
	order.Add(order, new(big.Int).Lsh(big.NewInt(1), 252)) // L = 2^252 + 27742317777372353535851937790883648493
	s := new(big.Int).SetBytes(reversed(e.Sig[32:]))
	if s.Cmp(order) >= 0 {
		t.Fatal("the genuine S is not below L")
	}
	l := testLog()
	appendAll(t, l, []Entry{e}, t0)
	before := stateOf(l, a.id.ID)

	tried := 0
	for k := int64(1); ; k++ {
		m := new(big.Int).Add(s, new(big.Int).Mul(big.NewInt(k), order))
		if m.BitLen() > 256 {
			break
		}
		if new(big.Int).Mod(m, order).Cmp(s) != 0 {
			t.Fatalf("k=%d: S + kL is not S mod L", k)
		}
		mal := e
		mal.Sig = append(slices.Clone(e.Sig[:32]), reversed(m.FillBytes(make([]byte, 32)))...)
		if wantHash(mal) == wantHash(e) {
			t.Fatalf("k=%d: the malleated entry has the genuine hash; the fixture shows nothing", k)
		}
		if ed25519.Verify(a.pub, append([]byte(fmtSigPrefix), wantMessage(mal)...), mal.Sig) {
			t.Fatalf("k=%d: crypto/ed25519 accepts S + kL; a relayer can forge a second signature", k)
		}
		if err := mal.Verify(a.pub); !errors.Is(err, ErrSignature) {
			t.Errorf("k=%d: Verify err = %v, want %v", k, err, ErrSignature)
		}
		if err := l.Append(mal, t0); !errors.Is(err, ErrSignature) || errors.Is(err, ErrFork) {
			t.Errorf("k=%d: Append err = %v, want %v and no fork", k, err, ErrSignature)
		}
		tried++
	}
	if tried < 2 {
		t.Fatalf("measured nothing: %d malleated signatures fit in 32 bytes", tried)
	}
	if after := stateOf(l, a.id.ID); !reflect.DeepEqual(after, before) {
		t.Fatal("a malleated signature changed the log")
	}
	t.Logf("%d malleated signatures (S + kL, k = 1..%d) refused", tried, tried)
}
