package node

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"math"
	"math/rand/v2"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/deliver"
	"github.com/TAIPANBOX/rollcall/internal/events"
	"github.com/TAIPANBOX/rollcall/internal/history"
	"github.com/TAIPANBOX/rollcall/internal/identity"
	"github.com/TAIPANBOX/rollcall/internal/ids"
	"github.com/TAIPANBOX/rollcall/internal/member"
)

// t0 is the reception time of every fixture entry.
var t0 = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)

// router is one test member with a deterministic key; router n has ID byte
// 0 = n, so routers sort by n.
type router struct {
	id  *identity.Identity
	pub ed25519.PublicKey
}

func testRouter(n byte) router {
	var id ids.MemberID
	id[0], id[15] = n, 0x17
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{n}, ed25519.SeedSize))
	return router{id: &identity.Identity{ID: id, Sign: key}, pub: key.Public().(ed25519.PublicKey)}
}

var (
	self  = testRouter(1) // the member coming back: ap-office in security spec 5.8
	rx    = testRouter(2)
	ry    = testRouter(3)
	rz    = testRouter(4)
	other = testRouter(5) // another member, which some claims are about
	rw    = testRouter(6)
)

// testKeys holds the public key of testRouter(n) for every n.
var testKeys = func() map[ids.MemberID]ed25519.PublicKey {
	keys := map[ids.MemberID]ed25519.PublicKey{}
	for n := 0; n < 256; n++ {
		r := testRouter(byte(n))
		keys[r.id.ID] = r.pub
	}
	return keys
}()

func keyOf(o ids.MemberID) (ed25519.PublicKey, bool) {
	k, ok := testKeys[o]
	return k, ok
}

// bootID returns the boot ID numbered n.
func bootID(n byte) ids.BootID {
	var b ids.BootID
	b[0], b[15] = n, 0xb0
	return b
}

// boot returns self's boot with sequence number seq; fakeBoot returns a boot
// with the same sequence number and an ID self never had.
func boot(seq uint64) Boot     { return Boot{ID: bootID(byte(seq)), Seq: seq} }
func fakeBoot(seq uint64) Boot { return Boot{ID: bootID(byte(seq) + 100), Seq: seq} }

// bootRecord returns the record of self's boot seq.
func bootRecord(seq uint64, version string, planned bool) BootBody {
	return BootBody{Boot: boot(seq), Version: version, Planned: planned}
}

// world is the log of the member coming back, with the claims of the others.
type world struct {
	t   testing.TB
	log *history.Log
	cur BootBody // the boot self runs now
}

func newWorld(t testing.TB) *world { return newWorldMax(t, 0) }

func newWorldMax(t testing.TB, maxPerOrigin int) *world {
	return &world{t: t, log: history.NewLog(keyOf, maxPerOrigin)}
}

// add signs an entry by r after r's head and appends it.
func (w *world) add(r router, kind history.Kind, body any) history.Entry {
	w.t.Helper()
	e, err := history.NewEntry(r.id, w.log.Head(r.id.ID), kind, body)
	if err != nil {
		w.t.Fatalf("NewEntry(%s, %s): %v", r.id.ID, kind, err)
	}
	if err := w.log.Append(e, t0); err != nil {
		w.t.Fatalf("Append(%s seq %d): %v", r.id.ID, e.Seq, err)
	}
	return e
}

// booted records self's boot b and makes it the boot self runs now.
func (w *world) booted(b BootBody) history.Entry {
	w.t.Helper()
	w.cur = b
	return w.add(self, history.KindBoot, b)
}

// note records one entry of self's own: a change of its own internet.
func (w *world) note() history.Entry {
	w.t.Helper()
	return w.add(self, history.KindEvent, EventBody{Subject: self.id.ID, Type: events.InternetLost})
}

// claim records r's event entry.
func (w *world) claim(r router, b EventBody) history.Entry {
	w.t.Helper()
	return w.add(r, history.KindEvent, b)
}

// reconcile runs Reconcile as self, from the head of self's chain.
func (w *world) reconcile(claims ...history.Entry) Result {
	w.t.Helper()
	r, err := Reconcile(self.id, w.log.Head(self.id.ID), w.cur, w.log, claims)
	if err != nil {
		w.t.Fatalf("Reconcile: %v", err)
	}
	return r
}

// apply appends r's corrections to the log, as the caller does.
func (w *world) apply(r Result) {
	w.t.Helper()
	for _, c := range r.Corrections {
		for _, e := range c.Entries {
			if err := w.log.Append(e, t0); err != nil {
				w.t.Fatalf("Append correction seq %d: %v", e.Seq, err)
			}
		}
	}
}

// about returns an event body about self.
func about(typ events.Type, last, back Boot) EventBody {
	return EventBody{Subject: self.id.ID, Type: typ, Last: last, Back: back}
}

// seen returns b with Ref naming e: the head of self's chain the claimant held.
func seen(b EventBody, e history.Entry) EventBody {
	b.Ref = EntryRef{Seq: e.Seq, Hash: e.Hash()}
	return b
}

func hashesOf(es ...history.Entry) []ids.Hash {
	out := make([]ids.Hash, len(es))
	for i, e := range es {
		out[i] = e.Hash()
	}
	return out
}

// refsOf returns the refs of every entry of c, in order, and checks that
// each entry is a correction of c.Class.
func refsOf(t testing.TB, c Correction) []ids.Hash {
	t.Helper()
	var out []ids.Hash
	for _, e := range c.Entries {
		b, err := history.DecodeCorrection(e)
		if err != nil {
			t.Fatalf("correction seq %d: %v", e.Seq, err)
		}
		if b.Class != c.Class || b.Note != "" {
			t.Fatalf("correction seq %d: class %q note %q, want class %q and no note", e.Seq, b.Class, b.Note, c.Class)
		}
		out = append(out, b.Refs...)
	}
	return out
}

// short names hashes by their first bytes, for messages.
func short(hs []ids.Hash) []string {
	out := make([]string, len(hs))
	for i, h := range hs {
		out[i] = h.String()[:8]
	}
	return out
}

func wantHashes(t testing.TB, what string, got, want []ids.Hash) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Fatalf("%s = %v, want %v", what, short(got), short(want))
	}
}

// falseHashes returns the claims of r's falsehoods.
func falseHashes(r Result) []ids.Hash {
	var out []ids.Hash
	for _, f := range r.Falsehoods {
		out = append(out, f.Claim.Hash())
	}
	return out
}

// updates is what the caller queues for r: one update message for each
// correction whose Update is set.
func updates(r Result) int {
	n := 0
	for _, c := range r.Corrections {
		if c.Update {
			n++
		}
	}
	return n
}

// wantAgree fails unless r is an agreement with nothing to add.
func wantAgree(t testing.TB, r Result) {
	t.Helper()
	if r.Outcome != Agree || len(r.Corrections) != 0 || len(r.Falsehoods) != 0 {
		t.Fatalf("Outcome %v with %d corrections and %d falsehoods, want an agreement with none", r.Outcome, len(r.Corrections), len(r.Falsehoods))
	}
}

func cloneEntries(es []history.Entry) []history.Entry {
	out := make([]history.Entry, len(es))
	for i, e := range es {
		e.Body = bytes.Clone(e.Body)
		e.Sig = bytes.Clone(e.Sig)
		out[i] = e
	}
	return out
}

// TestReturnAgree: the others recorded what self's own chain shows, a crash
// and an earlier link loss, so there is nothing to add.
func TestReturnAgree(t *testing.T) {
	w := newWorld(t)
	w.booted(bootRecord(7, "24.10.4", false))
	before := w.note()
	zLink := w.claim(rz, seen(about(events.LinkLost, boot(7), boot(7)), before)) // an earlier link loss in boot 7
	crash := w.booted(bootRecord(8, "24.10.4", false))
	xSilent := w.claim(rx, seen(about(events.MemberSilent, boot(7), Boot{}), before))
	xBack := w.claim(rx, seen(about(events.RebootUnplanned, boot(7), boot(8)), crash))
	ySilent := w.claim(ry, about(events.MemberSilent, boot(7), Boot{}))
	yBack := w.claim(ry, about(events.RebootUnplanned, boot(7), boot(8)))
	claims := []history.Entry{yBack, zLink, xSilent, ySilent, xBack}
	kept := cloneEntries(claims)
	head := w.log.Head(self.id.ID)

	for call := range 3 {
		r := w.reconcile(claims...)
		wantAgree(t, r)
		if len(r.Unchecked) != 0 {
			t.Fatalf("call %d: unchecked %v, want none: every claim is one self can check", call, short(r.Unchecked))
		}
	}
	if !reflect.DeepEqual(claims, kept) {
		t.Fatalf("Reconcile modified its claims")
	}
	if h := w.log.Head(self.id.ID); h != head {
		t.Fatalf("Reconcile changed the log: head %+v, want %+v", h, head)
	}
	if s := Agree.String(); s != "agree" {
		t.Fatalf("Agree.String() = %q", s)
	}
}

// TestReturnLinkLostCorrection is the example of security spec 5.8: the
// others recorded ap-office silent and rebooted, while its own chain shows the
// same boot throughout. One correction, class link_lost, refers to every one
// of their entries; the incident's meaning changed, so one update is due.
func TestReturnLinkLostCorrection(t *testing.T) {
	w := newWorld(t)
	w.booted(bootRecord(7, "24.10.4", false))
	first := w.note() // recorded while cut off
	last := w.note()
	xSilent := w.claim(rx, seen(about(events.MemberSilent, boot(7), Boot{}), first))
	xReboot := w.claim(rx, seen(about(events.RebootUnplanned, boot(7), boot(7)), last))
	ySilent := w.claim(ry, about(events.MemberSilent, boot(7), Boot{}))
	yReboot := w.claim(ry, about(events.RebootUnplanned, boot(7), Boot{}))
	zReboot := w.claim(rz, about(events.RebootUnplanned, boot(7), boot(7)))
	aboutOther := w.claim(rx, EventBody{Subject: other.id.ID, Type: events.RebootUnplanned})
	head := w.log.Head(self.id.ID)
	claims := []history.Entry{zReboot, aboutOther, yReboot, last, xReboot, ySilent, xSilent}

	r := w.reconcile(claims...)
	if r.Outcome != HonestDifference || len(r.Falsehoods) != 0 || len(r.Unchecked) != 0 {
		t.Fatalf("Outcome %v, %d falsehoods, unchecked %v; want an honest difference only", r.Outcome, len(r.Falsehoods), short(r.Unchecked))
	}
	if len(r.Corrections) != 1 {
		t.Fatalf("%d corrections, want 1", len(r.Corrections))
	}
	c := r.Corrections[0]
	if c.Class != history.ClassLinkLost || c.Told != events.RebootUnplanned || !c.Update || c.From != boot(7) || c.To != boot(7) {
		t.Fatalf("correction class %q told %q update %v from %+v to %+v; want link_lost after reboot_unplanned, an update, boot 7 to 7",
			c.Class, c.Told, c.Update, c.From, c.To)
	}
	if len(c.Entries) != 1 {
		t.Fatalf("%d correction entries, want 1", len(c.Entries))
	}
	e := c.Entries[0]
	if e.Origin != self.id.ID || e.Seq != head.Seq+1 || e.Prev != head.Hash || e.Kind != history.KindCorrection {
		t.Fatalf("correction origin %s seq %d prev %s kind %s; want self's next entry after seq %d", e.Origin, e.Seq, e.Prev, e.Kind, head.Seq)
	}
	if err := e.Verify(self.pub); err != nil {
		t.Fatalf("correction does not verify under self's key: %v", err)
	}
	wantHashes(t, "refs", refsOf(t, c), hashesOf(xSilent, xReboot, ySilent, yReboot, zReboot))
	if n := updates(r); n != 1 {
		t.Fatalf("%d update messages, want 1", n)
	}

	w.apply(r)
	for call := range 2 {
		again := w.reconcile(claims...)
		wantAgree(t, again)
		if len(again.Unchecked) != 0 {
			t.Fatalf("call %d after the correction: unchecked %v", call, short(again.Unchecked))
		}
	}
	for _, orig := range []history.Entry{xSilent, xReboot, ySilent, yReboot, zReboot} {
		held := w.log.Range(orig.Origin, orig.Seq, orig.Seq)
		if len(held) != 1 || held[0].Hash() != orig.Hash() {
			t.Fatalf("the corrected claim %s seq %d changed in the log", orig.Origin, orig.Seq)
		}
	}
	if s := HonestDifference.String(); s != "honest difference" {
		t.Fatalf("HonestDifference.String() = %q", s)
	}
}

// TestReturnProvenFalsehood: a signed claim that contradicts self's signed
// chain is a proven falsehood, with a proof anyone holding both keys can
// check; the honest claims of the same return are still corrected.
func TestReturnProvenFalsehood(t *testing.T) {
	w := newWorld(t)
	rec := w.booted(bootRecord(7, "24.10.4", false))
	e2 := w.note()
	w.note()

	forged := seen(about(events.RebootUnplanned, boot(7), boot(7)), e2)
	forged.Ref.Hash[0] ^= 1 // an entry self never produced at seq 2
	xRef := w.claim(rx, forged)
	yLast := w.claim(ry, about(events.MemberSilent, fakeBoot(7), Boot{}))
	zBack := w.claim(rz, about(events.RebootUnplanned, boot(7), fakeBoot(7)))
	wHonest := w.claim(rw, about(events.MemberSilent, boot(7), Boot{}))

	r := w.reconcile(wHonest, zBack, yLast, xRef)
	if r.Outcome != ProvenFalsehood {
		t.Fatalf("Outcome %v, want proven falsehood", r.Outcome)
	}
	if len(r.Falsehoods) != 3 {
		t.Fatalf("%d falsehoods, want 3", len(r.Falsehoods))
	}
	want := []struct {
		claim, own history.Entry
		by         router
	}{{xRef, e2, rx}, {yLast, rec, ry}, {zBack, rec, rz}}
	for i, f := range r.Falsehoods {
		if f.Claim.Hash() != want[i].claim.Hash() || f.Own.Hash() != want[i].own.Hash() {
			t.Fatalf("falsehood %d: claim %s seq %d against own seq %d; want claim %s seq %d against own seq %d",
				i, f.Claim.Origin, f.Claim.Seq, f.Own.Seq, want[i].claim.Origin, want[i].claim.Seq, want[i].own.Seq)
		}
		if err := f.Verify(want[i].by.pub, self.pub); err != nil {
			t.Fatalf("falsehood %d does not verify: %v", i, err)
		}
	}
	if len(r.Corrections) != 1 || r.Corrections[0].Class != history.ClassLinkLost {
		t.Fatalf("%d corrections, want one link_lost for the honest claim", len(r.Corrections))
	}
	wantHashes(t, "refs", refsOf(t, r.Corrections[0]), hashesOf(wHonest))
	if len(r.Unchecked) != 0 {
		t.Fatalf("unchecked %v, want none", short(r.Unchecked))
	}
	if s := ProvenFalsehood.String(); s != "proven falsehood" {
		t.Fatalf("ProvenFalsehood.String() = %q", s)
	}
	if s := Outcome(0).String(); s != "unknown" {
		t.Fatalf("Outcome(0).String() = %q", s)
	}
}

// TestFalsehoodVerify: a proof verifies only as what it is: a statement
// signed by another member about the subject, and an entry signed by the
// subject that it contradicts.
func TestFalsehoodVerify(t *testing.T) {
	w := newWorld(t)
	rec := w.booted(bootRecord(7, "24.10.4", false))
	e2 := w.note()
	e3 := w.note()
	forged := seen(about(events.RebootUnplanned, boot(7), Boot{}), e2)
	forged.Ref.Hash[0] ^= 1
	xRef := w.claim(rx, forged)
	yBoot := w.claim(ry, about(events.RebootUnplanned, boot(7), fakeBoot(7)))
	honest := w.claim(rz, seen(about(events.RebootUnplanned, boot(7), boot(7)), e3))
	selfClaim := w.add(self, history.KindEvent, forged) // self's own statement about itself
	otherBody := forged
	otherBody.Subject = other.id.ID
	aboutOther := w.claim(rx, otherBody)
	witness := w.add(rx, history.KindWitness, history.WitnessBody{Ref: e2.Hash()})

	tampered := xRef
	tampered.Sig = bytes.Clone(xRef.Sig)
	tampered.Sig[0] ^= 1
	tamperedOwn := e2
	tamperedOwn.Sig = bytes.Clone(e2.Sig)
	tamperedOwn.Sig[0] ^= 1

	cases := []struct {
		name               string
		f                  Falsehood
		claimant, subject  ed25519.PublicKey
		ok                 bool
		notFalsehood, sigE bool
	}{
		{name: "a reference to an entry self never produced", f: Falsehood{Claim: xRef, Own: e2}, claimant: rx.pub, subject: self.pub, ok: true},
		{name: "a boot self never had", f: Falsehood{Claim: yBoot, Own: rec}, claimant: ry.pub, subject: self.pub, ok: true},
		{name: "keys swapped", f: Falsehood{Claim: xRef, Own: e2}, claimant: self.pub, subject: rx.pub, sigE: true},
		{name: "another claimant's key", f: Falsehood{Claim: xRef, Own: e2}, claimant: ry.pub, subject: self.pub, sigE: true},
		{name: "a tampered claim", f: Falsehood{Claim: tampered, Own: e2}, claimant: rx.pub, subject: self.pub, sigE: true},
		{name: "a tampered own entry", f: Falsehood{Claim: xRef, Own: tamperedOwn}, claimant: rx.pub, subject: self.pub, sigE: true},
		{name: "an entry at another seq", f: Falsehood{Claim: xRef, Own: e3}, claimant: rx.pub, subject: self.pub, notFalsehood: true},
		{name: "a reference that matches", f: Falsehood{Claim: honest, Own: e3}, claimant: rz.pub, subject: self.pub, notFalsehood: true},
		{name: "a ref claim against a boot record", f: Falsehood{Claim: xRef, Own: rec}, claimant: rx.pub, subject: self.pub, notFalsehood: true},
		{name: "a boot claim against an event", f: Falsehood{Claim: yBoot, Own: e2}, claimant: ry.pub, subject: self.pub, notFalsehood: true},
		{name: "a boot that matches", f: Falsehood{Claim: honest, Own: rec}, claimant: rz.pub, subject: self.pub, notFalsehood: true},
		{name: "the subject's own statement", f: Falsehood{Claim: selfClaim, Own: e2}, claimant: self.pub, subject: self.pub, notFalsehood: true},
		{name: "a claim about another member", f: Falsehood{Claim: aboutOther, Own: e2}, claimant: rx.pub, subject: self.pub, notFalsehood: true},
		{name: "a witness statement", f: Falsehood{Claim: witness, Own: e2}, claimant: rx.pub, subject: self.pub, notFalsehood: true},
	}
	for _, tc := range cases {
		err := tc.f.Verify(tc.claimant, tc.subject)
		switch {
		case tc.ok && err != nil:
			t.Errorf("%s: %v, want nil", tc.name, err)
		case tc.notFalsehood && !errors.Is(err, ErrNotFalsehood):
			t.Errorf("%s: %v, want ErrNotFalsehood", tc.name, err)
		case tc.sigE && !errors.Is(err, history.ErrSignature):
			t.Errorf("%s: %v, want history.ErrSignature", tc.name, err)
		}
	}
	// A proof of a bad Back boot, with the Last boot right: Back is checked too.
	backOnly := w.claim(rw, about(events.RebootUnplanned, boot(7), fakeBoot(7)))
	if err := (Falsehood{Claim: backOnly, Own: rec}).Verify(rw.pub, self.pub); err != nil {
		t.Errorf("a boot self never came back in: %v", err)
	}
	// And of a bad Last boot with no Back at all.
	lastOnly := w.claim(rw, about(events.MemberSilent, fakeBoot(7), Boot{}))
	if err := (Falsehood{Claim: lastOnly, Own: rec}).Verify(rw.pub, self.pub); err != nil {
		t.Errorf("a boot self was never last heard in: %v", err)
	}
	// A boot at another seq is no contradiction.
	elsewhere := w.claim(rw, about(events.MemberSilent, fakeBoot(8), fakeBoot(9)))
	if err := (Falsehood{Claim: elsewhere, Own: rec}).Verify(rw.pub, self.pub); !errors.Is(err, ErrNotFalsehood) {
		t.Errorf("a boot at another seq: %v, want ErrNotFalsehood", err)
	}
}

// TestDifferenceIsNeverFalsehood: what self could not observe (the others'
// internet probes, WAN and uplink, silences seen at different times, entries
// of self's chain it no longer holds or never received, boots it holds no
// record of) yields Agree or HonestDifference, never ProvenFalsehood.
func TestDifferenceIsNeverFalsehood(t *testing.T) {
	w := newWorld(t)
	w.booted(bootRecord(7, "24.10.3", false))
	e2 := w.note()
	w.note()
	r8 := w.booted(bootRecord(8, "24.10.3", false))
	e5 := w.note()

	beyond := about(events.RebootUnplanned, boot(7), boot(8))
	beyond.Ref = EntryRef{Seq: 9, Hash: e5.Hash()} // a head self lost in a power cut, or has not received yet
	cases := []history.Entry{
		w.claim(rx, EventBody{Subject: self.id.ID, Type: events.InternetLost}),
		w.claim(rx, seen(EventBody{Subject: self.id.ID, Type: events.WanDown, Last: boot(8)}, e5)),
		w.claim(ry, EventBody{Subject: self.id.ID, Type: events.UplinkSwitched, Last: boot(7), Back: boot(8)}),
		w.claim(ry, EventBody{Subject: self.id.ID, Type: "x_future_type"}),
		w.claim(rx, seen(about(events.MemberSilent, boot(8), Boot{}), e5)),
		w.claim(ry, seen(about(events.MemberSilent, boot(8), Boot{}), r8)), // the same silence, seen earlier
		w.claim(rz, beyond),
		w.claim(rz, about(events.MemberSilent, fakeBoot(3), Boot{})),                     // a boot self holds no record of
		w.claim(rw, about(events.RebootPlanned, Boot{}, boot(8))),                        // the start unknown
		w.claim(rw, about(events.LinkLost, fakeBoot(9), fakeBoot(9))),                    // a boot beyond the current one
		w.claim(rw, seen(about(events.LinkLost, boot(7), boot(7)), e2)),                  // an earlier link loss
		w.claim(rx, about(events.RebootUnplanned, Boot{ID: bootID(8), Seq: 1}, boot(8))), // seq 1: no record
	}
	r := w.reconcile(cases...)
	if r.Outcome == ProvenFalsehood || len(r.Falsehoods) != 0 {
		t.Fatalf("Outcome %v with falsehoods %v", r.Outcome, short(falseHashes(r)))
	}
	if r.Outcome != HonestDifference {
		t.Fatalf("Outcome %v, want an honest difference: the silences in boot 8 were a link loss", r.Outcome)
	}
	// In (origin, seq) order: rx's claims 0, 1 and 11, ry's 2 and 3, rz's 7, rw's 8 and 9.
	wantHashes(t, "unchecked", r.Unchecked, hashesOf(cases[0], cases[1], cases[11], cases[2], cases[3], cases[7], cases[8], cases[9]))
	if len(r.Corrections) != 1 || r.Corrections[0].Class != history.ClassLinkLost {
		t.Fatalf("%d corrections, want one link_lost", len(r.Corrections))
	}
	wantHashes(t, "refs", refsOf(t, r.Corrections[0]), hashesOf(cases[4], cases[5]))

	// Entries and boot records Prune dropped can no longer be compared.
	p := newWorldMax(t, 3)
	p.booted(bootRecord(7, "24.10.3", false))
	old := p.note()
	p.note()
	p.note()
	p.note()
	if held := p.log.Range(self.id.ID, 1, 2); len(held) != 0 {
		t.Fatalf("fixture: seq 1 and 2 still held")
	}
	stale := seen(about(events.RebootUnplanned, boot(7), boot(7)), old)
	stale.Ref.Hash[0] ^= 1
	pruned := []history.Entry{
		p.claim(rx, stale),
		p.claim(ry, about(events.MemberSilent, fakeBoot(7), Boot{})),
		p.claim(rz, about(events.MemberSilent, boot(7), Boot{})),
	}
	pr := p.reconcile(pruned...)
	if pr.Outcome == ProvenFalsehood || len(pr.Falsehoods) != 0 {
		t.Fatalf("pruned: Outcome %v with falsehoods %v", pr.Outcome, short(falseHashes(pr)))
	}
	wantHashes(t, "pruned: unchecked", pr.Unchecked, hashesOf(pruned[1]))
	if len(pr.Corrections) != 1 {
		t.Fatalf("pruned: %d corrections, want 1", len(pr.Corrections))
	}
	wantHashes(t, "pruned: refs", refsOf(t, pr.Corrections[0]), hashesOf(pruned[0], pruned[2]))

	// Many claims drawn from what self cannot contradict: never a falsehood.
	q := newWorld(t)
	q.booted(bootRecord(7, "24.10.3", false))
	q.note()
	q.note()
	q.booted(bootRecord(8, "24.10.4", true))
	q.note()
	mine := q.log.Range(self.id.ID, 1, 5)
	rng := rand.New(rand.NewPCG(17, 5))
	types := append(slices.Clone(allTypes), "x_future_type")
	pick := func() Boot {
		switch rng.IntN(5) {
		case 0:
			return Boot{}
		case 1:
			return boot(7)
		case 2:
			return boot(8)
		case 3:
			return Boot{ID: bootID(byte(rng.IntN(250) + 1)), Seq: uint64(rng.IntN(6) + 1)} // seqs 1-6: no record
		default:
			return Boot{ID: bootID(byte(rng.IntN(250) + 1)), Seq: uint64(rng.IntN(100) + 9)} // beyond the current boot
		}
	}
	var many []history.Entry
	for i := range 300 {
		b := EventBody{Subject: self.id.ID, Type: types[rng.IntN(len(types))], Last: pick(), Back: pick()}
		switch rng.IntN(3) {
		case 0:
			e := mine[rng.IntN(len(mine))]
			b.Ref = EntryRef{Seq: e.Seq, Hash: e.Hash()}
		case 1:
			var h ids.Hash
			h[0], h[31] = byte(i), 1
			b.Ref = EntryRef{Seq: uint64(rng.IntN(50) + 6), Hash: h}
		}
		many = append(many, q.claim(testRouter(byte(2+i%40)), b))
	}
	mr := q.reconcile(many...)
	if mr.Outcome == ProvenFalsehood || len(mr.Falsehoods) != 0 {
		t.Fatalf("random claims: Outcome %v with %d falsehoods", mr.Outcome, len(mr.Falsehoods))
	}
}

// allTypes is every event type of v1.
var allTypes = []events.Type{
	events.MemberSilent, events.MemberBack, events.RebootPlanned, events.RebootUnplanned, events.Upgraded, events.LinkLost,
	events.WanDown, events.WanUp, events.InternetLost, events.InternetRestored, events.UplinkSwitched,
	events.MemberJoined, events.MemberLeft, events.UnderFlood, events.DuplicateIdentity, events.Fork,
	events.RosterChanged, events.RosterChangesDropped,
}

// TestUpdateOnlyWhenClassChanges: a correction that changes what the
// incident tells queues exactly one update message; one that does not change
// it queues none.
func TestUpdateOnlyWhenClassChanges(t *testing.T) {
	crash := func(w *world) {
		w.booted(bootRecord(7, "24.10.4", false))
		w.note()
		w.booted(bootRecord(8, "24.10.4", false))
	}
	cases := []struct {
		name    string
		history func(*world)
		claims  func(*world) []history.Entry
		class   string      // "" for no correction
		told    events.Type // what the incident told
		refs    []int       // indexes of the claims corrected
		updates int
	}{
		{
			name:    "told a reboot, it was a link loss",
			history: func(w *world) { w.booted(bootRecord(7, "24.10.4", false)); w.note() },
			claims: func(w *world) []history.Entry {
				return []history.Entry{
					w.claim(rx, about(events.RebootUnplanned, boot(7), boot(7))),
					w.claim(ry, about(events.MemberSilent, boot(7), Boot{})),
				}
			},
			class: history.ClassLinkLost, told: events.RebootUnplanned, refs: []int{0, 1}, updates: 1,
		},
		{
			name: "told an upgrade; one member, which did not know the version, said a crash",
			history: func(w *world) {
				w.booted(bootRecord(7, "24.10.3", false))
				w.note()
				w.booted(bootRecord(8, "24.10.4", false))
			},
			claims: func(w *world) []history.Entry {
				return []history.Entry{
					w.claim(rx, about(events.Upgraded, boot(7), boot(8))),
					w.claim(ry, about(events.RebootUnplanned, boot(7), boot(8))),
					w.claim(rz, about(events.MemberSilent, boot(7), Boot{})),
				}
			},
			class: history.ClassUpgraded, told: events.Upgraded, refs: []int{1}, updates: 0,
		},
		{
			name: "told a crash, it was planned",
			history: func(w *world) {
				w.booted(bootRecord(7, "24.10.4", false))
				w.note()
				w.booted(bootRecord(8, "24.10.4", true))
			},
			claims: func(w *world) []history.Entry {
				return []history.Entry{
					w.claim(rx, about(events.RebootUnplanned, boot(7), boot(8))),
					w.claim(ry, about(events.MemberSilent, boot(7), Boot{})),
				}
			},
			class: history.ClassRebootPlanned, told: events.RebootUnplanned, refs: []int{0, 1}, updates: 1,
		},
		{
			name:    "told a link loss; a member that knew no more said member_back",
			history: func(w *world) { w.booted(bootRecord(7, "24.10.4", false)); w.note() },
			claims: func(w *world) []history.Entry {
				return []history.Entry{
					w.claim(rx, about(events.LinkLost, boot(7), boot(7))),
					w.claim(ry, about(events.MemberBack, boot(7), Boot{})),
					w.claim(rz, about(events.MemberSilent, boot(7), Boot{})),
				}
			},
			updates: 0,
		},
		{
			name:    "told a crash; one member said a link loss",
			history: crash,
			claims: func(w *world) []history.Entry {
				return []history.Entry{
					w.claim(rx, about(events.RebootUnplanned, boot(7), boot(8))),
					w.claim(ry, about(events.LinkLost, boot(7), boot(8))),
				}
			},
			class: history.ClassRebootUnplanned, told: events.RebootUnplanned, refs: []int{1}, updates: 0,
		},
		{
			name:    "told only that it came back",
			history: crash,
			claims: func(w *world) []history.Entry {
				return []history.Entry{w.claim(rx, about(events.MemberBack, boot(7), boot(8)))}
			},
			class: history.ClassRebootUnplanned, told: events.MemberBack, refs: []int{0}, updates: 1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			tc.history(w)
			claims := tc.claims(w)
			r := w.reconcile(claims...)
			if n := updates(r); n != tc.updates {
				t.Fatalf("%d update messages, want %d", n, tc.updates)
			}
			if tc.class == "" {
				wantAgree(t, r)
				return
			}
			if r.Outcome != HonestDifference || len(r.Corrections) != 1 {
				t.Fatalf("Outcome %v with %d corrections, want an honest difference with one", r.Outcome, len(r.Corrections))
			}
			c := r.Corrections[0]
			if c.Class != tc.class || c.Told != tc.told || c.Update != (tc.updates == 1) {
				t.Fatalf("class %q told %q update %v, want class %q told %q", c.Class, c.Told, c.Update, tc.class, tc.told)
			}
			var want []history.Entry
			for _, i := range tc.refs {
				want = append(want, claims[i])
			}
			wantHashes(t, "refs", refsOf(t, c), hashesOf(want...))
			w.apply(r)
			if n := updates(w.reconcile(claims...)); n != 0 {
				t.Fatalf("after the correction: %d update messages, want 0", n)
			}
		})
	}
}

// TestRebootClassification: what really happened, from self's own boot
// records, shown by the correction of a member_back claim, which says
// nothing about the cause.
func TestRebootClassification(t *testing.T) {
	cases := []struct {
		name       string
		records    []BootBody
		current    *BootBody // the boot self runs now, when it is not the last record
		last, back Boot
		want       string // the class; "" for unchecked
	}{
		{name: "crash", records: []BootBody{bootRecord(7, "v1", false), bootRecord(8, "v1", false)}, last: boot(7), back: boot(8), want: history.ClassRebootUnplanned},
		{name: "planned", records: []BootBody{bootRecord(7, "v1", false), bootRecord(8, "v1", true)}, last: boot(7), back: boot(8), want: history.ClassRebootPlanned},
		{name: "upgraded", records: []BootBody{bootRecord(7, "v1", false), bootRecord(8, "v2", false)}, last: boot(7), back: boot(8), want: history.ClassUpgraded},
		{name: "upgraded as planned", records: []BootBody{bootRecord(7, "v1", true), bootRecord(8, "v2", true)}, last: boot(7), back: boot(8), want: history.ClassUpgraded},
		{name: "version unknown before", records: []BootBody{bootRecord(7, "", false), bootRecord(8, "v2", false)}, last: boot(7), back: boot(8), want: history.ClassRebootUnplanned},
		{name: "version unknown after", records: []BootBody{bootRecord(7, "v1", false), bootRecord(8, "", true)}, last: boot(7), back: boot(8), want: history.ClassRebootPlanned},
		{name: "two reboots, one a crash", records: []BootBody{bootRecord(7, "v1", false), bootRecord(8, "v1", true), bootRecord(9, "v1", false)}, last: boot(7), back: boot(9), want: history.ClassRebootUnplanned},
		{name: "two reboots, the crash first", records: []BootBody{bootRecord(7, "v1", false), bootRecord(8, "v1", false), bootRecord(9, "v1", true)}, last: boot(7), back: boot(9), want: history.ClassRebootUnplanned},
		{name: "two planned reboots", records: []BootBody{bootRecord(7, "v1", false), bootRecord(8, "v1", true), bootRecord(9, "v1", true)}, last: boot(7), back: boot(9), want: history.ClassRebootPlanned},
		{name: "a later crash is not this absence", records: []BootBody{bootRecord(7, "v1", false), bootRecord(8, "v1", true), bootRecord(9, "v1", false)}, last: boot(7), back: boot(8), want: history.ClassRebootPlanned},
		{name: "upgraded and back to the old version", records: []BootBody{bootRecord(7, "v1", false), bootRecord(8, "v2", true), bootRecord(9, "v1", true)}, last: boot(7), back: boot(9), want: history.ClassRebootPlanned},
		{name: "came back in the same boot", records: []BootBody{bootRecord(7, "v1", false), bootRecord(8, "v1", false)}, last: boot(7), back: boot(7), want: history.ClassLinkLost},
		{name: "last heard in the current boot", records: []BootBody{bootRecord(7, "v1", false), bootRecord(8, "v1", false)}, last: boot(8), want: history.ClassLinkLost},
		{name: "last heard in the current boot, back named wrong", records: []BootBody{bootRecord(7, "v1", false), bootRecord(8, "v1", false)}, last: boot(8), back: boot(7), want: history.ClassLinkLost},
		{name: "the current boot without its record", records: []BootBody{bootRecord(7, "v1", false)}, current: &BootBody{Boot: boot(8), Version: "v1", Planned: true}, last: boot(7), back: boot(8), want: history.ClassRebootPlanned},
		{name: "upgraded into the current boot without its record", records: []BootBody{bootRecord(7, "v1", false)}, current: &BootBody{Boot: boot(8), Version: "v2"}, last: boot(7), back: boot(8), want: history.ClassUpgraded},
		{name: "back before last", records: []BootBody{bootRecord(7, "v1", false), bootRecord(8, "v1", false), bootRecord(9, "v1", false)}, last: boot(8), back: boot(7)},
		{name: "back unknown, last an old boot", records: []BootBody{bootRecord(7, "v1", false), bootRecord(8, "v1", false)}, last: boot(7)},
		{name: "last unknown", records: []BootBody{bootRecord(7, "v1", false), bootRecord(8, "v1", false)}, back: boot(8)},
		{name: "last without a record", records: []BootBody{bootRecord(7, "v1", false), bootRecord(8, "v1", false)}, last: boot(5), back: boot(8)},
		{name: "back without a record", records: []BootBody{bootRecord(7, "v1", false), bootRecord(9, "v1", false)}, last: boot(7), back: boot(8)},
		{name: "back beyond the current boot", records: []BootBody{bootRecord(7, "v1", false), bootRecord(8, "v1", false)}, last: boot(7), back: boot(9)},
		{name: "the current seq with an ID it does not have", records: []BootBody{bootRecord(7, "v1", false)}, current: &BootBody{Boot: boot(8)}, last: boot(7), back: fakeBoot(8)},
		{name: "two boot IDs for one seq in self's records", records: []BootBody{bootRecord(7, "v1", false), {Boot: fakeBoot(7), Version: "v1"}, bootRecord(8, "v1", false)}, last: boot(7), back: fakeBoot(7)},
		{name: "the other of two boot IDs for one seq", records: []BootBody{bootRecord(7, "v1", false), {Boot: fakeBoot(7), Version: "v1"}, bootRecord(8, "v1", false)}, last: fakeBoot(7), back: boot(8), want: history.ClassRebootUnplanned},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			for _, b := range tc.records {
				w.booted(b)
				w.note()
			}
			if tc.current != nil {
				w.cur = *tc.current
			}
			c := w.claim(rx, about(events.MemberBack, tc.last, tc.back))
			r := w.reconcile(c)
			if len(r.Falsehoods) != 0 {
				t.Fatalf("falsehoods %v", short(falseHashes(r)))
			}
			if tc.want == "" {
				if len(r.Corrections) != 0 || r.Outcome != Agree {
					t.Fatalf("Outcome %v with %d corrections, want the claim unchecked", r.Outcome, len(r.Corrections))
				}
				wantHashes(t, "unchecked", r.Unchecked, hashesOf(c))
				return
			}
			if len(r.Corrections) != 1 || len(r.Unchecked) != 0 {
				t.Fatalf("%d corrections, unchecked %v; want one correction", len(r.Corrections), short(r.Unchecked))
			}
			if got := r.Corrections[0].Class; got != tc.want {
				t.Fatalf("class %q, want %q", got, tc.want)
			}
			wantHashes(t, "refs", refsOf(t, r.Corrections[0]), hashesOf(c))
		})
	}
}

// TestSilencePairing: a silence ends with the same member's next record of
// self's return; one with no such record is the absence self is coming back
// from now. Each absence, from the boot last heard to the boot self came
// back in, is one incident with its own correction.
func TestSilencePairing(t *testing.T) {
	w := newWorld(t)
	w.booted(bootRecord(7, "24.10.4", false))
	e2 := w.note()
	xSilent1 := w.claim(rx, seen(about(events.MemberSilent, boot(7), Boot{}), e2)) // a link loss in boot 7
	xBack1 := w.claim(rx, about(events.LinkLost, boot(7), boot(7)))
	w.note()
	xOther := w.claim(rx, EventBody{Subject: self.id.ID, Type: events.InternetLost}) // between, not an absence
	xSilent2 := w.claim(rx, about(events.MemberSilent, boot(7), Boot{}))             // the absence now, a crash
	ySilentA := w.claim(ry, about(events.MemberSilent, boot(7), Boot{}))             // ry restarted and lost track
	ySilentB := w.claim(ry, about(events.MemberSilent, boot(7), Boot{}))
	crash := w.booted(bootRecord(8, "24.10.4", false))
	zSilent := w.claim(rz, seen(about(events.MemberSilent, boot(8), Boot{}), crash)) // lost after the reboot

	r := w.reconcile(zSilent, ySilentB, xSilent2, xOther, ySilentA, xBack1, xSilent1)
	if r.Outcome != HonestDifference || len(r.Falsehoods) != 0 {
		t.Fatalf("Outcome %v with %d falsehoods", r.Outcome, len(r.Falsehoods))
	}
	wantHashes(t, "unchecked", r.Unchecked, hashesOf(xOther, ySilentA))
	if len(r.Corrections) != 2 {
		t.Fatalf("%d corrections, want 2", len(r.Corrections))
	}
	crashed, lost := r.Corrections[0], r.Corrections[1]
	if crashed.Class != history.ClassRebootUnplanned || crashed.From != boot(7) || crashed.To != boot(8) || crashed.Told != events.MemberSilent || !crashed.Update {
		t.Fatalf("first correction %q from %+v to %+v told %q update %v; want reboot_unplanned from 7 to 8 after member_silent, an update",
			crashed.Class, crashed.From, crashed.To, crashed.Told, crashed.Update)
	}
	wantHashes(t, "crash refs", refsOf(t, crashed), hashesOf(xSilent2, ySilentB))
	if lost.Class != history.ClassLinkLost || lost.From != boot(8) || lost.To != boot(8) || !lost.Update {
		t.Fatalf("second correction %q from %+v to %+v update %v; want link_lost in boot 8, an update", lost.Class, lost.From, lost.To, lost.Update)
	}
	wantHashes(t, "link refs", refsOf(t, lost), hashesOf(zSilent))
	head := w.log.Head(self.id.ID)
	if e := crashed.Entries[0]; e.Seq != head.Seq+1 || e.Prev != head.Hash {
		t.Fatalf("first correction at seq %d, want %d after the head", e.Seq, head.Seq+1)
	}
	if e, prev := lost.Entries[0], crashed.Entries[0]; e.Seq != prev.Seq+1 || e.Prev != prev.Hash() {
		t.Fatalf("second correction at seq %d prev %s, want chained after the first", e.Seq, e.Prev)
	}
	w.apply(r)
	wantAgree(t, w.reconcile(zSilent, ySilentB, xSilent2, xOther, ySilentA, xBack1, xSilent1))
}

// TestManyClaimsChunked: more claims than one correction can name are split
// over several entries, chained, each claim in exactly one of them.
func TestManyClaimsChunked(t *testing.T) {
	w := newWorld(t)
	w.booted(bootRecord(7, "24.10.4", false))
	w.note()
	var claims []history.Entry
	for n := byte(2); n < 2+history.MaxRefs+4; n++ {
		claims = append(claims, w.claim(testRouter(n), about(events.RebootUnplanned, boot(7), boot(7))))
	}
	head := w.log.Head(self.id.ID)
	r := w.reconcile(claims...)
	if len(r.Corrections) != 1 || updates(r) != 1 {
		t.Fatalf("%d corrections and %d updates, want one of each", len(r.Corrections), updates(r))
	}
	c := r.Corrections[0]
	if len(c.Entries) != 2 {
		t.Fatalf("%d entries, want 2", len(c.Entries))
	}
	first, second := c.Entries[0], c.Entries[1]
	if first.Seq != head.Seq+1 || first.Prev != head.Hash || second.Seq != head.Seq+2 || second.Prev != first.Hash() {
		t.Fatalf("entries at seq %d and %d are not chained after head %d", first.Seq, second.Seq, head.Seq)
	}
	b1, _ := history.DecodeCorrection(first)
	b2, _ := history.DecodeCorrection(second)
	if len(b1.Refs) != history.MaxRefs || len(b2.Refs) != 4 {
		t.Fatalf("entries name %d and %d claims, want %d and 4", len(b1.Refs), len(b2.Refs), history.MaxRefs)
	}
	wantHashes(t, "refs", refsOf(t, c), hashesOf(claims...))
	w.apply(r)
	wantAgree(t, w.reconcile(claims...))
}

// TestOnlyClaimsAboutSelf: Reconcile judges only other members' event
// entries about self that the log holds, each once.
func TestOnlyClaimsAboutSelf(t *testing.T) {
	w := newWorld(t)
	w.booted(bootRecord(7, "24.10.4", false))
	e2 := w.note()
	o1 := w.add(other, history.KindBoot, BootBody{Boot: Boot{ID: bootID(50), Seq: 3}})

	againstOther := EventBody{Subject: other.id.ID, Type: events.RebootUnplanned, Last: Boot{ID: bootID(51), Seq: 3},
		Ref: EntryRef{Seq: o1.Seq, Hash: e2.Hash()}} // would contradict the other member's chain
	aboutOther := w.claim(rx, againstOther)
	forgedRef := seen(about(events.RebootUnplanned, boot(7), boot(7)), e2)
	forgedRef.Ref.Hash[0] ^= 1
	fromSelf := w.add(self, history.KindEvent, forgedRef) // self's own entry about itself
	witness := w.add(rx, history.KindWitness, history.WitnessBody{Ref: e2.Hash()})
	malformed := w.add(ry, history.KindEvent, json.RawMessage(`{"subject":"`+self.id.ID.String()+`","type":"Reboot"}`))
	if _, err := DecodeEvent(malformed); err == nil {
		t.Fatalf("fixture: DecodeEvent accepts the malformed body")
	}
	unheld, err := history.NewEntry(ry.id, w.log.Head(ry.id.ID), history.KindEvent, about(events.MemberSilent, fakeBoot(7), Boot{}))
	if err != nil {
		t.Fatal(err)
	}
	held := w.claim(ry, about(events.RebootPlanned, fakeBoot(7), Boot{})) // the log holds this one at that seq
	notHeld := unheld                                                     // same origin and seq, another entry
	if notHeld.Seq != held.Seq || notHeld.Hash() == held.Hash() {
		t.Fatalf("fixture: unheld entry is not a second entry at the held seq")
	}
	honest := w.claim(rz, about(events.MemberSilent, boot(7), Boot{}))
	var zero history.Entry

	r := w.reconcile(aboutOther, fromSelf, witness, malformed, notHeld, honest, honest, zero)
	if r.Outcome != HonestDifference || len(r.Falsehoods) != 0 || len(r.Unchecked) != 0 {
		t.Fatalf("Outcome %v, falsehoods %v, unchecked %v; want only the honest claim corrected", r.Outcome, short(falseHashes(r)), short(r.Unchecked))
	}
	if len(r.Corrections) != 1 {
		t.Fatalf("%d corrections, want 1", len(r.Corrections))
	}
	wantHashes(t, "refs", refsOf(t, r.Corrections[0]), hashesOf(honest))

	// The held claim with the bad boot is a falsehood once it is given.
	if fr := w.reconcile(held); len(fr.Falsehoods) != 1 || fr.Falsehoods[0].Claim.Hash() != held.Hash() {
		t.Fatalf("the held claim: %d falsehoods, want it", len(fr.Falsehoods))
	}
}

// TestOwnChainOddEntries: a boot record or a correction in self's chain
// that does not decode (written by a newer version, say) counts as neither.
func TestOwnChainOddEntries(t *testing.T) {
	w := newWorld(t)
	w.booted(bootRecord(7, "24.10.4", false))
	w.note()
	w.booted(bootRecord(8, "24.10.4", false))
	// A record of boot 9, beyond the current boot, with a version no record
	// may carry: read as a record, it would make the current boot an old one.
	odd := `{"boot":{"id":"` + bootID(9).String() + `","seq":9},"version":"x y","planned":false}`
	w.add(self, history.KindBoot, json.RawMessage(odd))
	silent := w.claim(rx, about(events.MemberSilent, boot(8), Boot{}))
	nine := w.claim(ry, about(events.MemberSilent, fakeBoot(9), Boot{})) // a falsehood only against the odd record
	// A correction of the silence with a class no correction may carry.
	w.add(self, history.KindCorrection, json.RawMessage(`{"refs":["`+silent.Hash().String()+`"],"class":"lost_link","note":""}`))

	r := w.reconcile(silent, nine)
	if len(r.Falsehoods) != 0 {
		t.Fatalf("falsehoods %v, want none: the odd record is no record", short(falseHashes(r)))
	}
	wantHashes(t, "unchecked", r.Unchecked, hashesOf(nine))
	if len(r.Corrections) != 1 {
		t.Fatalf("%d corrections, want one: the odd correction corrects nothing", len(r.Corrections))
	}
	wantHashes(t, "refs", refsOf(t, r.Corrections[0]), hashesOf(silent))
}

// TestReconcileRejects: Reconcile refuses what it cannot judge from, rather
// than produce entries that would fork self's own chain.
func TestReconcileRejects(t *testing.T) {
	base := func(t *testing.T) *world {
		w := newWorld(t)
		w.booted(bootRecord(7, "24.10.4", false))
		w.note()
		w.claim(rx, about(events.RebootUnplanned, boot(7), boot(7)))
		return w
	}
	claimsOf := func(w *world) []history.Entry { return w.log.Range(rx.id.ID, 1, 10) }
	cases := []struct {
		name string
		run  func(t *testing.T) error
		want error
	}{
		{"nil identity", func(t *testing.T) error {
			w := base(t)
			_, err := Reconcile(nil, w.log.Head(self.id.ID), w.cur, w.log, claimsOf(w))
			return err
		}, ErrInvalid},
		{"nil log", func(t *testing.T) error {
			w := base(t)
			_, err := Reconcile(self.id, w.log.Head(self.id.ID), w.cur, nil, claimsOf(w))
			return err
		}, ErrInvalid},
		{"zero member ID", func(t *testing.T) error {
			w := base(t)
			_, err := Reconcile(&identity.Identity{Sign: self.id.Sign}, w.log.Head(self.id.ID), w.cur, w.log, claimsOf(w))
			return err
		}, ErrInvalid},
		{"unknown current boot", func(t *testing.T) error {
			w := base(t)
			_, err := Reconcile(self.id, w.log.Head(self.id.ID), BootBody{}, w.log, claimsOf(w))
			return err
		}, ErrInvalid},
		{"current boot with a bad version", func(t *testing.T) error {
			w := base(t)
			cur := w.cur
			cur.Version = "24.10 rc"
			_, err := Reconcile(self.id, w.log.Head(self.id.ID), cur, w.log, claimsOf(w))
			return err
		}, ErrInvalid},
		{"head behind the chain", func(t *testing.T) error {
			w := base(t)
			head := w.log.Head(self.id.ID)
			w.note()
			_, err := Reconcile(self.id, head, w.cur, w.log, claimsOf(w))
			return err
		}, ErrInvalid},
		{"head of another chain", func(t *testing.T) error {
			w := base(t)
			_, err := Reconcile(self.id, w.log.Head(rx.id.ID), w.cur, w.log, claimsOf(w))
			return err
		}, ErrInvalid},
		{"zero head over a chain", func(t *testing.T) error {
			w := base(t)
			_, err := Reconcile(self.id, history.Head{}, w.cur, w.log, claimsOf(w))
			return err
		}, ErrInvalid},
		{"current boot contradicts its record", func(t *testing.T) error {
			w := base(t)
			cur := w.cur
			cur.Planned = true
			_, err := Reconcile(self.id, w.log.Head(self.id.ID), cur, w.log, claimsOf(w))
			return err
		}, ErrInvalid},
		{"current boot ID contradicts its record", func(t *testing.T) error {
			w := base(t)
			cur := w.cur
			cur.Boot = fakeBoot(7)
			_, err := Reconcile(self.id, w.log.Head(self.id.ID), cur, w.log, claimsOf(w))
			return err
		}, ErrInvalid},
		{"current boot older than a record", func(t *testing.T) error {
			w := base(t)
			_, err := Reconcile(self.id, w.log.Head(self.id.ID), bootRecord(6, "24.10.4", false), w.log, claimsOf(w))
			return err
		}, ErrInvalid},
		{"own chain forked", func(t *testing.T) error {
			w := base(t)
			second, err := history.NewEntry(self.id, history.Head{}, history.KindEvent, EventBody{Subject: self.id.ID, Type: events.WanUp})
			if err != nil {
				t.Fatal(err)
			}
			var fe *history.ForkError
			if err := w.log.Append(second, t0); !errors.As(err, &fe) {
				t.Fatalf("fixture: Append = %v, want a fork", err)
			}
			_, err = Reconcile(self.id, w.log.Head(self.id.ID), w.cur, w.log, claimsOf(w))
			return err
		}, ErrOwnFork},
		{"signing key of the wrong length", func(t *testing.T) error {
			w := base(t)
			bad := &identity.Identity{ID: self.id.ID, Sign: self.id.Sign[:10]}
			_, err := Reconcile(bad, w.log.Head(self.id.ID), w.cur, w.log, claimsOf(w))
			return err
		}, ErrInvalid},
		{"signing key whose public half is another's", func(t *testing.T) error {
			w := base(t)
			key := append(bytes.Clone(self.id.Sign[:ed25519.SeedSize]), rx.pub...)
			bad := &identity.Identity{ID: self.id.ID, Sign: key}
			_, err := Reconcile(bad, w.log.Head(self.id.ID), w.cur, w.log, claimsOf(w))
			return err
		}, history.ErrSignature},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.run(t)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}

	// Another member's fork does not stop self from judging.
	w := base(t)
	fork, err := history.NewEntry(rx.id, history.Head{}, history.KindEvent, EventBody{Subject: rx.id.ID, Type: events.WanUp})
	if err != nil {
		t.Fatal(err)
	}
	var fe *history.ForkError
	if err := w.log.Append(fork, t0); !errors.As(err, &fe) {
		t.Fatalf("fixture: Append = %v, want a fork", err)
	}
	if _, err := Reconcile(self.id, w.log.Head(self.id.ID), w.cur, w.log, claimsOf(w)); err != nil {
		t.Fatalf("another member's fork: %v", err)
	}
	// An empty chain with the zero head, and nothing to judge, is fine.
	e := newWorld(t)
	r, err := Reconcile(self.id, history.Head{}, bootRecord(1, "", false), e.log, nil)
	if err != nil || r.Outcome != Agree {
		t.Fatalf("empty chain: Outcome %v, err %v", r.Outcome, err)
	}
}

// TestEventBodyWireForm pins the bodies byte for byte.
func TestEventBodyWireForm(t *testing.T) {
	var subject ids.MemberID
	subject[0], subject[15] = 0xab, 0x01
	full := EventBody{
		Subject: subject, Type: events.RebootUnplanned,
		Last: Boot{ID: bootID(7), Seq: 7}, Back: Boot{ID: bootID(8), Seq: 18446744073709551615},
		Ref: EntryRef{Seq: 12, Hash: ids.Hash{0: 0xff, 31: 0x0e}},
	}
	e, err := NewEvent(rx.id, history.Head{}, full)
	if err != nil {
		t.Fatal(err)
	}
	zeros := func(n int) string { return strings.Repeat("0", n) }
	want := `{"subject":"ab` + zeros(28) + `01","type":"reboot_unplanned",` +
		`"last":{"id":"07` + zeros(28) + `b0","seq":7},` +
		`"back":{"id":"08` + zeros(28) + `b0","seq":18446744073709551615},` +
		`"ref":{"seq":12,"hash":"ff` + zeros(60) + `0e"}}`
	if string(e.Body) != want || e.Kind != history.KindEvent || e.Origin != rx.id.ID || e.Seq != 1 {
		t.Fatalf("NewEvent body\n %s\nwant\n %s", e.Body, want)
	}
	got, err := DecodeEvent(e)
	if err != nil || !reflect.DeepEqual(got, full) {
		t.Fatalf("DecodeEvent = %+v, %v; want %+v", got, err, full)
	}

	bare, err := NewEvent(rx.id, history.Head{}, EventBody{Type: events.UnderFlood})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"subject":"` + zeros(32) + `","type":"under_flood"}`; string(bare.Body) != want {
		t.Fatalf("bare body %s, want %s", bare.Body, want)
	}

	b, err := NewBoot(self.id, history.Head{}, BootBody{Boot: Boot{ID: bootID(7), Seq: 7}, Version: "24.10.4-r1+x~y_z", Planned: true})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"boot":{"id":"07` + zeros(28) + `b0","seq":7},"version":"24.10.4-r1+x~y_z","planned":true}`; string(b.Body) != want || b.Kind != history.KindBoot {
		t.Fatalf("boot body %s, want %s", b.Body, want)
	}
	gb, err := DecodeBoot(b)
	if err != nil || gb != (BootBody{Boot: Boot{ID: bootID(7), Seq: 7}, Version: "24.10.4-r1+x~y_z", Planned: true}) {
		t.Fatalf("DecodeBoot = %+v, %v", gb, err)
	}
	plain, err := NewBoot(self.id, history.Head{}, BootBody{Boot: Boot{ID: bootID(1), Seq: 1}})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"boot":{"id":"01` + zeros(28) + `b0","seq":1},"version":"","planned":false}`; string(plain.Body) != want {
		t.Fatalf("plain boot body %s, want %s", plain.Body, want)
	}
}

// TestBodyRules: NewEvent and NewBoot refuse bodies outside the rules with
// history.ErrBody and sign nothing; the limits are the ones documented.
func TestBodyRules(t *testing.T) {
	sub := self.id.ID
	ok := EventBody{Subject: sub, Type: events.LinkLost}
	long := strings.Repeat("a", maxType)
	good := []EventBody{
		ok,
		{Subject: sub, Type: events.Type(long)},
		{Subject: sub, Type: "a_b"},
		{Subject: sub, Type: events.MemberSilent, Last: boot(7)},
		{Subject: sub, Type: events.MemberBack, Back: boot(7)},
		{Subject: sub, Type: events.MemberBack, Ref: EntryRef{Seq: 1, Hash: ids.Hash{1}}},
		{Type: events.UnderFlood},
		{Type: events.UnderFlood, At: At{Wall: t0, Mono: 5, Trusted: true, Boot: bootID(1)}},
		{Subject: sub, Type: events.Upgraded, Detail: map[string]string{"from": "24.10.3", "to": "24.10.4"}},
		{Subject: sub, Type: events.RebootUnplanned, At: At{Wall: t0, Mono: 5, Trusted: true, Boot: bootID(2)},
			Since: At{Wall: t0.Add(-time.Minute), Mono: 9, Boot: bootID(1)}},
		{Subject: sub, Type: events.RebootPlanned, At: At{Wall: t0, Mono: 5, Boot: bootID(2)}, Since: At{Wall: t0.Add(-time.Minute), Trusted: true}},
		{Subject: sub, Type: events.Fork, Detail: map[string]string{"a": strings.Repeat("f", 64), "a_seq": "18446744073709551615"}},
	}
	for i, b := range good {
		if _, err := NewEvent(rx.id, history.Head{}, b); err != nil {
			t.Errorf("good %d (%+v): %v", i, b, err)
		}
	}
	bad := map[string]EventBody{
		"empty type":             {Subject: sub},
		"type too long":          {Subject: sub, Type: events.Type(long + "a")},
		"type in capitals":       {Subject: sub, Type: "Link_lost"},
		"type with a space":      {Subject: sub, Type: "link lost"},
		"type with a digit":      {Subject: sub, Type: "link2"},
		"type starting with _":   {Subject: sub, Type: "_link"},
		"type with a quote":      {Subject: sub, Type: `link"`},
		"type with a non-ASCII":  {Subject: sub, Type: events.Type("link" + string(rune(0xe9)))},
		"last without a seq":     {Subject: sub, Type: ok.Type, Last: Boot{ID: bootID(7)}},
		"last without an ID":     {Subject: sub, Type: ok.Type, Last: Boot{Seq: 7}},
		"back without a seq":     {Subject: sub, Type: ok.Type, Back: Boot{ID: bootID(7)}},
		"back without an ID":     {Subject: sub, Type: ok.Type, Back: Boot{Seq: 7}},
		"ref without a seq":      {Subject: sub, Type: ok.Type, Ref: EntryRef{Hash: ids.Hash{1}}},
		"ref without a hash":     {Subject: sub, Type: ok.Type, Ref: EntryRef{Seq: 1}},
		"last of no member":      {Type: ok.Type, Last: boot(7)},
		"back of no member":      {Type: ok.Type, Back: boot(7)},
		"ref into no member":     {Type: ok.Type, Ref: EntryRef{Seq: 1, Hash: ids.Hash{1}}},
		"type in capitals, long": {Subject: sub, Type: events.Type(strings.Repeat("A", maxType))},
		"stamp before 1970":      {Subject: sub, Type: ok.Type, At: At{Wall: time.Unix(-1, 0).UTC()}},
		"stamp after 9999":       {Subject: sub, Type: ok.Type, At: At{Wall: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)}},
		"stamp not in UTC":       {Subject: sub, Type: ok.Type, At: At{Wall: t0.In(time.FixedZone("x", 3600))}},
		"stamp before its boot":  {Subject: sub, Type: ok.Type, At: At{Wall: t0, Mono: -1}},
		"start without a stamp":  {Subject: sub, Type: ok.Type, Since: At{Wall: t0}},
		"start before 1970":      {Subject: sub, Type: ok.Type, At: At{Wall: t0}, Since: At{Wall: time.Unix(-1, 0).UTC()}},
		"start not in UTC":       {Subject: sub, Type: ok.Type, At: At{Wall: t0}, Since: At{Wall: t0.In(time.FixedZone("x", 3600))}},
		"start before its boot":  {Subject: sub, Type: ok.Type, At: At{Wall: t0}, Since: At{Wall: t0, Mono: -1}},
		"empty detail":           {Subject: sub, Type: ok.Type, Detail: map[string]string{}},
		"detail too long":        {Subject: sub, Type: ok.Type, Detail: map[string]string{"a": "1", "b": "1", "c": "1", "d": "1", "e": "1", "f": "1", "g": "1"}},
		"detail key in capitals": {Subject: sub, Type: ok.Type, Detail: map[string]string{"From": "1"}},
		"detail key too long":    {Subject: sub, Type: ok.Type, Detail: map[string]string{strings.Repeat("k", maxDetailKey+1): "1"}},
		"detail empty key":       {Subject: sub, Type: ok.Type, Detail: map[string]string{"": "1"}},
		"detail value spaced":    {Subject: sub, Type: ok.Type, Detail: map[string]string{"to": "24 10"}},
		"detail value too long":  {Subject: sub, Type: ok.Type, Detail: map[string]string{"to": strings.Repeat("9", maxVersion+1)}},
		"detail value a link":    {Subject: sub, Type: ok.Type, Detail: map[string]string{"to": "https://x"}},
	}
	for name, b := range bad {
		e, err := NewEvent(rx.id, history.Head{}, b)
		if !errors.Is(err, history.ErrBody) || e.Sig != nil {
			t.Errorf("%s: err %v, sig %x; want history.ErrBody and nothing signed", name, err, e.Sig)
		}
	}

	if maxVersion != member.MaxVersionLen {
		t.Fatalf("maxVersion %d, the heartbeat's limit is %d", maxVersion, member.MaxVersionLen)
	}
	okBoot := Boot{ID: bootID(7), Seq: 7}
	for _, v := range []string{"", "24.10.4", strings.Repeat("A", maxVersion), "a.b-c+d_e~f", "SNAPSHOT"} {
		if _, err := NewBoot(self.id, history.Head{}, BootBody{Boot: okBoot, Version: v}); err != nil {
			t.Errorf("version %q: %v", v, err)
		}
	}
	badBoot := map[string]BootBody{
		"unknown boot":              {},
		"boot without a seq":        {Boot: Boot{ID: bootID(7)}},
		"boot without an ID":        {Boot: Boot{Seq: 7}},
		"version too long":          {Boot: okBoot, Version: strings.Repeat("1", maxVersion+1)},
		"version with a space":      {Boot: okBoot, Version: "24.10 rc"},
		"version with a slash":      {Boot: okBoot, Version: "24/10"},
		"version with a quote":      {Boot: okBoot, Version: `24"10`},
		"version with an ampersand": {Boot: okBoot, Version: "24&10"},
		"version with a colon":      {Boot: okBoot, Version: "24:10"},
		"version non-ASCII":         {Boot: okBoot, Version: "24.10" + string(rune(0xe9))},
		"version with a NUL":        {Boot: okBoot, Version: "24\x00"},
	}
	for name, b := range badBoot {
		e, err := NewBoot(self.id, history.Head{}, b)
		if !errors.Is(err, history.ErrBody) || e.Sig != nil {
			t.Errorf("%s: err %v; want history.ErrBody and nothing signed", name, err)
		}
	}
	// NewEvent and NewBoot pass history.NewEntry's own refusals on.
	if _, err := NewEvent(nil, history.Head{}, ok); !errors.Is(err, history.ErrInvalid) {
		t.Errorf("NewEvent with a nil identity: %v", err)
	}
	if _, err := NewBoot(nil, history.Head{}, BootBody{Boot: okBoot}); !errors.Is(err, history.ErrInvalid) {
		t.Errorf("NewBoot with a nil identity: %v", err)
	}
}

// TestDecodeBodiesStrict: the decoders accept only the one form NewEvent and
// NewBoot write, and only on entries of their kind.
func TestDecodeBodiesStrict(t *testing.T) {
	sub := self.id.ID.String()
	id7 := bootID(7).String()
	bs := string(rune(92)) // a backslash, for JSON escapes
	event := func(body string) history.Entry {
		return history.Entry{Origin: rx.id.ID, Seq: 1, Kind: history.KindEvent, Body: json.RawMessage(body)}
	}
	if _, err := DecodeEvent(event(`{"subject":"` + sub + `","type":"link_lost"}`)); err != nil {
		t.Fatalf("a good body: %v", err)
	}
	hostile := map[string]string{
		"unknown field":         `{"subject":"` + sub + `","type":"link_lost","x":1}`,
		"capital key":           `{"Subject":"` + sub + `","type":"link_lost"}`,
		"reordered":             `{"type":"link_lost","subject":"` + sub + `"}`,
		"repeated key":          `{"subject":"` + sub + `","type":"link_lost","type":"link_lost"}`,
		"subject missing":       `{"type":"link_lost"}`,
		"type missing":          `{"subject":"` + sub + `"}`,
		"zero last written out": `{"subject":"` + sub + `","type":"link_lost","last":{"id":"00000000000000000000000000000000","seq":0}}`,
		"zero ref written out":  `{"subject":"` + sub + `","type":"link_lost","ref":{"seq":0,"hash":"` + strings.Repeat("0", 64) + `"}}`,
		"capital hex":           `{"subject":"` + sub + `","type":"link_lost","last":{"id":"` + strings.ToUpper(id7) + `","seq":7}}`,
		"escaped type":          `{"subject":"` + sub + `","type":"link` + bs + `u005flost"}`,
		"space":                 `{"subject":"` + sub + `", "type":"link_lost"}`,
		"trailing data":         `{"subject":"` + sub + `","type":"link_lost"}{}`,
		"trailing newline":      `{"subject":"` + sub + `","type":"link_lost"}` + "\n",
		"null":                  `null`,
		"array":                 `[]`,
		"empty":                 ``,
		"seq as string":         `{"subject":"` + sub + `","type":"link_lost","last":{"id":"` + id7 + `","seq":"7"}}`,
		"negative seq":          `{"subject":"` + sub + `","type":"link_lost","last":{"id":"` + id7 + `","seq":-7}}`,
		"seq as float":          `{"subject":"` + sub + `","type":"link_lost","last":{"id":"` + id7 + `","seq":7.0}}`,
		"half a boot":           `{"subject":"` + sub + `","type":"link_lost","last":{"id":"` + id7 + `","seq":0}}`,
		"short ID":              `{"subject":"` + sub[:30] + `","type":"link_lost"}`,
		"bad type":              `{"subject":"` + sub + `","type":"Link"}`,
		"too long":              `{"subject":"` + sub + `","type":"link_lost"` + strings.Repeat(" ", maxBody) + `}`,
		"unknown nested field":  `{"subject":"` + sub + `","type":"link_lost","last":{"id":"` + id7 + `","seq":7,"x":1}}`,
	}
	for name, body := range hostile {
		got, err := DecodeEvent(event(body))
		if !errors.Is(err, history.ErrBody) || !reflect.DeepEqual(got, EventBody{}) {
			t.Errorf("event, %s: %+v, %v; want history.ErrBody and the zero body", name, got, err)
		}
	}
	bootEntry := func(body string) history.Entry {
		return history.Entry{Origin: self.id.ID, Seq: 1, Kind: history.KindBoot, Body: json.RawMessage(body)}
	}
	if _, err := DecodeBoot(bootEntry(`{"boot":{"id":"` + id7 + `","seq":7},"version":"","planned":false}`)); err != nil {
		t.Fatalf("a good boot body: %v", err)
	}
	hostileBoot := map[string]string{
		"planned missing": `{"boot":{"id":"` + id7 + `","seq":7},"version":""}`,
		"version missing": `{"boot":{"id":"` + id7 + `","seq":7},"planned":false}`,
		"boot missing":    `{"version":"","planned":false}`,
		"unknown field":   `{"boot":{"id":"` + id7 + `","seq":7},"version":"","planned":false,"x":0}`,
		"planned as 0":    `{"boot":{"id":"` + id7 + `","seq":7},"version":"","planned":0}`,
		"bad version":     `{"boot":{"id":"` + id7 + `","seq":7},"version":"a b","planned":false}`,
		"escaped version": `{"boot":{"id":"` + id7 + `","seq":7},"version":"` + bs + `u0061","planned":false}`,
		"zero boot":       `{"boot":{"id":"00000000000000000000000000000000","seq":0},"version":"","planned":false}`,
		"too long":        `{"boot":{"id":"` + id7 + `","seq":7},"version":"` + strings.Repeat("a", maxBody) + `","planned":false}`,
	}
	for name, body := range hostileBoot {
		got, err := DecodeBoot(bootEntry(body))
		if !errors.Is(err, history.ErrBody) || got != (BootBody{}) {
			t.Errorf("boot, %s: %+v, %v; want history.ErrBody and the zero body", name, got, err)
		}
	}
	for _, k := range []history.Kind{history.KindBoot, history.KindWitness, history.KindCorrection, history.KindCheckpoint, history.KindObjection, "x"} {
		e := event(`{"subject":"` + sub + `","type":"link_lost"}`)
		e.Kind = k
		if got, err := DecodeEvent(e); !errors.Is(err, history.ErrInvalid) || !reflect.DeepEqual(got, EventBody{}) {
			t.Errorf("DecodeEvent of a %s entry: %v", k, err)
		}
	}
	for _, k := range []history.Kind{history.KindEvent, history.KindWitness, history.KindCorrection, history.KindCheckpoint, history.KindObjection, "x"} {
		e := bootEntry(`{"boot":{"id":"` + id7 + `","seq":7},"version":"","planned":false}`)
		e.Kind = k
		if got, err := DecodeBoot(e); !errors.Is(err, history.ErrInvalid) || got != (BootBody{}) {
			t.Errorf("DecodeBoot of a %s entry: %v", k, err)
		}
	}
}

// TestBodySizes: the largest bodies NewEvent and NewBoot write fit the
// decoders' limit, which is below the log's.
func TestBodySizes(t *testing.T) {
	var max ids.MemberID
	for i := range max {
		max[i] = 0xff
	}
	detail := map[string]string{}
	for i := 0; i < maxDetail; i++ {
		detail[strings.Repeat(string(rune('a'+i)), maxDetailKey)] = strings.Repeat("~", maxVersion)
	}
	biggest := EventBody{
		Subject: max, Type: events.Type(strings.Repeat("z", maxType)),
		Last: Boot{ID: bootID(255), Seq: 1<<64 - 1}, Back: Boot{ID: bootID(255), Seq: 1<<64 - 1},
		Ref:    EntryRef{Seq: 1<<64 - 1, Hash: ids.Hash{0: 1}},
		At:     At{Wall: time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.UTC), Mono: math.MaxInt64, Trusted: true, Boot: bootID(255)},
		Since:  At{Wall: time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.UTC), Mono: math.MaxInt64, Trusted: true, Boot: bootID(255)},
		Detail: detail,
	}
	e, err := NewEvent(rx.id, history.Head{}, biggest)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewBoot(self.id, history.Head{}, BootBody{Boot: Boot{ID: bootID(255), Seq: 1<<64 - 1}, Version: strings.Repeat("~", maxVersion), Planned: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("largest event body %d bytes, largest boot body %d bytes, limit %d (slack %d and %d)", len(e.Body), len(b.Body), maxBody, maxBody-len(e.Body), maxBody-len(b.Body))
	if len(e.Body) > maxBody || len(b.Body) > maxBody || maxBody > history.MaxBodySize {
		t.Fatalf("bodies %d and %d bytes, limit %d, log limit %d", len(e.Body), len(b.Body), maxBody, history.MaxBodySize)
	}
	if _, err := DecodeEvent(e); err != nil {
		t.Fatalf("DecodeEvent of the largest body: %v", err)
	}
	if _, err := DecodeBoot(b); err != nil {
		t.Fatalf("DecodeBoot of the largest body: %v", err)
	}
}

// TestToldMatchesRender: the absence an incident tells, as Reconcile ranks
// it, is the one deliver.Render puts in the message.
func TestToldMatchesRender(t *testing.T) {
	absences := []events.Type{events.Upgraded, events.RebootUnplanned, events.RebootPlanned, events.LinkLost, events.MemberBack, events.MemberSilent}
	render := func(types []events.Type) string {
		inc := events.Incident{Members: []string{self.id.ID.String()}, Causes: 1, Events: types}
		return deliver.Render(inc, "", time.UTC, deliver.Facts{})
	}
	for _, a := range absences {
		if !absence(a) {
			t.Errorf("%s is not an absence", a)
		}
		for _, b := range absences {
			got := told([]events.Type{a, b})
			if got != a && got != b {
				t.Fatalf("told(%s, %s) = %s", a, b, got)
			}
			alone := []events.Type{got}
			if (a == events.MemberSilent || b == events.MemberSilent) && got != events.MemberSilent {
				alone = append(alone, events.MemberSilent) // the message says when it began
			}
			if r1, r2 := render([]events.Type{a, b}), render(alone); r1 != r2 {
				t.Errorf("told(%s, %s) = %s, but the message for both is %q, for %v alone %q", a, b, got, r1, alone, r2)
			}
		}
	}
	for _, typ := range allTypes {
		if absence(typ) != slices.Contains(absences, typ) {
			t.Errorf("absence(%s) = %v", typ, absence(typ))
		}
	}
	if got := told([]events.Type{events.InternetLost, events.WanDown}); got != "" {
		t.Errorf("told of no absence = %q", got)
	}
}

// fuzzCur is the boot self runs in the fuzz targets, and fuzzSelf self's
// chain there, signed once: boot 7 at seq 1, two events, boot 8 (planned, a
// new version) at seq 4, one event.
var (
	fuzzCur  = bootRecord(8, "24.10.4", true)
	fuzzSelf = func() []history.Entry {
		var out []history.Entry
		var head history.Head
		add := func(kind history.Kind, body any) {
			e, err := history.NewEntry(self.id, head, kind, body)
			if err != nil {
				panic(err)
			}
			out = append(out, e)
			head = history.Head{Seq: e.Seq, Hash: e.Hash()}
		}
		ev := EventBody{Subject: self.id.ID, Type: events.InternetLost}
		add(history.KindBoot, bootRecord(7, "24.10.3", false))
		add(history.KindEvent, ev)
		add(history.KindEvent, ev)
		add(history.KindBoot, fuzzCur)
		add(history.KindEvent, ev)
		return out
	}()
	fuzzClaimants = []router{rx, ry, rz}
)

// fuzzContradicts reports, on its own, whether b contradicts fuzzSelf: a
// reference to a held seq with another hash, or a boot at seq 7 or 8 with
// another ID.
func fuzzContradicts(b EventBody) bool {
	if b.Ref != (EntryRef{}) && b.Ref.Seq >= 1 && b.Ref.Seq <= uint64(len(fuzzSelf)) && b.Ref.Hash != fuzzSelf[b.Ref.Seq-1].Hash() {
		return true
	}
	for _, bt := range []Boot{b.Last, b.Back} {
		if (bt.Seq == 7 && bt.ID != boot(7).ID) || (bt.Seq == 8 && bt.ID != boot(8).ID) {
			return true
		}
	}
	return false
}

// fuzzReconcile appends fuzzSelf and the claims to a new log, reconciles,
// and checks what must hold whatever the claims say.
func fuzzReconcile(t *testing.T, claims func(l *history.Log) []history.Entry) {
	l := history.NewLog(keyOf, 0)
	for _, e := range fuzzSelf {
		if err := l.Append(e, t0); err != nil {
			t.Fatal(err)
		}
	}
	cs := claims(l)
	head := l.Head(self.id.ID)
	r, err := Reconcile(self.id, head, fuzzCur, l, cs)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	switch {
	case len(r.Falsehoods) > 0 && r.Outcome != ProvenFalsehood,
		len(r.Falsehoods) == 0 && len(r.Corrections) > 0 && r.Outcome != HonestDifference,
		len(r.Falsehoods) == 0 && len(r.Corrections) == 0 && r.Outcome != Agree:
		t.Fatalf("Outcome %v with %d falsehoods and %d corrections", r.Outcome, len(r.Falsehoods), len(r.Corrections))
	}

	verdicts := map[ids.Hash]int{}
	for _, f := range r.Falsehoods {
		verdicts[f.Claim.Hash()]++
		if err := f.Verify(testKeys[f.Claim.Origin], self.pub); err != nil {
			t.Fatalf("a falsehood does not verify: %v", err)
		}
	}
	for _, h := range r.Unchecked {
		verdicts[h]++
	}
	prev := head
	for _, c := range r.Corrections {
		if c.Update != (events.Type(c.Class) != c.Told) || len(c.Entries) == 0 {
			t.Fatalf("correction %q told %q update %v with %d entries", c.Class, c.Told, c.Update, len(c.Entries))
		}
		for _, e := range c.Entries {
			if e.Seq != prev.Seq+1 || e.Prev != prev.Hash {
				t.Fatalf("correction seq %d not chained after %d", e.Seq, prev.Seq)
			}
			if err := l.Append(e, t0); err != nil {
				t.Fatalf("Append correction: %v", err)
			}
			prev = history.Head{Seq: e.Seq, Hash: e.Hash()}
			b, err := history.DecodeCorrection(e)
			if err != nil || b.Class != c.Class {
				t.Fatalf("correction body %+v, %v", b, err)
			}
			for _, ref := range b.Refs {
				verdicts[ref]++
			}
		}
	}

	given := map[ids.Hash]bool{}
	for _, c := range cs {
		h := c.Hash()
		given[h] = true
		b, err := DecodeEvent(c)
		about := err == nil && b.Subject == self.id.ID
		if !about {
			if verdicts[h] != 0 {
				t.Fatalf("a claim not about self got a verdict: %+v", b)
			}
			continue
		}
		if verdicts[h] > 1 {
			t.Fatalf("a claim got %d verdicts: %+v", verdicts[h], b)
		}
		if isFalse := slices.Contains(falseHashes(r), h); isFalse != fuzzContradicts(b) {
			t.Fatalf("falsehood %v for %+v, the contradiction check says %v", isFalse, b, !isFalse)
		}
		corrected := verdicts[h] == 1 && !slices.Contains(falseHashes(r), h) && !slices.Contains(r.Unchecked, h)
		if corrected && !absence(b.Type) {
			t.Fatalf("a claim of %q was corrected", b.Type)
		}
	}
	for h := range verdicts {
		if !given[h] {
			t.Fatalf("a verdict about an entry that was not given: %s", h)
		}
	}

	again, err := Reconcile(self.id, prev, fuzzCur, l, cs)
	if err != nil {
		t.Fatalf("Reconcile after the corrections: %v", err)
	}
	if len(again.Corrections) != 0 || !slices.Equal(falseHashes(again), falseHashes(r)) {
		t.Fatalf("after the corrections: %d corrections, falsehoods %v (were %v)", len(again.Corrections), short(falseHashes(again)), short(falseHashes(r)))
	}
}

// FuzzReconcileBodies reconciles claims with random bodies: data is split at
// line breaks, and every part that is JSON becomes the body of an event entry
// of rx, ry or rz in turn.
func FuzzReconcileBodies(f *testing.F) {
	seeds := []EventBody{
		about(events.RebootUnplanned, boot(7), boot(8)),
		about(events.MemberSilent, boot(8), Boot{}),
		about(events.LinkLost, fakeBoot(7), boot(7)),
		seen(about(events.MemberBack, boot(7), boot(8)), fuzzSelf[2]),
		{Subject: self.id.ID, Type: events.InternetLost, Ref: EntryRef{Seq: 3, Hash: fuzzSelf[1].Hash()}},
		{Subject: other.id.ID, Type: events.RebootUnplanned, Last: boot(7)},
	}
	var all [][]byte
	for _, s := range seeds {
		b, err := json.Marshal(s)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
		all = append(all, b)
	}
	f.Add(bytes.Join(all, []byte("\n")))
	f.Add([]byte(`{"subject":"` + self.id.ID.String() + `","type":"member_silent","last":{"id":"` + bootID(7).String() + `","seq":7}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		parts := bytes.Split(data, []byte("\n"))
		if len(parts) > 8 {
			parts = parts[:8]
		}
		fuzzReconcile(t, func(l *history.Log) []history.Entry {
			var out []history.Entry
			for i, p := range parts {
				if !json.Valid(p) {
					continue
				}
				c := fuzzClaimants[i%len(fuzzClaimants)]
				e, err := history.NewEntry(c.id, l.Head(c.id.ID), history.KindEvent, json.RawMessage(p))
				if err != nil {
					continue // a body the log refuses, too long for one
				}
				if err := l.Append(e, t0); err != nil {
					t.Fatalf("Append: %v", err)
				}
				out = append(out, e)
			}
			return out
		})
	})
}

// FuzzReconcileClaims reconciles claims built from a small domain, so that
// boots, references and pairings meet often: every 5 bytes of data are one
// claim (type, last boot, back boot, reference, claimant).
func FuzzReconcileClaims(f *testing.F) {
	f.Add([]byte{0, 1, 2, 0, 0, 1, 1, 0, 0, 1})
	f.Add([]byte{3, 1, 1, 5, 0, 0, 2, 0, 0, 1, 4, 3, 2, 6, 2})
	f.Add([]byte{1, 4, 5, 7, 0, 2, 6, 7, 8, 1, 5, 0, 0, 0, 2, 0, 1, 0, 3, 0})
	types := append(slices.Clone(allTypes), "x_future_type")
	boots := []Boot{{}, boot(7), boot(8), fakeBoot(7), fakeBoot(8), boot(6), boot(9), fakeBoot(9)}
	refs := []EntryRef{{}}
	for _, e := range fuzzSelf {
		refs = append(refs, EntryRef{Seq: e.Seq, Hash: e.Hash()})
	}
	forged := refs[3]
	forged.Hash[5] ^= 0x40
	refs = append(refs, forged, EntryRef{Seq: 9, Hash: fuzzSelf[0].Hash()})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 5*24 {
			data = data[:5*24]
		}
		fuzzReconcile(t, func(l *history.Log) []history.Entry {
			var out []history.Entry
			for ; len(data) >= 5; data = data[5:] {
				b := EventBody{
					Subject: self.id.ID,
					Type:    types[int(data[0])%len(types)],
					Last:    boots[int(data[1])%len(boots)],
					Back:    boots[int(data[2])%len(boots)],
					Ref:     refs[int(data[3])%len(refs)],
				}
				if data[0] >= 200 {
					b.Subject = other.id.ID
				}
				c := fuzzClaimants[int(data[4])%len(fuzzClaimants)]
				e, err := NewEvent(c.id, l.Head(c.id.ID), b)
				if err != nil {
					t.Fatalf("NewEvent: %v", err)
				}
				if err := l.Append(e, t0); err != nil {
					t.Fatalf("Append: %v", err)
				}
				out = append(out, e)
			}
			return out
		})
	})
}
