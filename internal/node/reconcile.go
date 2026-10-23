// Package node is one rollcall member: the state machine that ties the core
// packages together, and what a member does when it comes back after an
// absence (security spec 5.8), which this file holds. Nothing here touches
// the network or the clock.
//
// # Bodies
//
// The history package stores bodies it does not interpret; this package
// defines two of them, and its decoders accept only the one form its
// constructors write (as history.DecodeWitness does for statements).
//
// An entry of history.KindEvent carries an EventBody: one event its origin
// observed, about the member Subject.
//
//	{"subject":"<32 hex>","type":"reboot_unplanned",
//	 "last":{"id":"<32 hex>","seq":7},"back":{"id":"<32 hex>","seq":8},
//	 "ref":{"seq":17,"hash":"<64 hex>"},
//	 "at":{"wall":"2026-10-23T09:00:00Z","mono":1000000000,"trusted":true,"boot":"<32 hex>"},
//	 "since":{"wall":"2026-10-23T08:58:10Z","mono":7200000000000,"trusted":false,"boot":"<32 hex>"},
//	 "detail":{"from":"24.10.3","to":"24.10.4"}}
//
// Last is the Subject's boot when the origin last heard it before the event,
// Back the boot the Subject came back in (for a return), both as its
// heartbeats named them; Ref an entry of the Subject's own chain, normally
// its head as the origin held it when it recorded the event. Each is left
// out when unknown or not given, and a zero Subject (an event about no single
// member) names none of them. At is when the event happened on the origin's
// clocks (a clock.Stamp, wall clock in UTC), and Detail what a message needs
// beyond it (versions, a proof's entries); both are left out when not given,
// so every member builds the same event, and the same incident, from the
// entry. Since, only with At, is on a member's record of its own return
// (boot.go): the last moment it knows it was up before the absence, on the
// clocks of the boot it left (a zero boot and mono for a moment a peer
// gave), trusted only when exact; it is left out when unknown, and members
// read it only from an entry whose origin is its subject
// (events.Event.Since).
//
// An entry of history.KindBoot carries a BootBody: the boot record a member
// writes first in every boot.
//
//	{"boot":{"id":"<32 hex>","seq":8},"version":"24.10.4","planned":true}
//
// Version is the OpenWrt release (empty when unknown), Planned whether the
// boot before ended in an announced shutdown (the shutdown marker of design
// 4.6, written when the member told the others it was going down).
package node

import (
	"bytes"
	"cmp"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/clock"
	"github.com/TAIPANBOX/rollcall/internal/events"
	"github.com/TAIPANBOX/rollcall/internal/history"
	"github.com/TAIPANBOX/rollcall/internal/identity"
	"github.com/TAIPANBOX/rollcall/internal/ids"
)

const (
	// maxType is the longest event type, in bytes, as deliver renders them.
	maxType = 32
	// maxVersion is the longest version, in bytes: member.MaxVersionLen.
	maxVersion = 64
	// maxBody is the longest body DecodeEvent and DecodeBoot read. The
	// longest that NewEvent writes is 1141 bytes, NewBoot 169
	// (TestBodySizes).
	maxBody = 2 << 10
	// maxDetail is the most entries an event's Detail holds, maxDetailKey
	// the longest key; a value follows the rule of a version.
	maxDetail    = 6
	maxDetailKey = 16
)

var (
	// ErrInvalid reports an argument Reconcile cannot judge from.
	ErrInvalid = errors.New("node: invalid argument")
	// ErrOwnFork reports a log that holds a fork proof against the
	// reconciling member itself: its own chain is no witness then.
	ErrOwnFork = errors.New("node: the member's own chain has forked")
	// ErrNotFalsehood reports a Falsehood whose entries do not contradict
	// each other.
	ErrNotFalsehood = errors.New("node: not a proven falsehood")
)

// Boot names one boot of a member: the boot ID its kernel chose and the
// boot sequence number identity.NextBootSeq gave it. The zero Boot is
// unknown; any other has a non-zero ID and a Seq of at least 1.
type Boot struct {
	ID  ids.BootID `json:"id"`
	Seq uint64     `json:"seq"`
}

// known reports whether b names a boot.
func (b Boot) known() bool { return b != Boot{} }

// valid reports whether b is unknown or names a boot in full.
func (b Boot) valid() bool { return (b.ID == ids.BootID{}) == (b.Seq == 0) }

// EntryRef names one entry of a member's chain by its position and hash.
// The zero EntryRef names none; any other has a Seq of at least 1 and a
// non-zero Hash.
type EntryRef struct {
	Seq  uint64   `json:"seq"`
	Hash ids.Hash `json:"hash"`
}

// EventBody is the body of an entry of history.KindEvent; see the package
// doc. Type is 1 to 32 characters, a lowercase letter and then lowercase
// letters and '_' (every events.Type, and those of newer versions).
type EventBody struct {
	Subject ids.MemberID      `json:"subject"`         // the member the event is about; zero for none
	Type    events.Type       `json:"type"`            // what happened
	Last    Boot              `json:"last,omitzero"`   // the Subject's boot when last heard before the event
	Back    Boot              `json:"back,omitzero"`   // the boot the Subject came back in
	Ref     EntryRef          `json:"ref,omitzero"`    // an entry of the Subject's chain
	At      At                `json:"at,omitzero"`     // when, on the origin's clocks
	Since   At                `json:"since,omitzero"`  // on an own return: when the absence began
	Detail  map[string]string `json:"detail,omitzero"` // what a message needs beyond the event
}

// At is a clock.Stamp in the wire form of an event body. Wall is in UTC,
// from 1970 to 9999; Mono is nanoseconds since the origin's boot.
type At struct {
	Wall    time.Time  `json:"wall"`
	Mono    int64      `json:"mono"`
	Trusted bool       `json:"trusted"`
	Boot    ids.BootID `json:"boot"`
}

// AtOf returns s in the wire form of an event body.
func AtOf(s clock.Stamp) At {
	return At{Wall: s.Wall.UTC().Round(0), Mono: int64(s.Mono), Trusted: s.Trusted, Boot: s.Boot}
}

// Stamp returns a as a clock.Stamp.
func (a At) Stamp() clock.Stamp {
	return clock.Stamp{Wall: a.Wall, Mono: time.Duration(a.Mono), Trusted: a.Trusted, Boot: a.Boot}
}

// valid reports whether a is a stamp a body may carry: Wall in UTC within
// 1970..9999, Mono not negative.
func (a At) valid() bool {
	return !a.Wall.Before(minWall) && !a.Wall.After(maxWall) && a.Wall.Location() == time.UTC && a.Mono >= 0
}

var (
	minWall = time.Unix(0, 0).UTC()
	maxWall = time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.UTC)
)

// BootBody is the body of an entry of history.KindBoot; see the package doc.
// Boot is known; Version is empty or up to 64 characters from A-Z, a-z,
// 0-9 and ". - + _ ~", the rule of a heartbeat's versions.
type BootBody struct {
	Boot    Boot   `json:"boot"`
	Version string `json:"version"`
	Planned bool   `json:"planned"`
}

// check returns history.ErrBody unless b is a body NewEvent may sign. The
// error repeats at most 32 characters of the type.
func (b EventBody) check() error {
	none := b.Subject == ids.MemberID{}
	switch {
	case !validType(b.Type):
		return fmt.Errorf("%w: event type %.32q", history.ErrBody, b.Type)
	case !b.Last.valid() || !b.Back.valid():
		return fmt.Errorf("%w: a boot with only one of its ID and seq", history.ErrBody)
	case (b.Ref.Seq == 0) != (b.Ref.Hash == ids.Hash{}):
		return fmt.Errorf("%w: a reference with only one of its seq and hash", history.ErrBody)
	case none && (b.Last.known() || b.Back.known() || b.Ref != EntryRef{}):
		return fmt.Errorf("%w: boots or a reference of no member", history.ErrBody)
	case b.At != (At{}) && !b.At.valid():
		return fmt.Errorf("%w: a stamp outside 1970..9999 UTC or before its boot", history.ErrBody)
	case b.Since != (At{}) && (b.At == (At{}) || !b.Since.valid()):
		return fmt.Errorf("%w: a start without a stamp, or outside 1970..9999 UTC or before its boot", history.ErrBody)
	case b.Detail != nil && (len(b.Detail) == 0 || len(b.Detail) > maxDetail):
		return fmt.Errorf("%w: detail holds %d entries, 1 to %d", history.ErrBody, len(b.Detail), maxDetail)
	}
	for k, v := range b.Detail {
		if !validDetailKey(k) || !validVersion(v) {
			return fmt.Errorf("%w: a detail entry that is not a plain key and value", history.ErrBody)
		}
	}
	return nil
}

// validDetailKey reports whether k can be a key of an event's Detail: 1
// to maxDetailKey characters, lowercase letters and '_'.
func validDetailKey(k string) bool {
	if len(k) == 0 || len(k) > maxDetailKey {
		return false
	}
	for i := 0; i < len(k); i++ {
		if c := k[i]; !('a' <= c && c <= 'z' || c == '_') {
			return false
		}
	}
	return true
}

// check returns history.ErrBody unless b is a body NewBoot may sign.
func (b BootBody) check() error {
	if !b.Boot.known() || !b.Boot.valid() {
		return fmt.Errorf("%w: a boot record names no boot", history.ErrBody)
	}
	if !validVersion(b.Version) {
		return fmt.Errorf("%w: version is not a plain version of at most %d characters", history.ErrBody, maxVersion)
	}
	return nil
}

func validType(t events.Type) bool {
	if len(t) == 0 || len(t) > maxType || t[0] < 'a' || t[0] > 'z' {
		return false
	}
	for i := 0; i < len(t); i++ {
		if c := t[i]; !('a' <= c && c <= 'z' || c == '_') {
			return false
		}
	}
	return true
}

func validVersion(v string) bool {
	if len(v) > maxVersion {
		return false
	}
	for i := 0; i < len(v); i++ {
		switch c := v[i]; {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		case c == '.', c == '-', c == '+', c == '_', c == '~':
		default:
			return false
		}
	}
	return true
}

// NewEvent returns id's event entry with body b after prev, the head of
// id's own chain. It checks b first (history.ErrBody, nothing signed) and is
// then history.NewEntry, with its errors.
func NewEvent(id *identity.Identity, prev history.Head, b EventBody) (history.Entry, error) {
	if err := b.check(); err != nil {
		return history.Entry{}, err
	}
	return history.NewEntry(id, prev, history.KindEvent, b)
}

// NewBoot returns id's boot record b after prev, as NewEvent does for an
// event.
func NewBoot(id *identity.Identity, prev history.Head, b BootBody) (history.Entry, error) {
	if err := b.check(); err != nil {
		return history.Entry{}, err
	}
	return history.NewEntry(id, prev, history.KindBoot, b)
}

// DecodeEvent returns the body of the event entry e: history.ErrInvalid if
// e is of another kind, history.ErrBody unless the body is one NewEvent
// writes (at most maxBody bytes, decoded with DisallowUnknownFields,
// byte for byte what encoding/json writes for what it decoded, and within
// the rules). On error the body is zero. It does not verify e's signature.
func DecodeEvent(e history.Entry) (EventBody, error) {
	return decode[EventBody](e, history.KindEvent)
}

// DecodeBoot returns the body of the boot record e, as DecodeEvent does
// for an event.
func DecodeBoot(e history.Entry) (BootBody, error) {
	return decode[BootBody](e, history.KindBoot)
}

func decode[T interface{ check() error }](e history.Entry, kind history.Kind) (T, error) {
	var zero, b T
	if e.Kind != kind {
		return zero, fmt.Errorf("%w: a %.32q entry is not a %s entry", history.ErrInvalid, e.Kind, kind)
	}
	if len(e.Body) > maxBody {
		return zero, fmt.Errorf("%w: the body is %d bytes, at most %d", history.ErrBody, len(e.Body), maxBody)
	}
	d := json.NewDecoder(bytes.NewReader(e.Body))
	d.DisallowUnknownFields()
	if err := d.Decode(&b); err != nil {
		return zero, fmt.Errorf("%w: the %s body does not decode", history.ErrBody, kind)
	}
	again, err := json.Marshal(b)
	if err != nil || !bytes.Equal(again, e.Body) {
		return zero, fmt.Errorf("%w: the %s body is not in the one form encoding/json writes for it", history.ErrBody, kind)
	}
	if err := b.check(); err != nil {
		return zero, err
	}
	return b, nil
}

// Outcome is the verdict of a return on what the others recorded.
type Outcome int

// The outcomes, from the mildest. The zero Outcome is none of them.
const (
	Agree            Outcome = iota + 1 // nothing to add
	HonestDifference                    // the others saw it from another side; corrections are due
	ProvenFalsehood                     // a signed claim contradicts the member's signed chain
)

// String names the outcome.
func (o Outcome) String() string {
	switch o {
	case Agree:
		return "agree"
	case HonestDifference:
		return "honest difference"
	case ProvenFalsehood:
		return "proven falsehood"
	}
	return "unknown"
}

// Correction is what Reconcile appends for one absence of the member, as
// it places it: from boot From, which the others last heard, to boot To, in
// which it came back (the same boot for a link loss).
type Correction struct {
	// Class is what really happened, one of the history.Class constants
	// (never ClassMemberBack: the member knows more than that).
	Class string
	// Told is what the incident told before: of the absence types the
	// claims about this absence hold, the first in the order a message
	// tells them (Upgraded, RebootUnplanned, RebootPlanned, LinkLost,
	// MemberBack, MemberSilent; deliver.Render).
	Told events.Type
	// Update is true when Class is not Told: the meaning of the incident
	// changed and the caller sends one update message. When false, the
	// correction goes into the history and nothing to the chat.
	Update bool
	// From and To place the absence in the member's boots.
	From, To Boot
	// Entries are the signed corrections, history.NewCorrection with no
	// note, each of at most history.MaxRefs claims in (origin, seq) order,
	// chained after the head given to Reconcile in the order of
	// Result.Corrections, ready to append.
	Entries []history.Entry
}

// Falsehood is a proof against another member: Claim, its signed entry
// about the member, contradicts Own, an entry the member signed.
type Falsehood struct {
	Claim history.Entry
	Own   history.Entry
}

// Verify checks that f proves a falsehood, given the claimant's key and the
// key of the member the claim is about: both entries verify under their
// keys (Entry.Verify); Claim is an event entry (DecodeEvent) by another
// member than Own's origin, about Own's origin; and either Claim's Ref names
// Own's Seq with another hash, or Own is a boot record (DecodeBoot) whose
// seq Claim's Last or Back names with another boot ID. Anything else is
// ErrNotFalsehood.
//
// What it proves: the claimant signed a statement about the member that the
// member's own signed chain contradicts. A claimant that still holds an
// entry with the hash it named, signed by the member, can answer with it;
// the two entries of the member are then a fork proof against the member.
func (f Falsehood) Verify(claimant, subject ed25519.PublicKey) error {
	if err := f.Claim.Verify(claimant); err != nil {
		return fmt.Errorf("falsehood, the claim: %w", err)
	}
	if err := f.Own.Verify(subject); err != nil {
		return fmt.Errorf("falsehood, the contradicted entry: %w", err)
	}
	b, err := DecodeEvent(f.Claim)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrNotFalsehood, err)
	}
	if f.Claim.Origin == f.Own.Origin || b.Subject != f.Own.Origin {
		return fmt.Errorf("%w: the claim is not another member's statement about the origin of the entry", ErrNotFalsehood)
	}
	if b.Ref != (EntryRef{}) && b.Ref.Seq == f.Own.Seq && b.Ref.Hash != f.Own.Hash() {
		return nil
	}
	if r, err := DecodeBoot(f.Own); err == nil {
		for _, bt := range []Boot{b.Last, b.Back} {
			if bt.known() && bt.Seq == r.Boot.Seq && bt.ID != r.Boot.ID {
				return nil
			}
		}
	}
	return fmt.Errorf("%w: the claim does not contradict the entry", ErrNotFalsehood)
}

// Result is what Reconcile found.
type Result struct {
	Outcome     Outcome
	Corrections []Correction // ordered by From, then To
	Falsehoods  []Falsehood  // one per false claim, in (origin, seq) order
	Unchecked   []ids.Hash   // the claims it could neither confirm nor correct, in (origin, seq) order
}

// Reconcile checks what the others recorded about self against self's own
// chain, when self comes back after an absence (security spec 5.8). Self is
// the only member that knows the truth about itself for certain, and only
// about itself: Reconcile judges claims about self and no other member, and
// calls a claim a proven falsehood only when it contradicts an entry self
// signed, never for a mere difference in what was observed.
//
// # Inputs
//
// head is the head of self's chain in own, from which the corrections are
// chained; any other head is refused, since entries chained from it would
// fork self's chain. boot is the boot self runs now, its boot record as
// self wrote it (Task 18 knows it from the kernel and identity.NextBootSeq);
// it must equal a record of its seq in own, and no record in own may have a
// higher seq. Own must hold no fork proof against self (ErrOwnFork).
//
// A claim is an entry of claims that is of history.KindEvent, from another
// member than self, held by own (so Append verified its signature), whose
// body DecodeEvent accepts and names self as Subject, and that no
// correction in self's chain refers to yet (so a claim is corrected once,
// however often Reconcile runs). Every other entry is ignored, and a claim
// given twice counts once. A boot is known to self when it is boot, or when
// a boot record in self's chain names its seq and ID.
//
// # Verdicts
//
// Each claim gets one verdict, in this order.
//
//  1. Proven falsehood (Result.Falsehoods): its Ref names a Seq at which self's
//     chain holds an entry with another hash, or its Last or Back names a
//     boot seq for which self's chain holds boot records and none with that
//     boot ID. A Ref or a boot that self's chain holds nothing at (beyond its
//     head, pruned, lost with the RAM in a power cut) proves nothing.
//  2. For an absence (MemberSilent, MemberBack, LinkLost, RebootPlanned,
//     RebootUnplanned, Upgraded), what really happened from boot Last to the
//     boot self came back in, End. End is Back; for MemberSilent it is Back
//     of the same claimant's next absence claim about self among claims (the
//     return that ended the silence), unknown if that next one is another
//     silence, and boot if there is none (the absence is the one self comes
//     back from now). Then:
//     - Last is boot: LinkLost, whatever End; self has not rebooted since.
//     - Last unknown or not known to self; End unknown, not known to self,
//     or before Last; or Last and End two boot IDs at one seq: unchecked.
//     - End is Last: LinkLost.
//     - Otherwise self rebooted in between: events.Classify, Before the Last
//     boot with its version, announced when every boot of self after Last
//     up to End was Planned; Return the End boot with its version.
//  3. Anything else (the others' internet probes, WAN, uplink, alarms, types
//     of newer versions) is unchecked: self cannot see what others observed.
//
// # Corrections
//
// The claims placed from one Last to one End are one absence and one
// incident; Told is what its message told (see Correction). A claim of a
// cause (LinkLost, RebootPlanned, RebootUnplanned, Upgraded) other than what
// happened is corrected. A claim of no cause (MemberSilent, MemberBack) is
// corrected only when Told is not what happened; otherwise the incident
// already says it. Every absence with a corrected claim gives one Correction,
// and every claim is in at most one of its entries.
//
// The Outcome is ProvenFalsehood if any claim is one, else HonestDifference
// if there is any correction, else Agree. The honest claims are corrected
// also when others are false. On error the Result is zero; the error is
// ErrInvalid, ErrOwnFork, or one of history.NewCorrection's.
func Reconcile(self *identity.Identity, head history.Head, boot BootBody, own *history.Log, claims []history.Entry) (Result, error) {
	switch {
	case self == nil || own == nil:
		return Result{}, fmt.Errorf("%w: nil identity or log", ErrInvalid)
	case self.ID == ids.MemberID{}:
		return Result{}, fmt.Errorf("%w: the member ID is all zero", ErrInvalid)
	case len(self.Sign) != ed25519.PrivateKeySize:
		return Result{}, fmt.Errorf("%w: the signing key is %d bytes, want %d", ErrInvalid, len(self.Sign), ed25519.PrivateKeySize)
	}
	if err := boot.check(); err != nil {
		return Result{}, fmt.Errorf("%w: the current boot: %w", ErrInvalid, err)
	}
	for _, p := range own.Forks() {
		if p.A.Origin == self.ID {
			return Result{}, ErrOwnFork
		}
	}
	ch, err := readChain(self.ID, head, boot, own)
	if err != nil {
		return Result{}, err
	}

	all := ch.claimsAbout(claims, own)
	absences := map[[2]Boot]*absenceGroup{}
	var res Result
	for i, c := range all {
		if ch.corrected[c.hash] {
			continue // only the pairing of silences reads it
		}
		if f, found := ch.contradiction(c); found {
			res.Falsehoods = append(res.Falsehoods, f)
			continue
		}
		if !absence(c.body.Type) {
			res.Unchecked = append(res.Unchecked, c.hash)
			continue
		}
		from, to, placed := ch.place(c.body.Last, endOf(all, i, boot.Boot))
		if !placed {
			res.Unchecked = append(res.Unchecked, c.hash)
			continue
		}
		key := [2]Boot{from, to}
		g := absences[key]
		if g == nil {
			g = &absenceGroup{from: from, to: to, truth: ch.truth(from, to)}
			absences[key] = g
		}
		g.claims = append(g.claims, c)
	}

	groups := make([]*absenceGroup, 0, len(absences))
	for _, g := range absences {
		groups = append(groups, g)
	}
	slices.SortFunc(groups, func(a, b *absenceGroup) int {
		return cmp.Or(compareBoots(a.from, b.from), compareBoots(a.to, b.to))
	})
	prev := head
	for _, g := range groups {
		c, err := g.correct(self, &prev)
		if err != nil {
			return Result{}, err
		}
		if c != nil {
			res.Corrections = append(res.Corrections, *c)
		}
	}

	switch {
	case len(res.Falsehoods) > 0:
		res.Outcome = ProvenFalsehood
	case len(res.Corrections) > 0:
		res.Outcome = HonestDifference
	default:
		res.Outcome = Agree
	}
	return res, nil
}

// claim is one claim about self, with its hash and decoded body.
type claim struct {
	e    history.Entry // own's copy
	hash ids.Hash
	body EventBody
}

// ownChain is what self's chain in own says, read once.
type ownChain struct {
	self      ids.MemberID
	cur       BootBody                 // the boot self runs now
	entries   map[uint64]history.Entry // self's entries own holds, by Seq
	boots     []bootEntry              // self's boot records, in chain order
	corrected map[ids.Hash]bool        // every entry a correction of self's refers to
}

type bootEntry struct {
	e    history.Entry
	body BootBody
}

// readChain reads self's chain from own and checks that head is its head
// and boot agrees with its boot records.
func readChain(self ids.MemberID, head history.Head, boot BootBody, own *history.Log) (*ownChain, error) {
	mine := own.Range(self, 0, math.MaxUint64)
	var held history.Head // Prune keeps the head, so an empty range is an empty chain
	if n := len(mine); n > 0 {
		held = history.Head{Seq: mine[n-1].Seq, Hash: mine[n-1].Hash()}
	}
	if held != head {
		return nil, fmt.Errorf("%w: head seq %d is not the head of the member's own chain, seq %d", ErrInvalid, head.Seq, held.Seq)
	}
	ch := &ownChain{self: self, cur: boot, entries: make(map[uint64]history.Entry, len(mine)), corrected: map[ids.Hash]bool{}}
	for _, e := range mine {
		ch.entries[e.Seq] = e
		switch e.Kind {
		case history.KindBoot:
			b, err := DecodeBoot(e)
			if err != nil {
				continue
			}
			switch {
			case b.Boot.Seq > boot.Boot.Seq:
				return nil, fmt.Errorf("%w: the current boot seq %d is below boot seq %d recorded at seq %d", ErrInvalid, boot.Boot.Seq, b.Boot.Seq, e.Seq)
			case b.Boot.Seq == boot.Boot.Seq && b != boot:
				return nil, fmt.Errorf("%w: the current boot differs from its record at seq %d", ErrInvalid, e.Seq)
			}
			ch.boots = append(ch.boots, bootEntry{e: e, body: b})
		case history.KindCorrection:
			if b, err := history.DecodeCorrection(e); err == nil {
				for _, r := range b.Refs {
					ch.corrected[r] = true
				}
			}
		}
	}
	return ch, nil
}

// claimsAbout returns the claims about self among es, each once, in
// (origin, seq) order; see Reconcile.
func (ch *ownChain) claimsAbout(es []history.Entry, own *history.Log) []claim {
	seen := map[ids.Hash]bool{}
	var out []claim
	for _, e := range es {
		if e.Kind != history.KindEvent || e.Origin == ch.self {
			continue
		}
		h := e.Hash()
		if seen[h] {
			continue
		}
		held := own.Range(e.Origin, e.Seq, e.Seq)
		if len(held) != 1 || held[0].Hash() != h {
			continue // not verified by own
		}
		b, err := DecodeEvent(held[0])
		if err != nil || b.Subject != ch.self {
			continue
		}
		seen[h] = true
		out = append(out, claim{e: held[0], hash: h, body: b})
	}
	slices.SortFunc(out, func(a, b claim) int {
		return cmp.Or(bytes.Compare(a.e.Origin[:], b.e.Origin[:]), cmp.Compare(a.e.Seq, b.e.Seq))
	})
	return out
}

// contradiction returns the proof that c contradicts self's signed chain,
// if it does.
func (ch *ownChain) contradiction(c claim) (Falsehood, bool) {
	b := c.body
	if b.Ref != (EntryRef{}) {
		if e, held := ch.entries[b.Ref.Seq]; held && e.Hash() != b.Ref.Hash {
			return Falsehood{Claim: c.e, Own: e}, true
		}
	}
	for _, bt := range []Boot{b.Last, b.Back} {
		if !bt.known() {
			continue
		}
		var against *bootEntry
		for i, r := range ch.boots {
			if r.body.Boot.Seq != bt.Seq {
				continue
			}
			if r.body.Boot.ID == bt.ID {
				against = nil
				break
			}
			if against == nil {
				against = &ch.boots[i]
			}
		}
		if against != nil {
			return Falsehood{Claim: c.e, Own: against.e}, true
		}
	}
	return Falsehood{}, false
}

// endOf returns the boot the claim all[i] says self came back in: Back,
// or for a silence the Back of the same claimant's next absence claim (all
// is in (origin, seq) order), unknown if that is another silence, and cur
// if there is none.
func endOf(all []claim, i int, cur Boot) Boot {
	c := all[i]
	if c.body.Type != events.MemberSilent {
		return c.body.Back
	}
	for _, next := range all[i+1:] {
		if next.e.Origin != c.e.Origin {
			break
		}
		if !absence(next.body.Type) {
			continue
		}
		if next.body.Type == events.MemberSilent {
			return Boot{}
		}
		return next.body.Back
	}
	return cur
}

// record returns what self recorded of boot b: the current boot, or a boot
// record of its chain; false if b is neither, which is a boot not known to
// self.
func (ch *ownChain) record(b Boot) (BootBody, bool) {
	if b == ch.cur.Boot {
		return ch.cur, true
	}
	for _, r := range ch.boots {
		if r.body.Boot == b {
			return r.body, true
		}
	}
	return BootBody{}, false
}

// place returns the absence from last to end as self can place it in its
// boots; see Reconcile.
func (ch *ownChain) place(last, end Boot) (from, to Boot, ok bool) {
	_, lastKnown := ch.record(last)
	_, endKnown := ch.record(end)
	switch {
	case !lastKnown:
		return Boot{}, Boot{}, false
	case last == ch.cur.Boot:
		return last, last, true
	case !endKnown || end.Seq < last.Seq || (end.Seq == last.Seq && end != last):
		return Boot{}, Boot{}, false
	}
	return last, end, true
}

// truth returns what happened between two boots place returned, so both
// are known to self.
func (ch *ownChain) truth(from, to Boot) events.Type {
	if from == to {
		return events.LinkLost
	}
	announced := true
	for _, r := range ch.boots {
		if r.body.Boot.Seq > from.Seq && r.body.Boot.Seq <= to.Seq {
			announced = announced && r.body.Planned
		}
	}
	if ch.cur.Boot.Seq > from.Seq && ch.cur.Boot.Seq <= to.Seq {
		announced = announced && ch.cur.Planned
	}
	before, _ := ch.record(from)
	after, _ := ch.record(to)
	return events.Classify(
		events.Before{AnnouncedGoingDown: announced, BootID: from.ID, Version: before.Version},
		events.Return{BootID: to.ID, Version: after.Version},
	)
}

// absenceGroup is the claims about one absence.
type absenceGroup struct {
	from, to Boot
	truth    events.Type
	claims   []claim // in (origin, seq) order
}

// correct returns the correction of the group's claims, chained after
// *prev, which it moves past its entries; nil if nothing is to correct.
func (g *absenceGroup) correct(self *identity.Identity, prev *history.Head) (*Correction, error) {
	types := make([]events.Type, len(g.claims))
	for i, c := range g.claims {
		types[i] = c.body.Type
	}
	c := &Correction{Class: string(g.truth), Told: told(types), From: g.from, To: g.to}
	c.Update = events.Type(c.Class) != c.Told
	var refs []ids.Hash
	for _, cl := range g.claims {
		t := cl.body.Type
		if t == g.truth || (causeless(t) && !c.Update) {
			continue
		}
		refs = append(refs, cl.hash)
	}
	if len(refs) == 0 {
		return nil, nil
	}
	for chunk := range slices.Chunk(refs, history.MaxRefs) {
		e, err := history.NewCorrection(self, *prev, chunk, c.Class, "")
		if err != nil {
			return nil, err
		}
		c.Entries = append(c.Entries, e)
		*prev = history.Head{Seq: e.Seq, Hash: e.Hash()}
	}
	return c, nil
}

// toldOrder is the order in which a message tells an absence: the first of
// these an incident holds is what it says happened (deliver.Render;
// TestToldMatchesRender holds the two together).
var toldOrder = []events.Type{events.Upgraded, events.RebootUnplanned, events.RebootPlanned, events.LinkLost, events.MemberBack, events.MemberSilent}

// absence reports whether t is the absence or the return of a member.
func absence(t events.Type) bool { return slices.Contains(toldOrder, t) }

// causeless reports whether t says nothing about why a member was absent.
func causeless(t events.Type) bool { return t == events.MemberSilent || t == events.MemberBack }

// told returns the absence a message about types tells, "" for none.
func told(types []events.Type) events.Type {
	for _, t := range toldOrder {
		if slices.Contains(types, t) {
			return t
		}
	}
	return ""
}

func compareBoots(a, b Boot) int {
	return cmp.Or(cmp.Compare(a.Seq, b.Seq), bytes.Compare(a.ID[:], b.ID[:]))
}
