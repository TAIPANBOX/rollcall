package history

import (
	"bytes"
	"cmp"
	"encoding/json"
	"fmt"
	"slices"
	"unicode"
	"unicode/utf8"

	"github.com/TAIPANBOX/rollcall/internal/identity"
	"github.com/TAIPANBOX/rollcall/internal/ids"
)

// Witness statements and corrections (security spec 5.7 and 5.8).
//
// A member that saw another member's event appends an entry of KindWitness
// to its own chain whose body is a WitnessBody: "seen the same" (Agree) or
// "seen differently" (not Agree) about the event whose Hash is Ref. A member
// that comes back after an absence, and finds that the others recorded it
// differently from what its own chain shows, appends an entry of
// KindCorrection whose body is a CorrectionBody: the entries it corrects, by
// hash, and what really happened (Class). Neither changes the entries it
// refers to; they stay in their chains byte for byte, and a reader finds the
// statements about an entry with Confirmations and Corrections.
//
// The Log stores these bodies as it stores any body: it checks their form
// (see the package doc), not their meaning, so a malformed statement is
// appended and kept like any validly signed entry. DecodeWitness and
// DecodeCorrection check the meaning, and Confirmations and Corrections skip
// every entry they refuse.
//
// Wire form. A statement body is exactly the JSON encoding/json writes for
// the struct, fields in this order and no others:
//
//	{"ref":"<64 lowercase hex digits>","agree":true,"note":"..."}
//	{"refs":["<64 lowercase hex digits>",...],"class":"link_lost","note":"..."}
//
// The decoders accept a body only if encoding what they decoded gives the
// same bytes again, so every statement has one form: no unknown, missing,
// repeated or reordered fields, no capital hex digits, no escape the encoder
// would not write. Together with DisallowUnknownFields and the size limit
// this keeps the decoders from accepting anything NewWitness and
// NewCorrection would not write.

// The limits of a statement.
const (
	// MaxNote is the longest Note of a witness statement or a correction,
	// in bytes.
	MaxNote = 200
	// MaxRefs is the largest number of entries one correction refers to.
	MaxRefs = 16
)

// maxStatementBody is the longest body DecodeWitness and DecodeCorrection
// read. The longest body NewCorrection writes is 2319 bytes (MaxRefs refs,
// the longest class, and a note of MaxNote bytes that the encoder escapes to
// six bytes each); TestStatementSizes measures it.
const maxStatementBody = 4 << 10

// The classes of a correction: what the correcting member's own chain shows
// really happened while the others could not hear it. They are the outcomes
// of the classification on return (design 4.3) plus ClassMemberBack, spelled
// as the matching event types, and they are a closed set: a correction with
// any other class is refused.
const (
	ClassLinkLost        = "link_lost"        // it stayed up; the path to it broke
	ClassMemberBack      = "member_back"      // it is back; nothing more is claimed about the absence
	ClassRebootPlanned   = "reboot_planned"   // it rebooted after announcing it
	ClassRebootUnplanned = "reboot_unplanned" // it rebooted unannounced: a crash or a power cut
	ClassUpgraded        = "upgraded"         // it came back with a new firmware version
)

// knownClass reports whether c is one of the correction classes.
func knownClass(c string) bool {
	switch c {
	case ClassLinkLost, ClassMemberBack, ClassRebootPlanned, ClassRebootUnplanned, ClassUpgraded:
		return true
	}
	return false
}

// WitnessBody is the body of an entry of KindWitness: its origin's
// statement about another member's event. Ref is never all zero; Note is at
// most MaxNote bytes of printable UTF-8 (unicode.IsPrint: letters, marks,
// numbers, punctuation, symbols and the ASCII space; no control, format,
// private-use or unassigned characters, so no line breaks and no
// bidirectional overrides reach a message).
type WitnessBody struct {
	Ref   ids.Hash `json:"ref"`   // Hash of the event entry
	Agree bool     `json:"agree"` // true: seen the same; false: seen differently
	Note  string   `json:"note"`  // what the witness saw, for the message; may be empty
}

// CorrectionBody is the body of an entry of KindCorrection: its origin's
// correction of earlier entries, its own or other members'. Refs holds 1 to
// MaxRefs hashes, none all zero and none twice; Class is one of the
// correction classes; Note follows the rule of WitnessBody.
type CorrectionBody struct {
	Refs  []ids.Hash `json:"refs"`  // Hash of every entry corrected
	Class string     `json:"class"` // what really happened, one of the Class constants
	Note  string     `json:"note"`  // for the message; may be empty
}

// check returns ErrBody unless b is a witness body NewWitness may sign.
func (b WitnessBody) check() error {
	if b.Ref == (ids.Hash{}) {
		return fmt.Errorf("%w: the witness statement names no entry", ErrBody)
	}
	return checkNote(b.Note)
}

// check returns ErrBody unless b is a correction body NewCorrection may
// sign. The error never repeats more than 32 characters of the class.
func (b CorrectionBody) check() error {
	switch {
	case len(b.Refs) == 0:
		return fmt.Errorf("%w: the correction refers to no entry", ErrBody)
	case len(b.Refs) > MaxRefs:
		return fmt.Errorf("%w: the correction refers to %d entries, at most %d", ErrBody, len(b.Refs), MaxRefs)
	case !knownClass(b.Class):
		return fmt.Errorf("%w: unknown correction class %.32q", ErrBody, b.Class)
	}
	for i, r := range b.Refs {
		if r == (ids.Hash{}) {
			return fmt.Errorf("%w: ref %d of the correction is all zero", ErrBody, i)
		}
		if slices.Contains(b.Refs[:i], r) {
			return fmt.Errorf("%w: ref %d of the correction repeats an earlier one", ErrBody, i)
		}
	}
	return checkNote(b.Note)
}

// checkNote returns ErrBody unless note is at most MaxNote bytes of valid
// UTF-8 whose every character unicode.IsPrint accepts. The error never
// repeats the note.
func checkNote(note string) error {
	if len(note) > MaxNote {
		return fmt.Errorf("%w: the note is %d bytes, at most %d", ErrBody, len(note), MaxNote)
	}
	if !utf8.ValidString(note) {
		return fmt.Errorf("%w: the note is not valid UTF-8", ErrBody)
	}
	for i, r := range note {
		if !unicode.IsPrint(r) {
			return fmt.Errorf("%w: the note holds U+%04X at byte %d, which is not printable", ErrBody, r, i)
		}
	}
	return nil
}

// NewWitness returns id's witness statement after prev, the head of id's own
// chain: "seen the same" (agree) or "seen differently" (not agree) about the
// entry whose Hash is ref, with an optional note. It checks the body before
// it signs, ErrBody for an all-zero ref or a note WitnessBody does not
// allow, and is then NewEntry with KindWitness, with its errors.
func NewWitness(id *identity.Identity, prev Head, ref ids.Hash, agree bool, note string) (Entry, error) {
	b := WitnessBody{Ref: ref, Agree: agree, Note: note}
	if err := b.check(); err != nil {
		return Entry{}, err
	}
	return NewEntry(id, prev, KindWitness, b)
}

// NewCorrection returns id's correction after prev, the head of id's own
// chain, of the entries whose hashes are refs: class is what really
// happened, note optional. It checks the body before it signs, ErrBody for
// refs, a class or a note CorrectionBody does not allow, and is then
// NewEntry with KindCorrection, with its errors. The entries it corrects
// are not touched; it only names them.
func NewCorrection(id *identity.Identity, prev Head, refs []ids.Hash, class, note string) (Entry, error) {
	b := CorrectionBody{Refs: refs, Class: class, Note: note}
	if err := b.check(); err != nil {
		return Entry{}, err
	}
	return NewEntry(id, prev, KindCorrection, b)
}

// DecodeWitness returns the body of the witness statement e. It returns
// ErrInvalid if e is not of KindWitness, and ErrBody unless the body is one
// NewWitness writes: at most maxStatementBody bytes, decoded with
// DisallowUnknownFields, in the one wire form, and within the limits of
// WitnessBody. It does not verify e's signature; the Log did on Append.
func DecodeWitness(e Entry) (WitnessBody, error) {
	if e.Kind != KindWitness {
		return WitnessBody{}, fmt.Errorf("%w: a %.32q entry is not a witness statement", ErrInvalid, e.Kind)
	}
	var b WitnessBody
	if err := decodeStatement(e.Body, &b); err != nil {
		return WitnessBody{}, err
	}
	if err := b.check(); err != nil {
		return WitnessBody{}, err
	}
	return b, nil
}

// DecodeCorrection returns the body of the correction e, as DecodeWitness
// does for a witness statement: ErrInvalid if e is not of KindCorrection,
// ErrBody unless the body is one NewCorrection writes.
func DecodeCorrection(e Entry) (CorrectionBody, error) {
	if e.Kind != KindCorrection {
		return CorrectionBody{}, fmt.Errorf("%w: a %.32q entry is not a correction", ErrInvalid, e.Kind)
	}
	var b CorrectionBody
	if err := decodeStatement(e.Body, &b); err != nil {
		return CorrectionBody{}, err
	}
	if err := b.check(); err != nil {
		return CorrectionBody{}, err
	}
	return b, nil
}

// decodeStatement decodes body into v, a pointer to a statement body, and
// returns ErrBody unless body is at most maxStatementBody bytes, has no field
// v lacks, and is exactly what encoding/json writes for what it decoded to.
// The error never repeats the body.
func decodeStatement(body []byte, v any) error {
	if len(body) > maxStatementBody {
		return fmt.Errorf("%w: the statement is %d bytes, at most %d", ErrBody, len(body), maxStatementBody)
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return fmt.Errorf("%w: the statement does not decode", ErrBody)
	}
	again, err := json.Marshal(v)
	if err != nil || !bytes.Equal(again, body) {
		return fmt.Errorf("%w: the statement is not in the one form encoding/json writes for it", ErrBody)
	}
	return nil
}

// Confirmations returns who confirmed and who contradicted the event whose
// Hash is ref, as far as l holds their statements: the origins whose latest
// statement about it says "seen the same" (agree) and those whose latest
// says "seen differently" (disagree), each in ascending order of the
// MemberID bytes, nil when empty. A message shows len(agree) of
// len(agree)+len(disagree), "confirmed by 3 of 4"; how many members could
// have witnessed is for the caller to know.
//
// It computes on each call from the log as it is then:
//
//   - Only an event counts. If l holds no entry of KindEvent whose Hash is
//     ref (it has not arrived yet, it was pruned, or ref names an entry of
//     another kind), both lists are nil. Statements about an event that has
//     not arrived are kept like any entry and count once it arrives.
//   - The event's own origin does not witness its own event: its statements
//     about it are ignored.
//   - A forked origin, one Log.Forks holds a proof against, is not counted,
//     whatever its statements say. A fork of the event's own origin does
//     not hide the others' statements; they name the hash of the entry l
//     holds.
//   - Every other origin counts once, by its latest statement about ref (the
//     highest Seq); its statements about other entries do not matter.
//   - A statement DecodeWitness refuses is skipped as if it were not there,
//     and the count goes on.
func Confirmations(l *Log, ref ids.Hash) (agree, disagree []ids.MemberID) {
	event, held, statements, forked := l.snapshot(ref, KindWitness)
	if !held || event.Kind != KindEvent {
		return nil, nil
	}
	latest := map[ids.MemberID]bool{} // origin: Agree of its latest statement about ref
	for _, s := range statements {    // each origin's in ascending Seq
		if s.Origin == event.Origin || forked[s.Origin] {
			continue
		}
		b, err := DecodeWitness(s)
		if err != nil || b.Ref != ref {
			continue
		}
		latest[s.Origin] = b.Agree
	}
	for o, a := range latest {
		if a {
			agree = append(agree, o)
		} else {
			disagree = append(disagree, o)
		}
	}
	slices.SortFunc(agree, compareIDs)
	slices.SortFunc(disagree, compareIDs)
	return agree, disagree
}

// Corrections returns copies of the corrections l holds that refer to the
// entry whose Hash is ref, in ascending order of the origin's MemberID bytes
// and then of Seq, nil if there are none. A correction is returned whether
// or not l still holds the entry it refers to. As in Confirmations, a
// correction from a forked origin is left out, and so is one
// DecodeCorrection refuses; the lookup goes on past both. The entry ref
// names is never changed: a correction is a new entry in its author's
// chain, and the reader applies it.
func Corrections(l *Log, ref ids.Hash) []Entry {
	_, _, corrections, forked := l.snapshot(ref, KindCorrection)
	var out []Entry
	for _, c := range corrections {
		if forked[c.Origin] {
			continue
		}
		b, err := DecodeCorrection(c)
		if err != nil || !slices.Contains(b.Refs, ref) {
			continue
		}
		out = append(out, c.clone())
	}
	slices.SortFunc(out, func(a, b Entry) int {
		if c := compareIDs(a.Origin, b.Origin); c != 0 {
			return c
		}
		return cmp.Compare(a.Seq, b.Seq)
	})
	return out
}

// compareIDs orders member IDs by their bytes.
func compareIDs(a, b ids.MemberID) int { return bytes.Compare(a[:], b[:]) }

// snapshot returns, from one state of l taken under its lock: the entry l
// holds whose Hash is ref, if it holds one; every entry of kind k that l
// holds, each origin's together and in ascending Seq, the origins in no
// particular order; and the set of origins with a fork. The entries share
// Body and Sig with the log, which never writes to them; the caller must not
// write to them either, and hands out clones.
func (l *Log) snapshot(ref ids.Hash, k Kind) (target Entry, held bool, of []Entry, forked map[ids.MemberID]bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, c := range l.chains {
		for _, s := range c.entries {
			if s.hash == ref {
				target, held = s.e, true
			}
			if s.e.Kind == k {
				of = append(of, s.e)
			}
		}
	}
	forked = make(map[ids.MemberID]bool, len(l.forks))
	for o := range l.forks {
		forked[o] = true
	}
	return target, held, of, forked
}
