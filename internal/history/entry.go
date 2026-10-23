// Package history keeps the history of a rollcall group as one signed hash
// chain per router (security spec 5.7). Every router records its own events,
// witness statements, corrections and boot records in its own chain, and the
// other routers keep copies. No router can make an entry in another router's
// chain; deleting, changing or inserting an entry afterwards breaks the chain
// visibly; and two different signed entries with the same origin and
// sequence number prove that the origin showed different histories to
// different peers (a fork).
//
// # Entry
//
// An Entry is one record in the chain of its Origin. Seq is its position,
// from 1, and Prev the Hash of the entry at Seq-1; the first entry, and only
// the first, has an all-zero Prev. Kind says what it records: KindEvent,
// KindWitness, KindCorrection or KindBoot, or KindCheckpoint and
// KindObjection, which are reserved for v1.1 and in v1 are accepted and
// stored as opaque entries. Any other kind is refused.
//
// Body is JSON this package checks but does not interpret: at most
// MaxBodySize bytes, valid UTF-8, one JSON value, in exactly the form
// encoding/json emits for a json.RawMessage (compact, with <, >, & and
// U+2028, U+2029 escaped as \u003c, \u003e, \u0026, \u2028, \u2029). That
// form passes through an encoding/json round trip unchanged, byte for byte,
// so an entry relayed as JSON keeps its hash and its signature. A body in any
// other form would be rewritten on the way and break; it is refused before it
// can be stored.
//
// # Signature
//
// Sig is sig.Sign(key, "entry", m), so Ed25519 over
// "rollcall/v1/entry\x00" || m, with
//
//	m = Origin (16) || Seq (8, big endian) || Prev (32) ||
//	    len(Kind) (8, big endian) || Kind || len(Body) (8, big endian) || Body
//
// Every variable field carries its length, so m has one reading. The key is
// the origin's own signing key, so no router can make an entry that verifies
// as another router's.
//
// # Hash
//
// Entry.Hash is SHA-256 over
//
//	"rollcall/v1 entry-hash\x00" || m || len(Sig) (8, big endian) || Sig
//
// The next entry carries it in Prev. It covers the signature, so two
// different signatures over the same content are two different entries.
// That is still proof against the origin: Go's ed25519.Verify refuses a
// non-canonical S (S + L, the same scalar, does not verify; the tests check
// this) and sig refuses small-order keys, so only the holder of the origin's
// key can make a second valid signature.
//
// # Chain
//
// Log.Append takes the key of an entry's origin from the resolver the Log was
// made with (NewLog), keyOf(e.Origin), never from its caller or from the
// peer that relayed the entry; an origin the resolver does not know is
// refused with ErrUnknownOrigin. It then checks the entry cheapest first and
// the chain last: the key (sig.ValidPublicKey, ErrKey), the shape (a non-zero Origin and a Seq of at
// least 1, ErrFormat; the Seq and Prev rule above, ErrPrev; a known Kind,
// ErrKind; a 64-byte Sig, ErrSignature; the body rules, ErrBody), the
// signature (ErrSignature), and only then the origin's chain as the log holds
// it:
//
//   - Seq one past the head and Prev the head's Hash: the entry is appended
//     and is the new head. The first entry of an origin has Seq 1, unless
//     Log.StartAt set another base for the chain (see Pruning).
//   - Seq more than one past the head: ErrGap; the entries between are
//     missing and must be appended first. That holds for an empty chain
//     too: Append alone never starts a chain past Seq 1.
//   - Seq one past the head with another Prev: ErrPrev. If the entry is
//     validly signed, its origin signed another entry at Seq-1 than the one
//     held; fetching that entry and appending it shows the fork.
//   - Seq of an entry held, with the same Hash: a duplicate. Append returns
//     nil and nothing changes.
//   - Seq of an entry held, with another Hash: a fork. Append returns a
//     *ForkError, which matches ErrFork, carrying ForkProof{A, B}: A the
//     entry held, B the new one, both validly signed by the origin. The log
//     keeps the proof (Log.Forks) and the entry it held. From then on the
//     origin is untrusted: every later Append for it fails with ErrFork and
//     that first proof, and the log keeps no further proofs for it.
//   - Seq at or below what Prune dropped: ErrPruned. The log can no longer
//     compare it with what it held.
//
// Nothing changes an entry once it is held: Append stores copies, every
// method returns copies, a correction is a new entry of KindCorrection, and
// a second entry at a held position never replaces the first. Prune drops
// old entries and changes none.
//
// # Digest
//
// Log.Digest is SHA-256 over "rollcall/v1 history-digest\x00" followed, for
// every origin the log holds, in ascending order of the MemberID bytes, by
//
//	Origin (16) || head Seq (8, big endian) || head Hash (32)
//
// where an origin that forked contributes Seq 2^64-1 and an all-zero Hash
// instead of its head. Two peers that hold different branches of a forked
// chain thus agree once both know of the fork, instead of comparing heads
// with each other forever. The digest of an empty log is SHA-256 of the
// label alone, 0eb4708dfb7a41e89bd4b9524666b03f10e45294faa6755ca4a7b2834722590b.
//
// # Pruning
//
// The log is bounded per origin, twice: Append keeps every origin at most at
// the maxPerOrigin given to NewLog, at once, and Log.Prune applies the age
// limit and any tighter count. Both keep each origin's head, so every chain
// stays verifiable from it, and drop the oldest entries beyond the limits.
// For each origin they record the Seq and Hash of the last entry dropped
// (Log.Pruned): the oldest entry kept has that Hash as its Prev, Range
// reports the dropped entries as not available by leaving them out, and
// Append refuses an entry at or below that Seq with ErrPruned.
//
// A log that holds nothing of an origin takes a pruned chain the same way:
// Log.StartAt sets the base, the Seq and Hash just before the oldest entry
// at hand (the Pruned of the log it comes from, or the Prev of the oldest
// entry read back from a file), and Append takes the entries after it. So a
// chain longer than the bounds survives a restart and reaches a new member.
//
// A Log is safe for concurrent use. Make one with NewLog; a zero Log knows no
// origin and refuses every entry.
package history

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"unicode/utf8"

	"github.com/TAIPANBOX/rollcall/internal/identity"
	"github.com/TAIPANBOX/rollcall/internal/ids"
	"github.com/TAIPANBOX/rollcall/internal/sig"
)

// Kind says what an entry records.
type Kind string

// The kinds of entry. Checkpoints and objections are reserved for v1.1; v1
// accepts and stores them as opaque entries.
const (
	KindEvent      Kind = "event"      // an event the origin observed
	KindWitness    Kind = "witness"    // the origin's statement about another member's event
	KindCorrection Kind = "correction" // a correction of earlier entries, which stay as they are
	KindBoot       Kind = "boot"       // the origin's boot record
	KindCheckpoint Kind = "checkpoint" // reserved for v1.1
	KindObjection  Kind = "objection"  // reserved for v1.1
)

// MaxBodySize is the largest Body of an entry, in bytes.
const MaxBodySize = 8 << 10

const (
	sigKind   = "entry"                      // sig.Sign kind of every entry signature
	hashLabel = "rollcall/v1 entry-hash\x00" // starts the bytes Entry.Hash covers
)

var (
	// ErrKey reports a public key that sig.ValidPublicKey refuses; the error
	// also wraps the sig package's reason.
	ErrKey = errors.New("history: the public key cannot verify entries")
	// ErrFormat reports an entry with an all-zero Origin or a Seq of 0.
	ErrFormat = errors.New("history: malformed entry")
	// ErrKind reports an entry of an unknown kind.
	ErrKind = errors.New("history: unknown entry kind")
	// ErrBody reports a body that is too long, is not valid UTF-8 or JSON,
	// or is not in the form encoding/json emits.
	ErrBody = errors.New("history: invalid entry body")
	// ErrSignature reports a signature that is not 64 bytes long or does
	// not verify under the key given.
	ErrSignature = errors.New("history: the entry's signature does not verify under the key given")
	// ErrPrev reports an entry whose Prev does not match its chain: a first
	// entry with a Prev, a later one without, or a Prev other than the
	// head's Hash.
	ErrPrev = errors.New("history: the entry's previous hash does not match its chain")
	// ErrInvalid reports an argument NewEntry or Log.StartAt cannot use.
	ErrInvalid = errors.New("history: invalid argument")
)

// Entry is one signed record in the chain of its Origin.
type Entry struct {
	Origin ids.MemberID    `json:"origin"` // the member whose chain it is in, and who signed it
	Seq    uint64          `json:"seq"`    // its position in that chain, from 1
	Prev   ids.Hash        `json:"prev"`   // Hash of the entry at Seq-1; all zero for Seq 1
	Kind   Kind            `json:"kind"`
	Body   json.RawMessage `json:"body"` // JSON, in encoding/json's compact form
	Sig    []byte          `json:"sig"`  // Ed25519 by the origin's key, see the package doc
}

// known reports whether k is one of the kinds of entry.
func known(k Kind) bool {
	switch k {
	case KindEvent, KindWitness, KindCorrection, KindBoot, KindCheckpoint, KindObjection:
		return true
	}
	return false
}

// message returns m, the bytes the signature covers (see the package doc).
func (e Entry) message() []byte {
	b := make([]byte, 0, len(e.Origin)+8+len(e.Prev)+8+len(e.Kind)+8+len(e.Body))
	b = append(b, e.Origin[:]...)
	b = binary.BigEndian.AppendUint64(b, e.Seq)
	b = append(b, e.Prev[:]...)
	b = binary.BigEndian.AppendUint64(b, uint64(len(e.Kind)))
	b = append(b, e.Kind...)
	b = binary.BigEndian.AppendUint64(b, uint64(len(e.Body)))
	return append(b, e.Body...)
}

// Hash returns SHA-256 over the hash label, the signed bytes and the
// signature (see the package doc). It does not check the entry.
func (e Entry) Hash() ids.Hash {
	h := sha256.New()
	h.Write([]byte(hashLabel))
	h.Write(e.message())
	h.Write(binary.BigEndian.AppendUint64(nil, uint64(len(e.Sig))))
	h.Write(e.Sig)
	var out ids.Hash
	h.Sum(out[:0])
	return out
}

// Verify checks e on its own, cheapest first: the key, the shape, the kind,
// the length of the signature, the body, and the signature under pub. It
// does not check e against a chain; Log.Append does. The error matches one
// of ErrKey (with sig.ErrKeyLength or sig.ErrSmallOrderKey), ErrFormat,
// ErrPrev, ErrKind, ErrBody or ErrSignature.
func (e Entry) Verify(pub ed25519.PublicKey) error {
	if err := sig.ValidPublicKey(pub); err != nil {
		return fmt.Errorf("%w: %w", ErrKey, err)
	}
	switch {
	case e.Origin == ids.MemberID{}:
		return fmt.Errorf("%w: the origin is all zero", ErrFormat)
	case e.Seq == 0:
		return fmt.Errorf("%w: seq 0; a chain starts at 1", ErrFormat)
	case (e.Seq == 1) != (e.Prev == ids.Hash{}):
		return fmt.Errorf("%w: seq %d with prev %s; the first entry, and only the first, has an all-zero prev", ErrPrev, e.Seq, e.Prev)
	case !known(e.Kind):
		return fmt.Errorf("%w: %.32q", ErrKind, e.Kind) // at most 32 runes of a peer's string
	case len(e.Sig) != ed25519.SignatureSize:
		return fmt.Errorf("%w: the signature is %d bytes, want %d", ErrSignature, len(e.Sig), ed25519.SignatureSize)
	}
	if err := checkBody(e.Body); err != nil {
		return err
	}
	if !sig.Verify(pub, sigKind, e.message(), e.Sig) {
		return fmt.Errorf("%w: origin %s seq %d", ErrSignature, e.Origin, e.Seq)
	}
	return nil
}

// checkBody returns ErrBody unless b is a body the package doc allows. The
// error never repeats the body.
func checkBody(b []byte) error {
	if len(b) > MaxBodySize {
		return fmt.Errorf("%w: %d bytes, at most %d", ErrBody, len(b), MaxBodySize)
	}
	if !utf8.Valid(b) {
		return fmt.Errorf("%w: not valid UTF-8", ErrBody)
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, b); err != nil {
		return fmt.Errorf("%w: not one JSON value", ErrBody)
	}
	var canonical bytes.Buffer
	json.HTMLEscape(&canonical, compact.Bytes())
	if !bytes.Equal(canonical.Bytes(), b) {
		return fmt.Errorf("%w: not in the compact, escaped form encoding/json emits", ErrBody)
	}
	return nil
}

// NewEntry returns id's entry of the given kind after prev, the head of id's
// own chain (the zero Head for its first entry): Seq prev.Seq+1, Prev
// prev.Hash, and body encoded with encoding/json (pass a json.RawMessage for
// JSON already at hand; a []byte becomes a base64 string). The entry is
// checked with Verify under id's public key before it is returned, so it is
// one that Log.Append accepts after prev.
//
// It returns ErrInvalid for a nil identity, an all-zero member ID, a signing
// key of the wrong length, a prev whose Seq and Hash disagree (a zero Seq
// goes with a zero Hash and only with it), or a prev at the last Seq;
// ErrKind for an unknown kind; ErrBody for a body encoding/json cannot
// encode or that breaks the body rules; and Verify's errors for a key whose
// public half is unusable or does not belong to its seed.
func NewEntry(id *identity.Identity, prev Head, kind Kind, body any) (Entry, error) {
	switch {
	case id == nil:
		return Entry{}, fmt.Errorf("%w: nil identity", ErrInvalid)
	case id.ID == ids.MemberID{}:
		return Entry{}, fmt.Errorf("%w: the member ID is all zero", ErrInvalid)
	case len(id.Sign) != ed25519.PrivateKeySize:
		return Entry{}, fmt.Errorf("%w: the signing key is %d bytes, want %d", ErrInvalid, len(id.Sign), ed25519.PrivateKeySize)
	case (prev.Seq == 0) != (prev.Hash == ids.Hash{}):
		return Entry{}, fmt.Errorf("%w: prev seq %d with hash %s", ErrInvalid, prev.Seq, prev.Hash)
	case prev.Seq == math.MaxUint64:
		return Entry{}, fmt.Errorf("%w: the chain is at its last seq", ErrInvalid)
	}
	b, err := json.Marshal(body)
	if err != nil {
		return Entry{}, fmt.Errorf("%w: %w", ErrBody, err)
	}
	e := Entry{Origin: id.ID, Seq: prev.Seq + 1, Prev: prev.Hash, Kind: kind, Body: b}
	e.Sig = sig.Sign(id.Sign, sigKind, e.message())
	if err := e.Verify(id.Sign.Public().(ed25519.PublicKey)); err != nil {
		return Entry{}, err
	}
	return e, nil
}

// clone returns a copy of e that shares no memory with it.
func (e Entry) clone() Entry {
	e.Body = bytes.Clone(e.Body)
	e.Sig = bytes.Clone(e.Sig)
	return e
}
