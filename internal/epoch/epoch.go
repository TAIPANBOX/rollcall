// Package epoch makes group epoch keys, keeps the packet keys a member
// accepts, and seals an epoch key to one member for delivery (security spec
// 5.5).
//
// An epoch key is SecretSize random bytes with an epoch ID and a NotAfter
// date. It never encrypts a packet itself: a Ring keeps only the packet key
// that wire.PacketKey derives from it, computed once when the key is
// installed.
//
// # Ring
//
// A Ring accepts its current epoch at any time, and the epoch before it for
// Overlap (60 s) after the switch: from the switch time, inclusive, to 60 s
// later, exclusive. A clock that reads earlier than the switch closes the
// previous epoch rather than extending it. Only one previous epoch is kept.
// Install refuses an epoch ID that is not greater than the current one, so a
// replayed old delivery cannot bring back a key that a removed member still
// holds; the current key delivered again is accepted and changes nothing. An
// empty Ring accepts any first key, so a member installs its stored current
// key at start, before it accepts any delivery.
//
// NotAfter is the date by which the acting admin rotates the key. Members do
// not enforce it: a Ring keeps accepting its current key past NotAfter,
// because with both admins gone a key that expired on its own would take the
// whole group off the air with nobody left to deliver the next one.
//
// # Delivery
//
// Seal returns a blob of exactly BlobSize (1261) bytes:
//
//	version (1) = 1 | signer member ID (16) | HPKE ciphertext (1180) | signature (64)
//
// The ciphertext is single-shot HPKE base mode, hpke.Seal with the
// recipient's MLKEM768-X25519 key, HKDF-SHA256 and ChaCha20-Poly1305: the
// encapsulated key (1120) followed by the sealed plaintext and tag (44 + 16).
// The info is "rollcall/v1 epoch" followed by the recipient's 16-byte member
// ID, so a delivery opens only for the member it was sealed for. The
// plaintext is
//
//	epoch ID (4, big endian) | NotAfter (8, Unix seconds, big endian) | secret (32)
//
// with NotAfter from 1 to 253402300799 (9999-12-31T23:59:59Z). The signature
// is sig.Sign(admin, "epoch", bytes 0 to 1196): it covers everything sent
// before it, the version and the signer ID as well as the ciphertext.
//
// Open checks, cheapest first: its own arguments (ErrInvalid), the length and
// version (ErrFormat), the signature against the admin keys (ErrSignature),
// and only then decrypts (ErrDecrypt) and reads the plaintext
// (ErrInvalidKey). Nothing is decrypted under a signature that does not
// verify. Open does not decide whether a key is fresh: a captured delivery
// opens again, and Ring.Install is where an old epoch is refused.
//
// Every error is a sentinel, or wraps one with a message from the HPKE
// library; none carries key bytes.
package epoch

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
	"sync"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/identity"
	"github.com/TAIPANBOX/rollcall/internal/ids"
	"github.com/TAIPANBOX/rollcall/internal/sig"
	"github.com/TAIPANBOX/rollcall/internal/wire"
)

const (
	// SecretSize is the length of an epoch key's secret in bytes.
	SecretSize = 32
	// RotationPeriod is how long a new key from New lasts: NotAfter is set
	// this far ahead.
	RotationPeriod = 30 * 24 * time.Hour
	// Overlap is how long a Ring accepts the previous epoch after a switch.
	Overlap = 60 * time.Second
	// BlobSize is the length of every delivery blob in bytes.
	BlobSize = offSig + ed25519.SignatureSize
)

const (
	blobVersion = 1
	sigKind     = "epoch"
	infoLabel   = "rollcall/v1 epoch"

	memberIDSize   = len(ids.MemberID{})
	plaintextSize  = 4 + 8 + SecretSize
	encSize        = mlkem.CiphertextSize768 + 32 // X-Wing: ML-KEM-768 ciphertext and an X25519 point
	tagSize        = 16                           // ChaCha20-Poly1305
	ciphertextSize = encSize + plaintextSize + tagSize

	offSigner     = 1
	offCiphertext = offSigner + memberIDSize
	offSig        = offCiphertext + ciphertextSize

	// maxNotAfter is 9999-12-31T23:59:59Z in Unix seconds. Later values
	// overflow time.Time's internal seconds and compare as if in the past.
	maxNotAfter = 253402300799
)

var (
	recvKEM = hpke.MLKEM768X25519()
	kdf     = hpke.HKDFSHA256()
	aead    = hpke.ChaCha20Poly1305()
)

var (
	// ErrInvalidKey reports a secret that is not SecretSize bytes or is all
	// zero, or a NotAfter outside 1970-01-01T00:00:01Z..9999-12-31T23:59:59Z.
	ErrInvalidKey = errors.New("epoch: invalid key: the secret must be 32 bytes and not all zero, NotAfter within 1970..9999")
	// ErrStale reports a key whose epoch ID is not greater than the current
	// one, or is the current ID with another secret.
	ErrStale = errors.New("epoch: the key is not newer than the current epoch")
	// ErrInvalid reports a zero member ID, an unusable admin signing key, or
	// a self that cannot open deliveries.
	ErrInvalid = errors.New("epoch: invalid argument")
	// ErrRecipientKey reports a recipient key that is not MLKEM768-X25519,
	// or that HPKE cannot encapsulate to.
	ErrRecipientKey = errors.New("epoch: the recipient key is not a usable MLKEM768-X25519 key")
	// ErrFormat reports a delivery that is not a version 1 blob of exactly
	// BlobSize bytes.
	ErrFormat = errors.New("epoch: the delivery is not a 1261-byte version 1 blob")
	// ErrSignature reports a delivery that no listed admin key signed.
	ErrSignature = errors.New("epoch: the delivery is not signed by an admin")
	// ErrDecrypt reports a delivery that does not open with this member's
	// receive key and member ID.
	ErrDecrypt = errors.New("epoch: the delivery does not open for this member")
)

// Key is a group epoch key.
type Key struct {
	ID       uint32    // the epoch ID that packets carry
	Secret   []byte    // SecretSize random bytes
	NotAfter time.Time // the date by which the acting admin rotates
}

// String returns "epoch <id> not after <NotAfter in RFC 3339, UTC>".
func (k Key) String() string {
	return "epoch " + strconv.FormatUint(uint64(k.ID), 10) + " not after " + k.NotAfter.UTC().Format(time.RFC3339)
}

// Format prints String for every verb, so that no fmt verb can print the
// secret into a log.
func (k Key) Format(s fmt.State, _ rune) { io.WriteString(s, k.String()) }

// New returns a new epoch key with the given ID: SecretSize bytes from
// crypto/rand, and NotAfter RotationPeriod from now, in whole seconds and
// UTC, so the key survives Seal and Open unchanged.
func New(id uint32) (Key, error) {
	secret := make([]byte, SecretSize)
	// Since Go 1.24 rand.Read never returns an error: a failing system
	// source ends the program, so the secret is never left unfilled.
	rand.Read(secret)
	notAfter := time.Unix(time.Now().Add(RotationPeriod).Unix(), 0).UTC()
	return Key{ID: id, Secret: secret, NotAfter: notAfter}, nil
}

// Ring holds the packet keys a member accepts: the current epoch's, and the
// previous epoch's for Overlap after a switch. The zero value is an empty
// ring that uses time.Now. A Ring is safe for concurrent use and must not be
// copied after first use.
type Ring struct {
	// Now returns the time Lookup measures the overlap with; nil means
	// time.Now. It must read the same clock as the times passed to Install.
	// Set it before the Ring is used.
	Now func() time.Time

	mu       sync.RWMutex
	cur      slot
	prev     slot
	switched time.Time // when cur replaced prev
}

// slot is one epoch in a Ring.
type slot struct {
	set bool
	id  uint32
	key []byte // the packet key, never the epoch key
}

// Install makes k the current epoch at time now. The epoch it replaces stays
// valid until now + Overlap; any older one is dropped. It returns
// ErrInvalidKey for a secret that is not SecretSize bytes or is all zero, and
// ErrStale for an ID not greater than the current one (the current key
// itself, same ID and secret, is accepted and changes nothing). On error the
// Ring is unchanged. NotAfter is not checked (see the package comment).
func (r *Ring) Install(k Key, now time.Time) error {
	if len(k.Secret) != SecretSize {
		return ErrInvalidKey
	}
	pk, err := wire.PacketKey(k.Secret) // refuses an all-zero secret
	if err != nil {
		return ErrInvalidKey
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cur.set {
		if k.ID == r.cur.id && subtle.ConstantTimeCompare(pk, r.cur.key) == 1 {
			return nil
		}
		if k.ID <= r.cur.id {
			return ErrStale
		}
		r.prev = r.cur
		r.switched = now
	}
	r.cur = slot{set: true, id: k.ID, key: pk}
	return nil
}

// Lookup returns a copy of the packet key for epoch id: the current epoch's,
// or the previous epoch's from the switch until Overlap after it. Any other
// epoch gives (nil, false). Lookup is a wire.KeyLookup.
func (r *Ring) Lookup(id uint32) ([]byte, bool) {
	now := r.now()
	r.mu.RLock()
	defer r.mu.RUnlock()
	switch {
	case r.cur.set && id == r.cur.id:
		return bytes.Clone(r.cur.key), true
	case r.prev.set && id == r.prev.id && !now.Before(r.switched) && now.Before(r.switched.Add(Overlap)):
		return bytes.Clone(r.prev.key), true
	}
	return nil, false
}

func (r *Ring) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// Format prints the epoch IDs the Ring holds, and when the previous one
// stops being accepted, for every verb; never a key.
func (r *Ring) Format(s fmt.State, _ rune) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	switch {
	case !r.cur.set:
		io.WriteString(s, "epoch ring, empty")
	case !r.prev.set:
		fmt.Fprintf(s, "epoch ring, current %d", r.cur.id)
	default:
		fmt.Fprintf(s, "epoch ring, current %d, previous %d until %s",
			r.cur.id, r.prev.id, r.switched.Add(Overlap).UTC().Format(time.RFC3339))
	}
}

// Seal returns the delivery of k to the member recipient, whose receive key
// is to, signed with admin's key and naming signer, the admin's member ID.
// The blob layout is in the package comment. NotAfter travels in whole
// seconds; a fraction is dropped.
//
// It returns ErrInvalidKey for a bad secret or NotAfter, ErrRecipientKey if to
// is nil, is not MLKEM768-X25519, or cannot be encapsulated to, and
// ErrInvalid for a zero member ID or an admin key that is not 64 bytes or
// whose public half sig.ValidPublicKey rejects. k is not modified.
func Seal(k Key, to hpke.PublicKey, recipient, signer ids.MemberID, admin ed25519.PrivateKey) ([]byte, error) {
	notAfter := k.NotAfter.Unix()
	if len(k.Secret) != SecretSize || allZero(k.Secret) || notAfter < 1 || notAfter > maxNotAfter {
		return nil, ErrInvalidKey
	}
	if to == nil || to.KEM().ID() != recvKEM.ID() {
		return nil, ErrRecipientKey
	}
	if recipient == (ids.MemberID{}) || signer == (ids.MemberID{}) {
		return nil, ErrInvalid
	}
	if len(admin) != ed25519.PrivateKeySize || sig.ValidPublicKey(admin[ed25519.SeedSize:]) != nil {
		return nil, ErrInvalid
	}

	pt := make([]byte, plaintextSize)
	binary.BigEndian.PutUint32(pt[0:4], k.ID)
	binary.BigEndian.PutUint64(pt[4:12], uint64(notAfter))
	copy(pt[12:], k.Secret)
	ct, err := hpke.Seal(to, kdf, aead, deliveryInfo(recipient), pt)
	clear(pt)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRecipientKey, err)
	}

	blob := make([]byte, 0, BlobSize)
	blob = append(blob, blobVersion)
	blob = append(blob, signer[:]...)
	blob = append(blob, ct...)
	return append(blob, sig.Sign(admin, sigKind, blob)...), nil
}

// Open checks a delivery and returns the key it carries for self. adminPubs
// are the public keys of the admins whose deliveries self accepts; keys that
// sig.ValidPublicKey rejects are skipped. The order of the checks and their
// errors are in the package comment. On error the Key is the zero Key. The
// returned secret does not share memory with blob, and blob is not modified.
func Open(blob []byte, self *identity.Identity, adminPubs []ed25519.PublicKey) (Key, error) {
	if self == nil || self.Recv == nil || self.Recv.KEM().ID() != recvKEM.ID() || self.ID == (ids.MemberID{}) {
		return Key{}, ErrInvalid
	}
	if len(blob) != BlobSize || blob[0] != blobVersion {
		return Key{}, ErrFormat
	}
	if !signedByAdmin(blob, adminPubs) {
		return Key{}, ErrSignature
	}
	pt, err := hpke.Open(self.Recv, kdf, aead, deliveryInfo(self.ID), blob[offCiphertext:offSig])
	if err != nil {
		return Key{}, ErrDecrypt
	}
	defer clear(pt)
	return decodePlaintext(pt)
}

// decodePlaintext reads epoch ID | NotAfter | secret. A plaintext of another
// length is ErrFormat: a BlobSize blob cannot yield one, but the check keeps
// a later change to the format from turning into a panic. The secret is
// copied, so pt may be cleared afterwards.
func decodePlaintext(pt []byte) (Key, error) {
	if len(pt) != plaintextSize {
		return Key{}, ErrFormat
	}
	notAfter := binary.BigEndian.Uint64(pt[4:12])
	secret := pt[12:]
	if allZero(secret) || notAfter < 1 || notAfter > maxNotAfter {
		return Key{}, ErrInvalidKey
	}
	return Key{
		ID:       binary.BigEndian.Uint32(pt[0:4]),
		Secret:   bytes.Clone(secret),
		NotAfter: time.Unix(int64(notAfter), 0).UTC(),
	}, nil
}

// signedByAdmin reports whether the signature at the end of blob is a valid
// "epoch" signature, over everything before it, by one of adminPubs.
func signedByAdmin(blob []byte, adminPubs []ed25519.PublicKey) bool {
	msg, s := blob[:offSig], blob[offSig:]
	for _, pub := range adminPubs {
		if sig.ValidPublicKey(pub) != nil {
			continue
		}
		if sig.Verify(pub, sigKind, msg, s) {
			return true
		}
	}
	return false
}

// deliveryInfo returns the HPKE info for a delivery to recipient: the label
// followed by the member ID. The label has a fixed length, so no separator
// is needed.
func deliveryInfo(recipient ids.MemberID) []byte {
	return append([]byte(infoLabel), recipient[:]...)
}

// allZero reports whether b has no non-zero byte. It reads every byte
// whatever it finds, so its time does not depend on the secret.
func allZero(b []byte) bool {
	var acc byte
	for _, x := range b {
		acc |= x
	}
	return acc == 0
}
