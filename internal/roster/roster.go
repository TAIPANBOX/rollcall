// Package roster holds the signed, chained roster of a rollcall group
// (security spec 5.6 and 6.1): who is in the group, with which roles, who
// may change it, and the offline recovery key.
//
// # Shape
//
// Roster.Check accepts a roster only if: Version is at least 1; Site is a
// valid name (ValidName); there are 1 to MaxMembers members, each with a
// non-zero ID and a valid name, both unique; each member's SignPub is an
// Ed25519 key that sig.ValidPublicKey accepts and its RecvPub an
// MLKEM768-X25519 public key; RecoveryPub is an Ed25519 key that
// sig.ValidPublicKey accepts; no public key appears twice (two members, or
// the recovery key and a member); Admins lists 1 to MaxAdmins distinct
// members, Admins[0] the primary and the rest backups; the roles agree with
// Admins: Admins[0], and nobody else, has RolePrimary, the other admins, and
// nobody else, have RoleBackup; RoleSender may be on anyone; a member lists
// only known roles, each once; OwnerConfirmed is set only with Takeover; and
// Replaced, the primary a takeover replaced, is set exactly when Takeover
// is, is never Admins[0], and is one of the backups, Admins[1:], while the
// takeover is unconfirmed (OwnerConfirmed clear), so that the replaced
// primary can always sign its restore.
//
// # Body
//
// Signed.Body is the JSON that encoding/json makes of a Roster, with the
// fields in this order and nothing between the tokens:
//
//	{"version":N,"prev":"<64 hex digits>","site":"<name>",
//	 "members":[{"id":"<32 hex digits>","name":"<name>","sign_pub":"<base64>",
//	   "recv_pub":"<base64>","roles":["primary","sender"]},...],
//	 "admins":["<32 hex digits>",...],"recovery_pub":"<base64>",
//	 "takeover":false,"replaced":"<32 hex digits>","owner_confirmed":false}
//
// "roles" is left out for a member without roles; "replaced" is always
// written, as 32 zeros when there is no takeover. Hex is lower case, base64
// is the standard alphabet with padding. That exact encoding is the only one
// accepted: Verify decodes the body (unknown fields refused, nothing after
// the object) and requires that encoding the result again gives the same
// bytes, so one roster has one body and whitespace, key order, letter case,
// escapes or duplicate keys are refused. A body is at most MaxBodySize bytes.
//
// # Signature
//
// The signature is sig.Sign(key, "roster", m), so Ed25519 over
// "rollcall/v1/roster\x00" || m, with
//
//	m = SignerID (16) || recovery (1 byte: 0 or 1) || Body
//
// It covers the exact bytes of every field of Signed but itself, so neither
// the signer nor the recovery flag can be changed on the way. A roster
// signed with the recovery key has the zero SignerID and Recovery set; one
// signed by an admin has that admin's member ID and Recovery clear.
//
// # Hash
//
// Signed.Hash is SHA-256 over
//
//	"rollcall/v1 roster hash\x00" || len(Body) (8, big endian) || Body ||
//	SignerID (16) || recovery (1) || len(Sig) (8, big endian) || Sig
//
// The next version carries it in Prev, and heartbeats compare it.
//
// # Chain and authority
//
// Signed.Verify(prev) checks, cheapest first: the sizes and that SignerID
// and Recovery agree; the signature, under the key that prev gives the
// signer; only then the body (decoding, canonical form, Check); and the
// chain. Authority always comes from the previous roster, never from the
// new one:
//
//   - With prev nil the roster must be version 1 with a zero Prev, signed by
//     its own Admins[0] or by its own recovery key. A version 1 roster names
//     its own signer, so its body is decoded before its signature is
//     checked; nothing in it is used before the signature verifies. A
//     self-signed roster proves only that its primary made it; whether that
//     primary is the right one is decided outside, by the key fingerprint
//     in the join code.
//   - With prev set the roster must be version prev+1 with Prev equal to
//     prev.Hash(), signed by an admin listed in prev with that admin's key
//     in prev, or by prev's recovery key. Only a roster signed by the
//     recovery key may change RecoveryPub, so a compromised admin cannot
//     lock the owner's recovery code out. An admin of prev keeps its
//     signing and receive keys unless the roster is signed by that admin
//     itself or by the recovery key (ErrAdminKeys); otherwise the backup
//     could give the primary's entry a key of its own, in a roster that
//     changes nothing else, and then sign as the primary.
//
// prev is the Signed this member accepted last. Verify trusts it as it is:
// it decodes it and runs Check, but cannot check how it was accepted.
// Verify judges one link of the chain; it does not choose between two
// different rosters of the same version (Prefer does).
//
// # Takeover
//
// Spec 6.1: if the primary is gone, the backup takes over; the takeover is
// provisional, and the primary it replaced restores itself when it comes
// back, unless the owner has confirmed the takeover or used the recovery
// key. Verify holds the roster's side of this for a roster signed by an
// admin; one signed by the recovery key overrides both admins and is held
// to Check alone. With p the previous roster and r the new one:
//
//   - A roster signed by a backup of p that names a primary other than
//     p.Admins[0] is a takeover: it sets Takeover, with Replaced
//     p.Admins[0] (ErrTakeoverFlag, ErrTakeoverReplaced). The one exception
//     is the restore: while p's takeover is unconfirmed, the primary it
//     replaced may sign a roster that names itself primary with Takeover
//     clear.
//   - Nothing else raises Takeover: not the primary, not a backup that
//     keeps the primary, not a version 1 roster signed by an admin
//     (ErrTakeoverFlag). So the backup cannot name itself the replaced
//     primary and then restore itself past the ten-minute rule.
//   - Once raised, the takeover carries forward: Replaced stays
//     (ErrTakeoverReplaced), a confirmation is not withdrawn, and Takeover
//     is cleared only once the takeover is confirmed or when the replaced
//     primary is primary again (ErrTakeoverFlag).
//   - While the takeover is unconfirmed, Check keeps the replaced primary
//     among the backups, and so its keys stay as they were (ErrAdminKeys,
//     above): its restore can always be signed and verified.
//
// Whether a member accepts a takeover at all depends on whether it still
// hears the primary; that is AcceptTakeover, which the caller applies after
// Verify.
//
// # Anchored verification
//
// VerifyAnchored accepts a roster of any version without a previous one, on
// the authority of a key the caller trusts by other means (at pairing, the
// key whose fingerprint the join code carries): signed by that key, not
// with the recovery key, as an admin of that very roster, in canonical form,
// passing Check. Its errors wrap ErrAnchor.
//
// Every error is a sentinel, or wraps sentinels, and carries no text from
// the roster.
package roster

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/TAIPANBOX/rollcall/internal/ids"
	"github.com/TAIPANBOX/rollcall/internal/sig"
)

// Role is what a member may do besides watching.
type Role string

// The roles. They are the JSON values in a body.
const (
	RoleSender  Role = "sender"  // may hold the bot token and send to the chat
	RolePrimary Role = "primary" // the primary admin, Admins[0]
	RoleBackup  Role = "backup"  // a backup admin, Admins[1:]
)

const (
	// MaxAdmins is the most admins a roster lists: one primary and backups.
	MaxAdmins = 2
	// MaxMembers is the most members a roster holds.
	MaxMembers = 32
	// MaxBodySize is the largest Body that Verify reads.
	MaxBodySize = 128 << 10
)

const (
	sigKind   = "roster"
	hashLabel = "rollcall/v1 roster hash\x00"
)

// recvKEM is the KEM of every member's receive key.
var recvKEM = hpke.MLKEM768X25519()

// Member is one router of the group.
type Member struct {
	ID      ids.MemberID `json:"id"`
	Name    string       `json:"name"`
	SignPub []byte       `json:"sign_pub"`        // Ed25519
	RecvPub []byte       `json:"recv_pub"`        // MLKEM768-X25519
	Roles   []Role       `json:"roles,omitempty"` // in any order, each once
}

// Roster is one version of the group's membership.
type Roster struct {
	Version        uint64         `json:"version"`
	Prev           ids.Hash       `json:"prev"` // Hash of the previous Signed; zero at version 1
	Site           string         `json:"site"`
	Members        []Member       `json:"members"`
	Admins         []ids.MemberID `json:"admins"` // Admins[0] is the primary
	RecoveryPub    []byte         `json:"recovery_pub"`
	Takeover       bool           `json:"takeover"`
	Replaced       ids.MemberID   `json:"replaced"` // the primary a takeover replaced; zero without one
	OwnerConfirmed bool           `json:"owner_confirmed"`
}

// Signed is a roster body with its signature.
type Signed struct {
	Body     []byte
	SignerID ids.MemberID // the signing admin; zero when Recovery is set
	Recovery bool         // signed with the recovery key
	Sig      []byte
}

// Errors of Check, in the order Check looks for them.
var (
	ErrVersionZero    = errors.New("roster: version is 0")
	ErrSite           = errors.New("roster: invalid site name")
	ErrMemberCount    = errors.New("roster: needs 1 to 32 members")
	ErrMemberID       = errors.New("roster: member ID is zero")
	ErrDuplicateID    = errors.New("roster: two members have the same ID")
	ErrMemberName     = errors.New("roster: invalid member name")
	ErrDuplicateName  = errors.New("roster: two members have the same name")
	ErrSignKey        = errors.New("roster: invalid member signing key")
	ErrRecvKey        = errors.New("roster: invalid member receive key")
	ErrRole           = errors.New("roster: unknown or repeated role")
	ErrDuplicateKey   = errors.New("roster: a public key appears twice")
	ErrRecoveryKey    = errors.New("roster: missing or invalid recovery key")
	ErrNoPrimary      = errors.New("roster: no primary admin")
	ErrTooManyAdmins  = errors.New("roster: more admins than MaxAdmins")
	ErrAdminNotMember = errors.New("roster: admin is not a member")
	ErrDuplicateAdmin = errors.New("roster: admin listed twice")
	ErrTwoPrimaries   = errors.New("roster: more than one member has the primary role")
	ErrRoleMismatch   = errors.New("roster: member roles disagree with the admin list")
	ErrOwnerConfirmed = errors.New("roster: owner_confirmed without takeover")
	ErrReplaced       = errors.New("roster: replaced disagrees with takeover or the admin list")
)

// Errors of SignRoster and Verify.
var (
	ErrKey             = errors.New("roster: unusable private key")
	ErrFormat          = errors.New("roster: empty body or signature of the wrong length")
	ErrTooLarge        = errors.New("roster: body larger than MaxBodySize")
	ErrSigner          = errors.New("roster: signer ID and recovery flag disagree")
	ErrNotAdmin        = errors.New("roster: signer is not an admin of the previous roster")
	ErrSignature       = errors.New("roster: signature does not verify")
	ErrDecode          = errors.New("roster: body does not decode")
	ErrNotCanonical    = errors.New("roster: body is not in canonical form")
	ErrNoPrev          = errors.New("roster: version is not 1 and there is no previous roster")
	ErrVersion         = errors.New("roster: version is not the previous version plus one")
	ErrPrevHash        = errors.New("roster: prev is not the hash of the previous roster")
	ErrPrev            = errors.New("roster: previous roster is unusable")
	ErrRecoveryChanged = errors.New("roster: only the recovery key may replace the recovery key")
)

// Errors of the admin rules in Verify (package comment, Chain and authority,
// and Takeover).
var (
	ErrTakeoverFlag     = errors.New("roster: takeover flag or confirmation breaks the takeover rules")
	ErrTakeoverReplaced = errors.New("roster: replaced is not the primary the takeover replaced")
	ErrAdminKeys        = errors.New("roster: an admin's keys changed in a roster that admin did not sign")
)

// Check returns nil if r has the shape described in the package comment,
// and otherwise the first fault found, as one of the Check errors. Errors
// name a member by its index, never by its name.
func (r Roster) Check() error {
	if r.Version == 0 {
		return ErrVersionZero
	}
	if err := ValidName(r.Site); err != nil {
		return fmt.Errorf("%w: %w", ErrSite, err)
	}
	if len(r.Members) == 0 || len(r.Members) > MaxMembers {
		return fmt.Errorf("%w: has %d", ErrMemberCount, len(r.Members))
	}
	seenID := make(map[ids.MemberID]bool, len(r.Members))
	seenName := make(map[string]bool, len(r.Members))
	seenKey := make(map[string]bool, 2*len(r.Members)+1)
	for i := range r.Members {
		m := &r.Members[i]
		if m.ID == (ids.MemberID{}) {
			return fmt.Errorf("%w: member %d", ErrMemberID, i)
		}
		if seenID[m.ID] {
			return fmt.Errorf("%w: member %d", ErrDuplicateID, i)
		}
		seenID[m.ID] = true
		if err := ValidName(m.Name); err != nil {
			return fmt.Errorf("%w: member %d: %w", ErrMemberName, i, err)
		}
		if seenName[m.Name] {
			return fmt.Errorf("%w: member %d", ErrDuplicateName, i)
		}
		seenName[m.Name] = true
		if err := sig.ValidPublicKey(m.SignPub); err != nil {
			return fmt.Errorf("%w: member %d: %w", ErrSignKey, i, err)
		}
		if _, err := recvKEM.NewPublicKey(m.RecvPub); err != nil {
			return fmt.Errorf("%w: member %d", ErrRecvKey, i)
		}
		if err := checkRoles(m.Roles); err != nil {
			return fmt.Errorf("%w: member %d", err, i)
		}
		// Ed25519 keys are 32 bytes and receive keys 1216, so one set
		// holds both without mixing them up.
		for _, k := range [][]byte{m.SignPub, m.RecvPub} {
			if seenKey[string(k)] {
				return fmt.Errorf("%w: member %d", ErrDuplicateKey, i)
			}
			seenKey[string(k)] = true
		}
	}
	if err := sig.ValidPublicKey(r.RecoveryPub); err != nil {
		return fmt.Errorf("%w: %w", ErrRecoveryKey, err)
	}
	if seenKey[string(r.RecoveryPub)] {
		return fmt.Errorf("%w: the recovery key is a member's key", ErrDuplicateKey)
	}
	if len(r.Admins) == 0 {
		return ErrNoPrimary
	}
	if len(r.Admins) > MaxAdmins {
		return fmt.Errorf("%w: has %d", ErrTooManyAdmins, len(r.Admins))
	}
	for i, a := range r.Admins {
		if !seenID[a] {
			return fmt.Errorf("%w: admin %d", ErrAdminNotMember, i)
		}
		if slices.Contains(r.Admins[:i], a) {
			return fmt.Errorf("%w: admin %d", ErrDuplicateAdmin, i)
		}
	}
	primaries := 0
	for i := range r.Members {
		if slices.Contains(r.Members[i].Roles, RolePrimary) {
			primaries++
		}
	}
	if primaries == 0 {
		return ErrNoPrimary
	}
	if primaries > 1 {
		return ErrTwoPrimaries
	}
	for i := range r.Members {
		m := &r.Members[i]
		primary := m.ID == r.Admins[0]
		backup := slices.Contains(r.Admins[1:], m.ID)
		if slices.Contains(m.Roles, RolePrimary) != primary || slices.Contains(m.Roles, RoleBackup) != backup {
			return fmt.Errorf("%w: member %d", ErrRoleMismatch, i)
		}
	}
	if r.OwnerConfirmed && !r.Takeover {
		return ErrOwnerConfirmed
	}
	if r.Takeover != (r.Replaced != ids.MemberID{}) {
		return fmt.Errorf("%w: set without takeover, or missing with it", ErrReplaced)
	}
	if r.Takeover && r.Replaced == r.Admins[0] {
		return fmt.Errorf("%w: it is the primary", ErrReplaced)
	}
	if r.Takeover && !r.OwnerConfirmed && !slices.Contains(r.Admins[1:], r.Replaced) {
		return fmt.Errorf("%w: not a backup while the takeover is unconfirmed", ErrReplaced)
	}
	return nil
}

// checkRoles returns ErrRole if roles holds an unknown role or one role
// twice.
func checkRoles(roles []Role) error {
	for i, role := range roles {
		switch role {
		case RoleSender, RolePrimary, RoleBackup:
		default:
			return ErrRole
		}
		if slices.Contains(roles[:i], role) {
			return ErrRole
		}
	}
	return nil
}

// SignRoster encodes r and signs it with key: as the admin signer when
// recovery is false, or with the recovery key when recovery is true, in
// which case signer must be the zero ID. It refuses a roster that Check
// refuses, a signer that does not agree with recovery (ErrSigner), and a key
// that is not a whole, consistent Ed25519 private key (ErrKey). It does not
// decide authority: Verify does, against the previous roster. r is not
// modified, and the returned Signed shares no memory with it.
func SignRoster(r Roster, signer ids.MemberID, key ed25519.PrivateKey, recovery bool) (Signed, error) {
	if err := r.Check(); err != nil {
		return Signed{}, err
	}
	if recovery != (signer == ids.MemberID{}) {
		return Signed{}, ErrSigner
	}
	if len(key) != ed25519.PrivateKeySize || !bytes.Equal(ed25519.NewKeyFromSeed(key.Seed()), key) {
		return Signed{}, ErrKey
	}
	body, err := json.Marshal(r)
	if err != nil {
		return Signed{}, fmt.Errorf("roster: encode: %w", err)
	}
	return Signed{
		Body:     body,
		SignerID: signer,
		Recovery: recovery,
		Sig:      sig.Sign(key, sigKind, signedMessage(signer, recovery, body)),
	}, nil
}

// Verify returns the roster in s if s may follow prev, as the package
// comment describes, and otherwise the zero Roster and an error. prev is nil
// only for version 1. Neither s nor prev is modified, and the returned
// roster shares no memory with them.
func (s Signed) Verify(prev *Signed) (Roster, error) {
	if len(s.Body) == 0 || len(s.Sig) != ed25519.SignatureSize {
		return Roster{}, ErrFormat
	}
	if len(s.Body) > MaxBodySize {
		return Roster{}, ErrTooLarge
	}
	if s.Recovery != (s.SignerID == ids.MemberID{}) {
		return Roster{}, ErrSigner
	}

	var (
		r, p    Roster // the new roster once decoded, and the previous one
		key     ed25519.PublicKey
		decoded bool
		err     error
	)
	if prev == nil {
		if r, err = decodeBody(s.Body); err != nil {
			return Roster{}, err
		}
		if r.Version != 1 {
			return Roster{}, ErrNoPrev
		}
		decoded = true
		key, err = signingKey(&r, s, true)
	} else {
		if p, err = decodeBody(prev.Body); err == nil {
			err = p.Check()
		}
		if err != nil {
			return Roster{}, fmt.Errorf("%w: %w", ErrPrev, err)
		}
		key, err = signingKey(&p, s, false)
	}
	if err != nil {
		return Roster{}, err
	}
	if !sig.Verify(key, sigKind, signedMessage(s.SignerID, s.Recovery, s.Body), s.Sig) {
		return Roster{}, ErrSignature
	}

	if !decoded {
		if r, err = decodeBody(s.Body); err != nil {
			return Roster{}, err
		}
	}
	if err := r.Check(); err != nil {
		return Roster{}, err
	}
	if prev == nil {
		if r.Prev != (ids.Hash{}) {
			return Roster{}, ErrPrevHash
		}
		if r.Takeover && !s.Recovery {
			return Roster{}, ErrTakeoverFlag // version 1 has nothing to take over
		}
		return r, nil
	}
	if r.Version != p.Version+1 {
		return Roster{}, ErrVersion
	}
	if r.Prev != prev.Hash() {
		return Roster{}, ErrPrevHash
	}
	if !s.Recovery && !bytes.Equal(r.RecoveryPub, p.RecoveryPub) {
		return Roster{}, ErrRecoveryChanged
	}
	if err := checkTakeover(&p, &r, s); err != nil {
		return Roster{}, err
	}
	return r, nil
}

// signingKey returns the key that may sign s under the authority of a: a's
// recovery key when s.Recovery is set, otherwise the key a gives the admin
// s names. With primaryOnly only Admins[0] counts. a may be unchecked (a
// version 1 roster before its signature is verified), so a key is only ever
// looked up, never trusted for being there.
func signingKey(a *Roster, s Signed, primaryOnly bool) (ed25519.PublicKey, error) {
	if s.Recovery {
		return a.RecoveryPub, nil
	}
	admins := a.Admins
	if primaryOnly && len(admins) > 1 {
		admins = admins[:1]
	}
	if !slices.Contains(admins, s.SignerID) {
		return nil, ErrNotAdmin
	}
	for i := range a.Members {
		if a.Members[i].ID == s.SignerID {
			return a.Members[i].SignPub, nil
		}
	}
	return nil, ErrNotAdmin
}

// decodeBody decodes a body that must be the canonical encoding of a
// Roster: ErrDecode if it is not one JSON object of the Roster fields alone,
// ErrNotCanonical if encoding the result again does not give body back.
// The errors carry nothing from body.
func decodeBody(body []byte) (Roster, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var r Roster
	if err := dec.Decode(&r); err != nil {
		return Roster{}, ErrDecode
	}
	if _, err := dec.Token(); err != io.EOF {
		return Roster{}, ErrDecode
	}
	if again, err := json.Marshal(r); err != nil || !bytes.Equal(again, body) {
		return Roster{}, ErrNotCanonical
	}
	return r, nil
}

// signedMessage returns the bytes after the kind prefix that a roster
// signature covers: signer ID, recovery byte, body.
func signedMessage(signer ids.MemberID, recovery bool, body []byte) []byte {
	m := make([]byte, 0, len(signer)+1+len(body))
	m = append(m, signer[:]...)
	m = append(m, flag(recovery))
	return append(m, body...)
}

// Hash returns the hash of s as the package comment defines it. It is
// defined for any Signed, verified or not.
func (s Signed) Hash() ids.Hash {
	h := sha256.New()
	h.Write([]byte(hashLabel))
	h.Write(binary.BigEndian.AppendUint64(nil, uint64(len(s.Body))))
	h.Write(s.Body)
	h.Write(s.SignerID[:])
	h.Write([]byte{flag(s.Recovery)})
	h.Write(binary.BigEndian.AppendUint64(nil, uint64(len(s.Sig))))
	h.Write(s.Sig)
	var out ids.Hash
	h.Sum(out[:0])
	return out
}

// flag returns the byte that stands for the recovery flag.
func flag(recovery bool) byte {
	if recovery {
		return 1
	}
	return 0
}
