package roster

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"slices"

	"github.com/TAIPANBOX/rollcall/internal/sig"
)

// ErrAnchor reports a roster that VerifyAnchored refuses. It wraps the
// cause where the package has a sentinel for it.
var ErrAnchor = errors.New("roster: not a valid roster signed by the anchored key as an admin of it")

// VerifyAnchored returns the roster in s, of any version, on the authority
// of key alone, which the caller has tied to the group by other means: a
// joining router takes key from the response that the fingerprint in its
// join code names (pairing). There is no previous roster, so the chain is
// not judged.
//
// It checks, cheapest first: the sizes (ErrFormat, ErrTooLarge); that s is
// not signed with the recovery key; the signature under key, as the
// package signs, over s.SignerID, the recovery byte 0 and s.Body
// (ErrSignature); only then the body, which must be the one canonical
// encoding (ErrDecode, ErrNotCanonical) of a roster that passes Check; that
// s.SignerID is one of its Admins (ErrNotAdmin); and that the signer's
// SignPub is key. Every error wraps ErrAnchor. On error the Roster is the
// zero value. s is not modified, and the returned roster shares no memory
// with it.
func (s Signed) VerifyAnchored(key ed25519.PublicKey) (Roster, error) {
	if len(s.Body) == 0 || len(s.Sig) != ed25519.SignatureSize {
		return Roster{}, fmt.Errorf("%w: %w", ErrAnchor, ErrFormat)
	}
	if len(s.Body) > MaxBodySize {
		return Roster{}, fmt.Errorf("%w: %w", ErrAnchor, ErrTooLarge)
	}
	if s.Recovery {
		return Roster{}, fmt.Errorf("%w: signed with the recovery key", ErrAnchor)
	}
	if !sig.Verify(key, sigKind, signedMessage(s.SignerID, false, s.Body), s.Sig) {
		return Roster{}, fmt.Errorf("%w: %w", ErrAnchor, ErrSignature)
	}
	r, err := decodeBody(s.Body)
	if err != nil {
		return Roster{}, fmt.Errorf("%w: %w", ErrAnchor, err)
	}
	if err := r.Check(); err != nil {
		return Roster{}, fmt.Errorf("%w: %w", ErrAnchor, err)
	}
	if !slices.Contains(r.Admins, s.SignerID) {
		return Roster{}, fmt.Errorf("%w: %w", ErrAnchor, ErrNotAdmin)
	}
	// Check made every admin a member, so the signer is found.
	if i := slices.IndexFunc(r.Members, func(m Member) bool { return m.ID == s.SignerID }); !bytes.Equal(r.Members[i].SignPub, key) {
		return Roster{}, fmt.Errorf("%w: the key is not the signing admin's", ErrAnchor)
	}
	return r, nil
}
