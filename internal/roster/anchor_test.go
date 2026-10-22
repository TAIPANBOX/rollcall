package roster

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"testing"

	"github.com/TAIPANBOX/rollcall/internal/ids"
)

// anchorErr runs s.VerifyAnchored(key) and requires ErrAnchor, the cause
// want (which may be ErrAnchor itself), no other sentinel, and a zero
// roster.
func anchorErr(t *testing.T, what string, s Signed, key ed25519.PublicKey, want error) {
	t.Helper()
	got, err := s.VerifyAnchored(key)
	if !errors.Is(err, ErrAnchor) {
		t.Errorf("%s: err = %v, want ErrAnchor", what, err)
		return
	}
	checkErr(t, what, err, want, ErrAnchor)
	if !reflect.DeepEqual(got, Roster{}) {
		t.Errorf("%s: VerifyAnchored returned a roster together with the error", what)
	}
}

func TestVerifyAnchoredAccepts(t *testing.T) {
	ps := testParties()

	// A genesis roster signed by its primary.
	r := base(3)
	s := mustSign(t, r, ps[0])
	got, err := s.VerifyAnchored(pub(ps[0].Sign))
	if err != nil || !reflect.DeepEqual(got, r) {
		t.Errorf("genesis signed by the primary: %v", err)
	}

	// Any version, with any Prev, signed by the backup: no chain is judged.
	r5 := clone(r)
	r5.Version = 5
	r5.Prev = ids.Hash{1, 2, 3}
	s5 := mustSign(t, r5, ps[1])
	got, err = s5.VerifyAnchored(pub(ps[1].Sign))
	if err != nil || !reflect.DeepEqual(got, r5) {
		t.Errorf("version 5 signed by the backup: %v", err)
	}

	// The returned roster shares no memory with s.
	got.Members[0].SignPub[0] ^= 0xff
	if again, err := s5.VerifyAnchored(pub(ps[1].Sign)); err != nil || !reflect.DeepEqual(again, r5) {
		t.Errorf("changing the returned roster changed s: %v", err)
	}
}

func TestVerifyAnchoredRefuses(t *testing.T) {
	ps := testParties()
	r := base(3)
	body, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	s := mustSign(t, r, ps[0])

	// A member that is no admin signs with its own key.
	anchorErr(t, "signed by a member that is no admin", mustSign(t, r, ps[2]), pub(ps[2].Sign), ErrNotAdmin)

	// The anchored key signs, but names the backup as signer: the backup is
	// an admin, the key is not the backup's.
	anchorErr(t, "the primary's key signing as the backup", handSign(ps[0].Sign, ps[1].ID, false, body), pub(ps[0].Sign), ErrAnchor)

	// The signature is checked under the anchored key only.
	anchorErr(t, "signed by the primary, anchored to the backup", s, pub(ps[1].Sign), ErrSignature)
	anchorErr(t, "anchored to a stranger's key", s, pub(otherKey), ErrSignature)
	anchorErr(t, "anchored to no key", s, nil, ErrSignature)
	badSig := s
	badSig.Sig = bytes.Clone(s.Sig)
	badSig.Sig[7] ^= 1
	anchorErr(t, "signature changed", badSig, pub(ps[0].Sign), ErrSignature)

	// A roster signed with the recovery key is never anchored.
	anchorErr(t, "recovery-signed", mustSignRecovery(t, r, recoveryKey), pub(recoveryKey), ErrAnchor)
	flagged := s
	flagged.Recovery = true
	anchorErr(t, "recovery flag on an admin's signature", flagged, pub(ps[0].Sign), ErrAnchor)

	// The body must be the canonical encoding of a roster that passes Check.
	anchorErr(t, "leading space", handSign(ps[0].Sign, ps[0].ID, false, append([]byte{' '}, body...)), pub(ps[0].Sign), ErrNotCanonical)
	extra := append(bytes.Clone(body[:len(body)-1]), []byte(`,"extra":1}`)...)
	anchorErr(t, "unknown field", handSign(ps[0].Sign, ps[0].ID, false, extra), pub(ps[0].Sign), ErrDecode)
	anchorErr(t, "data after the object", handSign(ps[0].Sign, ps[0].ID, false, append(bytes.Clone(body), "{}"...)), pub(ps[0].Sign), ErrDecode)
	noAdmins := clone(r)
	noAdmins.Admins = nil
	unchecked, err := json.Marshal(noAdmins)
	if err != nil {
		t.Fatal(err)
	}
	anchorErr(t, "roster without admins", handSign(ps[0].Sign, ps[0].ID, false, unchecked), pub(ps[0].Sign), ErrNoPrimary)

	// Sizes are checked before anything else.
	anchorErr(t, "empty body", Signed{SignerID: ps[0].ID, Sig: s.Sig}, pub(ps[0].Sign), ErrFormat)
	anchorErr(t, "short signature", Signed{Body: body, SignerID: ps[0].ID, Sig: s.Sig[:63]}, pub(ps[0].Sign), ErrFormat)
	huge := handSign(ps[0].Sign, ps[0].ID, false, bytes.Repeat([]byte{'x'}, MaxBodySize+1))
	anchorErr(t, "body over MaxBodySize", huge, pub(ps[0].Sign), ErrTooLarge)

	// The largest version is no problem for an anchored roster.
	top := clone(r)
	top.Version = math.MaxUint64
	if _, err := mustSign(t, top, ps[0]).VerifyAnchored(pub(ps[0].Sign)); err != nil {
		t.Errorf("version MaxUint64: %v", err)
	}
}
