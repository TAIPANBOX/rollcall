package roster

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/TAIPANBOX/rollcall/internal/ids"
	"github.com/TAIPANBOX/rollcall/internal/sig"
)

// The format, written out here so that a change in the package shows as a
// red test instead of passing on both sides.
const (
	fmtKind      = "rollcall/v1/roster\x00" // prefix of the signed bytes
	fmtHashLabel = "rollcall/v1 roster hash\x00"
)

// party is one test member with deterministic keys.
type party struct {
	ID   ids.MemberID
	Name string
	Sign ed25519.PrivateKey
	Recv []byte // public receive key, MLKEM768-X25519
}

var (
	partiesOnce sync.Once
	parties     []party
	recoveryKey ed25519.PrivateKey // the group's recovery key in every fixture
	otherKey    ed25519.PrivateKey // a key that belongs to nobody in any fixture
)

// testParties returns 40 parties with fixed keys; party i has ID byte 0 = i+1.
func testParties() []party {
	partiesOnce.Do(func() {
		kem := hpke.MLKEM768X25519()
		for i := 0; i < 40; i++ {
			var id ids.MemberID
			id[0] = byte(i + 1)
			id[15] = 0x5a
			seed := bytes.Repeat([]byte{byte(i + 1)}, ed25519.SeedSize)
			recv, err := kem.DeriveKeyPair(append([]byte("recv"), seed...))
			if err != nil {
				panic(err)
			}
			parties = append(parties, party{
				ID:   id,
				Name: fmt.Sprintf("member-%02d", i+1),
				Sign: ed25519.NewKeyFromSeed(seed),
				Recv: recv.PublicKey().Bytes(),
			})
		}
		recoveryKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0xee}, ed25519.SeedSize))
		otherKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0xdd}, ed25519.SeedSize))
	})
	return parties
}

// pub returns a fresh copy of the public half of k.
func pub(k ed25519.PrivateKey) []byte {
	return bytes.Clone(k.Public().(ed25519.PublicKey))
}

// base returns a valid genesis roster of n members: member 0 is the primary
// and a sender, member 1 the backup, every other even member a sender, the
// odd ones ordinary members with no roles.
func base(n int) Roster {
	ps := testParties()
	r := Roster{Version: 1, Site: "home", RecoveryPub: pub(recoveryKey)}
	for i := 0; i < n; i++ {
		m := Member{ID: ps[i].ID, Name: ps[i].Name, SignPub: pub(ps[i].Sign), RecvPub: bytes.Clone(ps[i].Recv)}
		switch {
		case i == 0:
			m.Roles = []Role{RolePrimary, RoleSender}
		case i == 1:
			m.Roles = []Role{RoleBackup}
		case i%2 == 0:
			m.Roles = []Role{RoleSender}
		}
		r.Members = append(r.Members, m)
	}
	if n >= 1 {
		r.Admins = []ids.MemberID{ps[0].ID}
	}
	if n >= 2 {
		r.Admins = append(r.Admins, ps[1].ID)
	}
	return r
}

// clone returns a deep copy of r.
func clone(r Roster) Roster {
	c := r
	if r.Members != nil {
		c.Members = make([]Member, len(r.Members))
		for i, m := range r.Members {
			m.SignPub = bytes.Clone(m.SignPub)
			m.RecvPub = bytes.Clone(m.RecvPub)
			m.Roles = slices.Clone(m.Roles)
			c.Members[i] = m
		}
	}
	c.Admins = slices.Clone(r.Admins)
	c.RecoveryPub = bytes.Clone(r.RecoveryPub)
	return c
}

// next returns a copy of r as the version after the one prev carries.
func next(r Roster, prev Signed) Roster {
	c := clone(r)
	c.Version++
	c.Prev = prev.Hash()
	return c
}

// mustSign signs r as the admin p.
func mustSign(t testing.TB, r Roster, p party) Signed {
	t.Helper()
	s, err := SignRoster(r, p.ID, p.Sign, false)
	if err != nil {
		t.Fatalf("SignRoster as %s: %v", p.Name, err)
	}
	return s
}

// mustSignRecovery signs r with the recovery key k.
func mustSignRecovery(t testing.TB, r Roster, k ed25519.PrivateKey) Signed {
	t.Helper()
	s, err := SignRoster(r, ids.MemberID{}, k, true)
	if err != nil {
		t.Fatalf("SignRoster with the recovery key: %v", err)
	}
	return s
}

// handMessage builds the signed bytes without the package: the kind prefix,
// the signer ID, the recovery byte and the body.
func handMessage(signer ids.MemberID, recovery bool, body []byte) []byte {
	m := []byte(fmtKind)
	m = append(m, signer[:]...)
	if recovery {
		m = append(m, 1)
	} else {
		m = append(m, 0)
	}
	return append(m, body...)
}

// handSign signs body as the package would, but without it.
func handSign(k ed25519.PrivateKey, signer ids.MemberID, recovery bool, body []byte) Signed {
	return Signed{
		Body:     bytes.Clone(body),
		SignerID: signer,
		Recovery: recovery,
		Sig:      ed25519.Sign(k, handMessage(signer, recovery, body)),
	}
}

// handHash computes Signed.Hash without the package.
func handHash(s Signed) ids.Hash {
	var b []byte
	b = append(b, fmtHashLabel...)
	b = binary.BigEndian.AppendUint64(b, uint64(len(s.Body)))
	b = append(b, s.Body...)
	b = append(b, s.SignerID[:]...)
	if s.Recovery {
		b = append(b, 1)
	} else {
		b = append(b, 0)
	}
	b = binary.BigEndian.AppendUint64(b, uint64(len(s.Sig)))
	b = append(b, s.Sig...)
	return ids.Hash(sha256.Sum256(b))
}

// allErrors lists every sentinel of the package except ErrName, which the
// name errors wrap.
var allErrors = []error{
	ErrVersionZero, ErrSite, ErrMemberCount, ErrMemberID, ErrDuplicateID,
	ErrMemberName, ErrDuplicateName, ErrSignKey, ErrRecvKey, ErrRecoveryKey,
	ErrDuplicateKey, ErrRole, ErrNoPrimary, ErrTwoPrimaries, ErrTooManyAdmins,
	ErrAdminNotMember, ErrDuplicateAdmin, ErrRoleMismatch, ErrOwnerConfirmed,
	ErrFormat, ErrTooLarge, ErrSigner, ErrNotAdmin, ErrSignature, ErrDecode,
	ErrNotCanonical, ErrNoPrev, ErrVersion, ErrPrevHash, ErrPrev,
	ErrRecoveryChanged, ErrKey,
}

// checkErr fails unless err is want and no other sentinel of the package
// besides those in also.
func checkErr(t *testing.T, what string, err, want error, also ...error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Errorf("%s: err = %v, want %v", what, err, want)
		return
	}
	for _, e := range allErrors {
		if e != want && !slices.Contains(also, e) && errors.Is(err, e) {
			t.Errorf("%s: err = %v, which also matches %q", what, err, e)
		}
	}
}

// verifyErr runs s.Verify(prev) and requires the error want and a zero
// roster.
func verifyErr(t *testing.T, what string, s Signed, prev *Signed, want error, also ...error) {
	t.Helper()
	got, err := s.Verify(prev)
	checkErr(t, what, err, want, also...)
	if !reflect.DeepEqual(got, Roster{}) {
		t.Errorf("%s: Verify returned a roster together with the error", what)
	}
}

// verifyOK runs s.Verify(prev) and requires exactly want back.
func verifyOK(t *testing.T, what string, s Signed, prev *Signed, want Roster) {
	t.Helper()
	got, err := s.Verify(prev)
	if err != nil {
		t.Errorf("%s: Verify = %v, want success", what, err)
		return
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s: Verify returned\n%+v\nwant\n%+v", what, got, want)
	}
}

// memberIndex returns the index of the member with id in r.
func memberIndex(r Roster, id ids.MemberID) int {
	for i := range r.Members {
		if r.Members[i].ID == id {
			return i
		}
	}
	panic("no such member")
}

func TestConstants(t *testing.T) {
	if MaxAdmins != 2 || MaxMembers != 32 || MaxNameLen != 32 || MaxBodySize != 128<<10 {
		t.Errorf("MaxAdmins %d, MaxMembers %d, MaxNameLen %d, MaxBodySize %d; want 2, 32, 32, 131072",
			MaxAdmins, MaxMembers, MaxNameLen, MaxBodySize)
	}
	if RoleSender != "sender" || RolePrimary != "primary" || RoleBackup != "backup" {
		t.Errorf("roles %q %q %q, want sender primary backup", RoleSender, RolePrimary, RoleBackup)
	}
}

// smallOrder is the encoding of the identity point, a small-order Ed25519 key.
var smallOrder = append([]byte{1}, make([]byte, 31)...)

// TestRosterShape is the shape table of the brief plus the rulings: each
// invalid roster has exactly one fault and is refused with its own error.
func TestRosterShape(t *testing.T) {
	ps := testParties()
	valid := []struct {
		name string
		r    Roster
	}{
		{"one member, the primary", base(1)},
		{"primary and backup", base(2)},
		{"three members", base(3)},
		{"32 members", base(32)},
		{"primary only, others ordinary", func() Roster {
			r := base(3)
			r.Admins = r.Admins[:1]
			r.Members[1].Roles = nil
			return r
		}()},
		{"backup is a sender too", func() Roster {
			r := base(3)
			r.Members[1].Roles = []Role{RoleSender, RoleBackup}
			return r
		}()},
		{"no sender at all", func() Roster {
			r := base(3)
			r.Members[0].Roles = []Role{RolePrimary}
			r.Members[2].Roles = nil
			return r
		}()},
		{"backup listed first in the members", func() Roster {
			r := base(3)
			r.Members[0], r.Members[1] = r.Members[1], r.Members[0]
			return r
		}()},
		{"takeover", func() Roster { r := base(3); r.Takeover = true; return r }()},
		{"takeover confirmed", func() Roster { r := base(3); r.Takeover = true; r.OwnerConfirmed = true; return r }()},
		{"largest version", func() Roster { r := base(3); r.Version = math.MaxUint64; return r }()},
		{"names of 32 characters", func() Roster {
			r := base(2)
			r.Site = strings.Repeat("s", 32)
			r.Members[0].Name = strings.Repeat("a", 32)
			return r
		}()},
	}
	for _, c := range valid {
		if err := c.r.Check(); err != nil {
			t.Errorf("%s: Check = %v, want nil", c.name, err)
		}
	}

	invalid := []struct {
		name string
		edit func(r *Roster)
		want error
		also []error
	}{
		{"version 0", func(r *Roster) { r.Version = 0 }, ErrVersionZero, nil},
		{"empty site", func(r *Roster) { r.Site = "" }, ErrSite, nil},
		{"site of 33 characters", func(r *Roster) { r.Site = strings.Repeat("s", 33) }, ErrSite, nil},
		{"site in Cyrillic", func(r *Roster) { r.Site = "\u041a\u0443\u0445\u043d\u044f" }, ErrSite, nil},
		{"no members", func(r *Roster) { r.Members = nil }, ErrMemberCount, nil},
		{"33 members", func(r *Roster) { *r = base(33) }, ErrMemberCount, nil},
		{"zero member ID", func(r *Roster) { r.Members[2].ID = ids.MemberID{} }, ErrMemberID, nil},
		{"duplicate IDs", func(r *Roster) { r.Members[2].ID = r.Members[1].ID }, ErrDuplicateID, nil},
		{"member name with a space", func(r *Roster) { r.Members[2].Name = "a b" }, ErrMemberName, nil},
		{"empty member name", func(r *Roster) { r.Members[2].Name = "" }, ErrMemberName, nil},
		{"member name with RLO", func(r *Roster) { r.Members[2].Name = "ap\u202e" }, ErrMemberName, nil},
		{"duplicate names", func(r *Roster) { r.Members[2].Name = r.Members[0].Name }, ErrDuplicateName, nil},
		{"signing key missing", func(r *Roster) { r.Members[2].SignPub = nil }, ErrSignKey, nil},
		{"signing key of 31 bytes", func(r *Roster) { r.Members[2].SignPub = r.Members[2].SignPub[:31] }, ErrSignKey, nil},
		{"signing key of 33 bytes", func(r *Roster) { r.Members[2].SignPub = append(r.Members[2].SignPub, 0) }, ErrSignKey, nil},
		{"signing key of small order", func(r *Roster) { r.Members[2].SignPub = bytes.Clone(smallOrder) }, ErrSignKey, nil},
		{"admin signing key of small order, sign bit set", func(r *Roster) {
			k := bytes.Clone(smallOrder)
			k[31] |= 0x80
			r.Members[0].SignPub = k
		}, ErrSignKey, nil},
		{"receive key missing", func(r *Roster) { r.Members[2].RecvPub = nil }, ErrRecvKey, nil},
		{"receive key one byte short", func(r *Roster) { r.Members[2].RecvPub = r.Members[2].RecvPub[:1215] }, ErrRecvKey, nil},
		{"receive key one byte long", func(r *Roster) { r.Members[2].RecvPub = append(r.Members[2].RecvPub, 0) }, ErrRecvKey, nil},
		{"receive key is an X25519 key alone", func(r *Roster) { r.Members[2].RecvPub = r.Members[2].RecvPub[1184:] }, ErrRecvKey, nil},
		{"receive key with a bad ML-KEM part", func(r *Roster) {
			for i := 0; i < 1184; i++ {
				r.Members[2].RecvPub[i] = 0xff
			}
		}, ErrRecvKey, nil},
		{"recovery key missing", func(r *Roster) { r.RecoveryPub = nil }, ErrRecoveryKey, nil},
		{"recovery key of 31 bytes", func(r *Roster) { r.RecoveryPub = r.RecoveryPub[:31] }, ErrRecoveryKey, nil},
		{"recovery key of small order", func(r *Roster) { r.RecoveryPub = bytes.Clone(smallOrder) }, ErrRecoveryKey, nil},
		{"two members share a signing key", func(r *Roster) { r.Members[2].SignPub = bytes.Clone(r.Members[0].SignPub) }, ErrDuplicateKey, nil},
		{"two members share a receive key", func(r *Roster) { r.Members[2].RecvPub = bytes.Clone(r.Members[1].RecvPub) }, ErrDuplicateKey, nil},
		{"recovery key is the primary's signing key", func(r *Roster) { r.RecoveryPub = bytes.Clone(r.Members[0].SignPub) }, ErrDuplicateKey, nil},
		{"recovery key is a member's signing key", func(r *Roster) { r.RecoveryPub = bytes.Clone(r.Members[2].SignPub) }, ErrDuplicateKey, nil},
		{"unknown role", func(r *Roster) { r.Members[2].Roles = []Role{"admin"} }, ErrRole, nil},
		{"empty role", func(r *Roster) { r.Members[2].Roles = []Role{""} }, ErrRole, nil},
		{"role in capitals", func(r *Roster) { r.Members[2].Roles = []Role{"Sender"} }, ErrRole, nil},
		{"role twice", func(r *Roster) { r.Members[2].Roles = []Role{RoleSender, RoleSender} }, ErrRole, nil},
		{"admin role twice", func(r *Roster) { r.Members[0].Roles = []Role{RolePrimary, RoleSender, RolePrimary} }, ErrRole, nil},
		{"no admins", func(r *Roster) { r.Admins = nil }, ErrNoPrimary, nil},
		{"nobody has the primary role", func(r *Roster) {
			r.Admins = r.Admins[:1]
			r.Members[0].Roles = []Role{RoleSender}
			r.Members[1].Roles = nil
		}, ErrNoPrimary, nil},
		{"two primaries", func(r *Roster) { r.Members[1].Roles = []Role{RolePrimary} }, ErrTwoPrimaries, nil},
		{"two primaries, one admin listed", func(r *Roster) {
			r.Admins = r.Admins[:1]
			r.Members[1].Roles = []Role{RolePrimary}
		}, ErrTwoPrimaries, nil},
		{"backup also primary", func(r *Roster) { r.Members[1].Roles = []Role{RoleBackup, RolePrimary} }, ErrTwoPrimaries, nil},
		{"three admins", func(r *Roster) {
			r.Admins = append(r.Admins, r.Members[2].ID)
			r.Members[2].Roles = []Role{RoleBackup}
		}, ErrTooManyAdmins, nil},
		{"admin is not a member", func(r *Roster) { r.Admins[1] = ps[39].ID }, ErrAdminNotMember, nil},
		{"admin ID is zero", func(r *Roster) { r.Admins[1] = ids.MemberID{} }, ErrAdminNotMember, nil},
		{"primary is not a member", func(r *Roster) { r.Admins[0] = ps[39].ID }, ErrAdminNotMember, nil},
		{"admin listed twice", func(r *Roster) { r.Admins[1] = r.Admins[0] }, ErrDuplicateAdmin, nil},
		{"primary role on the backup admin", func(r *Roster) {
			r.Members[0].Roles = []Role{RoleBackup}
			r.Members[1].Roles = []Role{RolePrimary}
		}, ErrRoleMismatch, nil},
		{"primary role on a member who is not Admins[0]", func(r *Roster) {
			r.Admins = r.Admins[:1]
			r.Members[0].Roles = []Role{RoleSender}
			r.Members[1].Roles = nil
			r.Members[2].Roles = []Role{RolePrimary}
		}, ErrRoleMismatch, nil},
		{"backup role on an ordinary member", func(r *Roster) { r.Members[2].Roles = []Role{RoleBackup} }, ErrRoleMismatch, nil},
		{"backup admin without the backup role", func(r *Roster) { r.Members[1].Roles = []Role{RoleSender} }, ErrRoleMismatch, nil},
		{"primary also has the backup role", func(r *Roster) { r.Members[0].Roles = []Role{RolePrimary, RoleBackup} }, ErrRoleMismatch, nil},
		{"backup role without a backup admin", func(r *Roster) { r.Admins = r.Admins[:1] }, ErrRoleMismatch, nil},
		{"owner confirmed without takeover", func(r *Roster) { r.OwnerConfirmed = true }, ErrOwnerConfirmed, nil},
	}
	for _, c := range invalid {
		r := base(3)
		c.edit(&r)
		checkErr(t, c.name, r.Check(), c.want, c.also...)
	}
}

// TestShapeErrorsDistinct checks that the faults named by the brief give six
// different errors.
func TestShapeErrorsDistinct(t *testing.T) {
	edits := map[string]func(r *Roster){
		"no primary":           func(r *Roster) { r.Admins = nil },
		"two primaries":        func(r *Roster) { r.Members[1].Roles = []Role{RolePrimary} },
		"three admins":         func(r *Roster) { r.Admins = append(r.Admins, r.Members[2].ID); r.Members[2].Roles = []Role{RoleBackup} },
		"missing recovery key": func(r *Roster) { r.RecoveryPub = nil },
		"33 members":           func(r *Roster) { *r = base(33) },
		"duplicate IDs":        func(r *Roster) { r.Members[2].ID = r.Members[0].ID },
	}
	seen := map[string]string{}
	for name, edit := range edits {
		r := base(3)
		edit(&r)
		err := r.Check()
		if err == nil {
			t.Errorf("%s: Check accepted it", name)
			continue
		}
		var kind string
		for _, e := range allErrors {
			if errors.Is(err, e) {
				kind = e.Error()
			}
		}
		if other, dup := seen[kind]; dup {
			t.Errorf("%s and %s give the same error %q", name, other, kind)
		}
		seen[kind] = name
	}
}

// TestShapeErrorsCarryNoHostileText checks that refusing a hostile name or
// role does not copy it into the error.
func TestShapeErrorsCarryNoHostileText(t *testing.T) {
	hostile := "ap\u202e<script>"
	for _, edit := range []func(r *Roster){
		func(r *Roster) { r.Site = hostile },
		func(r *Roster) { r.Members[2].Name = hostile },
		func(r *Roster) { r.Members[2].Roles = []Role{Role(hostile)} },
	} {
		r := base(3)
		edit(&r)
		err := r.Check()
		if err == nil {
			t.Fatal("Check accepted a hostile string")
		}
		if msg := err.Error(); !isPlainASCII(msg) || strings.Contains(msg, "<script>") {
			t.Errorf("error %+q carries the hostile text", msg)
		}
	}
}

// TestSignVerifyGenesis covers version 1: self-signed by the primary, or
// signed by the recovery key, and nobody else.
func TestSignVerifyGenesis(t *testing.T) {
	ps := testParties()
	r := base(3)
	s := mustSign(t, r, ps[0])
	if s.SignerID != ps[0].ID || s.Recovery || len(s.Sig) != ed25519.SignatureSize {
		t.Errorf("Signed = signer %v recovery %v sig %d bytes; want the primary, false, 64", s.SignerID, s.Recovery, len(s.Sig))
	}
	verifyOK(t, "genesis by the primary", s, nil, r)
	verifyOK(t, "genesis by the recovery key", mustSignRecovery(t, r, recoveryKey), nil, r)
	verifyOK(t, "genesis of one member", mustSign(t, base(1), ps[0]), nil, base(1))

	verifyErr(t, "genesis by the backup", mustSign(t, r, ps[1]), nil, ErrNotAdmin)
	verifyErr(t, "genesis by an ordinary member", mustSign(t, r, ps[2]), nil, ErrNotAdmin)
	verifyErr(t, "genesis by a stranger", mustSign(t, r, ps[39]), nil, ErrNotAdmin)
	verifyErr(t, "genesis by a key other than the roster's recovery key", mustSignRecovery(t, r, otherKey), nil, ErrSignature)

	forged := s
	forged.Sig = ed25519.Sign(ps[1].Sign, handMessage(ps[0].ID, false, s.Body))
	verifyErr(t, "genesis naming the primary, signed by the backup's key", forged, nil, ErrSignature)

	withPrev := clone(r)
	withPrev.Prev[0] = 1
	verifyErr(t, "genesis with a previous hash", mustSign(t, withPrev, ps[0]), nil, ErrPrevHash)

	v2 := clone(r)
	v2.Version = 2
	verifyErr(t, "version 2 without the previous roster", mustSign(t, v2, ps[0]), nil, ErrNoPrev)

	// A genesis body names its own signer; one whose primary is missing from
	// the members, or that has no admins at all, has no key to verify with.
	noKey := clone(r)
	noKey.Admins[0] = ps[39].ID
	body, _ := json.Marshal(noKey)
	verifyErr(t, "genesis whose primary is not a member", handSign(ps[39].Sign, ps[39].ID, false, body), nil, ErrNotAdmin)
	noAdmins := clone(r)
	noAdmins.Admins = nil
	body, _ = json.Marshal(noAdmins)
	verifyErr(t, "genesis without admins", handSign(ps[0].Sign, ps[0].ID, false, body), nil, ErrNotAdmin)
}

// TestVerifyChain is the brief's chain test: the version must be the
// previous one plus one and Prev must be the previous Signed's hash.
func TestVerifyChain(t *testing.T) {
	ps := testParties()
	r1 := base(3)
	s1 := mustSign(t, r1, ps[0])

	r2 := next(r1, s1)
	r2.Members = append(r2.Members, base(4).Members[3])
	s2 := mustSign(t, r2, ps[0])
	verifyOK(t, "version 2 by the primary", s2, &s1, r2)

	r3 := next(r2, s2)
	r3.Members[3].Roles = []Role{RoleSender}
	s3 := mustSign(t, r3, ps[1])
	verifyOK(t, "version 3 by the backup", s3, &s2, r3)

	equal := next(r1, s1)
	equal.Version = 1
	verifyErr(t, "version equal to the previous", mustSign(t, equal, ps[0]), &s1, ErrVersion)

	skip := next(r1, s1)
	skip.Version = 3
	verifyErr(t, "version previous plus two", mustSign(t, skip, ps[0]), &s1, ErrVersion)

	verifyErr(t, "version 2 against version 3", s2, &s3, ErrVersion)
	verifyErr(t, "version 1 against version 2", s1, &s2, ErrVersion)
	verifyErr(t, "version 2 against itself", s2, &s2, ErrVersion)
	verifyErr(t, "version 3 straight after version 1", s3, &s1, ErrVersion)

	badPrev := func(name string, r Roster, prev Signed, h ids.Hash) {
		rr := next(r, prev)
		rr.Prev = h
		verifyErr(t, "previous hash "+name, mustSign(t, rr, ps[0]), &prev, ErrPrevHash)
	}
	flipped := s1.Hash()
	flipped[31] ^= 1
	badPrev("zero", r1, s1, ids.Hash{})
	badPrev("with one bit flipped", r1, s1, flipped)
	badPrev("is SHA-256 of the body only", r1, s1, sha256.Sum256(s1.Body))
	badPrev("is of the same body signed by the recovery key", r1, s1, mustSignRecovery(t, r1, recoveryKey).Hash())
	badPrev("is of the version before the previous", r2, s2, s1.Hash())

	verifyErr(t, "version 2 with no previous roster", s2, nil, ErrNoPrev)

	// The previous roster at the largest version: nothing can follow it.
	top := clone(r1)
	top.Version = math.MaxUint64
	sTop := mustSign(t, top, ps[0])
	for _, v := range []uint64{1, 2, math.MaxUint64} {
		after := next(top, sTop)
		after.Version = v
		verifyErr(t, fmt.Sprintf("version %d after the largest version", v), mustSign(t, after, ps[0]), &sTop, ErrVersion)
	}
}

// TestVerifyLeavesForksToPrefer pins that Verify judges one link: two
// different version-2 rosters, each signed by an admin of version 1, both
// verify; choosing between them is Task 8's Prefer.
func TestVerifyLeavesForksToPrefer(t *testing.T) {
	ps := testParties()
	r1 := base(3)
	s1 := mustSign(t, r1, ps[0])
	a := next(r1, s1)
	a.Members[2].Roles = nil
	b := next(r1, s1)
	b.Takeover = true
	verifyOK(t, "fork a by the primary", mustSign(t, a, ps[0]), &s1, a)
	verifyOK(t, "fork b by the backup", mustSign(t, b, ps[1]), &s1, b)
}

// TestVerifyAuthority is the brief's authority test plus the rulings: the
// signer's authority and key come from the previous roster, never from the
// new one, except at genesis.
func TestVerifyAuthority(t *testing.T) {
	ps := testParties()
	r1 := base(3)
	s1 := mustSign(t, r1, ps[0])
	r2 := next(r1, s1)
	r2.Members[2].Roles = nil

	verifyOK(t, "signed by the primary", mustSign(t, r2, ps[0]), &s1, r2)
	verifyOK(t, "signed by the backup", mustSign(t, r2, ps[1]), &s1, r2)
	verifyOK(t, "signed by the recovery key", mustSignRecovery(t, r2, recoveryKey), &s1, r2)
	verifyErr(t, "signed by an ordinary member", mustSign(t, r2, ps[2]), &s1, ErrNotAdmin)
	verifyErr(t, "signed by a stranger", mustSign(t, r2, ps[39]), &s1, ErrNotAdmin)
	verifyErr(t, "signed by a key that is not the recovery key", mustSignRecovery(t, r2, otherKey), &s1, ErrSignature)

	// A member made backup by the new roster has no authority over it.
	promote := next(r1, s1)
	promote.Admins = []ids.MemberID{ps[0].ID, ps[2].ID}
	promote.Members[1].Roles = nil
	promote.Members[2].Roles = []Role{RoleBackup, RoleSender}
	if err := promote.Check(); err != nil {
		t.Fatalf("promote fixture: %v", err)
	}
	verifyErr(t, "signed by the member it makes backup", mustSign(t, promote, ps[2]), &s1, ErrNotAdmin)
	verifyOK(t, "the same promotion by the primary", mustSign(t, promote, ps[0]), &s1, promote)

	// A member made primary by a stranger's genesis-style roster: the new
	// roster names a newcomer as primary and the newcomer signs it.
	coup := next(r1, s1)
	coup.Members = append(coup.Members, Member{ID: ps[39].ID, Name: ps[39].Name, SignPub: pub(ps[39].Sign), RecvPub: bytes.Clone(ps[39].Recv), Roles: []Role{RolePrimary}})
	coup.Members[0].Roles = []Role{RoleSender}
	coup.Admins = []ids.MemberID{ps[39].ID}
	coup.Members[1].Roles = nil
	if err := coup.Check(); err != nil {
		t.Fatalf("coup fixture: %v", err)
	}
	verifyErr(t, "signed by the newcomer it makes primary", mustSign(t, coup, ps[39]), &s1, ErrNotAdmin)

	// An admin removed by the new roster still signs it: authority is the
	// previous roster's.
	drop := next(r1, s1)
	drop.Members = slices.Delete(drop.Members, 1, 2)
	drop.Admins = drop.Admins[:1]
	verifyOK(t, "signed by the backup it removes", mustSign(t, drop, ps[1]), &s1, drop)

	// An admin key changed by the new roster: the old key signs, the new one
	// does not.
	rekey := next(r1, s1)
	rekey.Members[1].SignPub = pub(otherKey)
	verifyOK(t, "new backup key, signed with the old one", mustSign(t, rekey, ps[1]), &s1, rekey)
	verifyErr(t, "new backup key, signed with the new one", mustSign(t, rekey, party{ID: ps[1].ID, Sign: otherKey}), &s1, ErrSignature)

	// A recovery key named by the new roster has no authority over it.
	stolen := next(r1, s1)
	stolen.RecoveryPub = pub(otherKey)
	verifyErr(t, "recovery key replaced and used at once", mustSignRecovery(t, stolen, otherKey), &s1, ErrSignature)
	verifyOK(t, "recovery key replaced by the old recovery key", mustSignRecovery(t, stolen, recoveryKey), &s1, stolen)
	verifyErr(t, "recovery key replaced by the primary", mustSign(t, stolen, ps[0]), &s1, ErrRecoveryChanged)
	verifyErr(t, "recovery key replaced by the backup", mustSign(t, stolen, ps[1]), &s1, ErrRecoveryChanged)

	// The signer ID and the recovery flag are part of what is signed.
	s := mustSign(t, r2, ps[0])
	asBackup := s
	asBackup.SignerID = ps[1].ID
	verifyErr(t, "primary's signature relabelled as the backup's", asBackup, &s1, ErrSignature)
	backupKey := s
	backupKey.Sig = ed25519.Sign(ps[1].Sign, handMessage(ps[0].ID, false, s.Body))
	verifyErr(t, "names the primary, signed by the backup", backupKey, &s1, ErrSignature)
	bodyOnly := s
	bodyOnly.Sig = ed25519.Sign(ps[0].Sign, append([]byte(fmtKind), s.Body...))
	verifyErr(t, "primary's signature over the body alone", bodyOnly, &s1, ErrSignature)
	rec := mustSignRecovery(t, r2, recoveryKey)
	recNoFlag := handSign(recoveryKey, ids.MemberID{}, true, rec.Body)
	recNoFlag.Sig = ed25519.Sign(recoveryKey, handMessage(ids.MemberID{}, false, rec.Body))
	verifyErr(t, "recovery signature made without the recovery byte", recNoFlag, &s1, ErrSignature)

	// Signer ID and recovery flag must agree.
	zeroSigner := handSign(ps[0].Sign, ids.MemberID{}, false, s.Body)
	verifyErr(t, "no signer and no recovery flag", zeroSigner, &s1, ErrSigner)
	recWithSigner := handSign(recoveryKey, ps[0].ID, true, s.Body)
	verifyErr(t, "recovery flag with a signer ID", recWithSigner, &s1, ErrSigner)
	verifyErr(t, "recovery flag with a signer ID, genesis", handSign(recoveryKey, ps[0].ID, true, s1.Body), nil, ErrSigner)
}

// TestVerifyFormat checks the cheap checks that come before the signature.
func TestVerifyFormat(t *testing.T) {
	ps := testParties()
	r1 := base(3)
	s1 := mustSign(t, r1, ps[0])
	s2 := mustSign(t, next(r1, s1), ps[0])

	for _, n := range []int{0, 1, 63, 65, 128} {
		bad := s2
		bad.Sig = make([]byte, n)
		verifyErr(t, fmt.Sprintf("signature of %d bytes", n), bad, &s1, ErrFormat)
	}
	empty := s2
	empty.Body = nil
	verifyErr(t, "empty body", empty, &s1, ErrFormat)
	verifyErr(t, "empty body, genesis", Signed{SignerID: ps[0].ID, Sig: s1.Sig}, nil, ErrFormat)

	big := s2
	big.Body = bytes.Repeat([]byte{' '}, MaxBodySize+1)
	verifyErr(t, "body one byte over the limit, bad signature", big, &s1, ErrTooLarge)
	verifyErr(t, "body one byte over the limit, genesis", big, nil, ErrTooLarge)
	signedBig := handSign(ps[0].Sign, ps[0].ID, false, big.Body)
	verifyErr(t, "body one byte over the limit, good signature", signedBig, &s1, ErrTooLarge)
	atLimit := s2
	atLimit.Body = bytes.Repeat([]byte{' '}, MaxBodySize)
	verifyErr(t, "body at the limit, bad signature", atLimit, &s1, ErrSignature)
}

// TestVerifyRejectsTampering flips bits in every part of a signed roster.
func TestVerifyRejectsTampering(t *testing.T) {
	ps := testParties()
	r1 := base(3)
	s1 := mustSign(t, r1, ps[0])
	s2 := mustSign(t, next(r1, s1), ps[0])

	for i := 0; i < len(s2.Body); i++ {
		if i > 64 && i < len(s2.Body)-64 && i%17 != 0 {
			continue
		}
		bad := s2
		bad.Body = bytes.Clone(s2.Body)
		bad.Body[i] ^= 1 << (i % 8)
		verifyErr(t, fmt.Sprintf("body byte %d flipped", i), bad, &s1, ErrSignature)
	}
	for i := 0; i < len(s2.Sig); i++ {
		bad := s2
		bad.Sig = bytes.Clone(s2.Sig)
		bad.Sig[i] ^= 0x80
		verifyErr(t, fmt.Sprintf("signature byte %d flipped", i), bad, &s1, ErrSignature)
	}
	short := s2
	short.Body = s2.Body[:len(s2.Body)-1]
	verifyErr(t, "body cut by one byte", short, &s1, ErrSignature)
	long := s2
	long.Body = append(bytes.Clone(s2.Body), ' ')
	verifyErr(t, "body with a byte added", long, &s1, ErrSignature)
	flag := s2
	flag.Recovery, flag.SignerID = true, ids.MemberID{}
	verifyErr(t, "admin signature presented as recovery", flag, &s1, ErrSignature)
}

// TestVerifyStrictBody signs non-canonical and malformed bodies with a real
// admin key: the signature verifies, and the body is still refused.
func TestVerifyStrictBody(t *testing.T) {
	ps := testParties()
	r1 := base(4)
	s1 := mustSign(t, r1, ps[0])
	r2 := next(r1, s1)
	canon := string(mustSign(t, r2, ps[0]).Body)

	// four characters into the first signing key
	key4 := strings.Index(canon, `"sign_pub":"`) + len(`"sign_pub":"`) + 4
	// the end of member-04's object, which has no roles
	m4 := strings.Index(canon, `"name":"member-04"`)
	m4end := m4 + strings.Index(canon[m4:], "}")
	firstAdmin := strings.Index(canon, `"admins":["`) + len(`"admins":["`)
	var reordered map[string]json.RawMessage
	if err := json.Unmarshal([]byte(canon), &reordered); err != nil {
		t.Fatal(err)
	}
	sorted, _ := json.Marshal(reordered)

	cases := []struct {
		name, body string
		want       error
	}{
		{"unknown field", canon[:len(canon)-1] + `,"extra":1}`, ErrDecode},
		{"unknown member field", strings.Replace(canon, `{"id":`, `{"x":1,"id":`, 1), ErrDecode},
		{"unknown field with RLO in its name", canon[:len(canon)-1] + `,"x\u202e":1}`, ErrDecode},
		{"a second object after it", canon + `{}`, ErrDecode},
		{"garbage after it", canon + `x`, ErrDecode},
		{"version as a fraction", strings.Replace(canon, `{"version":2,`, `{"version":2.0,`, 1), ErrDecode},
		{"version as a string", strings.Replace(canon, `{"version":2,`, `{"version":"2",`, 1), ErrDecode},
		{"negative version", strings.Replace(canon, `{"version":2,`, `{"version":-2,`, 1), ErrDecode},
		{"version beyond uint64", strings.Replace(canon, `{"version":2,`, `{"version":18446744073709551616,`, 1), ErrDecode},
		{"short member ID", strings.Replace(canon, `"admins":["`, `"admins":["00`, 1), ErrDecode},
		{"array", `[]`, ErrDecode},
		{"not JSON", `x`, ErrDecode},
		{"cut short", canon[:len(canon)-1], ErrDecode},
		{"trailing newline", canon + "\n", ErrNotCanonical},
		{"trailing space", canon + " ", ErrNotCanonical},
		{"leading space", " " + canon, ErrNotCanonical},
		{"space after a colon", strings.Replace(canon, `"site":"home"`, `"site": "home"`, 1), ErrNotCanonical},
		{"duplicate key", canon[:len(canon)-1] + `,"site":"other-site"}`, ErrNotCanonical},
		{"duplicate key, same value", canon[:len(canon)-1] + `,"site":"home"}`, ErrNotCanonical},
		{"field name in capitals", strings.Replace(canon, `"version":`, `"Version":`, 1), ErrNotCanonical},
		{"fields in another order", string(sorted), ErrNotCanonical},
		{"member ID in capitals", canon[:firstAdmin] + strings.ToUpper(canon[firstAdmin:firstAdmin+32]) + canon[firstAdmin+32:], ErrNotCanonical},
		{"empty roles written out", canon[:m4end] + `,"roles":[]` + canon[m4end:], ErrNotCanonical},
		{"null roles written out", canon[:m4end] + `,"roles":null` + canon[m4end:], ErrNotCanonical},
		{"escaped letter in the site", strings.Replace(canon, `"site":"home"`, `"site":"\u0068ome"`, 1), ErrNotCanonical},
		{"newline inside base64", canon[:key4] + `\n` + canon[key4:], ErrNotCanonical},
		{"null", `null`, ErrNotCanonical},
		{"empty object", `{}`, ErrNotCanonical},
	}
	for _, c := range cases {
		if c.body == canon {
			t.Fatalf("%s: the edit changed nothing", c.name)
		}
		verifyErr(t, c.name, handSign(ps[0].Sign, ps[0].ID, false, []byte(c.body)), &s1, c.want)
	}
	verifyOK(t, "the canonical body, signed by hand", handSign(ps[0].Sign, ps[0].ID, false, []byte(canon)), &s1, r2)
}

// TestVerifyChecksShape signs bodies of the wrong shape with a real admin
// key: Verify must run Check after the signature.
func TestVerifyChecksShape(t *testing.T) {
	ps := testParties()
	r1 := base(3)
	s1 := mustSign(t, r1, ps[0])

	cases := []struct {
		name string
		edit func(r *Roster)
		want error
	}{
		{"three admins", func(r *Roster) {
			r.Admins = append(r.Admins, r.Members[2].ID)
			r.Members[2].Roles = []Role{RoleBackup}
		}, ErrTooManyAdmins},
		{"owner confirmed without takeover", func(r *Roster) { r.OwnerConfirmed = true }, ErrOwnerConfirmed},
		{"recovery key of small order", func(r *Roster) { r.RecoveryPub = bytes.Clone(smallOrder) }, ErrRecoveryKey},
		{"two primaries", func(r *Roster) { r.Members[1].Roles = []Role{RolePrimary} }, ErrTwoPrimaries},
		{"unknown role", func(r *Roster) { r.Members[2].Roles = []Role{"root"} }, ErrRole},
		{"member signing key of small order", func(r *Roster) { r.Members[2].SignPub = bytes.Clone(smallOrder) }, ErrSignKey},
		{"bad receive key", func(r *Roster) { r.Members[2].RecvPub = r.Members[2].RecvPub[:100] }, ErrRecvKey},
	}
	for _, c := range cases {
		r2 := next(r1, s1)
		c.edit(&r2)
		body, err := json.Marshal(r2)
		if err != nil {
			t.Fatal(err)
		}
		verifyErr(t, c.name+", version 2", handSign(ps[0].Sign, ps[0].ID, false, body), &s1, c.want)

		g := clone(r1)
		c.edit(&g)
		body, _ = json.Marshal(g)
		verifyErr(t, c.name+", genesis", handSign(ps[0].Sign, ps[0].ID, false, body), nil, c.want)
	}
}

// TestVerifyBadPrevious checks that a previous roster that does not decode
// or has the wrong shape gives no authority at all.
func TestVerifyBadPrevious(t *testing.T) {
	ps := testParties()
	r1 := base(3)
	s1 := mustSign(t, r1, ps[0])
	s2 := mustSign(t, next(r1, s1), ps[0])

	garbage := s1
	garbage.Body = []byte("not a roster")
	verifyErr(t, "previous body is not JSON", s2, &garbage, ErrPrev, ErrDecode)

	spaced := s1
	spaced.Body = append(bytes.Clone(s1.Body), ' ')
	verifyErr(t, "previous body not canonical", s2, &spaced, ErrPrev, ErrNotCanonical)

	bad := clone(r1)
	bad.Admins = nil
	body, _ := json.Marshal(bad)
	badPrev := handSign(ps[0].Sign, ps[0].ID, false, body)
	verifyErr(t, "previous roster without admins", s2, &badPrev, ErrPrev, ErrNoPrimary)
}

// TestSignRosterRejects covers what SignRoster refuses to sign.
func TestSignRosterRejects(t *testing.T) {
	ps := testParties()
	r := base(3)
	before := clone(r)

	three := clone(r)
	three.Admins = append(three.Admins, three.Members[2].ID)
	three.Members[2].Roles = []Role{RoleBackup}
	s, err := SignRoster(three, ps[0].ID, ps[0].Sign, false)
	checkErr(t, "three admins", err, ErrTooManyAdmins)
	if !reflect.DeepEqual(s, Signed{}) {
		t.Error("three admins: SignRoster returned a Signed with the error")
	}

	mixed := append(bytes.Clone(ps[0].Sign[:32]), ps[1].Sign[32:]...)
	for _, c := range []struct {
		name string
		key  ed25519.PrivateKey
	}{
		{"nil key", nil},
		{"seed only", ps[0].Sign.Seed()},
		{"63 bytes", ps[0].Sign[:63]},
		{"65 bytes", append(bytes.Clone(ps[0].Sign), 0)},
		{"seed of one key, public half of another", mixed},
	} {
		s, err := SignRoster(r, ps[0].ID, c.key, false)
		checkErr(t, c.name, err, ErrKey)
		if !reflect.DeepEqual(s, Signed{}) {
			t.Errorf("%s: SignRoster returned a Signed with the error", c.name)
		}
	}

	s, err = SignRoster(r, ps[0].ID, recoveryKey, true)
	checkErr(t, "recovery flag with a signer ID", err, ErrSigner)
	if !reflect.DeepEqual(s, Signed{}) {
		t.Error("recovery flag with a signer ID: SignRoster returned a Signed")
	}
	s, err = SignRoster(r, ids.MemberID{}, ps[0].Sign, false)
	checkErr(t, "no signer and no recovery flag", err, ErrSigner)
	if !reflect.DeepEqual(s, Signed{}) {
		t.Error("no signer: SignRoster returned a Signed")
	}

	if !reflect.DeepEqual(r, before) {
		t.Error("SignRoster changed its roster")
	}
}

// TestWireFormat writes the body, the signed bytes and the hash out by hand.
func TestWireFormat(t *testing.T) {
	ps := testParties()
	r := base(2)
	r.Version = 7
	r.Prev = ids.Hash{0xab, 0xcd}
	r.Members[1].Roles = append(r.Members[1].Roles, RoleSender)
	r.Members = append(r.Members, base(4).Members[3]) // no roles
	r.Takeover = true

	b64 := base64.StdEncoding.EncodeToString
	member := func(p party, roles string) string {
		s := fmt.Sprintf(`{"id":"%s","name":"%s","sign_pub":"%s","recv_pub":"%s"`,
			hex.EncodeToString(p.ID[:]), p.Name, b64(pub(p.Sign)), b64(p.Recv))
		if roles != "" {
			s += `,"roles":` + roles
		}
		return s + "}"
	}
	want := `{"version":7,"prev":"abcd` + strings.Repeat("0", 60) + `","site":"home","members":[` +
		member(ps[0], `["primary","sender"]`) + "," +
		member(ps[1], `["backup","sender"]`) + "," +
		member(ps[3], "") +
		`],"admins":["` + hex.EncodeToString(ps[0].ID[:]) + `","` + hex.EncodeToString(ps[1].ID[:]) +
		`"],"recovery_pub":"` + b64(pub(recoveryKey)) + `","takeover":true,"owner_confirmed":false}`

	s := mustSign(t, r, ps[1])
	if string(s.Body) != want {
		t.Errorf("Body =\n%s\nwant\n%s", s.Body, want)
	}
	if !ed25519.Verify(pub(ps[1].Sign), handMessage(ps[1].ID, false, s.Body), s.Sig) {
		t.Error("admin signature is not Ed25519 over the kind prefix, signer ID, byte 0 and body")
	}
	if !sig.Verify(pub(ps[1].Sign), "roster", append(append(bytes.Clone(ps[1].ID[:]), 0), s.Body...), s.Sig) {
		t.Error("admin signature does not verify with sig.Verify as kind roster")
	}
	rec := mustSignRecovery(t, r, recoveryKey)
	if rec.SignerID != (ids.MemberID{}) || !rec.Recovery {
		t.Errorf("recovery Signed: signer %v recovery %v", rec.SignerID, rec.Recovery)
	}
	if !ed25519.Verify(pub(recoveryKey), handMessage(ids.MemberID{}, true, rec.Body), rec.Sig) {
		t.Error("recovery signature is not Ed25519 over the kind prefix, zero ID, byte 1 and body")
	}
	if got, want := s.Hash(), handHash(s); got != want {
		t.Errorf("Hash = %v, want %v", got, want)
	}
	if got, want := rec.Hash(), handHash(rec); got != want {
		t.Errorf("recovery Hash = %v, want %v", got, want)
	}
}

// TestSignedHash checks that every field of a Signed changes its hash and
// that the length prefixes keep the fields apart.
func TestSignedHash(t *testing.T) {
	ps := testParties()
	s := mustSign(t, base(3), ps[0])
	h := s.Hash()
	if h != handHash(s) {
		t.Fatalf("Hash = %v, want %v", h, handHash(s))
	}
	if s.Hash() != h {
		t.Error("Hash is not deterministic")
	}
	variants := map[string]Signed{
		"body bit": func() Signed { v := s; v.Body = bytes.Clone(s.Body); v.Body[10] ^= 1; return v }(),
		"signer":   func() Signed { v := s; v.SignerID = ps[1].ID; return v }(),
		"recovery": func() Signed { v := s; v.Recovery = true; return v }(),
		"sig bit":  func() Signed { v := s; v.Sig = bytes.Clone(s.Sig); v.Sig[63] ^= 1; return v }(),
		"last body byte moved into the signature": func() Signed {
			v := s
			v.Body = s.Body[:len(s.Body)-1]
			v.Sig = append([]byte{s.Body[len(s.Body)-1]}, s.Sig...)
			return v
		}(),
		"empty signature": func() Signed { v := s; v.Sig = nil; return v }(),
	}
	for name, v := range variants {
		if v.Hash() == h {
			t.Errorf("%s: hash unchanged", name)
		}
		if v.Hash() != handHash(v) {
			t.Errorf("%s: Hash differs from the hand-computed hash", name)
		}
	}
	// Body and signature boundaries: the same bytes split differently.
	a := Signed{Body: []byte("ab"), Sig: []byte("c")}
	b := Signed{Body: []byte("a"), Sig: []byte("bc")}
	if a.Hash() == b.Hash() {
		t.Error("moving a byte between body and signature does not change the hash")
	}
	if got := (Signed{}).Hash(); got != handHash(Signed{}) {
		t.Errorf("zero Signed: Hash = %v, want %v", got, handHash(Signed{}))
	}
}

// TestLargestRosterFits signs and verifies the largest roster Check allows
// and reports its size against MaxBodySize and the 64 KiB TCP frame.
func TestLargestRosterFits(t *testing.T) {
	ps := testParties()
	r := base(MaxMembers)
	r.Site = strings.Repeat("s", MaxNameLen)
	for i := range r.Members {
		r.Members[i].Name = fmt.Sprintf("%02d", i) + strings.Repeat("n", MaxNameLen-2)
		if !slices.Contains(r.Members[i].Roles, RoleSender) {
			r.Members[i].Roles = append(r.Members[i].Roles, RoleSender)
		}
	}
	r.Version = math.MaxUint64
	r.Takeover, r.OwnerConfirmed = true, true
	for i := range r.Prev {
		r.Prev[i] = 0xff
	}
	s := mustSign(t, r, ps[0])
	if len(s.Body) > MaxBodySize {
		t.Fatalf("largest body is %d bytes, over MaxBodySize %d", len(s.Body), MaxBodySize)
	}
	t.Logf("largest body %d bytes: %d under MaxBodySize, %d under a 65536-byte frame", len(s.Body), MaxBodySize-len(s.Body), 65536-len(s.Body))
	r.Prev = ids.Hash{}
	r.Version = 1
	verifyOK(t, "largest roster", mustSign(t, r, ps[0]), nil, r)
}
