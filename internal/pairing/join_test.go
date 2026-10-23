package pairing

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/mlkem"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/TAIPANBOX/rollcall/internal/epoch"
	"github.com/TAIPANBOX/rollcall/internal/identity"
	"github.com/TAIPANBOX/rollcall/internal/ids"
	"github.com/TAIPANBOX/rollcall/internal/roster"
)

// lowOrderX25519 are the X25519 public values whose shared secret is all
// zero for every private key: the points of order 1, 2, 4 and 8, their
// non-canonical encodings, and each again with the top bit set, which X25519
// ignores.
var lowOrderX25519 = []string{
	"0000000000000000000000000000000000000000000000000000000000000000",
	"0100000000000000000000000000000000000000000000000000000000000000",
	"e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
	"5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"0000000000000000000000000000000000000000000000000000000000000080",
	"0100000000000000000000000000000000000000000000000000000000000080",
	"e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b880",
	"5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f11d7",
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
}

func TestJoinRoundTrip(t *testing.T) {
	f := newFixture(t)
	token := &Secrets{BotToken: canary, ChatID: -1001234567890}
	c, resp, s2 := f.pair(t, token, roster.RoleSender)
	if len(resp) > MaxResponseSize {
		t.Fatalf("response is %d bytes, over MaxResponseSize", len(resp))
	}
	got, ek, sec, err := OpenJoinResponse(c, resp, f.joiner)
	if err != nil {
		t.Fatalf("OpenJoinResponse: %v", err)
	}
	if !reflect.DeepEqual(got, s2) {
		t.Errorf("roster differs from the one the admin signed")
	}
	if ek.ID != f.ek.ID || !bytes.Equal(ek.Secret, f.ek.Secret) || !ek.NotAfter.Equal(f.ek.NotAfter) || ek.NotAfter.Location() != time.UTC {
		t.Errorf("epoch key = %v, want %v", ek, f.ek)
	}
	if sec == nil || *sec != *token {
		t.Errorf("secrets = %v, want the token and chat ID", sec)
	}
	// The roster the joiner holds continues the group's chain: a member that
	// held version 1 accepts it.
	if _, err := got.Verify(&f.s1); err != nil {
		t.Errorf("the joiner's roster does not follow version 1: %v", err)
	}
	if bytes.Contains(resp, []byte(canary)) {
		t.Errorf("the response carries the bot token in the clear")
	}
}

// TestJoinBackupAdmin pairs through the backup admin, with its own code.
func TestJoinBackupAdmin(t *testing.T) {
	f := newFixture(t)
	inv := &Inviter{}
	c, err := inv.Open(t0, netip.MustParseAddrPort(fmtTestBootstrap), f.backup)
	if err != nil {
		t.Fatal(err)
	}
	req := f.accepted(t, inv, c)
	_, s2 := f.withJoiner(t, f.backup)
	resp, err := NewJoinResponse(req, s2, f.ek, nil, f.backup)
	if err != nil {
		t.Fatalf("NewJoinResponse by the backup: %v", err)
	}
	if c.AdminFP != handFP(pubOf(f.backup)) {
		t.Errorf("the backup's code does not carry the backup's fingerprint")
	}
	got, ek, _, err := OpenJoinResponse(c, resp, f.joiner)
	if err != nil {
		t.Fatalf("OpenJoinResponse: %v", err)
	}
	if !reflect.DeepEqual(got, s2) || !bytes.Equal(ek.Secret, f.ek.Secret) {
		t.Errorf("roster or epoch key differs from what the backup sent")
	}
	// The primary's code does not anchor the backup's response.
	_, primary := f.open(t)
	_, _, _, err = OpenJoinResponse(primary, resp, f.joiner)
	wantErr(t, "backup's response under the primary's code", err, ErrAdminFP)
}

// TestJoinRequestFormat pins the request layout: the key from the join
// secret, the associated data, and the plaintext fields.
func TestJoinRequestFormat(t *testing.T) {
	f := newFixture(t)
	_, c := f.open(t)
	blob, err := NewJoinRequest(c, f.joiner, "ap-garden")
	if err != nil {
		t.Fatal(err)
	}
	if blob[0] != 1 || len(blob) != 1+24+16+32+fmtRecvKeySize+len("ap-garden")+16 {
		t.Fatalf("request: version %d, %d bytes", blob[0], len(blob))
	}
	a, err := chacha20poly1305.NewX(handJoinKey(t, c.Secret))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := a.Open(nil, blob[1:25], blob[25:], handRequestAD(c))
	if err != nil {
		t.Fatalf("the request does not open with hkdf(secret, %q) and AD version|expires|fp: %v", fmtJoinLabel, err)
	}
	want := handRequestPlain(f.joiner.ID, pubOf(f.joiner), recvOf(f.joiner), "ap-garden")
	if !bytes.Equal(pt, want) {
		t.Errorf("plaintext is not member ID | sign key | receive key | name")
	}
	// Two requests never share a nonce.
	again, _ := NewJoinRequest(c, f.joiner, "ap-garden")
	if bytes.Equal(blob[1:25], again[1:25]) {
		t.Errorf("two requests used the same nonce")
	}

	// A request laid out by hand opens.
	req, err := OpenJoinRequest(c, handRequest(t, c, want))
	if err != nil {
		t.Fatalf("OpenJoinRequest of a hand-made request: %v", err)
	}
	if req.ID != f.joiner.ID || req.Name != "ap-garden" || !bytes.Equal(req.SignPub, pubOf(f.joiner)) || !bytes.Equal(req.RecvPub, recvOf(f.joiner)) {
		t.Errorf("OpenJoinRequest fields differ from the request")
	}
	if !bytes.Equal(req.binding[:], handBinding(t, c.Secret)) || req.adminFP != c.AdminFP || req.accepted {
		t.Errorf("OpenJoinRequest: binding, fingerprint or accepted flag wrong")
	}
}

func TestJoinWrongSecret(t *testing.T) {
	f := newFixture(t)
	_, c := f.open(t)
	other := c
	other.Secret[0] ^= 0x80
	blob, err := NewJoinRequest(other, f.joiner, "ap-garden")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenJoinRequest(c, blob); !errors.Is(err, ErrRequestAuth) {
		t.Errorf("another secret: err = %v, want ErrRequestAuth", err)
	}
	// The code's expiry and fingerprint are bound as associated data.
	good, err := NewJoinRequest(c, f.joiner, "ap-garden")
	if err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(c *Code){
		"other expiry":      func(c *Code) { c.Expires = c.Expires.Add(time.Second) },
		"other fingerprint": func(c *Code) { c.AdminFP[3] ^= 1 },
	} {
		w := c
		edit(&w)
		if _, err := OpenJoinRequest(w, good); !errors.Is(err, ErrRequestAuth) {
			t.Errorf("%s: err = %v, want ErrRequestAuth", name, err)
		}
	}
	if _, err := OpenJoinRequest(Code{}, good); !errors.Is(err, ErrInvalid) {
		t.Errorf("zero code: err = %v, want ErrInvalid", err)
	}
	// The bootstrap address is where to connect, not part of the request.
	moved := c
	moved.Bootstrap = netip.MustParseAddrPort("10.0.0.1:7432")
	if _, err := OpenJoinRequest(moved, good); err != nil {
		t.Errorf("bootstrap changed: %v", err)
	}
	// Every flipped bit is refused.
	for i := range good {
		bad := bytes.Clone(good)
		bad[i] ^= 0x01
		_, err := OpenJoinRequest(c, bad)
		if i == 0 {
			wantErr(t, "version flipped", err, ErrRequestFormat)
		} else if !errors.Is(err, ErrRequestAuth) {
			t.Fatalf("bit flipped at %d: err = %v, want ErrRequestAuth", i, err)
		}
	}
}

func TestJoinRequestSizes(t *testing.T) {
	f := newFixture(t)
	_, c := f.open(t)
	shortest := handRequest(t, c, handRequestPlain(f.joiner.ID, pubOf(f.joiner), recvOf(f.joiner), "a"))
	longest := handRequest(t, c, handRequestPlain(f.joiner.ID, pubOf(f.joiner), recvOf(f.joiner), strings.Repeat("z", 32)))
	if len(longest) != MaxRequestSize {
		t.Errorf("longest request %d bytes, MaxRequestSize %d", len(longest), MaxRequestSize)
	}
	for name, blob := range map[string][]byte{"shortest": shortest, "longest": longest} {
		if _, err := OpenJoinRequest(c, blob); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	v2 := bytes.Clone(shortest)
	v2[0] = 2
	for name, blob := range map[string][]byte{
		"nil":          nil,
		"version only": {1},
		"one short":    shortest[:len(shortest)-1],
		"one over":     append(bytes.Clone(longest), 0),
		"far over":     make([]byte, 1<<16),
		"version 2":    v2,
		"empty name":   handRequest(t, c, handRequestPlain(f.joiner.ID, pubOf(f.joiner), recvOf(f.joiner), "")),
		"name of 33":   handRequest(t, c, handRequestPlain(f.joiner.ID, pubOf(f.joiner), recvOf(f.joiner), strings.Repeat("z", 33))),
	} {
		if _, err := OpenJoinRequest(c, blob); !errors.Is(err, ErrRequestFormat) {
			t.Errorf("%s: err = %v, want ErrRequestFormat", name, err)
		}
	}
}

// withX25519 returns the joiner's receive key with its X25519 part replaced.
func withX25519(recv []byte, x []byte) []byte {
	k := bytes.Clone(recv)
	copy(k[fmtX25519Offset:], x)
	return k
}

func TestJoinRequestRejectsContent(t *testing.T) {
	f := newFixture(t)
	_, c := f.open(t)
	sign, recv := pubOf(f.joiner), recvOf(f.joiner)
	open := func(id ids.MemberID, s, r []byte, name string) error {
		_, err := OpenJoinRequest(c, handRequest(t, c, handRequestPlain(id, s, r, name)))
		return err
	}

	wantErr(t, "zero member ID", open(ids.MemberID{}, sign, recv, "ap-garden"), ErrMemberID)
	for _, name := range []string{"AP-garden", "-ap", "ap garden", "ap_garden", "ap\x00", "ap\xff"} {
		wantErr(t, fmt.Sprintf("name %q", name), open(f.joiner.ID, sign, recv, name), ErrName)
	}
	small := make([]byte, 32)
	small[0] = 1 // y = 1, the identity point
	wantErr(t, "small-order signing key", open(f.joiner.ID, small, recv, "ap-garden"), ErrSignKey)

	// ML-KEM part that does not decode (coefficient out of range).
	badKEM := bytes.Clone(recv)
	for i := 0; i < 12; i++ {
		badKEM[i] = 0xff
	}
	wantErr(t, "ML-KEM key out of range", open(f.joiner.ID, sign, badKEM, "ap-garden"), ErrRecvKey)

	// The X25519 part sits after the 1184-byte ML-KEM-768 encapsulation key.
	for _, h := range lowOrderX25519 {
		x, _ := hex.DecodeString(h)
		k := withX25519(recv, x)
		if _, err := hpke.MLKEM768X25519().NewPublicKey(k); err != nil {
			t.Fatalf("hpke refuses %s at parse time (%v); the test no longer tests pairing's check", h[:8], err)
		}
		if err := open(f.joiner.ID, sign, k, "ap-garden"); !errors.Is(err, ErrRecvKey) {
			t.Errorf("X25519 part %s...%s: err = %v, want ErrRecvKey", h[:8], h[56:], err)
		}
	}
	// A changed but valid X25519 part is fine: the check is not a comparison.
	other := newIdentity(t, 9).Recv.PublicKey().Bytes()
	if err := open(f.joiner.ID, sign, withX25519(recv, other[fmtX25519Offset:]), "ap-garden"); err != nil {
		t.Errorf("another valid X25519 part: %v", err)
	}
	if err := open(f.joiner.ID, sign, recv, strings.Repeat("a", 32)); err != nil {
		t.Errorf("name of 32: %v", err)
	}
}

func TestNewJoinRequestRejects(t *testing.T) {
	f := newFixture(t)
	_, c := f.open(t)
	if _, err := NewJoinRequest(Code{}, f.joiner, "ap-garden"); !errors.Is(err, ErrInvalid) {
		t.Errorf("zero code: err = %v, want ErrInvalid", err)
	}
	zeroID := *f.joiner
	zeroID.ID = ids.MemberID{}
	noRecv := *f.joiner
	noRecv.Recv = nil
	dh, err := hpke.DHKEM(ecdh.X25519()).GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	otherKEM := *f.joiner
	otherKEM.Recv = dh
	short := *f.joiner
	short.Sign = f.joiner.Sign[:32]
	for name, self := range map[string]*identity.Identity{
		"nil":            nil,
		"zero member ID": &zeroID,
		"no receive key": &noRecv,
		"X25519 only":    &otherKEM,
		"short sign key": &short,
	} {
		if _, err := NewJoinRequest(c, self, "ap-garden"); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
	}
	// A receive key held elsewhere (a hardware module, say) whose X25519
	// half presents a low-order point is refused before it is sent.
	for _, h := range lowOrderX25519[:2] {
		x, _ := hex.DecodeString(h)
		pt, err := ecdh.X25519().NewPublicKey(x)
		if err != nil {
			t.Fatal(err)
		}
		dk, err := mlkem.GenerateKey768()
		if err != nil {
			t.Fatal(err)
		}
		recv, err := hpke.NewHybridPrivateKey(dk, fixedExchanger{pt})
		if err != nil {
			t.Fatal(err)
		}
		hw := *f.joiner
		hw.Recv = recv
		if _, err := NewJoinRequest(c, &hw, "ap-garden"); !errors.Is(err, ErrRecvKey) {
			t.Errorf("own X25519 part %s...: err = %v, want ErrRecvKey", h[:8], err)
		}
	}
	for _, name := range []string{"", "AP", strings.Repeat("a", 33), "-x"} {
		if _, err := NewJoinRequest(c, f.joiner, name); !errors.Is(err, ErrName) || !errors.Is(err, roster.ErrName) {
			t.Errorf("name %q: err = %v, want ErrName wrapping roster.ErrName", name, err)
		}
	}
}

func TestJoinResponseFormat(t *testing.T) {
	f := newFixture(t)
	token := &Secrets{BotToken: canary, ChatID: 42}
	c, resp, s2 := f.pair(t, token, roster.RoleSender)
	pt := handOpenResponse(t, resp, f.joiner, pubOf(f.admin))
	want := handPayload(handBinding(t, c.Secret), f.ek, token, s2)
	if !bytes.Equal(pt, want) {
		t.Errorf("payload is not binding | epoch key | secrets | roster signer | roster sig | body")
	}
	if len(resp) != fmtRespHeader+fmtEncSize+len(want)+16+fmtSigSize {
		t.Errorf("response is %d bytes, want %d", len(resp), fmtRespHeader+fmtEncSize+len(want)+16+fmtSigSize)
	}
	// A response laid out by hand opens.
	hand := handResponse(t, f.admin.Sign, pubOf(f.admin), f.joiner, want)
	if _, _, _, err := OpenJoinResponse(c, hand, f.joiner); err != nil {
		t.Errorf("hand-made response: %v", err)
	}
}

func TestJoinResponseWrongAdmin(t *testing.T) {
	f := newFixture(t)
	c, resp, s2 := f.pair(t, nil)
	binding := handBinding(t, c.Secret)

	// A stranger who saw the code answers with a group of its own that holds
	// the joiner.
	evil := cloneRoster(f.strangerR)
	evil.Members = append(evil.Members, memberOf(f.joiner, "ap-garden", roster.RoleSender))
	evilS := mustSign(t, evil, f.stranger)
	forged := handResponse(t, f.stranger.Sign, pubOf(f.stranger), f.joiner,
		handPayload(binding, f.ek, &Secrets{BotToken: "666:evil"}, evilS))
	_, _, sec, err := OpenJoinResponse(c, forged, f.joiner)
	wantErr(t, "stranger's group, stranger's key", err, ErrAdminFP)
	if sec != nil {
		t.Errorf("secrets returned with an error")
	}

	// The genuine response, re-signed by another key.
	n := len(resp) - fmtSigSize
	rewrapped := append([]byte{fmtRespVersion}, pubOf(f.stranger)...)
	rewrapped = append(rewrapped, resp[fmtRespHeader:n]...)
	rewrapped = append(rewrapped, ed25519.Sign(f.stranger.Sign, append([]byte("rollcall/v1/join-response\x00"), rewrapped...))...)
	_, _, _, err = OpenJoinResponse(c, rewrapped, f.joiner)
	wantErr(t, "genuine content, another key", err, ErrAdminFP)

	// The code's admin answers, but the roster inside is signed by the
	// backup admin of the same group.
	_, byBackup := f.withJoiner(t, f.backup)
	resp2 := handResponse(t, f.admin.Sign, pubOf(f.admin), f.joiner, handPayload(binding, f.ek, nil, byBackup))
	_, _, _, err = OpenJoinResponse(c, resp2, f.joiner)
	wantErr(t, "roster signed by the backup", err, ErrRosterAnchor)

	// The roster is signed by the code's admin, who is no admin in it.
	demoted := cloneRoster(f.r1)
	demoted.Admins = []ids.MemberID{f.backup.ID}
	demoted.Members[0].Roles = []roster.Role{roster.RoleSender}
	demoted.Members[1].Roles = []roster.Role{roster.RolePrimary}
	demoted.Members = append(demoted.Members, memberOf(f.joiner, "ap-garden"))
	demotedS := mustSign(t, demoted, f.admin) // SignRoster does not decide authority
	resp3 := handResponse(t, f.admin.Sign, pubOf(f.admin), f.joiner, handPayload(binding, f.ek, nil, demotedS))
	_, _, _, err = OpenJoinResponse(c, resp3, f.joiner)
	wantErr(t, "signer is not an admin of the roster", err, ErrRosterAnchor)

	// The roster's own signature does not verify.
	badSig := s2
	badSig.Sig = bytes.Clone(s2.Sig)
	badSig.Sig[5] ^= 1
	resp4 := handResponse(t, f.admin.Sign, pubOf(f.admin), f.joiner, handPayload(binding, f.ek, nil, badSig))
	_, _, _, err = OpenJoinResponse(c, resp4, f.joiner)
	wantErr(t, "roster signature broken", err, ErrRosterAnchor)

	// The code's key signs, but under the backup's member ID: the backup is
	// an admin of the roster, the key is not the backup's.
	asBackup := handSignRoster(f.admin.Sign, f.backup.ID, s2.Body)
	resp5b := handResponse(t, f.admin.Sign, pubOf(f.admin), f.joiner, handPayload(binding, f.ek, nil, asBackup))
	_, _, _, err = OpenJoinResponse(c, resp5b, f.joiner)
	wantErr(t, "code's key signing as the backup", err, ErrRosterAnchor)

	// The roster names another signer than the key that signed it.
	misnamed := s2
	misnamed.SignerID = f.backup.ID
	resp5 := handResponse(t, f.admin.Sign, pubOf(f.admin), f.joiner, handPayload(binding, f.ek, nil, misnamed))
	_, _, _, err = OpenJoinResponse(c, resp5, f.joiner)
	wantErr(t, "roster signer ID names the backup", err, ErrRosterAnchor)

	// A roster that fails Check, signed by the code's admin.
	r2, _ := f.withJoiner(t, f.admin)
	r2.Admins = nil
	body, err := jsonOf(r2)
	if err != nil {
		t.Fatal(err)
	}
	unchecked := handSignRoster(f.admin.Sign, f.admin.ID, body)
	resp6 := handResponse(t, f.admin.Sign, pubOf(f.admin), f.joiner, handPayload(binding, f.ek, nil, unchecked))
	_, _, _, err = OpenJoinResponse(c, resp6, f.joiner)
	wantErr(t, "roster without admins", err, ErrRosterAnchor)
	wantErr(t, "roster without admins (cause)", err, roster.ErrNoPrimary)

	// A body that is not in canonical form, signed by the code's admin.
	r2ok, _ := f.withJoiner(t, f.admin)
	bodyOK, _ := jsonOf(r2ok)
	spaced := append([]byte{' '}, bodyOK...)
	resp7 := handResponse(t, f.admin.Sign, pubOf(f.admin), f.joiner, handPayload(binding, f.ek, nil, handSignRoster(f.admin.Sign, f.admin.ID, spaced)))
	_, _, _, err = OpenJoinResponse(c, resp7, f.joiner)
	wantErr(t, "roster body with a leading space", err, ErrRosterAnchor)
	extra := append(bytes.Clone(bodyOK[:len(bodyOK)-1]), []byte(`,"extra":1}`)...)
	resp8 := handResponse(t, f.admin.Sign, pubOf(f.admin), f.joiner, handPayload(binding, f.ek, nil, handSignRoster(f.admin.Sign, f.admin.ID, extra)))
	_, _, _, err = OpenJoinResponse(c, resp8, f.joiner)
	wantErr(t, "roster body with an unknown field", err, ErrRosterAnchor)

	// The hand-signed canonical body is accepted, so the refusals above are
	// about the body, not about hand signing.
	resp9 := handResponse(t, f.admin.Sign, pubOf(f.admin), f.joiner, handPayload(binding, f.ek, nil, handSignRoster(f.admin.Sign, f.admin.ID, bodyOK)))
	if _, _, _, err := OpenJoinResponse(c, resp9, f.joiner); err != nil {
		t.Errorf("hand-signed canonical roster: %v", err)
	}

	// The admin side refuses to send any of these.
	inv, c2 := f.open(t)
	req := f.accepted(t, inv, c2)
	for name, s := range map[string]roster.Signed{
		"signed by the backup": byBackup,
		"signer not an admin":  demotedS,
		"broken signature":     badSig,
		"misnamed signer":      misnamed,
		"fails Check":          unchecked,
		"recovery-signed":      recoverySigned(t, f, r2ok),
		"recovery flag on an admin signature": {
			Body: s2.Body, SignerID: s2.SignerID, Recovery: true, Sig: s2.Sig,
		},
	} {
		if _, err := NewJoinResponse(req, s, f.ek, nil, f.admin); !errors.Is(err, ErrRosterAnchor) {
			t.Errorf("NewJoinResponse, roster %s: err = %v, want ErrRosterAnchor", name, err)
		}
	}
	rec := recoverySigned(t, f, r2ok)
	resp10 := handResponse(t, f.admin.Sign, pubOf(f.admin), f.joiner, handPayload(binding, f.ek, nil, rec))
	_, _, _, err = OpenJoinResponse(c, resp10, f.joiner)
	wantErr(t, "roster signed with the recovery key (signer ID zero)", err, ErrRosterAnchor)
}

// recoverySigned signs r with the group's recovery key.
func recoverySigned(t testing.TB, f *fixture, r roster.Roster) roster.Signed {
	t.Helper()
	s, err := roster.SignRoster(r, ids.MemberID{}, f.recovery, true)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestJoinResponseSignature(t *testing.T) {
	f := newFixture(t)
	c, resp, _ := f.pair(t, nil)
	n := len(resp) - fmtSigSize
	for _, i := range []int{0, 1, 20, 32, 33, 500, 1152, 1153, n - 1, n, len(resp) - 1} {
		bad := bytes.Clone(resp)
		bad[i] ^= 0x04
		_, _, _, err := OpenJoinResponse(c, bad, f.joiner)
		switch {
		case i == 0:
			wantErr(t, "version", err, ErrResponseFormat)
		case i < fmtRespHeader:
			wantErr(t, fmt.Sprintf("admin key byte %d", i), err, ErrAdminFP)
		default:
			wantErr(t, fmt.Sprintf("byte %d", i), err, ErrSignature)
		}
	}
	for name, blob := range map[string][]byte{
		"nil":       nil,
		"header":    resp[:fmtRespHeader],
		"truncated": resp[:fmtRespHeader+fmtEncSize+16+fmtSigSize],
		"too long":  append(bytes.Clone(resp), make([]byte, MaxResponseSize)...),
	} {
		_, _, _, err := OpenJoinResponse(c, blob, f.joiner)
		wantErr(t, name, err, ErrResponseFormat)
	}
}

func TestJoinResponseNotForMe(t *testing.T) {
	f := newFixture(t)
	c, resp, _ := f.pair(t, nil)
	// Another router, even with the joiner's member ID, cannot open it.
	impostor := newIdentity(t, 9)
	impostor.ID = f.joiner.ID
	_, _, _, err := OpenJoinResponse(c, resp, impostor)
	wantErr(t, "another receive key", err, ErrDecrypt)
	// The joiner's key under another member ID cannot open it either.
	renamed := *f.joiner
	renamed.ID[1] ^= 1
	_, _, _, err = OpenJoinResponse(c, resp, &renamed)
	wantErr(t, "another member ID", err, ErrDecrypt)
}

func TestJoinResponseBinding(t *testing.T) {
	f := newFixture(t)
	oldCode, oldResp, _ := f.pair(t, nil)
	// The admin invites again; a captured response from the first pairing is
	// replayed to the same router.
	newCode, _, _ := f.pair(t, nil)
	_, _, _, err := OpenJoinResponse(newCode, oldResp, f.joiner)
	wantErr(t, "response for the previous code", err, ErrBinding)
	if _, _, _, err := OpenJoinResponse(oldCode, oldResp, f.joiner); err != nil {
		t.Errorf("the response under its own code: %v", err)
	}
	// A response with a zero binding.
	_, s2 := f.withJoiner(t, f.admin)
	resp := handResponse(t, f.admin.Sign, pubOf(f.admin), f.joiner, handPayload(make([]byte, 32), f.ek, nil, s2))
	_, _, _, err = OpenJoinResponse(newCode, resp, f.joiner)
	wantErr(t, "zero binding", err, ErrBinding)
}

func TestJoinResponseSelfEntry(t *testing.T) {
	f := newFixture(t)
	_, c := f.open(t)
	binding := handBinding(t, c.Secret)
	respWith := func(r roster.Roster) []byte {
		return handResponse(t, f.admin.Sign, pubOf(f.admin), f.joiner, handPayload(binding, f.ek, nil, mustSign(t, r, f.admin)))
	}
	_, _, _, err := OpenJoinResponse(c, respWith(f.r1), f.joiner)
	wantErr(t, "roster without the joiner", err, ErrNotInRoster)

	other := newIdentity(t, 9)
	for name, edit := range map[string]func(m *roster.Member){
		"another signing key": func(m *roster.Member) { m.SignPub = pubOf(other) },
		"another receive key": func(m *roster.Member) { m.RecvPub = recvOf(other) },
		"another member ID":   func(m *roster.Member) { m.ID = other.ID },
	} {
		r, _ := f.withJoiner(t, f.admin)
		edit(&r.Members[len(r.Members)-1])
		_, _, _, err := OpenJoinResponse(c, respWith(r), f.joiner)
		wantErr(t, name, err, ErrNotInRoster)
	}
}

func TestSecretsOnlyForSender(t *testing.T) {
	f := newFixture(t)
	token := &Secrets{BotToken: canary, ChatID: 77}

	// Not a sender: the token is left out, whatever the admin passes.
	plain, _ := f.withJoiner(t, f.admin)
	backupAdmin := cloneRoster(plain) // the joiner becomes the backup admin, without the sender role
	backupAdmin.Admins = []ids.MemberID{f.admin.ID, f.joiner.ID}
	backupAdmin.Members[1].Roles = nil
	backupAdmin.Members[2].Roles = []roster.Role{roster.RoleBackup}
	for name, r := range map[string]roster.Roster{"no roles": plain, "backup admin": backupAdmin} {
		inv, c := f.open(t)
		req := f.accepted(t, inv, c)
		s := mustSign(t, r, f.admin)
		resp, err := NewJoinResponse(req, s, f.ek, token, f.admin)
		if err != nil {
			t.Fatalf("%s: NewJoinResponse: %v", name, err)
		}
		got, _, sec, err := OpenJoinResponse(c, resp, f.joiner)
		if err != nil {
			t.Fatalf("%s: OpenJoinResponse: %v", name, err)
		}
		if sec != nil {
			t.Errorf("%s: a router without the sender role received the secrets", name)
		}
		if !reflect.DeepEqual(got, s) {
			t.Errorf("%s: roster differs", name)
		}
		pt := handOpenResponse(t, resp, f.joiner, pubOf(f.admin))
		if pt[32+fmtEpochSize] != 0 || bytes.Contains(pt, []byte(canary)) {
			t.Errorf("%s: the sealed payload carries the token (secrets flag %d)", name, pt[32+fmtEpochSize])
		}
	}

	// A sender receives them.
	c, resp, _ := f.pair(t, token, roster.RoleSender)
	if _, _, sec, err := OpenJoinResponse(c, resp, f.joiner); err != nil || sec == nil || *sec != *token {
		t.Errorf("sender: secrets %v, err %v; want the token", sec, err)
	}
	// A sender while the admin has no token yet.
	c, resp, _ = f.pair(t, nil, roster.RoleSender)
	if _, _, sec, err := OpenJoinResponse(c, resp, f.joiner); err != nil || sec != nil {
		t.Errorf("sender without a token: secrets %v, err %v; want none", sec, err)
	}

	// The joiner refuses a response that hands the token to a non-sender.
	_, c = f.open(t)
	_, s2 := f.withJoiner(t, f.admin)
	bad := handResponse(t, f.admin.Sign, pubOf(f.admin), f.joiner, handPayload(handBinding(t, c.Secret), f.ek, token, s2))
	_, _, sec, err := OpenJoinResponse(c, bad, f.joiner)
	wantErr(t, "secrets for a non-sender", err, ErrSecretsNotSender)
	if sec != nil {
		t.Errorf("secrets returned with an error")
	}
}

func TestNewJoinResponseRejects(t *testing.T) {
	f := newFixture(t)
	inv, c := f.open(t)
	req := f.accepted(t, inv, c)
	_, s2 := f.withJoiner(t, f.admin, roster.RoleSender)

	// Only a request that an Inviter accepted, and so burned, is answered.
	raw, err := OpenJoinRequest(c, mustRequest(t, c, f.joiner))
	if err != nil {
		t.Fatal(err)
	}
	for name, r := range map[string]JoinRequest{
		"opened, not accepted": raw,
		"zero request":         {},
		"hand-made":            {ID: req.ID, Name: req.Name, SignPub: req.SignPub, RecvPub: req.RecvPub, accepted: true},
	} {
		if _, err := NewJoinResponse(r, s2, f.ek, nil, f.admin); !errors.Is(err, ErrNotAccepted) {
			t.Errorf("%s: err = %v, want ErrNotAccepted", name, err)
		}
	}

	// The request was made for this admin's code.
	if _, err := NewJoinResponse(req, mustSign(t, s2Roster(t, f), f.backup), f.ek, nil, f.backup); !errors.Is(err, ErrInvalid) {
		t.Errorf("answered by the backup for the primary's code: err = %v, want ErrInvalid", err)
	}
	for name, admin := range map[string]*identity.Identity{
		"nil admin":   nil,
		"small order": smallOrderAdmin(f.admin),
	} {
		if _, err := NewJoinResponse(req, s2, f.ek, nil, admin); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
	}
	// The admin's member ID must be the roster's signer.
	renamed := *f.admin
	renamed.ID[2] ^= 1
	if _, err := NewJoinResponse(req, s2, f.ek, nil, &renamed); !errors.Is(err, ErrRosterAnchor) {
		t.Errorf("admin ID is not the roster signer: err = %v, want ErrRosterAnchor", err)
	}

	// The roster must hold the joiner with the keys from its request.
	if _, err := NewJoinResponse(req, f.s1, f.ek, nil, f.admin); !errors.Is(err, ErrNotInRoster) {
		t.Errorf("roster without the joiner: err = %v, want ErrNotInRoster", err)
	}
	r2 := s2Roster(t, f)
	r2.Members[2].RecvPub = recvOf(newIdentity(t, 9))
	if _, err := NewJoinResponse(req, mustSign(t, r2, f.admin), f.ek, nil, f.admin); !errors.Is(err, ErrNotInRoster) {
		t.Errorf("joiner with another receive key: err = %v, want ErrNotInRoster", err)
	}
	r2 = s2Roster(t, f)
	r2.Members[2].SignPub = pubOf(newIdentity(t, 9))
	if _, err := NewJoinResponse(req, mustSign(t, r2, f.admin), f.ek, nil, f.admin); !errors.Is(err, ErrNotInRoster) {
		t.Errorf("joiner with another signing key: err = %v, want ErrNotInRoster", err)
	}

	for name, ek := range map[string]epoch.Key{
		"zero secret":    {ID: 1, Secret: make([]byte, 32), NotAfter: t0},
		"short secret":   {ID: 1, Secret: bytes.Repeat([]byte{1}, 31), NotAfter: t0},
		"long secret":    {ID: 1, Secret: bytes.Repeat([]byte{1}, 33), NotAfter: t0},
		"no NotAfter":    {ID: 1, Secret: bytes.Repeat([]byte{1}, 32)},
		"NotAfter 10000": {ID: 1, Secret: bytes.Repeat([]byte{1}, 32), NotAfter: time.Unix(fmtMaxNotAfter+1, 0)},
	} {
		if _, err := NewJoinResponse(req, s2, ek, nil, f.admin); !errors.Is(err, ErrEpochKey) {
			t.Errorf("epoch key %s: err = %v, want ErrEpochKey", name, err)
		}
	}
	for name, tok := range map[string]string{
		"empty":     "",
		"too long":  strings.Repeat("a", MaxTokenLen+1),
		"slash":     "123:abc/def",
		"space":     "123:abc def",
		"newline":   "123:abc\n",
		"percent":   "123:abc%2f",
		"question":  "123:abc?x=1",
		"non-ASCII": "123:abcé",
	} {
		_, err := NewJoinResponse(req, s2, f.ek, &Secrets{BotToken: tok, ChatID: 1}, f.admin)
		if !errors.Is(err, ErrToken) {
			t.Errorf("token %s: err = %v, want ErrToken", name, err)
		}
	}
	// The longest token and the extreme chat IDs are fine.
	for _, sec := range []Secrets{
		{BotToken: strings.Repeat("A", MaxTokenLen), ChatID: math.MaxInt64},
		{BotToken: "1:a_b-C", ChatID: math.MinInt64},
		{BotToken: canary, ChatID: 0},
	} {
		inv, c := f.open(t)
		req := f.accepted(t, inv, c)
		resp, err := NewJoinResponse(req, s2, f.ek, &sec, f.admin)
		if err != nil {
			t.Errorf("token of %d bytes, chat %d: %v", len(sec.BotToken), sec.ChatID, err)
			continue
		}
		if _, _, got, err := OpenJoinResponse(c, resp, f.joiner); err != nil || got == nil || *got != sec {
			t.Errorf("token of %d bytes, chat %d: got %v, %v", len(sec.BotToken), sec.ChatID, got, err)
		}
	}
}

// fixedExchanger is an X25519 key held elsewhere that presents pub.
type fixedExchanger struct{ pub *ecdh.PublicKey }

func (k fixedExchanger) PublicKey() *ecdh.PublicKey { return k.pub }
func (fixedExchanger) Curve() ecdh.Curve            { return ecdh.X25519() }
func (fixedExchanger) ECDH(*ecdh.PublicKey) ([]byte, error) {
	return nil, errors.New("fixedExchanger: no private key")
}

// s2Roster returns version 2 of the group with the joiner as a sender.
func s2Roster(t testing.TB, f *fixture) roster.Roster {
	r, _ := f.withJoiner(t, f.admin, roster.RoleSender)
	return r
}

func mustRequest(t testing.TB, c Code, self *identity.Identity) []byte {
	t.Helper()
	b, err := NewJoinRequest(c, self, "ap-garden")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestOpenJoinResponseArgs(t *testing.T) {
	f := newFixture(t)
	c, resp, _ := f.pair(t, nil)
	if _, _, _, err := OpenJoinResponse(Code{}, resp, f.joiner); !errors.Is(err, ErrInvalid) {
		t.Errorf("zero code: err = %v, want ErrInvalid", err)
	}
	noRecv := *f.joiner
	noRecv.Recv = nil
	zeroID := *f.joiner
	zeroID.ID = ids.MemberID{}
	dh, err := hpke.DHKEM(ecdh.X25519()).GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	otherKEM := *f.joiner
	otherKEM.Recv = dh
	short := *f.joiner
	short.Sign = f.joiner.Sign[:32]
	for name, self := range map[string]*identity.Identity{
		"nil": nil, "no receive key": &noRecv, "zero ID": &zeroID, "X25519 only": &otherKEM, "short sign key": &short,
	} {
		if _, _, _, err := OpenJoinResponse(c, resp, self); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
	}
}

func TestJoinResponsePayloadStrict(t *testing.T) {
	f := newFixture(t)
	_, c := f.open(t)
	binding := handBinding(t, c.Secret)
	_, s2 := f.withJoiner(t, f.admin, roster.RoleSender)
	good := handPayload(binding, f.ek, &Secrets{BotToken: canary, ChatID: 5}, s2)
	open := func(p []byte) error {
		_, _, _, err := OpenJoinResponse(c, handResponse(t, f.admin.Sign, pubOf(f.admin), f.joiner, p), f.joiner)
		return err
	}
	if err := open(good); err != nil {
		t.Fatalf("good payload: %v", err)
	}
	flagAt := 32 + fmtEpochSize
	tokenLenAt := flagAt + 1 + 8
	withByte := func(i int, v byte) []byte {
		p := bytes.Clone(good)
		p[i] = v
		return p
	}
	wantErr(t, "secrets flag 2", open(withByte(flagAt, 2)), ErrResponseFormat)
	wantErr(t, "token length 0", open(withByte(tokenLenAt, 0)), ErrToken)
	wantErr(t, "token length past the end", open(withByte(tokenLenAt, 255)), ErrToken)
	wantErr(t, "token with a slash", open(withByte(tokenLenAt+3, '/')), ErrToken)
	// A wrong token length shifts every field after it: one longer takes in
	// the signer ID's first byte (0x01, not a token character); one shorter
	// leaves the roster signature misaligned.
	wantErr(t, "token length one longer", open(withByte(tokenLenAt, byte(len(canary)+1))), ErrToken)
	wantErr(t, "token length one shorter", open(withByte(tokenLenAt, byte(len(canary)-1))), ErrRosterAnchor)
	wantErr(t, "truncated in the epoch key", open(good[:50]), ErrResponseFormat)
	wantErr(t, "no roster body", open(good[:len(good)-len(s2.Body)]), ErrResponseFormat)
	wantErr(t, "trailing byte after the body", open(append(bytes.Clone(good), ' ')), ErrRosterAnchor)

	zeroKey := handPayload(binding, epoch.Key{ID: 1, Secret: make([]byte, 32), NotAfter: t0}, nil, s2)
	wantErr(t, "zero epoch secret", open(zeroKey), ErrEpochKey)
	noAfter := handPayload(binding, epoch.Key{ID: 1, Secret: bytes.Repeat([]byte{1}, 32), NotAfter: time.Unix(0, 0)}, nil, s2)
	wantErr(t, "NotAfter 0", open(noAfter), ErrEpochKey)
	late := handPayload(binding, epoch.Key{ID: 1, Secret: bytes.Repeat([]byte{1}, 32), NotAfter: time.Unix(fmtMaxNotAfter+1, 0)}, nil, s2)
	wantErr(t, "NotAfter after 9999", open(late), ErrEpochKey)
	// A token length that runs past the end of the payload.
	short := handPayload(binding, f.ek, nil, s2)[:32+fmtEpochSize]
	short = append(short, 1, 0, 0, 0, 0, 0, 0, 0, 5, MaxTokenLen)
	short = append(short, bytes.Repeat([]byte{'A'}, 100)...)
	wantErr(t, "token longer than what is left", open(short), ErrResponseFormat)
	// decodePayload on its own refuses what OpenJoinResponse's length check
	// keeps from it.
	for _, n := range []int{0, 1, payloadFixed} {
		if _, err := decodePayload(good[:n]); !errors.Is(err, ErrResponseFormat) {
			t.Errorf("decodePayload of %d bytes: err = %v, want ErrResponseFormat", n, err)
		}
	}
	big := handPayload(binding, f.ek, nil, roster.Signed{Body: bytes.Repeat([]byte{'x'}, roster.MaxBodySize+1), SignerID: f.admin.ID, Sig: make([]byte, 64)})
	if err := open(big); err == nil {
		t.Errorf("roster body over MaxBodySize accepted")
	}
}

// TestLargestResponseFits builds the largest roster Check allows, with the
// joiner in it, and the longest token, and reports the slack under
// MaxResponseSize.
func TestLargestResponseFits(t *testing.T) {
	f := newFixture(t)
	inv, c := f.open(t)
	req := f.accepted(t, inv, c)
	r := cloneRoster(f.r1)
	r.Site = strings.Repeat("s", roster.MaxNameLen)
	r.Version = math.MaxUint64
	for i := range r.Prev {
		r.Prev[i] = 0xff
	}
	r.Members = append(r.Members, memberOf(f.joiner, "ap-garden"))
	for i := len(r.Members); i < roster.MaxMembers; i++ {
		m := newIdentity(t, byte(100+i))
		r.Members = append(r.Members, memberOf(m, ""))
	}
	for i := range r.Members {
		r.Members[i].Name = fmt.Sprintf("%02d", i) + strings.Repeat("n", roster.MaxNameLen-2)
		if !slices.Contains(r.Members[i].Roles, roster.RoleSender) {
			r.Members[i].Roles = append(r.Members[i].Roles, roster.RoleSender)
		}
	}
	s := mustSign(t, r, f.admin)
	token := &Secrets{BotToken: strings.Repeat("T", MaxTokenLen), ChatID: math.MinInt64}
	resp, err := NewJoinResponse(req, s, f.ek, token, f.admin)
	if err != nil {
		t.Fatalf("largest response: %v", err)
	}
	t.Logf("largest response %d bytes (roster body %d): %d under MaxResponseSize, %d under a 65536-byte frame",
		len(resp), len(s.Body), MaxResponseSize-len(resp), 65536-len(resp))
	if _, _, got, err := OpenJoinResponse(c, resp, f.joiner); err != nil || got == nil {
		t.Errorf("largest response does not open: %v", err)
	}
	// sealResponse refuses a payload that would not fit.
	payload := make([]byte, MaxResponseSize)
	if _, err := sealResponse(payload, f.joiner.Recv.PublicKey(), f.joiner.ID, f.admin.Sign); !errors.Is(err, ErrTooLarge) {
		t.Errorf("oversized payload: err = %v, want ErrTooLarge", err)
	}
	fit := make([]byte, MaxResponseSize-(fmtRespHeader+fmtEncSize+16+fmtSigSize))
	if blob, err := sealResponse(fit, f.joiner.Recv.PublicKey(), f.joiner.ID, f.admin.Sign); err != nil || len(blob) != MaxResponseSize {
		t.Errorf("payload that fits exactly: %d bytes, %v", len(blob), err)
	}
	if _, err := sealResponse(append(fit, 0), f.joiner.Recv.PublicKey(), f.joiner.ID, f.admin.Sign); !errors.Is(err, ErrTooLarge) {
		t.Errorf("payload one byte over: err = %v, want ErrTooLarge", err)
	}
}

// TestErrorsCarryNoSecrets plants a canary token and checks every error the
// package returns on the paths that handle it, the join secret, the epoch
// key and the private keys.
func TestErrorsCarryNoSecrets(t *testing.T) {
	f := newFixture(t)
	token := &Secrets{BotToken: canary, ChatID: 31337}
	inv, c := f.open(t)
	recvSeed, _ := f.joiner.Recv.Bytes()
	secrets := map[string][]byte{
		"bot token":     []byte(canary),
		"join code":     []byte(c.String()),
		"join secret":   c.Secret[:],
		"epoch secret":  f.ek.Secret,
		"admin seed":    f.admin.Sign.Seed(),
		"joiner seed":   f.joiner.Sign.Seed(),
		"receive seed":  recvSeed,
		"join key":      handJoinKey(t, c.Secret),
		"binding value": handBinding(t, c.Secret),
	}
	var errs []error
	note := func(err error) {
		if err == nil {
			t.Errorf("a failure path returned no error")
			return
		}
		errs = append(errs, err)
	}

	// Code text with typos and bad fields.
	s := c.String()
	_, err := ParseCode(s[:len(s)-1])
	note(err)
	_, err = ParseCode(strings.Replace(s, s[3:4], "Z", 1) + "Q")
	note(err)
	note(inv.Consume(Code{Secret: c.Secret}, t0))

	// Requests.
	blob := mustRequest(t, c, f.joiner)
	other := c
	other.Secret[0] ^= 1
	_, err = OpenJoinRequest(other, blob)
	note(err)
	_, err = OpenJoinRequest(c, handRequest(t, c, handRequestPlain(f.joiner.ID, pubOf(f.joiner), withX25519(recvOf(f.joiner), make([]byte, 32)), "ap-garden")))
	note(err)
	_, err = NewJoinRequest(c, f.joiner, canary)
	note(err)

	// Responses that carry the canary.
	req, err := inv.Accept(blob, t0.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	_, s2 := f.withJoiner(t, f.admin, roster.RoleSender)
	_, err = NewJoinResponse(req, s2, f.ek, &Secrets{BotToken: canary + "/", ChatID: 1}, f.admin)
	note(err)
	_, err = NewJoinResponse(req, s2, epoch.Key{ID: 1, Secret: make([]byte, 32), NotAfter: t0}, token, f.admin)
	note(err)
	_, err = NewJoinResponse(req, f.s1, f.ek, token, f.admin)
	note(err)
	resp, err := NewJoinResponse(req, s2, f.ek, token, f.admin)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, err = OpenJoinResponse(other, resp, f.joiner)
	note(err)
	_, _, _, err = OpenJoinResponse(c, resp, newIdentity(t, 9))
	note(err)
	bad := bytes.Clone(resp)
	bad[len(bad)-1] ^= 1
	_, _, _, err = OpenJoinResponse(c, bad, f.joiner)
	note(err)
	_, nonSender := f.withJoiner(t, f.admin)
	_, _, _, err = OpenJoinResponse(c, handResponse(t, f.admin.Sign, pubOf(f.admin), f.joiner, handPayload(handBinding(t, c.Secret), f.ek, token, nonSender)), f.joiner)
	note(err)
	tokenSlash := handPayload(handBinding(t, c.Secret), f.ek, &Secrets{BotToken: canary[:8] + "/" + canary[9:], ChatID: 1}, s2)
	_, _, _, err = OpenJoinResponse(c, handResponse(t, f.admin.Sign, pubOf(f.admin), f.joiner, tokenSlash), f.joiner)
	note(err)

	for _, err := range errs {
		if what, bad := leaks(err.Error(), secrets); bad {
			t.Errorf("error %q carries the %s", err, what)
		}
		if strings.Contains(fmt.Sprintf("%+v %#v", err, err), canary) {
			t.Errorf("error %v carries the canary under %%+v or %%#v", err)
		}
	}
	t.Logf("%d errors checked", len(errs))
}

// jsonOf encodes r as the roster package does, without its checks.
func jsonOf(r roster.Roster) ([]byte, error) { return json.Marshal(r) }

// TestJoinKeyBoundToRoster (A1): the first epoch key a router receives is
// bound to the roster it receives with it, its version and hash. A key
// without a binding is bound to that roster by NewJoinResponse; a key
// bound to another roster is refused on both sides; a sequence number or
// authority out of range is refused when it is read.
func TestJoinKeyBoundToRoster(t *testing.T) {
	f := newFixture(t)
	c, resp, s2 := f.pair(t, nil)
	_, ek, _, err := OpenJoinResponse(c, resp, f.joiner)
	if err != nil {
		t.Fatalf("OpenJoinResponse: %v", err)
	}
	want := epoch.Binding{Version: 2, Hash: s2.Hash()}
	if ek.Roster != want || ek.Seq != 1 || ek.Authority != 0 {
		t.Fatalf("the joiner's key is bound to %+v, seq %d, authority %d; want version 2 with the roster's hash, seq 1, authority 0", ek.Roster, ek.Seq, ek.Authority)
	}

	// A key the admin bound to the roster it sends goes through as it is.
	inv, c2 := f.open(t)
	req := f.accepted(t, inv, c2)
	bound := f.ek
	bound.Roster, bound.Seq, bound.Authority = want, 5, 1
	resp, err = NewJoinResponse(req, s2, bound, nil, f.admin)
	if err != nil {
		t.Fatalf("NewJoinResponse with a key bound to the roster: %v", err)
	}
	if _, ek, _, err := OpenJoinResponse(c2, resp, f.joiner); err != nil || ek.Roster != want || ek.Seq != 5 || ek.Authority != 1 {
		t.Fatalf("OpenJoinResponse of a bound key: %v, %+v seq %d authority %d", err, ek.Roster, ek.Seq, ek.Authority)
	}

	// The admin refuses to send a key bound to another roster, or with a
	// sequence number or authority out of range.
	inv, c3 := f.open(t)
	req = f.accepted(t, inv, c3)
	key := func(b epoch.Binding, seq uint16, authority uint8) epoch.Key {
		return epoch.Key{ID: 1, Secret: f.ek.Secret, NotAfter: f.ek.NotAfter, Roster: b, Seq: seq, Authority: authority}
	}
	for name, k := range map[string]epoch.Key{
		"bound to the roster before": key(epoch.Binding{Version: 1, Hash: f.s1.Hash()}, 1, 0),
		"bound to another hash":      key(epoch.Binding{Version: 2, Hash: f.s1.Hash()}, 1, 0),
		"sequence past MaxSeq":       key(want, epoch.MaxSeq+1, 0),
		"authority 4":                key(want, 1, 4),
	} {
		if _, err := NewJoinResponse(req, s2, k, nil, f.admin); !errors.Is(err, ErrEpochKey) {
			t.Errorf("NewJoinResponse, key %s: %v, want ErrEpochKey", name, err)
		}
	}

	// The joiner refuses a key bound to another roster than the one in the
	// response, or out of range, though sealed and signed by the admin.
	binding := handBinding(t, c3.Secret)
	open := func(k epoch.Key) error {
		p := handPayload(binding, k, nil, s2)
		_, _, _, err := OpenJoinResponse(c3, handResponse(t, f.admin.Sign, pubOf(f.admin), f.joiner, p), f.joiner)
		return err
	}
	if err := open(f.ek); err != nil {
		t.Fatalf("a hand-built payload bound to its roster: %v", err)
	}
	for name, k := range map[string]epoch.Key{
		"bound to the roster before": key(epoch.Binding{Version: 1, Hash: f.s1.Hash()}, 1, 0),
		"bound to version 3":         key(epoch.Binding{Version: 3, Hash: s2.Hash()}, 1, 0),
		"bound to another hash":      key(epoch.Binding{Version: 2, Hash: f.s1.Hash()}, 1, 0),
		"sequence past MaxSeq":       key(want, epoch.MaxSeq+1, 0),
		"authority 4":                key(want, 1, 4),
	} {
		wantErr(t, name, open(k), ErrEpochKey)
	}
	// handPayload writes sequence 1 for a key without one: patch 0 into a
	// good payload.
	p := handPayload(binding, f.ek, nil, s2)
	at := 32 + 4 + 8 + 8 + 32
	p[at], p[at+1] = 0, 0
	_, _, _, err = OpenJoinResponse(c3, handResponse(t, f.admin.Sign, pubOf(f.admin), f.joiner, p), f.joiner)
	wantErr(t, "sequence 0", err, ErrEpochKey)
}
