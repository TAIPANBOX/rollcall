package pairing

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/TAIPANBOX/rollcall/internal/epoch"
	"github.com/TAIPANBOX/rollcall/internal/identity"
	"github.com/TAIPANBOX/rollcall/internal/ids"
	"github.com/TAIPANBOX/rollcall/internal/roster"
	"github.com/TAIPANBOX/rollcall/internal/sig"
)

// The formats, written out here so that a change in the package shows as a
// red test instead of passing on both sides.
const (
	fmtCrockford     = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	fmtCodeLabel     = "rollcall/v1 join-code\x00"
	fmtFPLabel       = "rollcall/v1 admin-fp\x00"
	fmtJoinLabel     = "rollcall/v1 join"
	fmtBindingLabel  = "rollcall/v1 join-binding"
	fmtResponseInfo  = "rollcall/v1 join-response"
	fmtResponseKind  = "join-response"
	fmtRosterKind    = "roster"
	fmtX25519Offset  = 1184 // ML-KEM-768 encapsulation key, then the X25519 point
	fmtRecvKeySize   = 1216
	fmtEncSize       = 1120 // ML-KEM-768 ciphertext (1088) and an X25519 point (32)
	fmtRespHeader    = 1 + 32
	fmtRespVersion   = 2
	fmtEpochSize     = 87 // ID 4, NotAfter 8, roster version 8, roster hash 32, seq 2, authority 1, secret 32
	fmtSigSize       = 64
	fmtMaxNotAfter   = 253402300799
	fmtTestBootstrap = "192.168.1.1:7432"
)

var (
	t0        = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	canary    = "CANARY-123:abc"
	crockford = base32.NewEncoding(fmtCrockford).WithPadding(base32.NoPadding)
)

// newIdentity returns an identity with keys fixed by n.
func newIdentity(t testing.TB, n byte) *identity.Identity {
	t.Helper()
	var id ids.MemberID
	id[0] = n
	id[15] = 0xa5
	sign := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{n}, ed25519.SeedSize))
	recv, err := hpke.MLKEM768X25519().DeriveKeyPair(append([]byte("pairing test receive key seed "), n))
	if err != nil {
		t.Fatalf("derive receive key: %v", err)
	}
	return &identity.Identity{ID: id, Sign: sign, Recv: recv}
}

func pubOf(id *identity.Identity) ed25519.PublicKey {
	return bytes.Clone(id.Sign[ed25519.SeedSize:])
}

func recvOf(id *identity.Identity) []byte { return id.Recv.PublicKey().Bytes() }

func memberOf(id *identity.Identity, name string, roles ...roster.Role) roster.Member {
	return roster.Member{ID: id.ID, Name: name, SignPub: pubOf(id), RecvPub: recvOf(id), Roles: roles}
}

// fixture is a group of two admins (admin primary and sender, backup) with a
// recovery key, a router that joins it, and a stranger with a group of its
// own.
type fixture struct {
	admin, backup, joiner, stranger *identity.Identity
	recovery                        ed25519.PrivateKey
	r1                              roster.Roster // genesis of the group
	s1                              roster.Signed
	strangerR                       roster.Roster // the stranger's own genesis
	strangerS                       roster.Signed
	ek                              epoch.Key
}

func newFixture(t testing.TB) *fixture {
	t.Helper()
	f := &fixture{
		admin:    newIdentity(t, 1),
		backup:   newIdentity(t, 2),
		joiner:   newIdentity(t, 3),
		stranger: newIdentity(t, 4),
		recovery: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0xee}, ed25519.SeedSize)),
	}
	f.r1 = roster.Roster{
		Version: 1,
		Site:    "home",
		Members: []roster.Member{
			memberOf(f.admin, "gateway", roster.RolePrimary, roster.RoleSender),
			memberOf(f.backup, "ap-office", roster.RoleBackup),
		},
		Admins:      []ids.MemberID{f.admin.ID, f.backup.ID},
		RecoveryPub: bytes.Clone(f.recovery.Public().(ed25519.PublicKey)),
	}
	f.s1 = mustSign(t, f.r1, f.admin)
	f.strangerR = roster.Roster{
		Version:     1,
		Site:        "evil",
		Members:     []roster.Member{memberOf(f.stranger, "evil-gw", roster.RolePrimary)},
		Admins:      []ids.MemberID{f.stranger.ID},
		RecoveryPub: bytes.Clone(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0xdd}, 32)).Public().(ed25519.PublicKey)),
	}
	f.strangerS = mustSign(t, f.strangerR, f.stranger)
	f.ek = epoch.Key{ID: 7, Secret: bytes.Repeat([]byte{0x5e}, epoch.SecretSize), NotAfter: t0.Add(epoch.RotationPeriod)}
	return f
}

func mustSign(t testing.TB, r roster.Roster, by *identity.Identity) roster.Signed {
	t.Helper()
	s, err := roster.SignRoster(r, by.ID, by.Sign, false)
	if err != nil {
		t.Fatalf("sign roster: %v", err)
	}
	return s
}

// withJoiner returns version 2 of the group: the genesis plus the joiner
// with the given roles, signed by signer.
func (f *fixture) withJoiner(t testing.TB, signer *identity.Identity, roles ...roster.Role) (roster.Roster, roster.Signed) {
	t.Helper()
	r := cloneRoster(f.r1)
	r.Version = 2
	r.Prev = f.s1.Hash()
	r.Members = append(r.Members, memberOf(f.joiner, "ap-garden", roles...))
	return r, mustSign(t, r, signer)
}

func cloneRoster(r roster.Roster) roster.Roster {
	c := r
	c.Members = make([]roster.Member, len(r.Members))
	for i, m := range r.Members {
		m.SignPub = bytes.Clone(m.SignPub)
		m.RecvPub = bytes.Clone(m.RecvPub)
		m.Roles = append([]roster.Role(nil), m.Roles...)
		c.Members[i] = m
	}
	c.Admins = append([]ids.MemberID(nil), r.Admins...)
	c.RecoveryPub = bytes.Clone(r.RecoveryPub)
	return c
}

// open opens a code on a new Inviter of the admin at t0.
func (f *fixture) open(t testing.TB) (*Inviter, Code) {
	t.Helper()
	inv := &Inviter{}
	c, err := inv.Open(t0, netip.MustParseAddrPort(fmtTestBootstrap), f.admin)
	if err != nil {
		t.Fatalf("Inviter.Open: %v", err)
	}
	return inv, c
}

// accepted runs the joiner's request through the Inviter.
func (f *fixture) accepted(t testing.TB, inv *Inviter, c Code) JoinRequest {
	t.Helper()
	blob, err := NewJoinRequest(c, f.joiner, "ap-garden")
	if err != nil {
		t.Fatalf("NewJoinRequest: %v", err)
	}
	req, err := inv.Accept(blob, t0.Add(time.Minute))
	if err != nil {
		t.Fatalf("Inviter.Accept: %v", err)
	}
	return req
}

// pair runs a whole join: code, request, roster version 2 with the joiner
// holding roles, response with token.
func (f *fixture) pair(t testing.TB, token *Secrets, roles ...roster.Role) (Code, []byte, roster.Signed) {
	t.Helper()
	inv, c := f.open(t)
	req := f.accepted(t, inv, c)
	_, s2 := f.withJoiner(t, f.admin, roles...)
	resp, err := NewJoinResponse(req, s2, f.ek, token, f.admin)
	if err != nil {
		t.Fatalf("NewJoinResponse: %v", err)
	}
	return c, resp, s2
}

// handFP is the admin fingerprint as the brief defines it.
func handFP(pub []byte) [16]byte {
	sum := sha256.Sum256(append([]byte(fmtFPLabel), pub...))
	var fp [16]byte
	copy(fp[:], sum[:16])
	return fp
}

// handCodeBody returns the code payload before the checksum.
func handCodeBody(version byte, ap netip.AddrPort, fp, secret [16]byte, expires int64) []byte {
	b := []byte{version}
	a := ap.Addr()
	if a.Is4() {
		b = append(b, 4)
		v := a.As4()
		b = append(b, v[:]...)
	} else {
		b = append(b, 6)
		v := a.As16()
		b = append(b, v[:]...)
	}
	b = binary.BigEndian.AppendUint16(b, ap.Port())
	b = append(b, fp[:]...)
	b = append(b, secret[:]...)
	return binary.BigEndian.AppendUint64(b, uint64(expires))
}

// handCodeText checksums body and encodes it with encoding/base32 under the
// Crockford alphabet, in groups of five.
func handCodeText(body []byte) string {
	sum := sha256.Sum256(append([]byte(fmtCodeLabel), body...))
	raw := crockford.EncodeToString(append(bytes.Clone(body), sum[:4]...))
	return group(raw)
}

func group(raw string) string {
	var parts []string
	for len(raw) > 5 {
		parts = append(parts, raw[:5])
		raw = raw[5:]
	}
	return strings.Join(append(parts, raw), "-")
}

func handJoinKey(t testing.TB, secret [16]byte) []byte {
	t.Helper()
	k, err := hkdf.Key(sha256.New, secret[:], nil, fmtJoinLabel, 32)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func handBinding(t testing.TB, secret [16]byte) []byte {
	t.Helper()
	k, err := hkdf.Key(sha256.New, secret[:], nil, fmtBindingLabel, 32)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func handRequestAD(c Code) []byte {
	ad := []byte{1}
	ad = binary.BigEndian.AppendUint64(ad, uint64(c.Expires.Unix()))
	return append(ad, c.AdminFP[:]...)
}

// handRequestPlain lays out a request plaintext.
func handRequestPlain(id ids.MemberID, signPub, recvPub []byte, name string) []byte {
	pt := append([]byte(nil), id[:]...)
	pt = append(pt, signPub...)
	pt = append(pt, recvPub...)
	return append(pt, name...)
}

// handRequest seals pt as a version 1 request under the code's key.
func handRequest(t testing.TB, c Code, pt []byte) []byte {
	t.Helper()
	a, err := chacha20poly1305.NewX(handJoinKey(t, c.Secret))
	if err != nil {
		t.Fatal(err)
	}
	nonce := bytes.Repeat([]byte{0x24}, chacha20poly1305.NonceSizeX)
	blob := append([]byte{1}, nonce...)
	return a.Seal(blob, nonce, pt, handRequestAD(c))
}

// handPayload lays out a response payload. The epoch key is bound to s,
// its version read from the body and its hash, unless ek carries a
// binding of its own; its sequence number is 1 unless ek has one.
func handPayload(binding []byte, ek epoch.Key, sec *Secrets, s roster.Signed) []byte {
	if ek.Roster == (epoch.Binding{}) {
		var v struct {
			Version uint64 `json:"version"`
		}
		_ = json.Unmarshal(s.Body, &v)
		ek.Roster = epoch.Binding{Version: v.Version, Hash: s.Hash()}
	}
	if ek.Seq == 0 {
		ek.Seq = 1
	}
	p := append([]byte(nil), binding...)
	p = binary.BigEndian.AppendUint32(p, ek.ID)
	p = binary.BigEndian.AppendUint64(p, uint64(ek.NotAfter.Unix()))
	p = binary.BigEndian.AppendUint64(p, ek.Roster.Version)
	p = append(p, ek.Roster.Hash[:]...)
	p = binary.BigEndian.AppendUint16(p, ek.Seq)
	p = append(p, ek.Authority)
	p = append(p, ek.Secret...)
	if sec == nil {
		p = append(p, 0)
	} else {
		p = append(p, 1)
		p = binary.BigEndian.AppendUint64(p, uint64(sec.ChatID))
		p = append(p, byte(len(sec.BotToken)))
		p = append(p, sec.BotToken...)
	}
	p = append(p, s.SignerID[:]...)
	p = append(p, s.Sig...)
	return append(p, s.Body...)
}

// handResponse seals payload to the joiner and signs it with key, placing
// outerPub in the header.
func handResponse(t testing.TB, key ed25519.PrivateKey, outerPub []byte, to *identity.Identity, payload []byte) []byte {
	t.Helper()
	ct, err := hpke.Seal(to.Recv.PublicKey(), hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(),
		append([]byte(fmtResponseInfo), to.ID[:]...), payload)
	if err != nil {
		t.Fatalf("hpke.Seal: %v", err)
	}
	blob := append([]byte{fmtRespVersion}, outerPub...)
	blob = append(blob, ct...)
	return append(blob, sig.Sign(key, fmtResponseKind, blob)...)
}

// handOpenResponse checks the layout of a response and returns its payload.
func handOpenResponse(t testing.TB, blob []byte, to *identity.Identity, adminPub []byte) []byte {
	t.Helper()
	if blob[0] != fmtRespVersion {
		t.Fatalf("response version %d, want %d", blob[0], fmtRespVersion)
	}
	if !bytes.Equal(blob[1:fmtRespHeader], adminPub) {
		t.Fatalf("response header does not carry the admin's public key")
	}
	n := len(blob) - fmtSigSize
	if !sig.Verify(adminPub, fmtResponseKind, blob[:n], blob[n:]) {
		t.Fatalf("response signature is not sig.Sign(admin, %q, everything before it)", fmtResponseKind)
	}
	pt, err := hpke.Open(to.Recv, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(),
		append([]byte(fmtResponseInfo), to.ID[:]...), blob[fmtRespHeader:n])
	if err != nil {
		t.Fatalf("hpke.Open of the response by hand: %v", err)
	}
	return pt
}

// handSignRoster signs body as the roster package does, without its checks.
func handSignRoster(key ed25519.PrivateKey, signer ids.MemberID, body []byte) roster.Signed {
	m := append(append(append([]byte(nil), signer[:]...), 0), body...)
	return roster.Signed{Body: body, SignerID: signer, Sig: sig.Sign(key, fmtRosterKind, m)}
}

// wantErr fails unless err is want (errors.Is).
func wantErr(t *testing.T, what string, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Errorf("%s: err = %v, want %v", what, err, want)
	}
}

// leakForms returns the encodings in which a secret could reach a string.
func leakForms(secret []byte) []string {
	forms := []string{
		string(secret),
		hex.EncodeToString(secret),
		strings.ToUpper(hex.EncodeToString(secret)),
		base64.StdEncoding.EncodeToString(secret),
		base64.RawURLEncoding.EncodeToString(secret),
		fmt.Sprint(secret),
		fmt.Sprintf("%#v", secret),
		crockford.EncodeToString(secret),
	}
	if len(secret) > 6 {
		// A prefix of the secret in the common encodings, in case only part leaks.
		forms = append(forms, hex.EncodeToString(secret[:6]), strings.ToUpper(hex.EncodeToString(secret[:6])))
	}
	return forms
}

// leaks reports the first form of any secret found in s.
func leaks(s string, secrets map[string][]byte) (string, bool) {
	for name, secret := range secrets {
		for _, form := range leakForms(secret) {
			if form != "" && strings.Contains(s, form) {
				return name + " as " + fmt.Sprintf("%q", form), true
			}
		}
	}
	return "", false
}
