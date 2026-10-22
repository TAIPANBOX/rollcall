package pairing

import (
	"bytes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hpke"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/TAIPANBOX/rollcall/internal/epoch"
	"github.com/TAIPANBOX/rollcall/internal/identity"
	"github.com/TAIPANBOX/rollcall/internal/ids"
	"github.com/TAIPANBOX/rollcall/internal/roster"
	"github.com/TAIPANBOX/rollcall/internal/sig"
)

const (
	// MaxTokenLen is the longest bot token a join response carries.
	MaxTokenLen = 128
	// MaxRequestSize is the length of a request with a 32-character name,
	// the longest there is.
	MaxRequestSize = reqHeader + reqFixed + roster.MaxNameLen + tagSize
	// MaxResponseSize is the longest join response: 1 KiB below the 64 KiB
	// TCP frame, so the transport's own header always fits beside it. The
	// largest roster with the longest token needs about 59.5 KB.
	MaxResponseSize = 63 << 10
)

const (
	reqVersion   = 1
	joinLabel    = "rollcall/v1 join"
	bindingLabel = "rollcall/v1 join-binding"

	nonceSize = chacha20poly1305.NonceSizeX
	tagSize   = 16
	reqHeader = 1 + nonceSize

	memberIDSize = len(ids.MemberID{})
	recvKeySize  = mlkem.EncapsulationKeySize768 + 32
	reqFixed     = memberIDSize + ed25519.PublicKeySize + recvKeySize
	minRequest   = reqHeader + reqFixed + 1 + tagSize

	respVersion  = 1
	respKind     = "join-response"
	respInfo     = "rollcall/v1 join-response"
	rosterKind   = "roster"
	encSize      = mlkem.CiphertextSize768 + 32 // X-Wing: ML-KEM-768 ciphertext and an X25519 point
	respHeader   = 1 + ed25519.PublicKeySize
	respOverhead = respHeader + encSize + tagSize + ed25519.SignatureSize

	bindingSize = 32
	epochSize   = 4 + 8 + epoch.SecretSize
	// The payload's fixed part: binding, epoch key, secrets flag, roster
	// signer and roster signature. The roster body follows, at least 1 byte.
	payloadFixed = bindingSize + epochSize + 1 + memberIDSize + ed25519.SignatureSize
	minResponse  = respOverhead + payloadFixed + 1
)

var (
	recvKEM = hpke.MLKEM768X25519()
	kdf     = hpke.HKDFSHA256()
	aead    = hpke.ChaCha20Poly1305()

	// probe is a fixed X25519 key. Its shared secret with a public value is
	// all zero, which ECDH refuses, exactly for the low-order points: every
	// X25519 scalar is a multiple of 8.
	probe = func() *ecdh.PrivateKey {
		k, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{0x5a}, 32))
		if err != nil {
			panic(err)
		}
		return k
	}()
)

// Request errors.
var (
	// ErrRequestFormat reports a request that is not version 1 or whose
	// length no valid request has.
	ErrRequestFormat = errors.New("pairing: the join request is not a version 1 request of a valid length")
	// ErrRequestAuth reports a request that does not open under the code:
	// made with another code, or changed on the way.
	ErrRequestAuth = errors.New("pairing: the join request was not made with this join code")
	// ErrMemberID reports a zero member ID.
	ErrMemberID = errors.New("pairing: the member ID is zero")
	// ErrSignKey reports a signing public key that sig.ValidPublicKey refuses.
	ErrSignKey = errors.New("pairing: invalid signing public key")
	// ErrRecvKey reports a receive public key that is not MLKEM768-X25519,
	// or whose X25519 part is a low-order point (the all-zero value among
	// them).
	ErrRecvKey = errors.New("pairing: invalid receive public key")
	// ErrName reports a router name that roster.ValidName refuses; it wraps
	// that error.
	ErrName = errors.New("pairing: invalid router name")
)

// Response errors.
var (
	// ErrNotAccepted reports a JoinRequest that Inviter.Accept did not
	// return, so no code was burned for it.
	ErrNotAccepted = errors.New("pairing: the join request was not accepted by an Inviter")
	// ErrEpochKey reports an epoch key whose secret is not 32 bytes or is
	// all zero, or whose NotAfter is outside 1970..9999.
	ErrEpochKey = errors.New("pairing: invalid epoch key")
	// ErrToken reports a bot token that is empty, longer than MaxTokenLen,
	// or has a byte outside A-Z, a-z, 0-9, ':', '_' and '-'.
	ErrToken = errors.New("pairing: invalid bot token")
	// ErrTooLarge reports a response that would be longer than
	// MaxResponseSize.
	ErrTooLarge = errors.New("pairing: the join response would be longer than MaxResponseSize")
	// ErrResponseFormat reports a response that is not version 1, whose
	// length no valid response has, or whose payload does not decode.
	ErrResponseFormat = errors.New("pairing: the join response is malformed")
	// ErrAdminFP reports a response whose key is not the one the code names.
	ErrAdminFP = errors.New("pairing: the join response is not from the admin the join code names")
	// ErrSignature reports a response whose signature does not verify.
	ErrSignature = errors.New("pairing: the join response signature does not verify")
	// ErrDecrypt reports a response that does not open with this router's
	// receive key and member ID.
	ErrDecrypt = errors.New("pairing: the join response does not open for this router")
	// ErrBinding reports a response made for another join code.
	ErrBinding = errors.New("pairing: the join response was made for another join code")
	// ErrRosterAnchor reports a roster that is not a valid roster signed by
	// the admin the code names, as an admin of that roster. It may wrap the
	// roster package's error.
	ErrRosterAnchor = errors.New("pairing: the roster is not a valid roster signed by the admin the join code names")
	// ErrNotInRoster reports a roster that does not hold the joining router
	// under its member ID with its own keys.
	ErrNotInRoster = errors.New("pairing: the roster does not hold the joining router with its own keys")
	// ErrSecretsNotSender reports a response that carries the bot token for
	// a router without the sender role.
	ErrSecretsNotSender = errors.New("pairing: the join response carries the bot token for a router without the sender role")
)

// Secrets are what only a router with the sender role receives.
type Secrets struct {
	BotToken string // 1 to MaxTokenLen bytes from A-Z, a-z, 0-9, ':', '_', '-'
	ChatID   int64  // the bound chat; 0 while none is bound
}

// Format prints neither the token nor the chat ID, for every verb.
func (Secrets) Format(s fmt.State, _ rune) { io.WriteString(s, "telegram secrets (redacted)") }

// JoinRequest is a join request that opened under a code.
type JoinRequest struct {
	ID      ids.MemberID      // the joining router's member ID
	Name    string            // its name; roster.ValidName accepts it
	SignPub ed25519.PublicKey // its signing key; sig.ValidPublicKey accepts it
	RecvPub []byte            // its MLKEM768-X25519 receive key, 1216 bytes

	binding  [bindingSize]byte // from the code's secret; the response carries it
	adminFP  [16]byte          // the code's AdminFP
	accepted bool              // set by Inviter.Accept, once the code is burned
}

// Format prints the member ID, for every verb; never the binding.
func (r JoinRequest) Format(s fmt.State, _ rune) {
	fmt.Fprintf(s, "join request from member %s", r.ID)
}

// NewJoinRequest returns self's request to join with code c under name.
//
// The request is
//
//	version (1) = 1 | nonce (24) | ciphertext and tag (16)
//
// XChaCha20-Poly1305 under hkdf.Key(sha256.New, c.Secret, nil,
// "rollcall/v1 join", 32), with a random nonce and the associated data
//
//	version (1) | c.Expires (8, Unix seconds, big endian) | c.AdminFP (16)
//
// of the plaintext
//
//	member ID (16) | Ed25519 public key (32) | MLKEM768-X25519 public key (1216) | name (1..32)
//
// so it is 1306 to 1337 bytes long. It returns ErrInvalid for a Code that
// ParseCode would refuse or an unusable self (zero member ID, signing key
// not whole and consistent, receive key not MLKEM768-X25519), ErrRecvKey for
// a receive key OpenJoinRequest would refuse, and ErrName for a name
// roster.ValidName refuses.
func NewJoinRequest(c Code, self *identity.Identity, name string) ([]byte, error) {
	if c.check() != nil {
		return nil, ErrInvalid
	}
	signPub, err := signingKey(self)
	if err != nil {
		return nil, err
	}
	if self.Recv == nil || self.Recv.KEM().ID() != recvKEM.ID() {
		return nil, ErrInvalid
	}
	recvPub := self.Recv.PublicKey().Bytes()
	if err := checkRecvKey(recvPub); err != nil {
		return nil, err
	}
	if err := roster.ValidName(name); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrName, err)
	}

	pt := make([]byte, 0, reqFixed+len(name))
	pt = append(pt, self.ID[:]...)
	pt = append(pt, signPub...)
	pt = append(pt, recvPub...)
	pt = append(pt, name...)

	a, err := joinAEAD(c.Secret)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceSize)
	rand.Read(nonce) // never fails since Go 1.24
	blob := make([]byte, 0, reqHeader+len(pt)+tagSize)
	blob = append(append(blob, reqVersion), nonce...)
	return a.Seal(blob, nonce, pt, requestAD(c)), nil
}

// OpenJoinRequest checks a request against c and returns what it carries.
// It checks, cheapest first: c (ErrInvalid), the length and version
// (ErrRequestFormat), the AEAD under the code's key and associated data
// (ErrRequestAuth), and only then the fields: the member ID (ErrMemberID),
// the signing key (ErrSignKey), the receive key (ErrRecvKey, including an
// X25519 part that is a low-order point) and the name (ErrName). The
// returned request is not yet accepted; Inviter.Accept is what accepts one.
// On error the JoinRequest is the zero value.
func OpenJoinRequest(c Code, blob []byte) (JoinRequest, error) {
	if c.check() != nil {
		return JoinRequest{}, ErrInvalid
	}
	if len(blob) < minRequest || len(blob) > MaxRequestSize || blob[0] != reqVersion {
		return JoinRequest{}, ErrRequestFormat
	}
	a, err := joinAEAD(c.Secret)
	if err != nil {
		return JoinRequest{}, err
	}
	pt, err := a.Open(nil, blob[1:reqHeader], blob[reqHeader:], requestAD(c))
	if err != nil {
		return JoinRequest{}, ErrRequestAuth
	}
	id := ids.MemberID(pt[:memberIDSize])
	signPub := bytes.Clone(pt[memberIDSize : memberIDSize+ed25519.PublicKeySize])
	recvPub := bytes.Clone(pt[memberIDSize+ed25519.PublicKeySize : reqFixed])
	name := string(pt[reqFixed:])
	if id == (ids.MemberID{}) {
		return JoinRequest{}, ErrMemberID
	}
	if sig.ValidPublicKey(signPub) != nil {
		return JoinRequest{}, ErrSignKey
	}
	if err := checkRecvKey(recvPub); err != nil {
		return JoinRequest{}, err
	}
	if err := roster.ValidName(name); err != nil {
		return JoinRequest{}, fmt.Errorf("%w: %w", ErrName, err)
	}
	b, err := binding(c.Secret)
	if err != nil {
		return JoinRequest{}, err
	}
	return JoinRequest{ID: id, Name: name, SignPub: signPub, RecvPub: recvPub, binding: b, adminFP: c.AdminFP}, nil
}

// checkRecvKey returns ErrRecvKey unless pub is an MLKEM768-X25519 public
// key whose X25519 part is not a low-order point. The X25519 part is the
// last 32 bytes, after the 1184-byte ML-KEM-768 encapsulation key (Go's
// crypto/hpke, hybridKEM.NewPublicKey). hpke accepts a low-order point
// there and only fails when sealing to it; the all-zero value is one.
func checkRecvKey(pub []byte) error {
	if _, err := recvKEM.NewPublicKey(pub); err != nil {
		return ErrRecvKey
	}
	x, err := ecdh.X25519().NewPublicKey(pub[mlkem.EncapsulationKeySize768:])
	if err != nil {
		return ErrRecvKey
	}
	if _, err := probe.ECDH(x); err != nil {
		return ErrRecvKey
	}
	return nil
}

// joinAEAD returns XChaCha20-Poly1305 under the join key of secret.
func joinAEAD(secret [16]byte) (cipher.AEAD, error) {
	key, err := hkdf.Key(sha256.New, secret[:], nil, joinLabel, chacha20poly1305.KeySize)
	if err != nil {
		return nil, ErrInvalid
	}
	defer clear(key)
	a, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, ErrInvalid
	}
	return a, nil
}

func requestAD(c Code) []byte {
	ad := make([]byte, 0, 1+8+16)
	ad = append(ad, reqVersion)
	ad = binary.BigEndian.AppendUint64(ad, uint64(c.Expires.Unix()))
	return append(ad, c.AdminFP[:]...)
}

// binding returns hkdf.Key(sha256.New, secret, nil, "rollcall/v1 join-binding", 32):
// a value only a holder of the code can compute, which ties a response to
// the code it answers.
func binding(secret [16]byte) ([bindingSize]byte, error) {
	k, err := hkdf.Key(sha256.New, secret[:], nil, bindingLabel, bindingSize)
	if err != nil {
		return [bindingSize]byte{}, ErrInvalid
	}
	return [bindingSize]byte(k), nil
}

// NewJoinResponse answers req, which Inviter.Accept returned, with r, the
// roster that now holds the joining router, the epoch key ek and, only if
// the router's entry in r has roster.RoleSender, the secrets in token.
//
// The response is
//
//	version (1) = 1 | admin's Ed25519 public key (32) | HPKE ciphertext | signature (64)
//
// The ciphertext is hpke.Seal, base mode, to req.RecvPub with HKDF-SHA256
// and ChaCha20-Poly1305 and the info "rollcall/v1 join-response" followed by
// req.ID: the encapsulated key (1120) and the sealed payload and tag (16).
// The signature is sig.Sign(admin, "join-response", everything before it).
// The payload is
//
//	binding (32) | epoch ID (4) | NotAfter (8, Unix seconds) | epoch secret (32) |
//	secrets (1): 0, or 1 followed by chat ID (8) | token length (1) | token |
//	roster signer ID (16) | roster signature (64) | roster body (the rest)
//
// integers big endian, with the binding hkdf.Key(sha256.New, code secret,
// nil, "rollcall/v1 join-binding", 32). The epoch key travels in the payload
// itself rather than as a separate epoch.Seal delivery: the payload is
// already sealed to the router and signed by the admin.
//
// It returns, cheapest first: ErrInvalid for an unusable admin identity or
// one whose fingerprint is not the code's; ErrNotAccepted for a request that
// Inviter.Accept did not return; ErrRosterAnchor for a roster that
// OpenJoinResponse would refuse (signed by anyone but admin, as an admin of
// r, with a valid signature, passing Check); ErrNotInRoster if r does not
// hold req.ID with req's keys; ErrEpochKey; ErrToken for a token that is
// sent and invalid; ErrTooLarge. A token for a router that is not a sender
// is left out without an error.
func NewJoinResponse(req JoinRequest, r roster.Signed, ek epoch.Key, token *Secrets, admin *identity.Identity) ([]byte, error) {
	adminPub, err := signingKey(admin)
	if err != nil {
		return nil, err
	}
	if !req.accepted || req.binding == ([bindingSize]byte{}) {
		return nil, ErrNotAccepted
	}
	if AdminFingerprint(adminPub) != req.adminFP {
		return nil, ErrInvalid
	}
	if r.SignerID != admin.ID {
		return nil, ErrRosterAnchor
	}
	rr, err := verifyAnchored(r, adminPub)
	if err != nil {
		return nil, err
	}
	m := findMember(&rr, req.ID)
	if m == nil || !bytes.Equal(m.SignPub, req.SignPub) || !bytes.Equal(m.RecvPub, req.RecvPub) {
		return nil, ErrNotInRoster
	}
	if err := checkEpochKey(ek.Secret, ek.NotAfter.Unix()); err != nil {
		return nil, err
	}
	var sec *Secrets
	if token != nil && slices.Contains(m.Roles, roster.RoleSender) {
		if !validToken(token.BotToken) {
			return nil, ErrToken
		}
		sec = token
	}
	to, err := recvKEM.NewPublicKey(req.RecvPub)
	if err != nil {
		return nil, ErrRecvKey
	}
	payload := encodePayload(req.binding, ek, sec, r)
	defer clear(payload)
	return sealResponse(payload, to, req.ID, admin.Sign)
}

// sealResponse seals payload to the joiner and signs it, or returns
// ErrTooLarge if the response would exceed MaxResponseSize.
func sealResponse(payload []byte, to hpke.PublicKey, joiner ids.MemberID, admin ed25519.PrivateKey) ([]byte, error) {
	if respOverhead+len(payload) > MaxResponseSize {
		return nil, ErrTooLarge
	}
	ct, err := hpke.Seal(to, kdf, aead, responseInfo(joiner), payload)
	if err != nil {
		return nil, ErrRecvKey
	}
	blob := make([]byte, 0, respOverhead+len(payload))
	blob = append(blob, respVersion)
	blob = append(blob, admin[ed25519.SeedSize:]...)
	blob = append(blob, ct...)
	return append(blob, sig.Sign(admin, respKind, blob)...), nil
}

func responseInfo(joiner ids.MemberID) []byte {
	return append([]byte(respInfo), joiner[:]...)
}

// encodePayload lays out the payload as NewJoinResponse describes it.
func encodePayload(b [bindingSize]byte, ek epoch.Key, sec *Secrets, r roster.Signed) []byte {
	n := payloadFixed + len(r.Body)
	if sec != nil {
		n += 8 + 1 + len(sec.BotToken)
	}
	p := make([]byte, 0, n)
	p = append(p, b[:]...)
	p = binary.BigEndian.AppendUint32(p, ek.ID)
	p = binary.BigEndian.AppendUint64(p, uint64(ek.NotAfter.Unix()))
	p = append(p, ek.Secret...)
	if sec == nil {
		p = append(p, 0)
	} else {
		p = append(p, 1)
		p = binary.BigEndian.AppendUint64(p, uint64(sec.ChatID))
		p = append(p, byte(len(sec.BotToken)))
		p = append(p, sec.BotToken...)
	}
	p = append(p, r.SignerID[:]...)
	p = append(p, r.Sig...)
	return append(p, r.Body...)
}

// payload is a decoded response payload.
type payload struct {
	binding []byte
	key     epoch.Key
	secrets *Secrets
	roster  roster.Signed
}

// decodePayload reads a payload. Every value it returns is a copy, so p may
// be cleared afterwards.
func decodePayload(p []byte) (payload, error) {
	if len(p) < payloadFixed+1 {
		return payload{}, ErrResponseFormat
	}
	var out payload
	out.binding = bytes.Clone(p[:bindingSize])
	p = p[bindingSize:]
	notAfter := int64(binary.BigEndian.Uint64(p[4:12]))
	if err := checkEpochKey(p[12:epochSize], notAfter); err != nil {
		return payload{}, err
	}
	out.key = epoch.Key{
		ID:       binary.BigEndian.Uint32(p[0:4]),
		Secret:   bytes.Clone(p[12:epochSize]),
		NotAfter: time.Unix(notAfter, 0).UTC(),
	}
	p = p[epochSize:]
	switch p[0] {
	case 0:
		p = p[1:]
	case 1:
		// At least 82 bytes are left here (the length check above), more
		// than flag, chat ID and token length need.
		chat := int64(binary.BigEndian.Uint64(p[1:9]))
		n := int(p[9]) // validToken refuses 0 and anything over MaxTokenLen
		p = p[10:]
		if len(p) < n {
			return payload{}, ErrResponseFormat
		}
		tok := string(p[:n])
		if !validToken(tok) {
			return payload{}, ErrToken
		}
		out.secrets = &Secrets{BotToken: tok, ChatID: chat}
		p = p[n:]
	default:
		return payload{}, ErrResponseFormat
	}
	if len(p) < memberIDSize+ed25519.SignatureSize+1 {
		return payload{}, ErrResponseFormat
	}
	out.roster = roster.Signed{
		SignerID: ids.MemberID(p[:memberIDSize]),
		Sig:      bytes.Clone(p[memberIDSize : memberIDSize+ed25519.SignatureSize]),
		Body:     bytes.Clone(p[memberIDSize+ed25519.SignatureSize:]),
	}
	return out, nil
}

// OpenJoinResponse checks a response to self's request made with code c
// and returns the roster, the epoch key, and the secrets if self is a
// sender and the admin sent them.
//
// It checks, cheapest first: its arguments (ErrInvalid); the length and
// version (ErrResponseFormat); that the response's key has the code's
// fingerprint (ErrAdminFP); the signature under that key (ErrSignature);
// only then opens the HPKE ciphertext with self's receive key and member ID
// (ErrDecrypt) and decodes the payload (ErrResponseFormat, ErrEpochKey,
// ErrToken); the binding to c (ErrBinding); the roster (ErrRosterAnchor),
// which is accepted whatever its version, but only if it is signed by that
// same key, the key belongs to an admin of that roster, and the roster
// passes Check; that the roster holds self with its own keys
// (ErrNotInRoster); and that secrets come only to a sender
// (ErrSecretsNotSender). On error every value returned is zero.
func OpenJoinResponse(c Code, blob []byte, self *identity.Identity) (roster.Signed, epoch.Key, *Secrets, error) {
	if c.check() != nil {
		return roster.Signed{}, epoch.Key{}, nil, ErrInvalid
	}
	selfPub, err := signingKey(self)
	if err != nil || self.Recv == nil || self.Recv.KEM().ID() != recvKEM.ID() {
		return roster.Signed{}, epoch.Key{}, nil, ErrInvalid
	}
	if len(blob) < minResponse || len(blob) > MaxResponseSize || blob[0] != respVersion {
		return roster.Signed{}, epoch.Key{}, nil, ErrResponseFormat
	}
	adminPub := ed25519.PublicKey(blob[1:respHeader])
	if AdminFingerprint(adminPub) != c.AdminFP {
		return roster.Signed{}, epoch.Key{}, nil, ErrAdminFP
	}
	end := len(blob) - ed25519.SignatureSize
	if !sig.Verify(adminPub, respKind, blob[:end], blob[end:]) {
		return roster.Signed{}, epoch.Key{}, nil, ErrSignature
	}
	pt, err := hpke.Open(self.Recv, kdf, aead, responseInfo(self.ID), blob[respHeader:end])
	if err != nil {
		return roster.Signed{}, epoch.Key{}, nil, ErrDecrypt
	}
	defer clear(pt)
	p, err := decodePayload(pt)
	if err != nil {
		return roster.Signed{}, epoch.Key{}, nil, err
	}
	want, err := binding(c.Secret)
	if err != nil || subtle.ConstantTimeCompare(p.binding, want[:]) != 1 {
		return roster.Signed{}, epoch.Key{}, nil, ErrBinding
	}
	r, err := verifyAnchored(p.roster, bytes.Clone(adminPub))
	if err != nil {
		return roster.Signed{}, epoch.Key{}, nil, err
	}
	m := findMember(&r, self.ID)
	if m == nil || !bytes.Equal(m.SignPub, selfPub) || !bytes.Equal(m.RecvPub, self.Recv.PublicKey().Bytes()) {
		return roster.Signed{}, epoch.Key{}, nil, ErrNotInRoster
	}
	if p.secrets != nil && !slices.Contains(m.Roles, roster.RoleSender) {
		return roster.Signed{}, epoch.Key{}, nil, ErrSecretsNotSender
	}
	return p.roster, p.key, p.secrets, nil
}

// verifyAnchored accepts a roster of any version on the authority of key
// alone, which the caller has tied to a join code's fingerprint: the roster
// must be signed, not with the recovery key, by key as the member it names
// as signer; decode in the roster package's one canonical form; pass Check;
// and list that signer among its admins with key as its signing key. The
// signature is checked before the body is decoded. It does not judge the
// chain: there is no previous roster to judge it against. Every error is
// ErrRosterAnchor, wrapping the roster package's error where there is one.
func verifyAnchored(s roster.Signed, key ed25519.PublicKey) (roster.Roster, error) {
	// A zero signer ID or an empty body cannot pass the checks below: Check
	// keeps zero IDs out of Admins, and an empty body does not decode. A
	// body over roster.MaxBodySize does not fit a response.
	if s.Recovery {
		return roster.Roster{}, ErrRosterAnchor
	}
	// The roster package signs signer ID (16) | recovery (1) | body.
	m := make([]byte, 0, memberIDSize+1+len(s.Body))
	m = append(m, s.SignerID[:]...)
	m = append(m, 0)
	m = append(m, s.Body...)
	if !sig.Verify(key, rosterKind, m, s.Sig) {
		return roster.Roster{}, ErrRosterAnchor
	}
	r, err := decodeRoster(s.Body)
	if err != nil {
		return roster.Roster{}, ErrRosterAnchor
	}
	if err := r.Check(); err != nil {
		return roster.Roster{}, fmt.Errorf("%w: %w", ErrRosterAnchor, err)
	}
	if !slices.Contains(r.Admins, s.SignerID) {
		return roster.Roster{}, ErrRosterAnchor
	}
	if signer := findMember(&r, s.SignerID); signer == nil || !bytes.Equal(signer.SignPub, key) {
		return roster.Roster{}, ErrRosterAnchor
	}
	return r, nil
}

// decodeRoster decodes a roster body that must be in the roster package's
// canonical form: one JSON object of the Roster fields alone, nothing after
// it, which encoding again gives back byte for byte.
func decodeRoster(body []byte) (roster.Roster, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var r roster.Roster
	if err := dec.Decode(&r); err != nil {
		return roster.Roster{}, ErrRosterAnchor
	}
	// Data after the object makes the body longer than its encoding, so the
	// comparison refuses it too.
	if again, err := json.Marshal(r); err != nil || !bytes.Equal(again, body) {
		return roster.Roster{}, ErrRosterAnchor
	}
	return r, nil
}

// findMember returns r's member with id, or nil.
func findMember(r *roster.Roster, id ids.MemberID) *roster.Member {
	for i := range r.Members {
		if r.Members[i].ID == id {
			return &r.Members[i]
		}
	}
	return nil
}

// checkEpochKey returns ErrEpochKey unless secret is epoch.SecretSize bytes,
// not all zero, and notAfter (Unix seconds) is within 1..9999-12-31.
func checkEpochKey(secret []byte, notAfter int64) error {
	if len(secret) != epoch.SecretSize || notAfter < 1 || notAfter > maxUnix {
		return ErrEpochKey
	}
	var acc byte
	for _, b := range secret {
		acc |= b
	}
	if acc == 0 {
		return ErrEpochKey
	}
	return nil
}

// validToken reports whether t is 1 to MaxTokenLen bytes from A-Z, a-z,
// 0-9, ':', '_' and '-': a Telegram token is digits, ':' and a base64url
// string, and nothing in that set can change the request path it goes into.
func validToken(t string) bool {
	if len(t) == 0 || len(t) > MaxTokenLen {
		return false
	}
	for i := 0; i < len(t); i++ {
		c := t[i]
		if !('A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == ':' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}
