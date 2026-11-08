// Package attest makes the statement `rollcall attest --nonce <hex>` prints:
// the router's own word on its state at the moment an outside auditor asked,
// signed with its member key over the auditor's nonce. A copy of the router's
// files cannot give it for a nonce it has not seen, and the kernel's boot ID
// beside the latest boot record shows whether the router that answers is the
// one whose boot its chain records.
//
// # What is signed
//
// The signature is sig.Sign(key, "attest", m), so Ed25519 over
//
//	"rollcall/v1/attest\x00" || m
//
// with the member's own signing key (the one its history entries are signed
// with) and, all integers big endian,
//
//	m = len(Nonce) (8) || Nonce ||
//	    Member (16) ||
//	    Head.Seq (8) || Head.Hash (32) ||
//	    KernelBoot (16) ||
//	    BootID (16) || BootSeq (8) ||
//	    len(OpenWrt) (8) || OpenWrt ||
//	    len(Rollcall) (8) || Rollcall ||
//	    Time (8, Unix seconds, two's complement)
//
// Every variable field carries its length, so m has one reading. The kind
// "attest" puts the statement in a domain of its own: the bytes signed for a
// history entry start "rollcall/v1/entry\x00" and those of a roster
// "rollcall/v1/roster\x00", and since no kind holds a NUL, no signature made
// for one of them verifies as another. docs/attest.md gives the same format
// with a test vector, for a verifier written without this code.
//
// # The fields
//
// Nonce is the caller's, 16 to 64 bytes (ParseNonce). Member is the member
// ID. Head is the head of the member's own history chain as its file holds
// it (Seq 0 and an all-zero Hash when it holds none). KernelBoot is the
// kernel's boot ID at the moment of the statement. BootID, BootSeq and
// OpenWrt come from the latest boot record in that chain: the boot ID it
// names, its boot sequence number (one more on each boot) and the OpenWrt
// release it was written on; all zero and empty when the chain holds no boot
// record. Rollcall is the version of the rollcall that signs, and Time the
// router's wall clock, in whole seconds.
package attest

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/history"
	"github.com/TAIPANBOX/rollcall/internal/ids"
	"github.com/TAIPANBOX/rollcall/internal/sig"
)

// Kind is the sig kind of every attest signature.
const Kind = "attest"

// signedPrefix starts the bytes an attest signature covers: the sig
// package's domain, the kind and the NUL after it.
const signedPrefix = "rollcall/v1/" + Kind + "\x00"

// The bounds of a nonce, in bytes, and of a version string, in characters.
const (
	MinNonce   = 16
	MaxNonce   = 64
	MaxVersion = 64
)

// Schema is the value of "schema" in the JSON a statement is printed as. It
// goes with Kind: a later format takes another kind and another schema.
const Schema = 1

var (
	// ErrNonce reports a nonce that is not 16 to 64 bytes in hex.
	ErrNonce = errors.New("attest: the nonce must be 16 to 64 bytes in hex (32 to 128 hex digits)")
	// ErrStatement reports a statement Sign refuses to sign.
	ErrStatement = errors.New("attest: invalid statement")
	// ErrFormat reports JSON that is not a statement as Encode writes it.
	ErrFormat = errors.New("attest: not a statement in the form rollcall attest prints")
)

// Statement is what an attest signature covers; see the package doc.
type Statement struct {
	Nonce      []byte
	Member     ids.MemberID
	Head       history.Head
	KernelBoot ids.BootID
	BootID     ids.BootID
	BootSeq    uint64
	OpenWrt    string
	Rollcall   string
	Time       time.Time
}

// ParseNonce reads a nonce from its hex form: an even number of hex digits,
// lower or upper case, from 32 to 128 of them, and nothing else (no "0x", no
// space). The length is checked before anything is decoded, so a nonce of
// any size costs no more than its length.
func ParseNonce(s string) ([]byte, error) {
	if len(s) < 2*MinNonce || len(s) > 2*MaxNonce || len(s)%2 != 0 {
		return nil, ErrNonce
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, ErrNonce
	}
	return b, nil
}

// Message returns m, the bytes the signature covers after the domain and the
// kind (see the package doc). It does not check s.
func (s Statement) Message() []byte {
	b := make([]byte, 0, 8+len(s.Nonce)+16+8+32+16+16+8+8+len(s.OpenWrt)+8+len(s.Rollcall)+8)
	b = binary.BigEndian.AppendUint64(b, uint64(len(s.Nonce)))
	b = append(b, s.Nonce...)
	b = append(b, s.Member[:]...)
	b = binary.BigEndian.AppendUint64(b, s.Head.Seq)
	b = append(b, s.Head.Hash[:]...)
	b = append(b, s.KernelBoot[:]...)
	b = append(b, s.BootID[:]...)
	b = binary.BigEndian.AppendUint64(b, s.BootSeq)
	b = binary.BigEndian.AppendUint64(b, uint64(len(s.OpenWrt)))
	b = append(b, s.OpenWrt...)
	b = binary.BigEndian.AppendUint64(b, uint64(len(s.Rollcall)))
	b = append(b, s.Rollcall...)
	return binary.BigEndian.AppendUint64(b, uint64(s.Time.Unix()))
}

// SigningBytes returns every byte the signature covers: "rollcall/v1/attest",
// a NUL and m. Ed25519 over exactly these bytes is the signature, so a
// verifier needs nothing of rollcall but this format.
func (s Statement) SigningBytes() []byte {
	return append([]byte(signedPrefix), s.Message()...)
}

// Check returns ErrStatement unless s is a statement Sign signs: a nonce of
// 16 to 64 bytes, a member ID that is not all zero, a head whose Seq and
// Hash are both zero or both not, a boot whose ID and sequence number are
// both zero or both not, versions of at most 64 characters from A-Z, a-z,
// 0-9 and ". - + _ ~" (the rule of a boot record's version), and a time from
// 1970 to 9999.
func (s Statement) Check() error {
	switch {
	case len(s.Nonce) < MinNonce || len(s.Nonce) > MaxNonce:
		return fmt.Errorf("%w: a nonce of %d bytes, want %d to %d", ErrStatement, len(s.Nonce), MinNonce, MaxNonce)
	case s.Member == ids.MemberID{}:
		return fmt.Errorf("%w: the member ID is all zero", ErrStatement)
	case (s.Head.Seq == 0) != (s.Head.Hash == ids.Hash{}):
		return fmt.Errorf("%w: a head with only one of its seq and hash", ErrStatement)
	case (s.BootSeq == 0) != (s.BootID == ids.BootID{}):
		return fmt.Errorf("%w: a boot with only one of its ID and seq", ErrStatement)
	case !validVersion(s.OpenWrt) || !validVersion(s.Rollcall):
		return fmt.Errorf("%w: a version outside the rule", ErrStatement)
	case s.Time.Before(minTime) || s.Time.After(maxTime):
		return fmt.Errorf("%w: a time outside 1970 to 9999", ErrStatement)
	}
	return nil
}

var (
	minTime = time.Unix(0, 0).UTC()
	maxTime = time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)
)

// validVersion reports whether v is at most MaxVersion characters from A-Z,
// a-z, 0-9 and ". - + _ ~".
func validVersion(v string) bool {
	if len(v) > MaxVersion {
		return false
	}
	for i := 0; i < len(v); i++ {
		switch c := v[i]; {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		case c == '.', c == '-', c == '+', c == '_', c == '~':
		default:
			return false
		}
	}
	return true
}

// Sign returns the signature of s by priv, after Check. It panics, as
// ed25519.Sign does, on a key of the wrong length.
func Sign(priv ed25519.PrivateKey, s Statement) ([]byte, error) {
	if err := s.Check(); err != nil {
		return nil, err
	}
	return sig.Sign(priv, Kind, s.Message()), nil
}

// Verify reports whether signature is pub's attest signature of s. It is
// false for a statement Check refuses, and for a key sig.ValidPublicKey
// refuses.
func Verify(pub ed25519.PublicKey, s Statement, signature []byte) bool {
	return s.Check() == nil && sig.Verify(pub, Kind, s.Message(), signature)
}

// output is the JSON object rollcall attest prints; docs/attest.md describes
// each field. Hex is lowercase; the time is RFC 3339 in UTC, whole seconds.
type output struct {
	Schema       int          `json:"schema"`
	Nonce        string       `json:"nonce"`
	Member       ids.MemberID `json:"member"`
	Head         history.Head `json:"head"`
	KernelBootID ids.BootID   `json:"kernel_boot_id"`
	Boot         bootOutput   `json:"boot"`
	Rollcall     string       `json:"rollcall"`
	Time         string       `json:"time"`
	Sig          string       `json:"sig"`
}

type bootOutput struct {
	ID      ids.BootID `json:"id"`
	Seq     uint64     `json:"seq"`
	OpenWrt string     `json:"openwrt"`
}

// timeFormat writes a time as RFC 3339 in UTC, whole seconds.
const timeFormat = "2006-01-02T15:04:05Z"

// Encode returns s and its signature as the JSON object rollcall attest
// prints, on one line, without a newline.
func Encode(s Statement, signature []byte) ([]byte, error) {
	return json.Marshal(output{
		Schema: Schema, Nonce: hex.EncodeToString(s.Nonce), Member: s.Member, Head: s.Head,
		KernelBootID: s.KernelBoot, Boot: bootOutput{ID: s.BootID, Seq: s.BootSeq, OpenWrt: s.OpenWrt},
		Rollcall: s.Rollcall, Time: time.Unix(s.Time.Unix(), 0).UTC().Format(timeFormat),
		Sig: hex.EncodeToString(signature),
	})
}

// maxEncoded bounds what Decode reads: a statement with the longest nonce
// and versions is under 900 bytes.
const maxEncoded = 4 << 10

// Decode reads a statement as a verifier does: exactly the bytes Encode
// writes for it, optionally followed by one newline (as rollcall attest
// prints it), so no unknown field, no other order or spacing, lowercase hex
// of the right lengths, schema 1 and the time in Encode's form. It returns
// the statement and the signature; it does not verify them (Verify does).
func Decode(b []byte) (Statement, []byte, error) {
	if len(b) > maxEncoded {
		return Statement{}, nil, fmt.Errorf("%w: %d bytes", ErrFormat, len(b))
	}
	body := bytes.TrimSuffix(b, []byte("\n"))
	var o output
	if err := decodeStrict(body, &o); err != nil {
		return Statement{}, nil, fmt.Errorf("%w: %v", ErrFormat, err)
	}
	if o.Schema != Schema {
		return Statement{}, nil, fmt.Errorf("%w: schema %d", ErrFormat, o.Schema)
	}
	nonce, err := hex.DecodeString(o.Nonce)
	if err != nil {
		return Statement{}, nil, fmt.Errorf("%w: the nonce is not hex", ErrFormat)
	}
	signature, err := hex.DecodeString(o.Sig)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return Statement{}, nil, fmt.Errorf("%w: the signature is not %d bytes in hex", ErrFormat, ed25519.SignatureSize)
	}
	t, err := time.Parse(timeFormat, o.Time)
	if err != nil {
		return Statement{}, nil, fmt.Errorf("%w: the time", ErrFormat)
	}
	s := Statement{
		Nonce: nonce, Member: o.Member, Head: o.Head, KernelBoot: o.KernelBootID,
		BootID: o.Boot.ID, BootSeq: o.Boot.Seq, OpenWrt: o.Boot.OpenWrt, Rollcall: o.Rollcall, Time: t,
	}
	if err := s.Check(); err != nil {
		return Statement{}, nil, fmt.Errorf("%w: %w", ErrFormat, err)
	}
	if again, err := Encode(s, signature); err != nil || !bytes.Equal(again, body) {
		return Statement{}, nil, fmt.Errorf("%w: not in the one form rollcall attest prints", ErrFormat)
	}
	return s, signature, nil
}

// decodeStrict decodes exactly one JSON value into v, refusing unknown
// fields and anything after the value.
func decodeStrict(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("data after the JSON value")
	}
	return nil
}
