// Package pairing lets a new router join a group (security spec 6, join):
// the owner opens a one-time join code on an admin router and copies it by
// hand to the new router; the new router proves it holds the code with a
// join request; the admin answers with a join response that carries the
// signed roster, the current epoch key and, for a router with the sender
// role only, the Telegram bot token and chat ID.
//
// # Join code
//
// A Code names the admin router to connect to (Bootstrap), the fingerprint
// of the admin's Ed25519 key (AdminFP), a 128-bit one-time secret and the
// time it expires. Its text is Crockford base32 (0-9 and A-Z without I, L, O
// and U), upper case, in groups of five separated by "-", of the bytes
//
//	version (1) = 1 | family (1): 4 or 6 | address (4 or 16) | port (2) |
//	admin fingerprint (16) | secret (16) | expires (8, Unix seconds) |
//	checksum (4)
//
// all integers big endian, the checksum the first 4 bytes of SHA-256 over
// "rollcall/v1 join-code\x00" and every byte before it. Bits are taken most
// significant first; the last symbol is padded with zero bits. An IPv4 code
// is 52 bytes, 84 symbols.
//
// ParseCode forgives what copying by hand does: white space around the code,
// dashes anywhere, lower case, and O for 0, I or L for 1. Anything else is
// refused, and the errors say what kind of fault it is without repeating the
// text: ErrCodeTypo for a character that is not a symbol, a length that is no
// code, padding bits that are not zero or a checksum that does not match (so
// a typo never reaches the network as a wrong secret); ErrCodeVersion for a
// well-formed code of another version; ErrCodeInvalid for a well-formed
// version 1 code with a value no admin makes. Each Code has exactly one text.
//
// AdminFingerprint is the first 16 bytes of SHA-256 over
// "rollcall/v1 admin-fp\x00" and the admin's Ed25519 public key.
//
// # Inviter
//
// An Inviter holds the one open code of an admin router, in memory only.
// Open makes a new code valid for JoinWindow (10 minutes) and revokes any
// code opened before it. Accept opens a join request against the open code
// and burns the code when the request is valid; a request that does not open
// leaves the code open, so a stranger on the LAN cannot burn it without
// knowing it. Consume burns a code without a request. The window is measured
// as now minus the time of Open, so a monotonic clock reading (time.Now)
// measures it whatever the wall clock does; a time earlier than Open closes
// the code. The Expires a code shows is that end in whole seconds, rounded
// down, and is not enforced on its own.
//
// # Join request and response
//
// NewJoinRequest seals the new router's member ID, public keys and name
// with XChaCha20-Poly1305 under a key derived from the code's secret, with
// the code's expiry and fingerprint as associated data, so only a holder of
// the code can make one. NewJoinResponse seals the roster, the epoch key
// and the secrets to the new router's receive key with HPKE and signs the
// whole response with the admin's key; OpenJoinResponse checks that key
// against the code's fingerprint before anything else. A response also
// carries a value derived from the code's secret, so a response captured in
// an earlier pairing does not open under a new code. The layouts are in the
// comments of NewJoinRequest and NewJoinResponse. Both are fixed binary
// layouts rather than JSON: the largest roster body is about 58 KB and would
// not fit the 64 KiB TCP frame in base64.
//
// The roster in a response may be of any version, since the new router has
// none to compare it with. It is accepted on the authority of the code
// alone (roster.Signed.VerifyAnchored): signed by the key whose fingerprint
// the code carries, that key an admin's in that very roster, and the roster
// passing Check.
//
// Every error is a sentinel, or wraps sentinels, and never carries a secret,
// a token, key bytes or the text of a code.
package pairing

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/identity"
	"github.com/TAIPANBOX/rollcall/internal/ids"
)

// JoinWindow is how long a join code stays open.
const JoinWindow = 10 * time.Minute

const (
	codeVersion  = 1
	codeLabel    = "rollcall/v1 join-code\x00"
	fpLabel      = "rollcall/v1 admin-fp\x00"
	checksumSize = 4
	maxCodeText  = 256 // an IPv6 code is 103 symbols and 20 dashes
	alphabet     = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

	// maxUnix is 9999-12-31T23:59:59Z. Later values overflow time.Time's
	// internal seconds.
	maxUnix = 253402300799
)

// Code errors.
var (
	// ErrCodeTypo reports text that is not a join code as typed: a character
	// that is not a symbol, a wrong length, or a checksum that does not match.
	ErrCodeTypo = errors.New("pairing: the join code has a typo or is not a join code; copy it again")
	// ErrCodeVersion reports a well-formed code of another version.
	ErrCodeVersion = errors.New("pairing: the join code was made by another version of rollcall")
	// ErrCodeInvalid reports a well-formed version 1 code with a value no
	// admin makes: a zero secret or fingerprint, an unusable address, an
	// expiry outside 1970..9999, or a length that does not match the family.
	ErrCodeInvalid = errors.New("pairing: the join code holds an invalid value")
	// ErrBootstrap reports a bootstrap address that is not a unicast IPv4 or
	// IPv6 address without a zone, with a port other than 0.
	ErrBootstrap = errors.New("pairing: the bootstrap address must be a unicast IPv4 or IPv6 address without a zone, and a port")
	// ErrInvalid reports an unusable argument: an identity without valid
	// keys or member ID, a Code that ParseCode would refuse, or a time out of
	// range.
	ErrInvalid = errors.New("pairing: invalid argument")
	// ErrCodeClosed reports that no join code is open for the request: none
	// was opened, or it was used, replaced or closed by expiry, or the code
	// given is not the open one.
	ErrCodeClosed = errors.New("pairing: no such join code is open")
	// ErrCodeExpired reports that the open code's window is over. The code is
	// closed by it.
	ErrCodeExpired = errors.New("pairing: the join code has expired")
)

// Code is a one-time join code.
type Code struct {
	Bootstrap netip.AddrPort // the admin router to connect to
	AdminFP   [16]byte       // AdminFingerprint of the admin's signing key
	Secret    [16]byte       // the one-time join secret
	Expires   time.Time      // when the admin stops accepting it
}

// String returns the code's text as the package comment describes it, for
// root to copy. A Code that ParseCode would refuse has the empty text, so an
// invalid code is never shown as if it worked. Fractions of a second in
// Expires are dropped.
//
// String is the only way to the text: fmt prints a Code through Format,
// which leaves the secret out.
func (c Code) String() string {
	b, err := c.payload()
	if err != nil {
		return ""
	}
	sum := codeChecksum(b)
	raw := encode32(append(b, sum[:]...))
	var s strings.Builder
	for i := 0; i < len(raw); i += 5 {
		if i > 0 {
			s.WriteByte('-')
		}
		s.WriteString(raw[i:min(i+5, len(raw))])
	}
	return s.String()
}

// Format prints the bootstrap address and the expiry for every verb, never
// the secret or the text of the code.
func (c Code) Format(s fmt.State, _ rune) {
	fmt.Fprintf(s, "join code for %s, expires %s", c.Bootstrap, c.Expires.UTC().Format(time.RFC3339))
}

// payload returns the code's bytes before the checksum, or ErrCodeInvalid.
func (c Code) payload() ([]byte, error) {
	if err := c.check(); err != nil {
		return nil, err
	}
	a := c.Bootstrap.Addr()
	b := make([]byte, 0, 64)
	b = append(b, codeVersion)
	if a.Is4() {
		v := a.As4()
		b = append(append(b, 4), v[:]...)
	} else {
		v := a.As16()
		b = append(append(b, 6), v[:]...)
	}
	b = binary.BigEndian.AppendUint16(b, c.Bootstrap.Port())
	b = append(b, c.AdminFP[:]...)
	b = append(b, c.Secret[:]...)
	return binary.BigEndian.AppendUint64(b, uint64(c.Expires.Unix())), nil
}

// check returns ErrCodeInvalid unless c is a code an admin could have made.
func (c Code) check() error {
	if err := checkBootstrap(c.Bootstrap); err != nil {
		return fmt.Errorf("%w: %w", ErrCodeInvalid, err)
	}
	if c.AdminFP == ([16]byte{}) || c.Secret == ([16]byte{}) {
		return ErrCodeInvalid
	}
	if e := c.Expires.Unix(); e < 1 || e > maxUnix {
		return ErrCodeInvalid
	}
	return nil
}

// checkBootstrap returns ErrBootstrap unless ap is a unicast IPv4 address,
// or an IPv6 address that is not IPv4-mapped and has no zone, with a port
// other than 0. A zone names an interface of the admin, which means nothing
// to the router that reads the code.
func checkBootstrap(ap netip.AddrPort) error {
	a := ap.Addr()
	if !ap.IsValid() || a.Zone() != "" || a.Is4In6() || a.IsUnspecified() || a.IsMulticast() || ap.Port() == 0 {
		return ErrBootstrap
	}
	return nil
}

// ParseCode reads a code's text as the package comment describes it.
func ParseCode(s string) (Code, error) {
	s = strings.TrimSpace(s)
	if len(s) > maxCodeText {
		return Code{}, ErrCodeTypo
	}
	syms := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '-' {
			continue
		}
		v, ok := symbol(s[i])
		if !ok {
			return Code{}, ErrCodeTypo
		}
		syms = append(syms, v)
	}
	b, ok := decode32(syms)
	if !ok || len(b) <= checksumSize {
		return Code{}, ErrCodeTypo
	}
	body := b[:len(b)-checksumSize]
	sum := codeChecksum(body)
	if !bytes.Equal(sum[:], b[len(body):]) {
		return Code{}, ErrCodeTypo
	}
	if body[0] != codeVersion {
		return Code{}, ErrCodeVersion
	}
	return decodeCodeBody(body)
}

// decodeCodeBody reads a version 1 body whose checksum matched.
func decodeCodeBody(b []byte) (Code, error) {
	if len(b) < 2 {
		return Code{}, ErrCodeInvalid
	}
	var addr netip.Addr
	rest := b[2:]
	switch b[1] {
	case 4:
		if len(rest) != 4+2+16+16+8 {
			return Code{}, ErrCodeInvalid
		}
		addr = netip.AddrFrom4([4]byte(rest[:4]))
		rest = rest[4:]
	case 6:
		if len(rest) != 16+2+16+16+8 {
			return Code{}, ErrCodeInvalid
		}
		addr = netip.AddrFrom16([16]byte(rest[:16]))
		rest = rest[16:]
	default:
		return Code{}, ErrCodeInvalid
	}
	// An expiry past 2^63 reads as negative; check refuses it as it refuses
	// every value outside 1..maxUnix.
	c := Code{
		Bootstrap: netip.AddrPortFrom(addr, binary.BigEndian.Uint16(rest[0:2])),
		AdminFP:   [16]byte(rest[2:18]),
		Secret:    [16]byte(rest[18:34]),
		Expires:   time.Unix(int64(binary.BigEndian.Uint64(rest[34:42])), 0).UTC(),
	}
	if err := c.check(); err != nil {
		return Code{}, err
	}
	return c, nil
}

// codeChecksum returns the first 4 bytes of SHA-256 over the label and b.
func codeChecksum(b []byte) [checksumSize]byte {
	h := sha256.New()
	h.Write([]byte(codeLabel))
	h.Write(b)
	var sum [checksumSize]byte
	copy(sum[:], h.Sum(nil))
	return sum
}

// symbol returns the 5-bit value of a Crockford base32 character: either
// case, O read as 0 and I or L as 1. U and everything else are refused.
func symbol(c byte) (byte, bool) {
	if 'a' <= c && c <= 'z' {
		c -= 'a' - 'A'
	}
	switch c {
	case 'O':
		return 0, true
	case 'I', 'L':
		return 1, true
	}
	if i := strings.IndexByte(alphabet, c); i >= 0 {
		return byte(i), true
	}
	return 0, false
}

// encode32 encodes b in Crockford base32, most significant bits first, the
// last symbol padded with zero bits.
func encode32(b []byte) string {
	out := make([]byte, 0, (len(b)*8+4)/5)
	var acc uint32
	var n uint
	for _, x := range b {
		acc = acc<<8 | uint32(x)
		n += 8
		for n >= 5 {
			n -= 5
			out = append(out, alphabet[acc>>n&31])
		}
		acc &= 1<<n - 1
	}
	if n > 0 {
		out = append(out, alphabet[acc<<(5-n)&31])
	}
	return string(out)
}

// decode32 decodes 5-bit symbol values into bytes. It refuses a count of
// symbols that no byte length encodes to, and padding bits that are not
// zero, so that each byte string has exactly one encoding.
func decode32(syms []byte) ([]byte, bool) {
	out := make([]byte, 0, len(syms)*5/8)
	var acc uint32
	var n uint
	for _, v := range syms {
		acc = acc<<5 | uint32(v)
		n += 5
		if n >= 8 {
			n -= 8
			out = append(out, byte(acc>>n))
		}
		acc &= 1<<n - 1
	}
	if n >= 5 || acc != 0 {
		return nil, false
	}
	return out, true
}

// AdminFingerprint returns the first 16 bytes of SHA-256 over
// "rollcall/v1 admin-fp\x00" and pub.
func AdminFingerprint(pub ed25519.PublicKey) [16]byte {
	h := sha256.New()
	h.Write([]byte(fpLabel))
	h.Write(pub)
	var fp [16]byte
	copy(fp[:], h.Sum(nil))
	return fp
}

// signingKey returns the public half of id's signing key, or ErrInvalid if id
// is nil, has a zero member ID, or has a signing key that is not a whole,
// consistent Ed25519 private key. A key derived from its seed is never of
// small order, so the public half needs no further check.
func signingKey(id *identity.Identity) (ed25519.PublicKey, error) {
	if id == nil || id.ID == (ids.MemberID{}) || len(id.Sign) != ed25519.PrivateKeySize {
		return nil, ErrInvalid
	}
	if !bytes.Equal(ed25519.NewKeyFromSeed(id.Sign.Seed()), id.Sign) {
		return nil, ErrInvalid
	}
	return bytes.Clone(id.Sign[ed25519.SeedSize:]), nil
}

// Inviter holds an admin router's open join code. The zero value has none.
// It is safe for concurrent use and must not be copied after first use.
type Inviter struct {
	mu     sync.Mutex
	open   bool
	code   Code
	opened time.Time // the now of Open, with its monotonic reading if any
}

// Open makes a new join code for admin, to be reached at bootstrap, valid
// from now for JoinWindow, and revokes any code opened before it. An
// IPv4-mapped bootstrap address is shown as IPv4. It returns ErrBootstrap
// for an address checkBootstrap refuses, and ErrInvalid for an unusable
// admin identity or a now whose window would end outside 1970..9999.
func (i *Inviter) Open(now time.Time, bootstrap netip.AddrPort, admin *identity.Identity) (Code, error) {
	pub, err := signingKey(admin)
	if err != nil {
		return Code{}, err
	}
	if bootstrap.Addr().Zone() != "" {
		return Code{}, ErrBootstrap
	}
	bootstrap = netip.AddrPortFrom(bootstrap.Addr().Unmap(), bootstrap.Port())
	if err := checkBootstrap(bootstrap); err != nil {
		return Code{}, err
	}
	end := now.Add(JoinWindow).Unix()
	if end < 1 || end > maxUnix {
		return Code{}, ErrInvalid
	}
	c := Code{Bootstrap: bootstrap, AdminFP: AdminFingerprint(pub), Expires: time.Unix(end, 0).UTC()}
	for c.Secret == ([16]byte{}) {
		// Since Go 1.24 rand.Read never returns an error: a failing system
		// source ends the program.
		rand.Read(c.Secret[:])
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	i.open, i.code, i.opened = true, c, now
	return c, nil
}

// Consume burns c, the open code. It returns ErrCodeExpired, and closes the
// code, if the window is over at now; ErrCodeClosed if no code is open or c
// is not the open code (which then stays open).
func (i *Inviter) Consume(c Code, now time.Time) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.consumeLocked(c, now)
}

// Accept opens blob with OpenJoinRequest against the open code and, if it is
// a valid request, burns the code and returns the request, marked as
// accepted: NewJoinResponse answers no other. A blob that does not open
// returns OpenJoinRequest's error and leaves the code open. Expiry and a
// closed code are reported as by Consume, before blob is read.
func (i *Inviter) Accept(blob []byte, now time.Time) (JoinRequest, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if err := i.checkLocked(now); err != nil {
		return JoinRequest{}, err
	}
	req, err := OpenJoinRequest(i.code, blob)
	if err != nil {
		return JoinRequest{}, err
	}
	i.closeLocked() // burned: the lock is held since checkLocked
	req.accepted = true
	return req, nil
}

// checkLocked returns ErrCodeClosed if no code is open, and ErrCodeExpired,
// closing the code, if now is not within JoinWindow from Open.
func (i *Inviter) checkLocked(now time.Time) error {
	if !i.open {
		return ErrCodeClosed
	}
	if d := now.Sub(i.opened); d < 0 || d >= JoinWindow {
		i.closeLocked()
		return ErrCodeExpired
	}
	return nil
}

func (i *Inviter) consumeLocked(c Code, now time.Time) error {
	if err := i.checkLocked(now); err != nil {
		return err
	}
	if !sameCode(c, i.code) {
		return ErrCodeClosed
	}
	i.closeLocked()
	return nil
}

func (i *Inviter) closeLocked() {
	i.open, i.code, i.opened = false, Code{}, time.Time{}
}

// sameCode reports whether a and b are the same code. The secret is
// compared in constant time.
func sameCode(a, b Code) bool {
	return subtle.ConstantTimeCompare(a.Secret[:], b.Secret[:]) == 1 &&
		a.AdminFP == b.AdminFP && a.Expires.Equal(b.Expires) && a.Bootstrap == b.Bootstrap
}

// Format prints that an Inviter is there, never its code.
func (i *Inviter) Format(s fmt.State, _ rune) { io.WriteString(s, "join code inviter") }
