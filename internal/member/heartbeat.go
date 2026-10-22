// Package member keeps the membership of a rollcall group: the signed
// heartbeat every member sends every 5 s (design 4.2), and the Table in which
// a member follows the others, decides who is suspect and who is silent, and
// says what happened when a silent member comes back.
//
// # Heartbeat
//
// A heartbeat travels as the plaintext of one sealed packet (package wire),
// in this binary layout; numbers are big endian:
//
//	offset  size  field
//	     0     1  format version, FormatVersion
//	     1     4  epoch the packet is sealed under
//	     5    16  From, the sender's member ID
//	    21     8  BootSeq, the sender's boot sequence number
//	    29    16  Boot, the sender's boot ID
//	    45     8  Counter, the sender's packet counter in this boot
//	    53     1  flags: 1 WanUp, 2 InternetOK, 4 ClockTrusted, 8 GoingDown
//	    54     8  Uptime, nanoseconds
//	    62     8  Wall, nanoseconds since 1970-01-01 UTC
//	    70     8  Mono, nanoseconds
//	    78     8  TelegramOK, nanoseconds since 1970-01-01 UTC; 0 for never
//	    86     4  Priority, two's complement
//	    90     8  Head.Seq
//	    98    32  Head.Hash
//	   130    32  Digest
//	   162    32  RosterHash
//	   194     1  n, the length of Name
//	   195     n  Name
//	           1  v, the length of Versions[0], the OpenWrt release
//	           v  Versions[0]
//	           1  w, the length of Versions[1], the rollcall version
//	           w  Versions[1]
//	          64  signature
//
// The signature is sig.Sign(key, "heartbeat", body), Ed25519 over
// "rollcall/v1/heartbeat\x00" || body, where body is every byte before it:
// the signature covers exactly the bytes sent, the epoch among them
// (security spec 5.1). The fixed part comes first, so that the fields the
// replay check needs (From, BootSeq, Boot, Counter) sit at fixed offsets and
// are read before anything else, and the signature last, so that it is found
// by the length alone.
//
// Exactly one encoding is accepted for each heartbeat: no flag beyond the
// four, no byte after the last version, every number in range. The fields
// must be:
//
//   - From and Boot not all zero, BootSeq at least 1;
//   - Name a valid roster name (roster.ValidName: 1 to roster.MaxNameLen
//     characters from a-z, 0-9 and '-'); the sender's name in the roster;
//   - each version empty (unknown) or up to MaxVersionLen characters from
//     A-Z, a-z, 0-9 and ". - + _ ~", so no space, quote, slash or control
//     character reaches a message;
//   - Uptime and Mono not negative; Wall from 1970-01-01 to 2262-04-11 (what
//     an int64 of nanoseconds holds); TelegramOK the zero time for never, or
//     after 1970-01-01T00:00:00Z and up to 2262-04-11;
//   - Priority within int32; Head.Seq 0 exactly when Head.Hash is all zero.
//
// A heartbeat is at most MaxEncodedLen (421) bytes, so sealed with the 30
// byte header, the 16 byte tag and a message type byte it takes 468 of the
// 1200 bytes of a packet, whatever the number of members: the history goes in
// as one head and one digest (security spec 5.7).
package member

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/history"
	"github.com/TAIPANBOX/rollcall/internal/identity"
	"github.com/TAIPANBOX/rollcall/internal/ids"
	"github.com/TAIPANBOX/rollcall/internal/roster"
	"github.com/TAIPANBOX/rollcall/internal/sig"
)

const (
	// FormatVersion is the heartbeat layout this package writes and reads.
	FormatVersion = 1
	// MaxVersionLen is the longest version string, in bytes.
	MaxVersionLen = 64
	// MaxEncodedLen is the length of the largest heartbeat, signature
	// included.
	MaxEncodedLen = fixedLen + 1 + roster.MaxNameLen + 2*(1+MaxVersionLen) + ed25519.SignatureSize
)

// kindHeartbeat is the signature kind of a heartbeat.
const kindHeartbeat = "heartbeat"

// Offsets of the fixed part of the layout.
const (
	offEpoch      = 1
	offFrom       = 5
	offBootSeq    = 21
	offBoot       = 29
	offCounter    = 45
	offFlags      = 53
	offUptime     = 54
	offWall       = 62
	offMono       = 70
	offTelegramOK = 78
	offPriority   = 86
	offHeadSeq    = 90
	offHeadHash   = 98
	offDigest     = 130
	offRosterHash = 162
	fixedLen      = 194

	// minEncodedLen is the length of the smallest heartbeat: a one-letter
	// name and two empty versions.
	minEncodedLen = fixedLen + 1 + 1 + 2 + ed25519.SignatureSize
)

// The flag bits.
const (
	flagWanUp = 1 << iota
	flagInternetOK
	flagClockTrusted
	flagGoingDown

	flagsKnown = flagWanUp | flagInternetOK | flagClockTrusted | flagGoingDown
)

var (
	// ErrInvalid reports a heartbeat or identity EncodeHeartbeat refuses.
	ErrInvalid = errors.New("member: invalid heartbeat")
	// ErrMalformed reports bytes that are not a heartbeat in the one
	// encoding this package accepts.
	ErrMalformed = errors.New("member: malformed heartbeat")
)

// Heartbeat is what a member says about itself every Interval (design 4.2).
type Heartbeat struct {
	Epoch        uint32        // the epoch whose key seals the packet
	From         ids.MemberID  // the sender
	BootSeq      uint64        // the sender's boot sequence number
	Boot         ids.BootID    // the sender's boot ID
	Counter      uint64        // the sender's packet counter in this boot
	Name         string        // the sender's name in the roster
	Uptime       time.Duration // since the sender booted
	Versions     [2]string     // the OpenWrt release and the rollcall version; empty when unknown
	WanUp        bool          // the sender's WAN interface is up
	InternetOK   bool          // the sender's internet probes succeed
	TelegramOK   time.Time     // the sender's last successful Telegram API call; zero for never
	Priority     int           // the sender's priority as a sender (design 4.5)
	Head         history.Head  // the head of the sender's own history chain
	Digest       ids.Hash      // the digest over the heads of all chains the sender holds
	RosterHash   ids.Hash      // the hash of the roster the sender holds
	Wall         time.Time     // the sender's wall clock
	Mono         time.Duration // the sender's monotonic clock since boot
	ClockTrusted bool          // the sender's wall clock was NTP-synced in this boot
	GoingDown    bool          // the sender announced that it is going down (a planned reboot)
}

// EncodeHeartbeat returns h in the layout of the package doc, signed with
// id's key. h.From must be id.ID. It returns ErrInvalid, and nothing, for a
// nil identity, a signing key of the wrong length, or a field outside the
// rules of the package doc.
func EncodeHeartbeat(h Heartbeat, id *identity.Identity) ([]byte, error) {
	if id == nil || len(id.Sign) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: no usable signing key", ErrInvalid)
	}
	if h.From != id.ID {
		return nil, fmt.Errorf("%w: From is not the identity's member ID", ErrInvalid)
	}
	body, err := appendBody(make([]byte, 0, MaxEncodedLen), h)
	if err != nil {
		return nil, err
	}
	return append(body, sig.Sign(id.Sign, kindHeartbeat, body)...), nil
}

// appendBody appends the signed part of h's encoding to b, or returns
// ErrInvalid if h breaks a field rule.
func appendBody(b []byte, h Heartbeat) ([]byte, error) {
	if err := h.check(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	var flags byte
	if h.WanUp {
		flags |= flagWanUp
	}
	if h.InternetOK {
		flags |= flagInternetOK
	}
	if h.ClockTrusted {
		flags |= flagClockTrusted
	}
	if h.GoingDown {
		flags |= flagGoingDown
	}
	var telegram int64
	if !h.TelegramOK.IsZero() {
		telegram = h.TelegramOK.UnixNano()
	}
	b = append(b, FormatVersion)
	b = binary.BigEndian.AppendUint32(b, h.Epoch)
	b = append(b, h.From[:]...)
	b = binary.BigEndian.AppendUint64(b, h.BootSeq)
	b = append(b, h.Boot[:]...)
	b = binary.BigEndian.AppendUint64(b, h.Counter)
	b = append(b, flags)
	b = binary.BigEndian.AppendUint64(b, uint64(h.Uptime))
	b = binary.BigEndian.AppendUint64(b, uint64(h.Wall.UnixNano()))
	b = binary.BigEndian.AppendUint64(b, uint64(h.Mono))
	b = binary.BigEndian.AppendUint64(b, uint64(telegram))
	b = binary.BigEndian.AppendUint32(b, uint32(int32(h.Priority)))
	b = binary.BigEndian.AppendUint64(b, h.Head.Seq)
	b = append(b, h.Head.Hash[:]...)
	b = append(b, h.Digest[:]...)
	b = append(b, h.RosterHash[:]...)
	for _, s := range [...]string{h.Name, h.Versions[0], h.Versions[1]} {
		b = append(b, byte(len(s)))
		b = append(b, s...)
	}
	return b, nil
}

// The range of a wall clock reading: what an int64 of nanoseconds since
// 1970 holds.
var (
	minWall = time.Unix(0, 0)
	maxWall = time.Unix(0, math.MaxInt64)
)

// check returns an error naming the first field of h that breaks the rules
// of the package doc. The error never repeats a field's content.
func (h Heartbeat) check() error {
	switch {
	case h.From == (ids.MemberID{}):
		return errors.New("From is all zero")
	case h.Boot == (ids.BootID{}):
		return errors.New("Boot is all zero")
	case h.BootSeq == 0:
		return errors.New("BootSeq is 0")
	case roster.ValidName(h.Name) != nil:
		return errors.New("Name is not a valid roster name")
	case !validVersion(h.Versions[0]) || !validVersion(h.Versions[1]):
		return errors.New("a version is too long or has a character outside A-Z a-z 0-9 . - + _ ~")
	case h.Uptime < 0 || h.Mono < 0:
		return errors.New("Uptime or Mono is negative")
	case h.Wall.Before(minWall) || h.Wall.After(maxWall):
		return errors.New("Wall is outside 1970 to 2262")
	case !h.TelegramOK.IsZero() && (!h.TelegramOK.After(minWall) || h.TelegramOK.After(maxWall)):
		return errors.New("TelegramOK is neither zero nor after 1970 and up to 2262")
	case h.Priority < math.MinInt32 || h.Priority > math.MaxInt32:
		return errors.New("Priority is outside int32")
	case (h.Head.Seq == 0) != (h.Head.Hash == ids.Hash{}):
		return errors.New("Head.Seq and Head.Hash disagree")
	}
	return nil
}

// validVersion reports whether s may be a version string.
func validVersion(s string) bool {
	if len(s) > MaxVersionLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		case c == '.' || c == '-' || c == '+' || c == '_' || c == '~':
		default:
			return false
		}
	}
	return true
}

// packet is a heartbeat split at fixed offsets before its signature is
// verified: the numbers the replay check needs, the signed bytes and the
// signature. body and sig share memory with the bytes split was given.
type packet struct {
	epoch   uint32
	from    ids.MemberID
	bootSeq uint64
	boot    ids.BootID
	counter uint64
	body    []byte
	sig     []byte
}

// split checks the length and the format version of b and reads the fixed
// fields the replay check needs. Nothing it returns is authentic until the
// signature over body verifies; it decodes nothing else.
func split(b []byte) (packet, error) {
	if len(b) < minEncodedLen || len(b) > MaxEncodedLen || b[0] != FormatVersion {
		return packet{}, ErrMalformed
	}
	n := len(b) - ed25519.SignatureSize
	p := packet{
		epoch:   binary.BigEndian.Uint32(b[offEpoch:]),
		bootSeq: binary.BigEndian.Uint64(b[offBootSeq:]),
		counter: binary.BigEndian.Uint64(b[offCounter:]),
		body:    b[:n],
		sig:     b[n:],
	}
	copy(p.from[:], b[offFrom:])
	copy(p.boot[:], b[offBoot:])
	return p, nil
}

// decodeBody decodes the signed part of a heartbeat, whose signature the
// caller has verified. It returns ErrMalformed and the zero Heartbeat unless
// body is exactly the encoding appendBody makes of a heartbeat that passes
// check. Strings are copies; nothing returned shares memory with body.
func decodeBody(body []byte) (Heartbeat, error) {
	if len(body) < fixedLen || body[0] != FormatVersion || body[offFlags]&^flagsKnown != 0 {
		return Heartbeat{}, ErrMalformed
	}
	flags := body[offFlags]
	h := Heartbeat{
		Epoch:        binary.BigEndian.Uint32(body[offEpoch:]),
		BootSeq:      binary.BigEndian.Uint64(body[offBootSeq:]),
		Counter:      binary.BigEndian.Uint64(body[offCounter:]),
		WanUp:        flags&flagWanUp != 0,
		InternetOK:   flags&flagInternetOK != 0,
		ClockTrusted: flags&flagClockTrusted != 0,
		GoingDown:    flags&flagGoingDown != 0,
		Uptime:       time.Duration(binary.BigEndian.Uint64(body[offUptime:])),
		Mono:         time.Duration(binary.BigEndian.Uint64(body[offMono:])),
		Priority:     int(int32(binary.BigEndian.Uint32(body[offPriority:]))),
		Head:         history.Head{Seq: binary.BigEndian.Uint64(body[offHeadSeq:])},
	}
	copy(h.From[:], body[offFrom:])
	copy(h.Boot[:], body[offBoot:])
	copy(h.Head.Hash[:], body[offHeadHash:])
	copy(h.Digest[:], body[offDigest:])
	copy(h.RosterHash[:], body[offRosterHash:])

	wall := int64(binary.BigEndian.Uint64(body[offWall:]))
	telegram := int64(binary.BigEndian.Uint64(body[offTelegramOK:]))
	if wall < 0 || telegram < 0 {
		return Heartbeat{}, ErrMalformed
	}
	h.Wall = time.Unix(0, wall).UTC()
	if telegram != 0 {
		h.TelegramOK = time.Unix(0, telegram).UTC()
	}

	rest := body[fixedLen:]
	var strs [3]string
	for i := range strs {
		if len(rest) < 1 || len(rest) < 1+int(rest[0]) {
			return Heartbeat{}, ErrMalformed
		}
		strs[i], rest = string(rest[1:1+int(rest[0])]), rest[1+int(rest[0]):]
	}
	if len(rest) != 0 {
		return Heartbeat{}, ErrMalformed
	}
	h.Name, h.Versions = strs[0], [2]string{strs[1], strs[2]}
	if h.check() != nil {
		return Heartbeat{}, ErrMalformed
	}
	return h, nil
}
