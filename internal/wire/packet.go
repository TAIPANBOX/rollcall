// Package wire seals and opens rollcall's UDP packets:
//
//	version (1) | flags (1) = 0 | epoch (4, big endian) | nonce (24) | ciphertext and tag
//
// at most MaxPacket bytes, sealed with XChaCha20-Poly1305 under the epoch's
// packet key, with the 30-byte header as associated data.
//
// Open is the first code that touches bytes from the network. It checks the
// length, then the version, then that the epoch is known, and only then runs
// the AEAD; nothing else in a packet is read before the AEAD succeeds. Every
// error is a bare sentinel that carries no packet, key or plaintext bytes.
// Seal and Open keep no state and are safe for concurrent use.
package wire

import (
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// Version is the packet format this package writes and accepts.
	Version = 1
	// MaxPacket is the largest packet in bytes, header and tag included.
	MaxPacket = 1200
	// HeaderLen is the length of the header: version, flags, epoch and nonce.
	HeaderLen = 30
)

const (
	offFlags     = 1
	offEpoch     = 2
	offNonce     = 6
	keySize      = chacha20poly1305.KeySize
	overhead     = chacha20poly1305.Overhead
	minPacket    = HeaderLen + overhead             // an empty plaintext
	maxPlaintext = MaxPacket - HeaderLen - overhead // 1154
	packetLabel  = "rollcall/v1 packet"
)

var (
	// ErrTooLarge reports a packet longer than MaxPacket, or a plaintext
	// that would make one.
	ErrTooLarge = errors.New("wire: packet too large")
	// ErrShort reports a packet shorter than the header and the tag.
	ErrShort = errors.New("wire: packet shorter than header and tag")
	// ErrVersion reports a packet in a format this version does not speak:
	// a version byte other than Version, or flags set in an otherwise
	// authentic packet (v1 defines no flags).
	ErrVersion = errors.New("wire: unsupported packet version or flags")
	// ErrEpoch reports a packet for an epoch the lookup does not know.
	ErrEpoch = errors.New("wire: unknown epoch")
	// ErrAuth reports a packet that failed authentication under its
	// epoch's key.
	ErrAuth = errors.New("wire: packet authentication failed")
	// ErrKey reports a key of the wrong length, or an all-zero key, which
	// is what an unset key holds and anyone could seal under.
	ErrKey = errors.New("wire: key has the wrong length or is all zero")
)

// KeyLookup returns the packet key for an epoch, and false if the epoch is
// not known. Open passes it the epoch from an unauthenticated header, so it
// must accept any value.
type KeyLookup func(epoch uint32) (key []byte, ok bool)

// PacketKey derives the 32-byte packet key from a group epoch key with
// HKDF-SHA256, an empty salt and the label "rollcall/v1 packet". It returns
// ErrKey for an epoch key shorter than 32 bytes or all zero.
func PacketKey(epochKey []byte) ([]byte, error) {
	if len(epochKey) < keySize || allZero(epochKey) {
		return nil, ErrKey
	}
	// hkdf.Key fails only for an output longer than 255 hash blocks, or, in
	// FIPS 140-only mode, for a key shorter than 112 bits; neither applies.
	return hkdf.Key(sha256.New, epochKey, nil, packetLabel, keySize)
}

// Seal returns a packet carrying plaintext for the given epoch, sealed under
// key, a 32-byte packet key from PacketKey. Each packet gets a fresh random
// nonce. It returns ErrKey for a bad key and ErrTooLarge if the packet would
// exceed MaxPacket. plaintext is not modified, and the packet does not share
// its memory.
func Seal(key []byte, epoch uint32, plaintext []byte) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	if len(plaintext) > maxPlaintext {
		return nil, ErrTooLarge
	}

	// The header lives in its own array: cipher.AEAD forbids dst and the
	// associated data to overlap.
	var hdr [HeaderLen]byte
	hdr[0] = Version
	// hdr[offFlags] stays 0: v1 defines no flags.
	binary.BigEndian.PutUint32(hdr[offEpoch:offNonce], epoch)
	// Since Go 1.24 rand.Read never returns an error: if the system's random
	// source fails, it ends the program, so a nonce is never left unfilled.
	rand.Read(hdr[offNonce:])

	out := make([]byte, 0, HeaderLen+len(plaintext)+overhead)
	out = append(out, hdr[:]...)
	return aead.Seal(out, hdr[offNonce:], plaintext, hdr[:]), nil
}

// Open checks and decrypts a packet, cheapest check first:
//
//  1. length: ErrTooLarge above MaxPacket, ErrShort below the header and tag;
//  2. version: ErrVersion unless the first byte is Version;
//  3. epoch: ErrEpoch unless lookup knows it (a nil lookup knows nothing);
//     ErrKey if the key it returns is bad;
//  4. AEAD over the whole packet, header included: ErrAuth on failure;
//  5. flags: ErrVersion if an authentic packet has any flag set.
//
// On success it returns the epoch and a new, non-nil plaintext that does not
// share memory with packet. On any error the epoch is 0 and the plaintext
// nil, so nothing from an unauthenticated packet reaches the caller. packet
// is never modified, and lookup is called at most once.
func Open(lookup KeyLookup, packet []byte) (epoch uint32, plaintext []byte, err error) {
	switch {
	case len(packet) > MaxPacket:
		return 0, nil, ErrTooLarge
	case len(packet) < minPacket:
		return 0, nil, ErrShort
	case packet[0] != Version:
		return 0, nil, ErrVersion
	}

	e := binary.BigEndian.Uint32(packet[offEpoch:offNonce])
	if lookup == nil {
		return 0, nil, ErrEpoch
	}
	key, ok := lookup(e)
	if !ok {
		return 0, nil, ErrEpoch
	}
	aead, err := newAEAD(key)
	if err != nil {
		return 0, nil, err
	}

	hdr, body := packet[:HeaderLen], packet[HeaderLen:]
	// A fresh dst: the plaintext never aliases the caller's buffer, and is
	// non-nil even when empty.
	pt, err := aead.Open(make([]byte, 0, len(body)-overhead), hdr[offNonce:], body, hdr)
	if err != nil {
		return 0, nil, ErrAuth
	}
	// Flags are checked after the AEAD, so a flag changed in transit is an
	// authentication failure, and a flag an authentic peer set is a format
	// this version does not speak.
	if hdr[offFlags] != 0 {
		return 0, nil, ErrVersion
	}
	return e, pt, nil
}

// newAEAD returns XChaCha20-Poly1305 under key, or ErrKey for a key that is
// not 32 bytes or is all zero.
func newAEAD(key []byte) (cipher.AEAD, error) {
	if allZero(key) {
		return nil, ErrKey
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, ErrKey
	}
	return aead, nil
}

// allZero reports whether b has no non-zero byte (true for an empty b). It
// reads every byte whatever it finds, so its time does not depend on the key.
func allZero(b []byte) bool {
	var acc byte
	for _, x := range b {
		acc |= x
	}
	return acc == 0
}
