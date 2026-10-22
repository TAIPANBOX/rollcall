// Package sig makes Ed25519 signatures over "rollcall/v1/" + kind + "\x00" + msg. The prefix
// stops a signature for one kind, or from another protocol with the same key, passing as another.
// Small-order public keys are refused, because Ed25519 verification accepts forgeries under them.
package sig

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"strings"
)

// domain starts the signed bytes of every rollcall v1 signature.
const domain = "rollcall/v1/"

var (
	// ErrKeyLength reports a public key that is not ed25519.PublicKeySize bytes long.
	ErrKeyLength = errors.New("sig: public key is not 32 bytes")
	// ErrSmallOrderKey reports a public key that encodes a point of small order.
	ErrSmallOrderKey = errors.New("sig: public key is a small-order point")
)

// smallOrderY is libsodium's small-order blocklist: the y-coordinate
// encodings, with bit 255 (the sign of x) cleared, of the points of order 1,
// 2, 4 and 8, plus the non-canonical encodings y = p and y = p + 1.
var smallOrderY = []string{
	"0000000000000000000000000000000000000000000000000000000000000000", // y = 0, order 4
	"0100000000000000000000000000000000000000000000000000000000000000", // y = 1, identity
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", // order 8
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", // order 8
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // y = p - 1, order 2
	"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // y = p, non-canonical 0
	"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // y = p + 1, non-canonical 1
}

// ValidPublicKey returns ErrKeyLength if pub is not ed25519.PublicKeySize
// bytes long, and ErrSmallOrderKey if it encodes a small-order point, under
// which Ed25519 verification accepts signatures nobody made. Check a key
// where it enters trust; Verify checks it again. pub is not modified.
func ValidPublicKey(pub []byte) error {
	if len(pub) != ed25519.PublicKeySize {
		return ErrKeyLength
	}
	var y [ed25519.PublicKeySize]byte
	copy(y[:], pub)
	y[31] &= 0x7f // either sign of x on a small-order y is small-order
	enc := hex.EncodeToString(y[:])
	for _, bad := range smallOrderY {
		if enc == bad {
			return ErrSmallOrderKey
		}
	}
	return nil
}

// Sign returns the Ed25519 signature by priv of msg as the given kind.
//
// It panics if kind is empty or contains a NUL byte, since either would make
// the signed bytes ambiguous, and, like ed25519.Sign, if priv is not
// ed25519.PrivateKeySize bytes long. Kinds are constants and keys are local,
// so both are programming errors.
func Sign(priv ed25519.PrivateKey, kind string, msg []byte) []byte {
	if !validKind(kind) {
		panic("sig: kind must be non-empty and must not contain a NUL byte")
	}
	return ed25519.Sign(priv, signedBytes(kind, msg))
}

// Verify reports whether sig is pub's Ed25519 signature of msg as the given
// kind. It returns false, and never panics, for a public key that
// ValidPublicKey rejects, for a signature of the wrong length, and for an
// empty kind or one with a NUL byte.
func Verify(pub ed25519.PublicKey, kind string, msg, sig []byte) bool {
	if ValidPublicKey(pub) != nil || len(sig) != ed25519.SignatureSize || !validKind(kind) {
		return false
	}
	return ed25519.Verify(pub, signedBytes(kind, msg), sig)
}

// validKind reports whether kind can be placed before the NUL separator
// without ambiguity.
func validKind(kind string) bool {
	return kind != "" && strings.IndexByte(kind, 0) < 0
}

// signedBytes returns "rollcall/v1/" + kind + "\x00" + msg in a new slice.
func signedBytes(kind string, msg []byte) []byte {
	b := make([]byte, 0, len(domain)+len(kind)+1+len(msg))
	b = append(b, domain...)
	b = append(b, kind...)
	b = append(b, 0)
	return append(b, msg...)
}
