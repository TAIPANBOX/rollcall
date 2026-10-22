// Package sig makes Ed25519 signatures over "rollcall/v1/" + kind + "\x00" + msg. The prefix
// stops a signature for one kind, or from another protocol with the same key, passing as another.
package sig

import (
	"crypto/ed25519"
	"strings"
)

// domain starts the signed bytes of every rollcall v1 signature.
const domain = "rollcall/v1/"

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
// kind. It returns false, and never panics, for a public key or a signature
// of the wrong length, and for an empty kind or one with a NUL byte.
func Verify(pub ed25519.PublicKey, kind string, msg, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize || !validKind(kind) {
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
