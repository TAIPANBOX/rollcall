// Package ids holds the fixed-size identifiers used across rollcall.
// Random identifiers come from crypto/rand and travel as lowercase hex.
package ids

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// MemberID identifies one router in the roster.
type MemberID [16]byte

// BootID identifies one boot of a router.
type BootID [16]byte

// Hash is a 32-byte digest.
type Hash [32]byte

// NewMemberID returns a fresh random MemberID.
func NewMemberID() (MemberID, error) {
	var id MemberID
	_, err := rand.Read(id[:])
	return id, err
}

// NewBootID returns a fresh random BootID.
func NewBootID() (BootID, error) {
	var id BootID
	_, err := rand.Read(id[:])
	return id, err
}

// String returns the lowercase hex form of the ID.
func (id MemberID) String() string { return hex.EncodeToString(id[:]) }

// MarshalText encodes the ID as lowercase hex.
func (id MemberID) MarshalText() ([]byte, error) { return []byte(id.String()), nil }

// UnmarshalText decodes a hex ID of exactly 16 bytes.
func (id *MemberID) UnmarshalText(text []byte) error {
	return decodeHex("MemberID", text, id[:])
}

// String returns the lowercase hex form of the ID.
func (id BootID) String() string { return hex.EncodeToString(id[:]) }

// MarshalText encodes the ID as lowercase hex.
func (id BootID) MarshalText() ([]byte, error) { return []byte(id.String()), nil }

// UnmarshalText decodes a hex ID of exactly 16 bytes.
func (id *BootID) UnmarshalText(text []byte) error {
	return decodeHex("BootID", text, id[:])
}

// String returns the lowercase hex form of the digest.
func (h Hash) String() string { return hex.EncodeToString(h[:]) }

// MarshalText encodes the digest as lowercase hex.
func (h Hash) MarshalText() ([]byte, error) { return []byte(h.String()), nil }

// UnmarshalText decodes a hex digest of exactly 32 bytes.
func (h *Hash) UnmarshalText(text []byte) error {
	return decodeHex("Hash", text, h[:])
}

// decodeHex fills dst from text, which must be exactly two hex digits
// per byte of dst. dst is left untouched when text is rejected.
func decodeHex(name string, text []byte, dst []byte) error {
	if len(text) != hex.EncodedLen(len(dst)) {
		return fmt.Errorf("ids: %s needs %d hex digits, got %d", name, hex.EncodedLen(len(dst)), len(text))
	}
	buf := make([]byte, len(dst))
	if _, err := hex.Decode(buf, text); err != nil {
		return fmt.Errorf("ids: decode %s: %w", name, err)
	}
	copy(dst, buf)
	return nil
}
