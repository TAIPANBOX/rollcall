package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"strings"
)

// # Recovery code
//
// The recovery code is the seed of the group's recovery key (security spec
// 6), printed once by init and kept offline by the owner. Its text is
// Crockford base32, upper case, in groups of five separated by "-", of
//
//	version (1) = 1 | seed (32) | checksum (4)
//
// the checksum the first 4 bytes of SHA-256 over "rollcall/v1
// recovery-code\x00" and every byte before it: 37 bytes, 60 symbols, the last
// one padded with zero bits. Reading it forgives what copying by hand does
// (white space and dashes anywhere, lower case, O for 0, I or L for 1), and a
// typo is caught by the checksum before the seed is used. Errors never
// repeat the text.

const (
	recoveryVersion = 1
	recoveryLen     = 1 + ed25519.SeedSize + 4
	recoverySymbols = (recoveryLen*8 + 4) / 5
	crockford       = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
)

var (
	errRecoveryTypo    = errors.New("the recovery code has a typo or is not a recovery code; copy it again")
	errRecoveryVersion = errors.New("the recovery code was made by another version of rollcall")
)

func recoveryChecksum(b []byte) []byte {
	h := sha256.New()
	h.Write([]byte("rollcall/v1 recovery-code\x00"))
	h.Write(b)
	return h.Sum(nil)[:4]
}

// formatRecoveryCode returns the text of the code for seed.
func formatRecoveryCode(seed []byte) string {
	b := make([]byte, 0, recoveryLen)
	b = append(b, recoveryVersion)
	b = append(b, seed...)
	b = append(b, recoveryChecksum(b)...)
	var syms []byte
	var acc, bits uint
	for _, x := range b {
		acc, bits = acc<<8|uint(x), bits+8
		for bits >= 5 {
			bits -= 5
			syms = append(syms, crockford[acc>>bits&31])
		}
	}
	if bits > 0 {
		syms = append(syms, crockford[acc<<(5-bits)&31])
	}
	clear(b)
	var out strings.Builder
	for i, s := range syms {
		if i > 0 && i%5 == 0 {
			out.WriteByte('-')
		}
		out.WriteByte(s)
	}
	return out.String()
}

// parseRecoveryCode returns the seed in the text of a recovery code.
func parseRecoveryCode(text string) ([]byte, error) {
	var vals []byte
	for _, r := range text {
		switch {
		case r == '-' || r == ' ' || r == '\t' || r == '\n' || r == '\r':
			continue
		case r >= 'a' && r <= 'z':
			r -= 'a' - 'A'
		}
		switch r {
		case 'O':
			r = '0'
		case 'I', 'L':
			r = '1'
		}
		i := strings.IndexRune(crockford, r)
		if i < 0 {
			return nil, errRecoveryTypo
		}
		vals = append(vals, byte(i))
	}
	if len(vals) != recoverySymbols {
		return nil, errRecoveryTypo
	}
	b := make([]byte, 0, recoveryLen)
	var acc, bits uint
	for _, v := range vals {
		acc, bits = acc<<5|uint(v), bits+5
		if bits >= 8 {
			bits -= 8
			b = append(b, byte(acc>>bits))
		}
	}
	clear(vals)
	if acc&(1<<bits-1) != 0 || len(b) != recoveryLen {
		clear(b)
		return nil, errRecoveryTypo
	}
	defer clear(b)
	body, sum := b[:recoveryLen-4], b[recoveryLen-4:]
	if string(recoveryChecksum(body)) != string(sum) {
		return nil, errRecoveryTypo
	}
	if body[0] != recoveryVersion {
		return nil, errRecoveryVersion
	}
	return append([]byte(nil), body[1:]...), nil
}
