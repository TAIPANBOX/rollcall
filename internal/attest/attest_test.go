package attest

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/history"
	"github.com/TAIPANBOX/rollcall/internal/identity"
	"github.com/TAIPANBOX/rollcall/internal/ids"
	"github.com/TAIPANBOX/rollcall/internal/sig"
)

// The test vector of docs/attest.md. The signed bytes are written out by
// hand, field by field, from the format; the signature is crypto/ed25519
// over exactly those bytes with the seed 00 01 .. 1f, computed without any
// rollcall code.
const (
	vectorPub = "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"
	vectorSig = "384f30a0c33980c035f299d008cca53cbc591298f7564c39d425530b68c48f43" +
		"da7de68154f01e0f41f8f0ec0bae68d49330385a570d6ba157f3c0a1899dfe05"
	vectorJSON = `{"schema":1,"nonce":"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff","member":"00112233445566778899aabbccddeeff",` +
		`"head":{"seq":42,"hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},` +
		`"kernel_boot_id":"4e7c1b2a9d3f40e8b5a6c7d8e9f00112",` +
		`"boot":{"id":"4e7c1b2a9d3f40e8b5a6c7d8e9f00112","seq":7,"openwrt":"25.12.4"},` +
		`"rollcall":"1.0.0-rc2","time":"2026-11-08T12:00:00Z",` +
		`"sig":"` + vectorSig + `"}`
)

var vectorSigned = strings.Join([]string{
	hex.EncodeToString([]byte("rollcall/v1/attest\x00")), // the domain, the kind and a NUL
	"0000000000000010",                                        // len(nonce) = 16
	"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",                        // nonce
	"00112233445566778899aabbccddeeff",                        // member
	"000000000000002a",                                        // head seq = 42
	strings.Repeat("aa", 32),                                  // head hash
	"4e7c1b2a9d3f40e8b5a6c7d8e9f00112",                        // kernel boot ID
	"4e7c1b2a9d3f40e8b5a6c7d8e9f00112",                        // boot ID of the latest boot record
	"0000000000000007",                                        // its boot seq = 7
	"0000000000000007", hex.EncodeToString([]byte("25.12.4")), // len, OpenWrt
	"0000000000000009", hex.EncodeToString([]byte("1.0.0-rc2")), // len, rollcall
	"000000006af06440", // time = 1794139200 = 2026-11-08T12:00:00Z
}, "")

func vectorKey() ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func vectorStatement(t *testing.T) Statement {
	t.Helper()
	var s Statement
	s.Nonce = mustHex(t, "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
	copy(s.Member[:], mustHex(t, "00112233445566778899aabbccddeeff"))
	s.Head.Seq = 42
	copy(s.Head.Hash[:], bytes.Repeat([]byte{0xaa}, 32))
	copy(s.KernelBoot[:], mustHex(t, "4e7c1b2a9d3f40e8b5a6c7d8e9f00112"))
	s.BootID = s.KernelBoot
	s.BootSeq = 7
	s.OpenWrt, s.Rollcall = "25.12.4", "1.0.0-rc2"
	s.Time = time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	return s
}

// TestAttestVector: the statement of the vector signs to exactly the bytes
// written out by hand and to the signature computed from them alone, and is
// printed as the JSON of docs/attest.md, which reads back to it. A verifier
// that follows the document gets the same answer as this code.
func TestAttestVector(t *testing.T) {
	priv := vectorKey()
	pub := priv.Public().(ed25519.PublicKey)
	if got := hex.EncodeToString(pub); got != vectorPub {
		t.Fatalf("public key %s, want %s", got, vectorPub)
	}
	s := vectorStatement(t)
	if got := hex.EncodeToString(s.SigningBytes()); got != vectorSigned {
		t.Errorf("signing bytes\n got %s\nwant %s", got, vectorSigned)
	}
	if got, want := hex.EncodeToString(s.Message()), vectorSigned[2*len("rollcall/v1/attest\x00"):]; got != want {
		t.Errorf("m\n got %s\nwant %s", got, want)
	}
	signature, err := Sign(priv, s)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(signature); got != vectorSig {
		t.Errorf("signature\n got %s\nwant %s", got, vectorSig)
	}
	// The signature is plain Ed25519 over the documented bytes.
	if !ed25519.Verify(pub, mustHex(t, vectorSigned), mustHex(t, vectorSig)) {
		t.Error("the vector's signature does not verify over the vector's bytes with crypto/ed25519")
	}
	if !Verify(pub, s, signature) {
		t.Error("Verify refuses the vector")
	}
	out, err := Encode(s, signature)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != vectorJSON {
		t.Errorf("JSON\n got %s\nwant %s", out, vectorJSON)
	}
	back, backSig, err := Decode([]byte(vectorJSON + "\n"))
	if err != nil {
		t.Fatalf("Decode of the vector: %v", err)
	}
	if !bytes.Equal(back.SigningBytes(), s.SigningBytes()) || !bytes.Equal(backSig, signature) || !Verify(pub, back, backSig) {
		t.Error("the vector does not read back to the statement it was made of")
	}
}

// The second vector of docs/attest.md: a router that answers from a boot it
// has not recorded (the kernel's boot ID is not the newest boot record's),
// with the longest nonce. Every field differs from its neighbours, so a
// verifier that swaps two fields, or reads one in the wrong width, fails it.
const (
	vector2Signed = "726f6c6c63616c6c2f76312f61747465737400" + // rollcall/v1/attest, 0
		"0000000000000040" + // len(nonce) = 64
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
		"202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" + // nonce 00..3f
		"ffeeddccbbaa99887766554433221100" + // member
		"00000000000f4240" + // head seq = 1000000
		"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20" + // head hash 01..20
		"11111111222222223333333344444444" + // kernel boot ID
		"99999999888888887777777766666666" + // boot ID of the newest boot record
		"000000000000012c" + // its boot seq = 300
		"0000000000000007" + "32342e31302e35" + // OpenWrt "24.10.5"
		"0000000000000005" + "312e302e30" + // rollcall "1.0.0"
		"000000006af0795d" // time = 1794144605 = 2026-11-08T13:30:05Z
	vector2Sig = "6618344b394fc28c0d8e81af3a770a23aa64ba8a240a24eb9e982a076ef497c8" +
		"81866484cd6237efbafa74c80a8338fe95761249bbdea839bc0e7f6a443c900e"
)

// TestAttestVectorUnrecorded: the second vector signs to its hand-written
// bytes and its independently computed signature.
func TestAttestVectorUnrecorded(t *testing.T) {
	priv := vectorKey()
	var s Statement
	for i := range 64 {
		s.Nonce = append(s.Nonce, byte(i))
	}
	copy(s.Member[:], mustHex(t, "ffeeddccbbaa99887766554433221100"))
	s.Head.Seq = 1000000
	for i := range s.Head.Hash {
		s.Head.Hash[i] = byte(i + 1)
	}
	copy(s.KernelBoot[:], mustHex(t, "11111111222222223333333344444444"))
	copy(s.BootID[:], mustHex(t, "99999999888888887777777766666666"))
	s.BootSeq = 300
	s.OpenWrt, s.Rollcall = "24.10.5", "1.0.0"
	s.Time = time.Date(2026, 11, 8, 13, 30, 5, 0, time.UTC)
	if got := hex.EncodeToString(s.SigningBytes()); got != vector2Signed {
		t.Errorf("signing bytes\n got %s\nwant %s", got, vector2Signed)
	}
	signature, err := Sign(priv, s)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(signature); got != vector2Sig {
		t.Errorf("signature\n got %s\nwant %s", got, vector2Sig)
	}
	if !ed25519.Verify(priv.Public().(ed25519.PublicKey), mustHex(t, vector2Signed), mustHex(t, vector2Sig)) {
		t.Error("the second vector does not verify with crypto/ed25519")
	}
}

// TestAttestFieldsAreSigned: changing any one field of a statement, or the
// signature, makes it fail to verify; the statement as signed verifies.
func TestAttestFieldsAreSigned(t *testing.T) {
	priv := vectorKey()
	pub := priv.Public().(ed25519.PublicKey)
	base := vectorStatement(t)
	signature, err := Sign(priv, base)
	if err != nil {
		t.Fatal(err)
	}
	if !Verify(pub, base, signature) {
		t.Fatal("the statement as signed does not verify")
	}
	changes := map[string]func(*Statement){
		"a nonce byte":         func(s *Statement) { s.Nonce = append([]byte{}, s.Nonce...); s.Nonce[15] ^= 1 },
		"a longer nonce":       func(s *Statement) { s.Nonce = append(append([]byte{}, s.Nonce...), 0) },
		"the member":           func(s *Statement) { s.Member[0] ^= 1 },
		"the head seq":         func(s *Statement) { s.Head.Seq++ },
		"the head hash":        func(s *Statement) { s.Head.Hash[31] ^= 1 },
		"the kernel boot ID":   func(s *Statement) { s.KernelBoot[0] ^= 1 },
		"the recorded boot ID": func(s *Statement) { s.BootID[15] ^= 1 },
		"the boot seq":         func(s *Statement) { s.BootSeq++ },
		"the OpenWrt release":  func(s *Statement) { s.OpenWrt = "25.12.5" },
		"OpenWrt one longer":   func(s *Statement) { s.OpenWrt += "1" },
		"the rollcall version": func(s *Statement) { s.Rollcall = "1.0.0-rc3" },
		"rollcall one shorter": func(s *Statement) { s.Rollcall = s.Rollcall[:len(s.Rollcall)-1] },
		"the time, 1 s later":  func(s *Statement) { s.Time = s.Time.Add(time.Second) },
		"the time, 1 s before": func(s *Statement) { s.Time = s.Time.Add(-time.Second) },
		"bytes moved between the versions": func(s *Statement) {
			s.OpenWrt, s.Rollcall = "25.12.41", ".0.0-rc2"
		},
	}
	for name, change := range changes {
		s := vectorStatement(t)
		change(&s)
		if bytes.Equal(s.Message(), base.Message()) {
			t.Errorf("%s: m is the same, so the field is not signed", name)
		}
		if Verify(pub, s, signature) {
			t.Errorf("%s: the signature still verifies", name)
		}
	}
	bad := bytes.Clone(signature)
	bad[0] ^= 1
	if Verify(pub, base, bad) {
		t.Error("a changed signature verifies")
	}
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32)).Public().(ed25519.PublicKey)
	if Verify(other, base, signature) {
		t.Error("the signature verifies under another key")
	}
}

// signedKinds are the sig kinds the rest of rollcall signs under.
var signedKinds = []string{"entry", "roster", "epoch", "heartbeat", "message", "join-response"}

// TestAttestDomainSeparated: an attest signature never passes as a history
// entry's or a roster's (or any other kind rollcall signs), and none of
// theirs passes as an attest, even over the very same bytes.
func TestAttestDomainSeparated(t *testing.T) {
	priv := vectorKey()
	pub := priv.Public().(ed25519.PublicKey)
	s := vectorStatement(t)
	signature, err := Sign(priv, s)
	if err != nil {
		t.Fatal(err)
	}
	m := s.Message()
	if !sig.Verify(pub, Kind, m, signature) {
		t.Fatal("the attest signature does not verify as an attest")
	}
	for _, k := range signedKinds {
		if k == Kind {
			t.Fatalf("Kind %q is one of the other kinds", Kind)
		}
		if sig.Verify(pub, k, m, signature) {
			t.Errorf("an attest signature verifies as a %q signature over the same bytes", k)
		}
		if other := sig.Sign(priv, k, m); Verify(pub, s, other) {
			t.Errorf("a %q signature over the statement's bytes verifies as an attest", k)
		}
	}

	// A real history entry, signed by the same member, against its own
	// signed bytes written out from internal/history's format.
	id := &identity.Identity{ID: s.Member, Sign: priv}
	e, err := history.NewEntry(id, history.Head{}, history.KindBoot, map[string]any{"boot": 1})
	if err != nil {
		t.Fatal(err)
	}
	em := append([]byte{}, e.Origin[:]...)
	em = binary.BigEndian.AppendUint64(em, e.Seq)
	em = append(em, e.Prev[:]...)
	em = binary.BigEndian.AppendUint64(em, uint64(len(e.Kind)))
	em = append(em, e.Kind...)
	em = binary.BigEndian.AppendUint64(em, uint64(len(e.Body)))
	em = append(em, e.Body...)
	if !sig.Verify(pub, "entry", em, e.Sig) {
		t.Fatal("control: the entry's signature does not verify over its bytes as an entry")
	}
	if sig.Verify(pub, Kind, em, e.Sig) {
		t.Error("a history entry's signature verifies as an attest over the entry's bytes")
	}
	if Verify(pub, s, e.Sig) {
		t.Error("a history entry's signature verifies as the statement's")
	}
	// And the attest signature, put on an entry, does not make it valid.
	forged := e
	forged.Sig = signature
	if forged.Verify(pub) == nil {
		t.Error("an entry carrying an attest signature verifies")
	}
}

// TestStatementCheck: Sign refuses a statement outside the rules, and
// Verify is false for it, whatever the signature.
func TestStatementCheck(t *testing.T) {
	priv := vectorKey()
	pub := priv.Public().(ed25519.PublicKey)
	cases := map[string]func(*Statement){
		"a 15-byte nonce":       func(s *Statement) { s.Nonce = s.Nonce[:15] },
		"a 65-byte nonce":       func(s *Statement) { s.Nonce = make([]byte, 65) },
		"no nonce":              func(s *Statement) { s.Nonce = nil },
		"an all-zero member":    func(s *Statement) { s.Member = ids.MemberID{} },
		"a head seq, no hash":   func(s *Statement) { s.Head.Hash = ids.Hash{} },
		"a head hash, no seq":   func(s *Statement) { s.Head.Seq = 0 },
		"a boot seq, no ID":     func(s *Statement) { s.BootID = ids.BootID{} },
		"a boot ID, no seq":     func(s *Statement) { s.BootSeq = 0 },
		"OpenWrt with a space":  func(s *Statement) { s.OpenWrt = "25.12 4" },
		"OpenWrt of 65":         func(s *Statement) { s.OpenWrt = strings.Repeat("1", 65) },
		"rollcall with a quote": func(s *Statement) { s.Rollcall = `1"0` },
		"rollcall with a NUL":   func(s *Statement) { s.Rollcall = "1\x000" },
		"a time before 1970":    func(s *Statement) { s.Time = time.Date(1969, 12, 31, 23, 59, 59, 0, time.UTC) },
		"a time after 9999":     func(s *Statement) { s.Time = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC) },
		"a zero time":           func(s *Statement) { s.Time = time.Time{} },
	}
	for name, change := range cases {
		s := vectorStatement(t)
		change(&s)
		if got, err := Sign(priv, s); !errors.Is(err, ErrStatement) || got != nil {
			t.Errorf("%s: Sign = %x, %v; want ErrStatement and no signature", name, got, err)
		}
		if Verify(pub, s, sig.Sign(priv, Kind, s.Message())) {
			t.Errorf("%s: Verify accepts it", name)
		}
	}
	ok := map[string]func(*Statement){
		"a 16-byte nonce":      func(s *Statement) { s.Nonce = make([]byte, 16) },
		"a 64-byte nonce":      func(s *Statement) { s.Nonce = make([]byte, 64) },
		"no history":           func(s *Statement) { s.Head = history.Head{} },
		"no boot record":       func(s *Statement) { s.BootID, s.BootSeq, s.OpenWrt = ids.BootID{}, 0, "" },
		"versions of 64":       func(s *Statement) { s.OpenWrt, s.Rollcall = strings.Repeat("9", 64), strings.Repeat("v", 64) },
		"every version char":   func(s *Statement) { s.Rollcall = "aZ09.-+_~" },
		"1970 exactly":         func(s *Statement) { s.Time = time.Unix(0, 0) },
		"9999-12-31T23:59:59Z": func(s *Statement) { s.Time = time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC) },
	}
	for name, change := range ok {
		s := vectorStatement(t)
		change(&s)
		signature, err := Sign(priv, s)
		if err != nil || !Verify(pub, s, signature) {
			t.Errorf("%s: Sign = %v, or it does not verify", name, err)
		}
	}
}

// nonceRule is the rule of a nonce, written apart from ParseNonce: an even
// number of hex digits, 32 to 128 of them.
var nonceRule = regexp.MustCompile(`^(?:[0-9a-fA-F]{2}){16,64}$`)

// TestParseNonceHostile: a nonce is accepted exactly when it is 16 to 64
// bytes in hex: named edge cases, then a sweep of seeded random strings
// (ROLLCALL_SEEDS of them, 5000 by default) drawn from hex, near-hex and
// hostile characters, each judged against the rule written apart.
func TestParseNonceHostile(t *testing.T) {
	hex32 := strings.Repeat("ab", 16)
	named := map[string]bool{
		"":                                       false,
		strings.Repeat("a", 30):                  false, // 15 bytes
		strings.Repeat("a", 31):                  false, // odd
		strings.Repeat("a", 32):                  true,  // 16 bytes
		strings.Repeat("a", 33):                  false, // odd
		strings.Repeat("F", 128):                 true,  // 64 bytes, upper case
		strings.Repeat("f", 127):                 false, // odd
		strings.Repeat("f", 129):                 false, // odd and past 64
		strings.Repeat("f", 130):                 false, // 65 bytes
		strings.Repeat("0", 1<<20):               false, // 512 KiB
		"0x" + hex32[2:]:                         false,
		hex32[:31] + "g":                         false,
		hex32[:30] + " a":                        false,
		" " + hex32:                              false,
		hex32 + "\n":                             false,
		hex32 + "\x00\x00":                       false,
		strings.Repeat("é", 16):                  false, // 32 bytes of UTF-8, not hex
		strings.Repeat("\u0660", 16):             false, // Arabic-Indic zero, a Unicode digit
		strings.Repeat("ab", 15) + "-a":          false,
		strings.Repeat("ab", 15) + "ａｂ"[:2]:      false, // part of a fullwidth letter
		hex32:                                    true,
		strings.ToUpper(hex32[:16]) + hex32[16:]: true,
	}
	for in, want := range named {
		check(t, fmt.Sprintf("%.40q (len %d)", in, len(in)), in, want)
	}

	seeds := 5000
	if v, err := strconv.Atoi(os.Getenv("ROLLCALL_SEEDS")); err == nil && v > 0 {
		seeds = v
	}
	alphabets := []string{
		"0123456789abcdef",
		"0123456789abcdefABCDEF",
		"0123456789abcdefgxyzGXYZ -_:",
		"0123456789abcdef\x00\n\t\"\\é\u0660\uff21",
	}
	accepted := 0
	for seed := 1; seed <= seeds; seed++ {
		r := rand.New(rand.NewPCG(uint64(seed), 0x6e6f6e6365))
		n := r.IntN(160)
		if r.IntN(4) == 0 {
			n = 30 + r.IntN(102) // more of the lengths near the bounds
		}
		alpha := []rune(alphabets[r.IntN(len(alphabets))])
		var sb strings.Builder
		for sb.Len() < n {
			sb.WriteRune(alpha[r.IntN(len(alpha))])
		}
		in := sb.String()
		want := nonceRule.MatchString(in)
		if want {
			accepted++
		}
		check(t, fmt.Sprintf("seed %d: %.40q (len %d)", seed, in, len(in)), in, want)
	}
	if accepted == 0 || accepted == seeds {
		t.Errorf("the sweep accepted %d of %d: it does not reach both sides of the rule", accepted, seeds)
	}
	t.Logf("%d seeds, %d accepted, %d refused", seeds, accepted, seeds-accepted)
}

func check(t *testing.T, name, in string, want bool) {
	t.Helper()
	got, err := ParseNonce(in)
	switch {
	case want && err != nil:
		t.Errorf("%s: refused (%v), want accepted", name, err)
	case want:
		dec, _ := hex.DecodeString(in)
		if !bytes.Equal(got, dec) || len(got) < MinNonce || len(got) > MaxNonce {
			t.Errorf("%s: %x, want %x", name, got, dec)
		}
	case !errors.Is(err, ErrNonce) || got != nil:
		t.Errorf("%s: %x, %v; want ErrNonce and nothing", name, got, err)
	}
}

// TestDecodeRefusesOtherForms: Decode reads only the one form Encode
// writes, with or without one newline after it, and never panics on bytes
// changed at random; a statement it does read from changed bytes is either
// the one signed or fails to verify.
func TestDecodeRefusesOtherForms(t *testing.T) {
	priv := vectorKey()
	pub := priv.Public().(ed25519.PublicKey)
	for _, in := range []string{vectorJSON, vectorJSON + "\n"} {
		if _, _, err := Decode([]byte(in)); err != nil {
			t.Errorf("Decode(%.20q...): %v", in, err)
		}
	}
	refused := map[string]string{
		"two newlines":      vectorJSON + "\n\n",
		"a space":           strings.Replace(vectorJSON, `"schema":1`, `"schema": 1`, 1),
		"schema 2":          strings.Replace(vectorJSON, `"schema":1`, `"schema":2`, 1),
		"no schema":         strings.Replace(vectorJSON, `"schema":1,`, ``, 1),
		"an unknown field":  strings.Replace(vectorJSON, `"schema":1,`, `"schema":1,"x":1,`, 1),
		"upper-case nonce":  strings.Replace(vectorJSON, `f0f1f2f3`, `F0F1F2F3`, 1),
		"upper-case member": strings.Replace(vectorJSON, `aabbccddeeff"`, `AABBCCDDEEFF"`, 1),
		"upper-case sig":    strings.Replace(vectorJSON, vectorSig, strings.ToUpper(vectorSig), 1),
		"a short sig":       strings.Replace(vectorJSON, vectorSig, vectorSig[:126], 1),
		"a short nonce":     strings.Replace(vectorJSON, `"nonce":"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"`, `"nonce":"f0f1f2f3f4f5f6f7f8f9fafbfcfdfe"`, 1),
		"a time with zone":  strings.Replace(vectorJSON, `2026-11-08T12:00:00Z`, `2026-11-08T13:00:00+01:00`, 1),
		"a time with ns":    strings.Replace(vectorJSON, `2026-11-08T12:00:00Z`, `2026-11-08T12:00:00.5Z`, 1),
		"data after":        vectorJSON + `{}`,
		"fields reordered":  strings.Replace(vectorJSON, `{"schema":1,"nonce":"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",`, `{"nonce":"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff","schema":1,`, 1),
		"a head without its hash": strings.Replace(vectorJSON, `"seq":42,"hash":"`+strings.Repeat("aa", 32)+`"`,
			`"seq":42,"hash":"`+strings.Repeat("00", 32)+`"`, 1),
		"an array": `[` + vectorJSON + `]`,
		"too long": vectorJSON + strings.Repeat(" ", 5000),
		"empty":    ``,
	}
	for name, in := range refused {
		if s, sg, err := Decode([]byte(in)); !errors.Is(err, ErrFormat) {
			t.Errorf("%s: Decode = %+v, %x, %v; want ErrFormat", name, s, sg, err)
		}
	}
	base := []byte(vectorJSON)
	seeds := 3000
	if v, err := strconv.Atoi(os.Getenv("ROLLCALL_SEEDS")); err == nil && v > 0 {
		seeds = v
	}
	for seed := 1; seed <= seeds; seed++ {
		r := rand.New(rand.NewPCG(uint64(seed), 0x6465636f6465))
		b := bytes.Clone(base)
		for k := 1 + r.IntN(3); k > 0; k-- {
			b[r.IntN(len(b))] = byte(r.IntN(256))
		}
		s, sg, err := Decode(b)
		if err != nil {
			continue
		}
		if !bytes.Equal(b, base) && Verify(pub, s, sg) {
			t.Errorf("seed %d: changed bytes %q read back to a statement that verifies", seed, b)
		}
	}
}
