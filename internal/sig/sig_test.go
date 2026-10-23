package sig

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
)

// testKey returns a deterministic key pair for test key number n. The seeds
// are fixed fake values so that a failure reproduces; no real key is used.
func testKey(t *testing.T, n int) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	seed := sha256.Sum256([]byte(fmt.Sprintf("rollcall sig test key %d", n)))
	priv := ed25519.NewKeyFromSeed(seed[:])
	return priv.Public().(ed25519.PublicKey), priv
}

// testMessages returns the empty message, short ones, and one the size of a
// full UDP packet.
func testMessages() [][]byte {
	var out [][]byte
	for _, size := range []int{0, 1, 31, 64, 1200} {
		msg := make([]byte, size)
		for i := range msg {
			msg[i] = byte(i*7 + size)
		}
		out = append(out, msg)
	}
	return out
}

// verifyNoPanic calls Verify and turns a panic into a test error, so one
// panicking case does not hide the others.
func verifyNoPanic(t *testing.T, pub ed25519.PublicKey, kind string, msg, sig []byte) (ok bool) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Verify panicked: %v", r)
			ok = false
		}
	}()
	return Verify(pub, kind, msg, sig)
}

// panics reports whether f panics.
func panics(f func()) (did bool) {
	defer func() {
		if recover() != nil {
			did = true
		}
	}()
	f()
	return false
}

func TestSignVerify(t *testing.T) {
	for n := 0; n < 8; n++ {
		pub, priv := testKey(t, n)
		for _, msg := range testMessages() {
			origMsg := bytes.Clone(msg)
			s := Sign(priv, "entry", msg)
			if len(s) != ed25519.SignatureSize {
				t.Fatalf("key %d, %d-byte message: signature is %d bytes, want %d",
					n, len(msg), len(s), ed25519.SignatureSize)
			}
			origSig := bytes.Clone(s)
			if !Verify(pub, "entry", msg, s) {
				t.Fatalf("key %d, %d-byte message: Verify rejected the signature Sign made", n, len(msg))
			}
			if !bytes.Equal(msg, origMsg) {
				t.Fatalf("key %d, %d-byte message: Sign or Verify changed the message", n, len(msg))
			}
			if !bytes.Equal(s, origSig) {
				t.Fatalf("key %d, %d-byte message: Verify changed the signature", n, len(msg))
			}
		}
	}

	// A nil message signs the same bytes as an empty one.
	pub, priv := testKey(t, 0)
	if !Verify(pub, "entry", nil, Sign(priv, "entry", []byte{})) {
		t.Fatal("a signature of the empty message did not verify for a nil message")
	}
}

func TestKindSeparation(t *testing.T) {
	pub, priv := testKey(t, 1)
	msg := []byte(`{"seq":1}`)

	entrySig := Sign(priv, "entry", msg)
	if !Verify(pub, "entry", msg, entrySig) {
		t.Fatal(`Verify rejected a signature for kind "entry" under kind "entry"`)
	}
	for _, other := range []string{"roster", "entr", "entryx", "Entry", "entry ", "/entry", "v1/entry"} {
		if Verify(pub, other, msg, entrySig) {
			t.Errorf(`a signature made for kind "entry" verified for kind %q`, other)
		}
	}

	rosterSig := Sign(priv, "roster", msg)
	if !Verify(pub, "roster", msg, rosterSig) {
		t.Fatal(`Verify rejected a signature for kind "roster" under kind "roster"`)
	}
	if Verify(pub, "entry", msg, rosterSig) {
		t.Error(`a signature made for kind "roster" verified for kind "entry"`)
	}
	if bytes.Equal(entrySig, rosterSig) {
		t.Error(`kinds "entry" and "roster" gave the same signature over the same message`)
	}
}

// TestKindBoundary checks the NUL byte that ends the kind. Without it, kind
// "entry" with message "xyz" and kind "entryx" with message "yz" would sign
// the same bytes.
func TestKindBoundary(t *testing.T) {
	pub, priv := testKey(t, 2)
	s := Sign(priv, "entry", []byte("xyz"))
	if !Verify(pub, "entry", []byte("xyz"), s) {
		t.Fatal("Verify rejected the signature Sign made")
	}
	for _, c := range []struct{ kind, msg string }{
		{"entryx", "yz"},
		{"entryxyz", ""},
		{"entr", "yxyz"},
	} {
		if Verify(pub, c.kind, []byte(c.msg), s) {
			t.Errorf(`signature for kind "entry", message "xyz" verified for kind %q, message %q`, c.kind, c.msg)
		}
	}
}

// TestSignedBytesFormat pins the signed bytes to the literal format of the
// security spec, built here by hand rather than by the package. Ed25519 is
// deterministic, so Sign must equal a plain Ed25519 signature over them.
func TestSignedBytesFormat(t *testing.T) {
	pub, priv := testKey(t, 3)
	msg := []byte(`{"epoch":7}`)
	literal := append([]byte("rollcall/v1/roster\x00"), msg...)

	want := ed25519.Sign(priv, literal)
	if got := Sign(priv, "roster", msg); !bytes.Equal(got, want) {
		t.Errorf("Sign does not sign %q:\n got %x\nwant %x", literal, got, want)
	}
	if !Verify(pub, "roster", msg, want) {
		t.Errorf("Verify rejected a plain Ed25519 signature over %q", literal)
	}

	// The same key signing the bare message, as another protocol might, does
	// not give a rollcall signature of any kind.
	bare := ed25519.Sign(priv, msg)
	for _, kind := range []string{"roster", "entry"} {
		if Verify(pub, kind, msg, bare) {
			t.Errorf("a signature over the bare message verified for kind %q", kind)
		}
	}
}

// TestTamper flips every bit of the message and of the signature, one at a
// time, and also adds and removes a message byte.
func TestTamper(t *testing.T) {
	pub, priv := testKey(t, 4)
	msg := []byte(`{"origin":"0011","seq":42}`)
	s := Sign(priv, "entry", msg)
	if !Verify(pub, "entry", msg, s) {
		t.Fatal("Verify rejected the signature Sign made")
	}

	for i := 0; i < len(msg)*8; i++ {
		m := bytes.Clone(msg)
		m[i/8] ^= 1 << (i % 8)
		if Verify(pub, "entry", m, s) {
			t.Errorf("message bit %d flipped: signature still verifies", i)
		}
	}
	for i := 0; i < len(s)*8; i++ {
		bad := bytes.Clone(s)
		bad[i/8] ^= 1 << (i % 8)
		if Verify(pub, "entry", msg, bad) {
			t.Errorf("signature bit %d flipped: signature still verifies", i)
		}
	}
	if Verify(pub, "entry", append(bytes.Clone(msg), 0), s) {
		t.Error("a byte appended to the message: signature still verifies")
	}
	if Verify(pub, "entry", msg[:len(msg)-1], s) {
		t.Error("last message byte removed: signature still verifies")
	}
}

// TestWrongKey checks another member's key and every single-bit change of
// the signer's own public key.
func TestWrongKey(t *testing.T) {
	pubA, privA := testKey(t, 5)
	pubB, _ := testKey(t, 6)
	msg := []byte(`{"seq":7}`)
	s := Sign(privA, "entry", msg)
	if !Verify(pubA, "entry", msg, s) {
		t.Fatal("Verify rejected the signature Sign made")
	}
	if Verify(pubB, "entry", msg, s) {
		t.Error("a signature by key A verified under key B")
	}
	for i := 0; i < len(pubA)*8; i++ {
		p := bytes.Clone(pubA)
		p[i/8] ^= 1 << (i % 8)
		if verifyNoPanic(t, ed25519.PublicKey(p), "entry", msg, s) {
			t.Errorf("public key bit %d flipped: signature still verifies", i)
		}
	}
}

// TestVerifyRejectsWrongLengths checks that a public key or a signature of
// the wrong length gives false, and never a panic.
func TestVerifyRejectsWrongLengths(t *testing.T) {
	pub, priv := testKey(t, 7)
	msg := []byte("CANARY-123:abc")
	s := Sign(priv, "entry", msg)
	if !Verify(pub, "entry", msg, s) {
		t.Fatal("Verify rejected the signature Sign made")
	}

	for _, c := range []struct {
		name string
		pub  ed25519.PublicKey
	}{
		{"nil", nil},
		{"empty", ed25519.PublicKey{}},
		{"31 bytes", bytes.Clone(pub[:31])},
		{"33 bytes", append(bytes.Clone(pub), 0)},
		{"the 64-byte private key", ed25519.PublicKey(bytes.Clone(priv))},
	} {
		if verifyNoPanic(t, c.pub, "entry", msg, s) {
			t.Errorf("public key %s: Verify returned true", c.name)
		}
	}

	for _, c := range []struct {
		name string
		sig  []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"63 bytes", bytes.Clone(s[:63])},
		{"the valid signature plus one byte", append(bytes.Clone(s), 0)},
		{"the valid signature twice", append(bytes.Clone(s), s...)},
	} {
		if verifyNoPanic(t, pub, "entry", msg, c.sig) {
			t.Errorf("signature %s: Verify returned true", c.name)
		}
	}
}

// TestInvalidKind covers the kinds that would make the signed bytes
// ambiguous or meaningless: the empty kind, and any kind with a NUL byte.
func TestInvalidKind(t *testing.T) {
	pub, priv := testKey(t, 8)

	// Kind "a" with message "b\x00c" signs "rollcall/v1/a\x00b\x00c", the
	// same bytes kind "a\x00b" with message "c" would give.
	s := Sign(priv, "a", []byte("b\x00c"))
	if !Verify(pub, "a", []byte("b\x00c"), s) {
		t.Fatal("Verify rejected the signature Sign made")
	}
	if Verify(pub, "a\x00b", []byte("c"), s) {
		t.Error(`a signature for kind "a" verified for kind "a\x00b"`)
	}

	raw := ed25519.Sign(priv, []byte("rollcall/v1/\x00msg"))
	if Verify(pub, "", []byte("msg"), raw) {
		t.Error("Verify accepted the empty kind")
	}

	for _, kind := range []string{"", "\x00", "a\x00b", "entry\x00"} {
		if !panics(func() { Sign(priv, kind, []byte("msg")) }) {
			t.Errorf("Sign with kind %q did not panic", kind)
		}
	}
}

// smallOrderHex is the small-order blocklist as the review ruling gives it,
// kept apart from the package's copy so that a typo in either one shows.
// Values are y-coordinate encodings with bit 255 (the sign of x) cleared.
var smallOrderHex = []struct {
	name      string
	hex       string
	canonical bool
}{
	{"y=0, order 4", "0000000000000000000000000000000000000000000000000000000000000000", true},
	{"y=1, identity", "0100000000000000000000000000000000000000000000000000000000000000", true},
	{"order 8 (a)", "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", true},
	{"order 8 (b)", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", true},
	{"y=p-1, order 2", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", true},
	{"y=p, non-canonical 0", "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", false},
	{"y=p+1, non-canonical 1", "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", false},
}

// decodeKey decodes a 32-byte hex public key.
func decodeKey(t *testing.T, h string) []byte {
	t.Helper()
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != ed25519.PublicKeySize {
		t.Fatalf("bad test key %q: %d bytes, %v", h, len(b), err)
	}
	return b
}

// withSignBit returns a copy of pub with bit 255 set.
func withSignBit(pub []byte) []byte {
	c := bytes.Clone(pub)
	c[31] |= 0x80
	return c
}

// probeSig returns R || S with R the encoding of the base point B and S = 1.
// Under a key A whose order divides 8, the check [S]B = R + [k]A reduces to
// [k]A = identity, which holds for at least one message in eight.
func probeSig() []byte {
	sig := make([]byte, ed25519.SignatureSize)
	copy(sig, []byte{0x58})
	for i := 1; i < 32; i++ {
		sig[i] = 0x66
	}
	sig[32] = 1
	return sig
}

// forgery returns the first of 256 fixed messages m for which plain
// ed25519.Verify accepts the probe signature over prefix + m.
func forgery(pub []byte, prefix string) ([]byte, bool) {
	sig := probeSig()
	for i := 0; i < 256; i++ {
		m := []byte(fmt.Sprintf("small-order probe %d", i))
		if ed25519.Verify(pub, append([]byte(prefix), m...), sig) {
			return m, true
		}
	}
	return nil, false
}

// forgeable reports whether a signature nobody made verifies under pub.
func forgeable(pub []byte) bool {
	_, ok := forgery(pub, "")
	return ok
}

// TestSmallOrderBlocklistIsReal checks the constants themselves: the
// package's list is exactly the ruling's seven values, and every canonical
// one is a key under which a forged signature verifies.
func TestSmallOrderBlocklistIsReal(t *testing.T) {
	if hex.EncodeToString(probeSig()[:32]) != "5866666666666666666666666666666666666666666666666666666666666666" {
		t.Fatalf("probe R is not the base point encoding: %x", probeSig()[:32])
	}
	ordinary, _ := testKey(t, 9)
	if forgeable(ordinary) {
		t.Fatal("the probe forges under an ordinary key: the oracle is broken")
	}

	if len(smallOrderY) != len(smallOrderHex) {
		t.Errorf("package blocklist has %d values, the ruling has %d", len(smallOrderY), len(smallOrderHex))
	}
	for i, c := range smallOrderHex {
		if i < len(smallOrderY) && smallOrderY[i] != c.hex {
			t.Errorf("package blocklist value %d is %s, want %s (%s)", i, smallOrderY[i], c.hex, c.name)
		}
	}

	for _, c := range smallOrderHex {
		pub := decodeKey(t, c.hex)
		plain, signed := forgeable(pub), forgeable(withSignBit(pub))
		t.Logf("%-24s forgeable: %v; with bit 255 set: %v", c.name, plain, signed)
		if c.canonical && !plain && !signed {
			t.Errorf("%s: no forgery under either sign, so the constant %s is not a small-order point", c.name, c.hex)
		}
	}
}

func TestValidPublicKeyRejectsSmallOrder(t *testing.T) {
	for _, c := range smallOrderHex {
		base := decodeKey(t, c.hex)
		for _, pub := range [][]byte{base, withSignBit(base)} {
			before := bytes.Clone(pub)
			if err := ValidPublicKey(pub); !errors.Is(err, ErrSmallOrderKey) {
				t.Errorf("%s, key %x: got %v, want ErrSmallOrderKey", c.name, pub, err)
			}
			if !bytes.Equal(pub, before) {
				t.Errorf("%s: ValidPublicKey changed the key from %x to %x", c.name, before, pub)
			}
		}
	}

	for _, n := range []int{0, 1, 31, 33, 64} {
		if err := ValidPublicKey(make([]byte, n)); !errors.Is(err, ErrKeyLength) {
			t.Errorf("%d-byte key: got %v, want ErrKeyLength", n, err)
		}
	}
	if err := ValidPublicKey(nil); !errors.Is(err, ErrKeyLength) {
		t.Errorf("nil key: got %v, want ErrKeyLength", err)
	}

	for i := 0; i < 100; i++ {
		pub, _, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		if err := ValidPublicKey(pub); err != nil {
			t.Errorf("generated key %x: %v", pub, err)
		}
		if forgeable(pub) {
			t.Errorf("generated key %x is forgeable", pub)
		}
	}
}

// TestVerifyRejectsSmallOrderKeys finds, for each blocklisted key, a message
// whose forged signature plain Ed25519 accepts over the exact bytes Verify
// checks, and requires Verify to refuse it.
func TestVerifyRejectsSmallOrderKeys(t *testing.T) {
	const kind = "roster"
	prefix := "rollcall/v1/" + kind + "\x00"
	sig := probeSig()
	forgedNames := map[string]bool{}
	forged := 0
	for _, c := range smallOrderHex {
		base := decodeKey(t, c.hex)
		for _, pub := range [][]byte{base, withSignBit(base)} {
			m, ok := forgery(pub, prefix)
			if !ok {
				continue
			}
			forged++
			forgedNames[c.name] = true
			if verifyNoPanic(t, pub, kind, m, sig) {
				t.Errorf("%s, key %x: Verify accepted a forged signature for message %q", c.name, pub, m)
			}
		}
	}
	t.Logf("forged signatures found for %d of %d blocklisted encodings", forged, 2*len(smallOrderHex))
	for _, c := range smallOrderHex {
		if c.canonical && !forgedNames[c.name] {
			t.Errorf("measured nothing for %s: no forgery found, so Verify was not exercised on it", c.name)
		}
	}
}
