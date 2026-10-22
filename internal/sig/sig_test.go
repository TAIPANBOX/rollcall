package sig

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
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
