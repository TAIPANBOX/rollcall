package wire

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

// testKey returns a fake 32-byte packet key, fixed per n so every failure
// reproduces.
func testKey(n int) []byte {
	k := sha256.Sum256([]byte(fmt.Sprintf("rollcall wire test packet key %d", n)))
	return k[:]
}

// testNonce returns a fake 24-byte nonce for packets built by hand.
func testNonce(b byte) []byte {
	return bytes.Repeat([]byte{b}, chacha20poly1305.NonceSizeX)
}

// canary returns n bytes of an obviously fake plaintext.
func canary(n int) []byte {
	return bytes.Repeat([]byte("CANARY-123:abc "), n/15+1)[:n]
}

// handSeal builds a packet without the package's code: the header laid out
// byte by byte from the spec, sealed with x/crypto directly, the header as
// associated data. It is the independent oracle for the wire format, and it
// makes authentic packets that Seal refuses to make (other versions, flags,
// sizes, the zero key).
func handSeal(t testing.TB, key []byte, version, flags byte, epoch uint32, nonce, plaintext []byte) []byte {
	t.Helper()
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		t.Fatalf("handSeal: %v", err)
	}
	hdr := []byte{version, flags, byte(epoch >> 24), byte(epoch >> 16), byte(epoch >> 8), byte(epoch)}
	hdr = append(hdr, nonce...)
	if len(hdr) != 30 {
		t.Fatalf("handSeal: header is %d bytes, the spec says 30", len(hdr))
	}
	return aead.Seal(bytes.Clone(hdr), nonce, plaintext, hdr)
}

// handOpen opens a packet with x/crypto directly: nonce at bytes 6..30, the
// first 30 bytes as associated data.
func handOpen(t testing.TB, key, packet []byte) ([]byte, error) {
	t.Helper()
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		t.Fatalf("handOpen: %v", err)
	}
	return aead.Open(nil, packet[6:30], packet[30:], packet[:30])
}

// ring is a fake KeyLookup that records every epoch it is asked for.
type ring struct {
	keys  map[uint32][]byte
	asked []uint32
}

func newRing(epoch uint32, key []byte) *ring {
	return &ring{keys: map[uint32][]byte{epoch: key}}
}

func (r *ring) lookup(epoch uint32) ([]byte, bool) {
	r.asked = append(r.asked, epoch)
	k, ok := r.keys[epoch]
	return k, ok
}

// mustSeal seals or fails the test.
func mustSeal(t testing.TB, key []byte, epoch uint32, plaintext []byte) []byte {
	t.Helper()
	p, err := Seal(key, epoch, plaintext)
	if err != nil {
		t.Fatalf("Seal(%d-byte plaintext): %v", len(plaintext), err)
	}
	return p
}

// mustOpen requires Open to accept packet with the given epoch and plaintext.
// Negative tests call it first, so an Open that rejects everything cannot pass
// them vacuously.
func mustOpen(t testing.TB, lookup KeyLookup, packet []byte, epoch uint32, plaintext []byte) {
	t.Helper()
	e, p, err := Open(lookup, packet)
	if err != nil || e != epoch || !bytes.Equal(p, plaintext) {
		t.Fatalf("positive guard: Open = (%d, %d bytes, %v), want (%d, the %d-byte plaintext, nil)",
			e, len(p), err, epoch, len(plaintext))
	}
}

// wantReject requires Open to fail with exactly want (identity, so an error
// that wraps or decorates the sentinel fails), a nil plaintext and epoch 0.
func wantReject(t testing.TB, what string, e uint32, p []byte, err, want error) {
	t.Helper()
	if err != want || p != nil || e != 0 {
		t.Errorf("%s: Open = (%d, %d bytes, non-nil plaintext %v, %v), want (0, nil, %v)",
			what, e, len(p), p != nil, err, want)
	}
}

func TestConstants(t *testing.T) {
	if Version != 1 || MaxPacket != 1200 || HeaderLen != 30 {
		t.Fatalf("Version, MaxPacket, HeaderLen = %d, %d, %d; the spec says 1, 1200, 30", Version, MaxPacket, HeaderLen)
	}
	if HeaderLen != 1+1+4+chacha20poly1305.NonceSizeX {
		t.Fatalf("HeaderLen %d is not version(1) + flags(1) + epoch(4) + nonce(%d)", HeaderLen, chacha20poly1305.NonceSizeX)
	}
	if maxPlaintext != 1200-30-16 {
		t.Fatalf("maxPlaintext = %d, want 1154", maxPlaintext)
	}
}

func TestSealOpen(t *testing.T) {
	key := testKey(1)
	for _, epoch := range []uint32{0, 1, 0x01020304, math.MaxUint32} {
		for _, n := range []int{0, 1, 15, 16, 17, 255, 1153, 1154} {
			pt := canary(n)
			ptCopy := bytes.Clone(pt)
			pkt := mustSeal(t, key, epoch, pt)
			if !bytes.Equal(pt, ptCopy) {
				t.Fatalf("Seal modified its plaintext")
			}
			if len(pkt) != 30+n+16 {
				t.Fatalf("epoch %d, %d-byte plaintext: packet is %d bytes, want %d", epoch, n, len(pkt), 30+n+16)
			}
			gotEpoch := uint32(pkt[2])<<24 | uint32(pkt[3])<<16 | uint32(pkt[4])<<8 | uint32(pkt[5])
			if pkt[0] != 1 || pkt[1] != 0 || gotEpoch != epoch {
				t.Fatalf("header = version %d, flags %d, epoch %#x; want 1, 0, %#x (big endian)", pkt[0], pkt[1], gotEpoch, epoch)
			}
			if n >= 16 && bytes.Contains(pkt, pt) {
				t.Fatalf("the %d-byte plaintext appears in the clear in the packet", n)
			}

			r := newRing(epoch, key)
			pktCopy := bytes.Clone(pkt)
			e, got, err := Open(r.lookup, pkt)
			if err != nil || e != epoch || !bytes.Equal(got, pt) || got == nil {
				t.Fatalf("epoch %#x, %d bytes: Open = (%#x, %q, %v)", epoch, n, e, got, err)
			}
			if !bytes.Equal(pkt, pktCopy) {
				t.Fatalf("Open modified the packet")
			}
			if len(r.asked) != 1 || r.asked[0] != epoch {
				t.Fatalf("lookup was asked for %v, want exactly [%d]", r.asked, epoch)
			}
			// A UDP reader reuses its buffer: the plaintext must not live in it.
			for i := range pkt {
				pkt[i] ^= 0xff
			}
			if !bytes.Equal(got, pt) {
				t.Fatalf("the plaintext Open returned changed when the packet buffer was rewritten")
			}
		}
	}
}

func TestWireFormat(t *testing.T) {
	key := testKey(1)
	pt := canary(40)

	// Seal's output opens with x/crypto directly, header as associated data.
	pkt := mustSeal(t, key, 0x0a0b0c0d, pt)
	got, err := handOpen(t, key, pkt)
	if err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("x/crypto could not open Seal's packet with the spec layout: %v", err)
	}

	// A packet built by hand from the spec opens with Open.
	hand := handSeal(t, key, 1, 0, 0x0a0b0c0d, testNonce(7), pt)
	r := newRing(0x0a0b0c0d, key)
	mustOpen(t, r.lookup, hand, 0x0a0b0c0d, pt)
	if len(r.asked) != 1 || r.asked[0] != 0x0a0b0c0d {
		t.Fatalf("lookup was asked for %x, want [a0b0c0d] (big endian)", r.asked)
	}
}

func TestOpenRejectsWrongKey(t *testing.T) {
	key, other := testKey(1), testKey(2)
	pkt := mustSeal(t, key, 7, canary(64))
	mustOpen(t, newRing(7, key).lookup, pkt, 7, canary(64))

	e, p, err := Open(newRing(7, other).lookup, pkt)
	wantReject(t, "packet sealed with another key", e, p, err, ErrAuth)

	// A packet sealed with epoch 8's key but labelled epoch 7.
	r := &ring{keys: map[uint32][]byte{7: key, 8: other}}
	relabelled := handSeal(t, other, 1, 0, 7, testNonce(1), canary(64))
	e, p, err = Open(r.lookup, relabelled)
	wantReject(t, "epoch 8 key, epoch 7 label", e, p, err, ErrAuth)
}

func TestOpenRejectsUnknownEpoch(t *testing.T) {
	key := testKey(1)
	pt := canary(64)
	pkt := mustSeal(t, key, 7, pt)
	mustOpen(t, newRing(7, key).lookup, pkt, 7, pt)

	// The lookup hands over the right key but says it does not know the
	// epoch: Open must not decrypt with it.
	var asked []uint32
	notFound := func(epoch uint32) ([]byte, bool) {
		asked = append(asked, epoch)
		return key, false
	}
	e, p, err := Open(notFound, pkt)
	wantReject(t, "lookup says not found (with the right key)", e, p, err, ErrEpoch)
	if len(asked) != 1 || asked[0] != 7 {
		t.Errorf("lookup was asked for %v, want [7]", asked)
	}

	e, p, err = Open(func(uint32) ([]byte, bool) { return nil, false }, pkt)
	wantReject(t, "lookup says not found", e, p, err, ErrEpoch)

	e, p, err = Open(newRing(8, key).lookup, pkt)
	wantReject(t, "only epoch 8 known", e, p, err, ErrEpoch)

	e, p, err = Open(nil, pkt)
	wantReject(t, "nil lookup", e, p, err, ErrEpoch)
}

func TestOpenRejectsVersion(t *testing.T) {
	key := testKey(1)
	pt := canary(64)
	mustOpen(t, newRing(7, key).lookup, handSeal(t, key, 1, 0, 7, testNonce(3), pt), 7, pt)

	for _, v := range []byte{0, 2, 0x81, 0xff} {
		// An authentic packet that claims another version, and a v1 packet
		// whose version byte was changed on the way.
		authentic := handSeal(t, key, v, 0, 7, testNonce(3), pt)
		flipped := mustSeal(t, key, 7, pt)
		flipped[0] = v
		for name, pkt := range map[string][]byte{"authentic": authentic, "changed": flipped} {
			r := newRing(7, key)
			e, p, err := Open(r.lookup, pkt)
			wantReject(t, fmt.Sprintf("%s packet, version %d", name, v), e, p, err, ErrVersion)
			if len(r.asked) != 0 {
				t.Errorf("version %d: lookup was asked for %v before the version was checked", v, r.asked)
			}
		}
	}
}

func TestOpenRejectsFlags(t *testing.T) {
	key := testKey(1)
	pt := canary(64)
	mustOpen(t, newRing(7, key).lookup, handSeal(t, key, 1, 0, 7, testNonce(4), pt), 7, pt)

	// Authentic packets with flags set, sealed under the right key: v1
	// defines no flags, so the format is not one this version speaks.
	for _, f := range []byte{1, 2, 0x80, 0xff} {
		pkt := handSeal(t, key, 1, f, 7, testNonce(4), pt)
		e, p, err := Open(newRing(7, key).lookup, pkt)
		wantReject(t, fmt.Sprintf("authentic packet with flags %#x", f), e, p, err, ErrVersion)
	}
}

func TestOpenRejectsOversize(t *testing.T) {
	key := testKey(1)
	full := handSeal(t, key, 1, 0, 7, testNonce(5), canary(1154))
	if len(full) != 1200 {
		t.Fatalf("fixture: %d bytes, want 1200", len(full))
	}
	mustOpen(t, newRing(7, key).lookup, full, 7, canary(1154))

	cases := map[string][]byte{
		"authentic 1201-byte packet":       handSeal(t, key, 1, 0, 7, testNonce(5), canary(1155)),
		"valid 1200-byte packet + 1 byte":  append(bytes.Clone(full), 0),
		"65535 zero bytes":                 make([]byte, 65535),
		"authentic 1201 bytes, version 2":  handSeal(t, key, 2, 0, 7, testNonce(5), canary(1155)),
		"authentic 2000 bytes, epoch kept": handSeal(t, key, 1, 0, 7, testNonce(5), canary(1954)),
	}
	for name, pkt := range cases {
		r := newRing(7, key)
		e, p, err := Open(r.lookup, pkt)
		wantReject(t, name, e, p, err, ErrTooLarge)
		if len(r.asked) != 0 {
			t.Errorf("%s: lookup was asked for %v before the size was checked", name, r.asked)
		}
	}
}

func TestOpenRejectsShort(t *testing.T) {
	key := testKey(1)
	empty := mustSeal(t, key, 7, nil)
	if len(empty) != 46 {
		t.Fatalf("fixture: empty plaintext sealed to %d bytes, want 46", len(empty))
	}
	mustOpen(t, newRing(7, key).lookup, empty, 7, nil)

	for n := 0; n < 46; n++ {
		r := newRing(7, key)
		e, p, err := Open(r.lookup, empty[:n])
		wantReject(t, fmt.Sprintf("%d-byte prefix", n), e, p, err, ErrShort)
		if len(r.asked) != 0 {
			t.Errorf("%d-byte prefix: lookup was asked for %v", n, r.asked)
		}
	}
}

func TestCheckOrder(t *testing.T) {
	// One more fault at each step: the cheapest check that fails decides the
	// error, and the lookup is asked only once length and version passed.
	key := testKey(1)
	unknown := newRing(99, key)
	big := handSeal(t, key, 2, 0, 7, testNonce(6), canary(1155))
	small := handSeal(t, key, 2, 0, 7, testNonce(6), nil)[:20]
	v2 := handSeal(t, key, 2, 0, 7, testNonce(6), canary(10))
	v1 := handSeal(t, key, 1, 0, 7, testNonce(6), canary(10))
	v1[len(v1)-1] ^= 1

	steps := []struct {
		name   string
		lookup *ring
		pkt    []byte
		want   error
		asked  int
	}{
		{"oversize, version 2, unknown epoch", unknown, big, ErrTooLarge, 0},
		{"short, version 2, unknown epoch", unknown, small, ErrShort, 0},
		{"version 2, unknown epoch", unknown, v2, ErrVersion, 0},
		{"unknown epoch, bad tag", unknown, v1, ErrEpoch, 1},
		{"known epoch, bad tag", newRing(7, key), v1, ErrAuth, 1},
	}
	for _, s := range steps {
		s.lookup.asked = nil
		e, p, err := Open(s.lookup.lookup, s.pkt)
		wantReject(t, s.name, e, p, err, s.want)
		if len(s.lookup.asked) != s.asked {
			t.Errorf("%s: lookup asked %d times, want %d", s.name, len(s.lookup.asked), s.asked)
		}
	}
}

func TestSealRejectsOversize(t *testing.T) {
	key := testKey(1)
	if p, err := Seal(key, 7, canary(1154)); err != nil || len(p) != 1200 {
		t.Fatalf("1154-byte plaintext: Seal = (%d bytes, %v), want a 1200-byte packet", len(p), err)
	}
	for _, n := range []int{1155, 1200, 4096} {
		p, err := Seal(key, 7, canary(n))
		if err != ErrTooLarge || p != nil {
			t.Errorf("%d-byte plaintext: Seal = (%d bytes, %v), want (nil, ErrTooLarge)", n, len(p), err)
		}
	}
}

func TestSealRejectsBadKey(t *testing.T) {
	cases := map[string][]byte{
		"nil":      nil,
		"empty":    {},
		"16 bytes": testKey(1)[:16],
		"31 bytes": testKey(1)[:31],
		"33 bytes": append(testKey(1), 1),
		"64 bytes": append(testKey(1), testKey(2)...),
		"all zero": make([]byte, 32),
		"zero, 31": make([]byte, 31),
		"zero, 64": make([]byte, 64),
	}
	for name, key := range cases {
		p, err := Seal(key, 7, canary(10))
		if err != ErrKey || p != nil {
			t.Errorf("key %s: Seal = (%d bytes, %v), want (nil, ErrKey)", name, len(p), err)
		}
	}
}

func TestOpenRejectsBadLookupKey(t *testing.T) {
	key := testKey(1)
	pt := canary(10)
	pkt := mustSeal(t, key, 7, pt)
	mustOpen(t, newRing(7, key).lookup, pkt, 7, pt)

	for name, k := range map[string][]byte{"nil": nil, "31 bytes": key[:31], "33 bytes": append(bytes.Clone(key), 0)} {
		e, p, err := Open(newRing(7, k).lookup, pkt)
		wantReject(t, "lookup key "+name, e, p, err, ErrKey)
	}

	// A ring holding the all-zero key (an unset key) must not open a packet
	// that anyone could seal under it.
	zero := make([]byte, 32)
	forged := handSeal(t, zero, 1, 0, 7, testNonce(9), pt)
	e, p, err := Open(newRing(7, zero).lookup, forged)
	wantReject(t, "packet sealed under the all-zero key", e, p, err, ErrKey)
}

func TestOnlyTheAllZeroKeyIsRefused(t *testing.T) {
	// A random key ends in a zero byte once in 256 tries: the zero-key check
	// must look at every byte, or such a key, and with it a whole epoch, is
	// refused.
	for i := 0; i < 32; i++ {
		k := make([]byte, 32)
		k[i] = 1
		pkt, err := Seal(k, 7, canary(10))
		if err != nil {
			t.Errorf("key with only byte %d set: Seal: %v", i, err)
			continue
		}
		mustOpen(t, newRing(7, k).lookup, pkt, 7, canary(10))
		if _, err := PacketKey(k); err != nil {
			t.Errorf("epoch key with only byte %d set: PacketKey: %v", i, err)
		}
	}
	long := make([]byte, 64)
	long[0] = 1
	if _, err := PacketKey(long); err != nil {
		t.Errorf("64-byte epoch key with only byte 0 set: PacketKey: %v", err)
	}
}

func TestHeaderIsAuthenticated(t *testing.T) {
	key := testKey(1)
	pt := canary(64)
	pkt := mustSeal(t, key, 7, pt)
	// The lookup has the key for every epoch, so a changed epoch still finds
	// a key and only the AEAD can notice the change.
	anyEpoch := func(uint32) ([]byte, bool) { return key, true }
	mustOpen(t, anyEpoch, pkt, 7, pt)

	for bit := 8; bit < 30*8; bit++ { // flags, epoch and nonce: every bit after the version byte
		bad := bytes.Clone(pkt)
		bad[bit/8] ^= 1 << (bit % 8)
		e, p, err := Open(anyEpoch, bad)
		wantReject(t, fmt.Sprintf("header bit %d flipped", bit), e, p, err, ErrAuth)
	}
}

func TestTamper(t *testing.T) {
	key := testKey(1)
	pt := canary(64)
	pkt := mustSeal(t, key, 7, pt)
	lookup := newRing(7, key).lookup
	mustOpen(t, lookup, pkt, 7, pt)

	for bit := 30 * 8; bit < len(pkt)*8; bit++ { // ciphertext and tag
		bad := bytes.Clone(pkt)
		bad[bit/8] ^= 1 << (bit % 8)
		e, p, err := Open(lookup, bad)
		wantReject(t, fmt.Sprintf("body bit %d flipped", bit), e, p, err, ErrAuth)
	}
	for cut := 1; cut <= len(pkt)-46; cut++ {
		e, p, err := Open(lookup, pkt[:len(pkt)-cut])
		wantReject(t, fmt.Sprintf("%d bytes cut from the end", cut), e, p, err, ErrAuth)
	}
	e, p, err := Open(lookup, append(bytes.Clone(pkt), 0))
	wantReject(t, "one byte appended", e, p, err, ErrAuth)
}

func TestNoncesDiffer(t *testing.T) {
	key := testKey(1)
	pt := canary(64)
	a, b := mustSeal(t, key, 7, pt), mustSeal(t, key, 7, pt)
	if bytes.Equal(a, b) {
		t.Fatal("two seals of the same plaintext are identical")
	}
	if bytes.Equal(a[6:30], b[6:30]) || bytes.Equal(a[30:], b[30:]) {
		t.Fatal("two seals of the same plaintext share a nonce or a ciphertext")
	}

	seen := make(map[string]bool)
	zero := make([]byte, 24)
	var values [24]map[byte]bool
	for i := range values {
		values[i] = make(map[byte]bool)
	}
	for i := 0; i < 1000; i++ {
		n := mustSeal(t, key, 7, pt)[6:30]
		if seen[string(n)] || bytes.Equal(n, zero) {
			t.Fatalf("seal %d: nonce %x repeated or zero", i, n)
		}
		seen[string(n)] = true
		for j, b := range n {
			values[j][b] = true
		}
	}
	// Every one of the 24 bytes is random: over 1000 nonces a random byte
	// takes about 251 of its 256 values, so fewer than 128 means a byte is
	// fixed or barely moves (a short random part, a counter).
	for j, v := range values {
		if len(v) < 128 {
			t.Errorf("nonce byte %d took only %d distinct values in 1000 seals", j, len(v))
		}
	}
}

// hkdfOracle is HKDF-SHA256 (RFC 5869) with an empty salt and one output
// block, written with crypto/hmac so it shares no code with crypto/hkdf.
func hkdfOracle(ikm []byte, info string) []byte {
	ext := hmac.New(sha256.New, make([]byte, sha256.Size))
	ext.Write(ikm)
	exp := hmac.New(sha256.New, ext.Sum(nil))
	exp.Write([]byte(info))
	exp.Write([]byte{1})
	return exp.Sum(nil)
}

func TestPacketKey(t *testing.T) {
	// Known answers computed outside Go (Python hmac, RFC 5869, the same
	// code reproduces RFC 5869 test case A.3) for info "rollcall/v1 packet".
	seq := make([]byte, 32)
	for i := range seq {
		seq[i] = byte(i)
	}
	shaKey := sha256.Sum256([]byte("rollcall wire test epoch key"))
	known := []struct {
		epochKey []byte
		want     string
	}{
		{seq, "4285424d2a1a1eeb8a1d3a80253a294d4cd8bb3f667496deaed5fe895b31d8a6"},
		{shaKey[:], "866eb11ed0e3a9b753a8946c933caa442c971ff00b70eb018cb0f30d419a6cda"},
	}
	for _, k := range known {
		got, err := PacketKey(k.epochKey)
		if err != nil || hex.EncodeToString(got) != k.want {
			t.Errorf("PacketKey(%x) = (%x, %v), want %s", k.epochKey, got, err, k.want)
		}
	}

	for _, n := range []int{32, 33, 64, 100} {
		ek := bytes.Repeat(testKey(n), 4)[:n]
		ekCopy := bytes.Clone(ek)
		pk, err := PacketKey(ek)
		if err != nil {
			t.Fatalf("%d-byte epoch key: %v", n, err)
		}
		if !bytes.Equal(pk, hkdfOracle(ek, "rollcall/v1 packet")) {
			t.Errorf("%d-byte epoch key: PacketKey differs from HKDF-SHA256(salt empty, info %q)", n, "rollcall/v1 packet")
		}
		if len(pk) != 32 || bytes.Equal(pk, ek[:32]) || !bytes.Equal(ek, ekCopy) {
			t.Errorf("%d-byte epoch key: packet key %d bytes, equal to the input %v, input changed %v",
				n, len(pk), bytes.Equal(pk, ek[:32]), !bytes.Equal(ek, ekCopy))
		}
		pk[0] ^= 0xff
		if !bytes.Equal(ek, ekCopy) {
			t.Errorf("%d-byte epoch key: the packet key shares memory with the epoch key", n)
		}
	}

	a, _ := PacketKey(testKey(1))
	b, _ := PacketKey(testKey(2))
	if bytes.Equal(a, b) {
		t.Error("two epoch keys gave the same packet key")
	}
	// The derived key seals and opens.
	pkt := mustSeal(t, a, 3, canary(20))
	mustOpen(t, newRing(3, a).lookup, pkt, 3, canary(20))

	bad := map[string][]byte{
		"nil": nil, "empty": {}, "1 byte": {1}, "16 bytes": testKey(1)[:16], "31 bytes": testKey(1)[:31],
		"32 zero bytes": make([]byte, 32), "64 zero bytes": make([]byte, 64),
	}
	for name, ek := range bad {
		pk, err := PacketKey(ek)
		if err != ErrKey || pk != nil {
			t.Errorf("epoch key %s: PacketKey = (%x, %v), want (nil, ErrKey)", name, pk, err)
		}
	}
}
