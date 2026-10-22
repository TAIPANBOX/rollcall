package epoch

// The delivery format's sizes, offsets and labels are written out in this file
// (fmt* constants, handSeal) instead of being taken from the package, so that a
// change to the format shows up as a failing test rather than passing quietly.

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/identity"
	"github.com/TAIPANBOX/rollcall/internal/ids"
	"github.com/TAIPANBOX/rollcall/internal/sig"
	"github.com/TAIPANBOX/rollcall/internal/wire"
)

// The documented delivery format.
const (
	fmtBlobSize  = 1261 // version 1 + signer 16 + HPKE ciphertext 1180 + signature 64
	fmtVersion   = 1
	fmtSignerOff = 1
	fmtCTOff     = 17
	fmtSigOff    = 1197
	fmtEncSize   = 1120 // ML-KEM-768 ciphertext 1088 + X25519 point 32
	fmtPTSize    = 44   // epoch ID 4 + NotAfter 8 + secret 32
	fmtInfoLabel = "rollcall/v1 epoch"
	fmtSigPrefix = "rollcall/v1/epoch\x00"
	fmtMaxUnix   = 253402300799 // 9999-12-31T23:59:59Z
)

// t0 is a fixed instant for the ring tests; testNotAfter is a fixed
// NotAfter, in whole seconds and UTC, as Open returns it.
var (
	t0           = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	testNotAfter = time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
)

// identityPoint is the Ed25519 encoding of the identity point, a small-order
// public key under which a signature nobody made verifies (see probeSig).
const identityPoint = "0100000000000000000000000000000000000000000000000000000000000000"

// testSecret returns 32 bytes that depend on n and are never all zero.
func testSecret(n byte) []byte {
	s := make([]byte, 32)
	for i := range s {
		s[i] = n ^ byte(0xa5+7*i)
	}
	return s
}

func testKey(id uint32, n byte) Key {
	return Key{ID: id, Secret: testSecret(n), NotAfter: testNotAfter}
}

// mustPacketKey derives the packet key with crypto/hkdf directly, so the
// ring is checked against the house rule and not against wire's own code.
func mustPacketKey(t testing.TB, secret []byte) []byte {
	t.Helper()
	k, err := hkdf.Key(sha256.New, secret, nil, "rollcall/v1 packet", 32)
	if err != nil {
		t.Fatalf("hkdf: %v", err)
	}
	return k
}

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = t
}

func mustInstall(t *testing.T, r *Ring, k Key, now time.Time) {
	t.Helper()
	if err := r.Install(k, now); err != nil {
		t.Fatalf("Install(epoch %d) = %v, want nil", k.ID, err)
	}
}

// wantKey asserts that Lookup(id) returns the packet key of secret.
func wantKey(t *testing.T, r *Ring, id uint32, secret []byte, when string) {
	t.Helper()
	got, ok := r.Lookup(id)
	if !ok {
		t.Errorf("%s: Lookup(%d) found nothing, want the epoch's packet key", when, id)
		return
	}
	if !bytes.Equal(got, mustPacketKey(t, secret)) {
		t.Errorf("%s: Lookup(%d) returned a key that is not the epoch's packet key", when, id)
	}
}

// wantNoKey asserts that Lookup(id) returns (nil, false).
func wantNoKey(t *testing.T, r *Ring, id uint32, when string) {
	t.Helper()
	if got, ok := r.Lookup(id); ok || got != nil {
		t.Errorf("%s: Lookup(%d) = (%d bytes, %v), want (nil, false)", when, id, len(got), ok)
	}
}

func TestConstants(t *testing.T) {
	if SecretSize != 32 {
		t.Errorf("SecretSize = %d, want 32", SecretSize)
	}
	if Overlap != 60*time.Second {
		t.Errorf("Overlap = %v, want 60s", Overlap)
	}
	if RotationPeriod != 30*24*time.Hour {
		t.Errorf("RotationPeriod = %v, want 720h (30 days)", RotationPeriod)
	}
	if BlobSize != fmtBlobSize {
		t.Errorf("BlobSize = %d, want %d", BlobSize, fmtBlobSize)
	}
}

// TestRingOverlap: after a switch the previous epoch is accepted for 60 s,
// valid at 59 s and invalid at 61 s; the current epoch is always accepted.
func TestRingOverlap(t *testing.T) {
	c := &fakeClock{now: t0}
	r := &Ring{Now: c.Now}
	old, cur := testKey(1, 1), testKey(2, 2)
	mustInstall(t, r, old, t0)
	wantKey(t, r, 1, old.Secret, "before the switch")
	wantNoKey(t, r, 2, "before the switch")

	switchAt := t0.Add(time.Hour)
	c.Set(switchAt)
	mustInstall(t, r, cur, switchAt)
	for _, tc := range []struct {
		after     time.Duration
		prevValid bool
	}{
		{0, true},
		{time.Second, true},
		{59 * time.Second, true},
		{60*time.Second - time.Nanosecond, true},
		{60 * time.Second, false},
		{61 * time.Second, false},
		{time.Hour, false},
		{RotationPeriod, false},
	} {
		c.Set(switchAt.Add(tc.after))
		when := fmt.Sprintf("%v after the switch", tc.after)
		wantKey(t, r, 2, cur.Secret, when)
		if tc.prevValid {
			wantKey(t, r, 1, old.Secret, when)
		} else {
			wantNoKey(t, r, 1, when)
		}
	}
}

// TestRingSecondSwitch: only one previous epoch is kept; a second switch
// within the overlap drops the oldest at once and starts a new overlap.
func TestRingSecondSwitch(t *testing.T) {
	c := &fakeClock{now: t0}
	r := &Ring{Now: c.Now}
	k1, k2, k3 := testKey(1, 1), testKey(2, 2), testKey(3, 3)
	mustInstall(t, r, k1, t0)
	t1 := t0.Add(time.Hour)
	mustInstall(t, r, k2, t1)
	t2 := t1.Add(10 * time.Second)
	c.Set(t2)
	mustInstall(t, r, k3, t2)

	wantNoKey(t, r, 1, "right after the second switch")
	wantKey(t, r, 2, k2.Secret, "right after the second switch")
	wantKey(t, r, 3, k3.Secret, "right after the second switch")

	c.Set(t2.Add(59 * time.Second))
	wantKey(t, r, 2, k2.Secret, "59 s after the second switch")
	c.Set(t2.Add(60 * time.Second))
	wantNoKey(t, r, 2, "60 s after the second switch")
	wantKey(t, r, 3, k3.Secret, "60 s after the second switch")
}

// TestRingClockBeforeSwitch: a clock that reads earlier than the switch
// (stepped back) does not keep the previous epoch open; the current stays.
func TestRingClockBeforeSwitch(t *testing.T) {
	c := &fakeClock{now: t0}
	r := &Ring{Now: c.Now}
	mustInstall(t, r, testKey(1, 1), t0)
	t1 := t0.Add(time.Hour)
	mustInstall(t, r, testKey(2, 2), t1)

	for _, back := range []time.Duration{time.Nanosecond, time.Second, time.Hour, 365 * 24 * time.Hour} {
		c.Set(t1.Add(-back))
		when := fmt.Sprintf("clock %v before the switch", back)
		wantNoKey(t, r, 1, when)
		wantKey(t, r, 2, testSecret(2), when)
	}
}

// TestRingDefaultClock: a zero Ring uses time.Now. Checked without sleeping
// by placing the switch in the past and in the future of the real clock.
func TestRingDefaultClock(t *testing.T) {
	var fresh Ring
	mustInstall(t, &fresh, testKey(1, 1), time.Now())
	mustInstall(t, &fresh, testKey(2, 2), time.Now())
	wantKey(t, &fresh, 1, testSecret(1), "switch just now, default clock")
	wantKey(t, &fresh, 2, testSecret(2), "switch just now, default clock")

	var stale Ring
	mustInstall(t, &stale, testKey(1, 1), time.Now().Add(-time.Hour))
	mustInstall(t, &stale, testKey(2, 2), time.Now().Add(-61*time.Second))
	wantNoKey(t, &stale, 1, "switch 61 s ago, default clock")
	wantKey(t, &stale, 2, testSecret(2), "switch 61 s ago, default clock")

	var future Ring
	mustInstall(t, &future, testKey(1, 1), time.Now())
	mustInstall(t, &future, testKey(2, 2), time.Now().Add(time.Hour))
	wantNoKey(t, &future, 1, "switch an hour ahead of the default clock")
}

// TestRingLookupReturnsPacketKey: Lookup is a wire.KeyLookup and returns
// the packet key derived from the epoch key, never the epoch key itself.
func TestRingLookupReturnsPacketKey(t *testing.T) {
	r := &Ring{}
	k := testKey(7, 7)
	mustInstall(t, r, k, time.Now())

	got, ok := r.Lookup(7)
	if !ok {
		t.Fatal("Lookup(7) found nothing")
	}
	want := mustPacketKey(t, k.Secret)
	if !bytes.Equal(got, want) {
		t.Errorf("Lookup(7) = %x, want the packet key %x", got, want)
	}
	if bytes.Equal(got, k.Secret) {
		t.Error("Lookup(7) returned the epoch key itself")
	}

	var lookup wire.KeyLookup = r.Lookup
	pkt, err := wire.Seal(want, 7, []byte("heartbeat"))
	if err != nil {
		t.Fatalf("wire.Seal: %v", err)
	}
	epoch, pt, err := wire.Open(lookup, pkt)
	if err != nil || epoch != 7 || string(pt) != "heartbeat" {
		t.Errorf("wire.Open(ring) of a packet under the packet key = (%d, %q, %v), want (7, heartbeat, nil)", epoch, pt, err)
	}
	raw, err := wire.Seal(k.Secret, 7, []byte("heartbeat"))
	if err != nil {
		t.Fatalf("wire.Seal: %v", err)
	}
	if _, _, err := wire.Open(lookup, raw); err != wire.ErrAuth {
		t.Errorf("wire.Open(ring) of a packet sealed under the raw epoch key = %v, want wire.ErrAuth", err)
	}
}

func TestRingUnknownEpoch(t *testing.T) {
	var r Ring
	for _, id := range []uint32{0, 1, math.MaxUint32} {
		wantNoKey(t, &r, id, "empty ring")
	}
	mustInstall(t, &r, testKey(5, 5), time.Now())
	for _, id := range []uint32{0, 4, 6, math.MaxUint32} {
		wantNoKey(t, &r, id, "ring holding epoch 5")
	}
}

// TestRingLookupCopies: a caller that changes the returned key changes
// nothing in the ring.
func TestRingLookupCopies(t *testing.T) {
	c := &fakeClock{now: t0}
	r := &Ring{Now: c.Now}
	mustInstall(t, r, testKey(1, 1), t0)
	mustInstall(t, r, testKey(2, 2), t0)
	for _, id := range []uint32{1, 2} {
		got, ok := r.Lookup(id)
		if !ok {
			t.Fatalf("Lookup(%d) found nothing", id)
		}
		for i := range got {
			got[i] ^= 0xff
		}
		wantKey(t, r, id, testSecret(byte(id)), "after the caller changed a returned key")
	}
}

// TestRingInstallRejectsBadSecret: a secret that is not 32 bytes, or is all
// zero, is refused and changes nothing.
func TestRingInstallRejectsBadSecret(t *testing.T) {
	bad := map[string][]byte{
		"nil":       nil,
		"empty":     {},
		"16 bytes":  testSecret(9)[:16],
		"31 bytes":  testSecret(9)[:31],
		"33 bytes":  append(testSecret(9), 1),
		"64 bytes":  append(testSecret(9), testSecret(10)...),
		"all zero":  make([]byte, 32),
		"zero 33 b": make([]byte, 33),
	}
	for name, secret := range bad {
		var empty Ring
		if err := empty.Install(Key{ID: 1, Secret: secret, NotAfter: testNotAfter}, t0); err != ErrInvalidKey {
			t.Errorf("%s, empty ring: Install = %v, want ErrInvalidKey", name, err)
		}
		wantNoKey(t, &empty, 1, name+", empty ring")

		c := &fakeClock{now: t0}
		r := &Ring{Now: c.Now}
		mustInstall(t, r, testKey(1, 1), t0)
		if err := r.Install(Key{ID: 2, Secret: secret, NotAfter: testNotAfter}, t0); err != ErrInvalidKey {
			t.Errorf("%s: Install = %v, want ErrInvalidKey", name, err)
		}
		c.Set(t0.Add(time.Hour))
		wantNoKey(t, r, 2, name)
		wantKey(t, r, 1, testSecret(1), name+": epoch 1 must still be current")
	}
}

// TestRingRejectsStaleEpoch: an epoch that is not newer than the current
// one is refused, so a replayed old delivery cannot bring back a key that a
// removed member knows.
func TestRingRejectsStaleEpoch(t *testing.T) {
	c := &fakeClock{now: t0}
	r := &Ring{Now: c.Now}
	mustInstall(t, r, testKey(5, 5), t0)

	for _, k := range []Key{
		testKey(4, 4),
		testKey(0, 4),
		{ID: 5, Secret: testSecret(6), NotAfter: testNotAfter}, // same ID, another secret
	} {
		if err := r.Install(k, t0); err != ErrStale {
			t.Errorf("Install(epoch %d) over epoch 5 = %v, want ErrStale", k.ID, err)
		}
	}
	c.Set(t0.Add(time.Hour))
	wantKey(t, r, 5, testSecret(5), "after the stale installs")
	wantNoKey(t, r, 4, "after the stale installs")
	wantNoKey(t, r, 0, "after the stale installs")

	t1 := t0.Add(2 * time.Hour)
	c.Set(t1)
	mustInstall(t, r, testKey(6, 6), t1)
	if err := r.Install(testKey(5, 5), t1.Add(time.Second)); err != ErrStale {
		t.Errorf("Install(epoch 5) after epoch 6 = %v, want ErrStale", err)
	}
	c.Set(t1.Add(30 * time.Second))
	wantKey(t, r, 6, testSecret(6), "epoch 6 after the refused reinstall of 5")
	wantKey(t, r, 5, testSecret(5), "epoch 5 within the overlap")
	c.Set(t1.Add(60 * time.Second))
	wantNoKey(t, r, 5, "epoch 5 after the overlap: the refused reinstall must not reopen it")

	mustInstall(t, r, testKey(math.MaxUint32, 7), t1.Add(time.Hour))
	if err := r.Install(testKey(math.MaxUint32-1, 8), t1.Add(time.Hour)); err != ErrStale {
		t.Errorf("Install(MaxUint32-1) after MaxUint32 = %v, want ErrStale", err)
	}
}

// TestRingReinstallSameKey: the current key delivered again is accepted and
// changes nothing; in particular it does not restart the overlap.
func TestRingReinstallSameKey(t *testing.T) {
	c := &fakeClock{now: t0}
	r := &Ring{Now: c.Now}
	mustInstall(t, r, testKey(4, 4), t0)
	t1 := t0.Add(time.Hour)
	mustInstall(t, r, testKey(5, 5), t1)
	c.Set(t1.Add(50 * time.Second))
	mustInstall(t, r, testKey(5, 5), t1.Add(50*time.Second))
	wantKey(t, r, 4, testSecret(4), "50 s after the switch, after the reinstall")
	c.Set(t1.Add(61 * time.Second))
	wantNoKey(t, r, 4, "61 s after the switch: the reinstall must not restart the overlap")
	wantKey(t, r, 5, testSecret(5), "61 s after the switch")

	var single Ring
	mustInstall(t, &single, testKey(9, 9), t0)
	mustInstall(t, &single, testKey(9, 9), t0)
	wantKey(t, &single, 9, testSecret(9), "single key installed twice")
}

// TestRingIgnoresNotAfter: NotAfter is the acting admin's rotation date, not
// a cut-off at members; a current key past it is still accepted, because an
// admin that is gone must not take the whole group off the air.
func TestRingIgnoresNotAfter(t *testing.T) {
	c := &fakeClock{now: t0}
	r := &Ring{Now: c.Now}
	k := Key{ID: 3, Secret: testSecret(3), NotAfter: t0.Add(-365 * 24 * time.Hour)}
	mustInstall(t, r, k, t0)
	c.Set(t0.Add(10 * 365 * 24 * time.Hour))
	wantKey(t, r, 3, k.Secret, "ten years after NotAfter")

	var zero Ring
	mustInstall(t, &zero, Key{ID: 1, Secret: testSecret(1)}, t0)
	wantKey(t, &zero, 1, testSecret(1), "key with a zero NotAfter")
}

// TestRingConcurrent: lookups running while keys are installed only ever see
// the right packet key for an epoch. Run with -race.
func TestRingConcurrent(t *testing.T) {
	const n = 200
	c := &fakeClock{now: t0}
	r := &Ring{Now: c.Now}
	want := make([][]byte, n+1)
	for id := range want {
		want[id] = mustPacketKey(t, testSecret(byte(id)))
	}
	mustInstall(t, r, testKey(0, 0), t0)

	done := make(chan struct{})
	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
				}
				for id := uint32(0); id <= n; id++ {
					if got, ok := r.Lookup(id); ok && !bytes.Equal(got, want[id]) {
						t.Errorf("concurrent Lookup(%d) returned another epoch's key", id)
						return
					}
				}
			}
		}()
	}
	for id := uint32(1); id <= n; id++ {
		if err := r.Install(testKey(id, byte(id)), t0); err != nil {
			t.Errorf("Install(%d) = %v", id, err)
		}
	}
	close(done)
	wg.Wait()
	wantKey(t, r, n, testSecret(n), "after the concurrent installs")
	wantKey(t, r, n-1, testSecret(n-1), "after the concurrent installs")
	wantNoKey(t, r, n-2, "after the concurrent installs")
}

func TestNew(t *testing.T) {
	before := time.Now()
	k, err := New(42)
	after := time.Now()
	if err != nil {
		t.Fatalf("New = %v", err)
	}
	if k.ID != 42 {
		t.Errorf("ID = %d, want 42", k.ID)
	}
	if len(k.Secret) != 32 || allZeroBytes(k.Secret) {
		t.Errorf("Secret is %d bytes, all zero %v; want 32 random bytes", len(k.Secret), allZeroBytes(k.Secret))
	}
	lo, hi := before.Add(RotationPeriod).Unix(), after.Add(RotationPeriod).Unix()
	if u := k.NotAfter.Unix(); u < lo || u > hi {
		t.Errorf("NotAfter = %v, want 30 days from now (Unix %d..%d)", k.NotAfter, lo, hi)
	}
	if !reflect.DeepEqual(k.NotAfter, time.Unix(k.NotAfter.Unix(), 0).UTC()) {
		t.Errorf("NotAfter %#v is not whole seconds in UTC without a monotonic reading", k.NotAfter)
	}
	for _, id := range []uint32{0, math.MaxUint32} {
		if k, err := New(id); err != nil || k.ID != id {
			t.Errorf("New(%d) = epoch %d, %v", id, k.ID, err)
		}
	}

	// 200 keys: all different, and every byte position takes many values
	// (a source that filled only part of the secret would fail here).
	const count = 200
	seen := map[string]bool{}
	var values [32]map[byte]bool
	for i := range values {
		values[i] = map[byte]bool{}
	}
	for i := 0; i < count; i++ {
		k, err := New(uint32(i))
		if err != nil {
			t.Fatalf("New = %v", err)
		}
		if seen[string(k.Secret)] {
			t.Fatal("New returned the same secret twice")
		}
		seen[string(k.Secret)] = true
		for j, b := range k.Secret {
			values[j][b] = true
		}
	}
	for j, v := range values {
		if len(v) < 80 {
			t.Errorf("secret byte %d took only %d distinct values in %d keys", j, len(v), count)
		}
	}
}

func allZeroBytes(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

// member returns a fresh identity.
func member(t testing.TB) *identity.Identity {
	t.Helper()
	m, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity.Generate: %v", err)
	}
	return m
}

func pubOf(m *identity.Identity) ed25519.PublicKey {
	return m.Sign.Public().(ed25519.PublicKey)
}

// seal seals k to m, signed by admin.
func seal(t testing.TB, k Key, m, admin *identity.Identity) []byte {
	t.Helper()
	blob, err := Seal(k, m.Recv.PublicKey(), m.ID, admin.ID, admin.Sign)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if len(blob) != fmtBlobSize {
		t.Fatalf("Seal returned %d bytes, want %d", len(blob), fmtBlobSize)
	}
	return blob
}

// handPlaintext builds the sealed plaintext from the documented layout.
func handPlaintext(id uint32, notAfter uint64, secret []byte) []byte {
	pt := binary.BigEndian.AppendUint32(nil, id)
	pt = binary.BigEndian.AppendUint64(pt, notAfter)
	return append(pt, secret...)
}

// handSeal builds a delivery blob from the documented layout, without the
// package: version | signer | hpke.Seal(info = label || recipient) |
// Ed25519 over "rollcall/v1/epoch\x00" || everything before the signature.
func handSeal(t testing.TB, version byte, pt []byte, to hpke.PublicKey, recipient, signer ids.MemberID, admin ed25519.PrivateKey) []byte {
	t.Helper()
	info := append([]byte(fmtInfoLabel), recipient[:]...)
	ct, err := hpke.Seal(to, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), info, pt)
	if err != nil {
		t.Fatalf("hpke.Seal: %v", err)
	}
	blob := append([]byte{version}, signer[:]...)
	blob = append(blob, ct...)
	return append(blob, ed25519.Sign(admin, append([]byte(fmtSigPrefix), blob...))...)
}

// keysEqual compares two keys field by field.
func keysEqual(a, b Key) bool {
	return a.ID == b.ID && bytes.Equal(a.Secret, b.Secret) && a.NotAfter.Equal(b.NotAfter)
}

func isZeroKey(k Key) bool {
	return k.ID == 0 && k.Secret == nil && k.NotAfter.IsZero()
}

// wantOpenErr asserts that Open fails with want and returns the zero Key.
func wantOpenErr(t *testing.T, blob []byte, self *identity.Identity, admins []ed25519.PublicKey, want error, what string) {
	t.Helper()
	k, err := Open(blob, self, admins)
	if !errors.Is(err, want) {
		t.Errorf("%s: Open = %v, want %v", what, err, want)
	}
	if !isZeroKey(k) {
		t.Errorf("%s: Open returned key %d with a %d-byte secret alongside the error", what, k.ID, len(k.Secret))
	}
}

func TestDeliverRoundTrip(t *testing.T) {
	admin, backup, m, other := member(t), member(t), member(t), member(t)
	k := testKey(9, 9)
	original := bytes.Clone(k.Secret)
	blob := seal(t, k, m, admin)
	if !bytes.Equal(k.Secret, original) {
		t.Error("Seal changed the key's secret")
	}
	if len(blob) != fmtBlobSize {
		t.Errorf("blob is %d bytes, want %d", len(blob), fmtBlobSize)
	}

	got, err := Open(blob, m, []ed25519.PublicKey{pubOf(admin)})
	if err != nil {
		t.Fatalf("Open = %v", err)
	}
	if !reflect.DeepEqual(got, k) {
		t.Errorf("Open = epoch %d, NotAfter %v; want epoch %d, NotAfter %v, same secret", got.ID, got.NotAfter, k.ID, k.NotAfter)
	}

	// The admin key may be anywhere in the list, after keys that are invalid
	// or belong to someone else.
	mixed := []ed25519.PublicKey{nil, pubOf(admin)[:31], mustHex(t, identityPoint), pubOf(other), pubOf(backup), pubOf(admin)}
	if got, err := Open(blob, m, mixed); err != nil || !keysEqual(got, k) {
		t.Errorf("Open with the admin key last in a mixed list = %v", err)
	}
	// A delivery signed by the backup admin opens against [primary, backup].
	byBackup := seal(t, k, m, backup)
	if got, err := Open(byBackup, m, []ed25519.PublicKey{pubOf(admin), pubOf(backup)}); err != nil || !keysEqual(got, k) {
		t.Errorf("Open of a delivery signed by the backup admin = %v", err)
	}

	// The returned secret does not share memory with the blob.
	for i := range blob {
		blob[i] = 0
	}
	if !bytes.Equal(got.Secret, original) {
		t.Error("clearing the blob changed the opened secret")
	}

	// Every Seal encapsulates afresh; both deliveries open.
	a, b := seal(t, k, m, admin), seal(t, k, m, admin)
	if bytes.Equal(a[fmtCTOff:fmtSigOff], b[fmtCTOff:fmtSigOff]) {
		t.Error("two Seals of the same key produced the same ciphertext")
	}

	// The opened key, installed, gives the admin's packet key.
	var r Ring
	if err := r.Install(got, time.Now()); err != nil {
		t.Fatalf("Install(opened key) = %v", err)
	}
	wantKey(t, &r, 9, original, "ring of the opened key")
}

func mustHex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex: %v", err)
	}
	return b
}

// probeSig is R || S with R the base point and S = 1. Under the identity
// point as public key, [S]B = R + [k]A holds for every message.
func probeSig() []byte {
	s := make([]byte, 64)
	s[0] = 0x58
	for i := 1; i < 32; i++ {
		s[i] = 0x66
	}
	s[32] = 1
	return s
}

func TestDeliverRejectsNonAdminSignature(t *testing.T) {
	admin, m, other := member(t), member(t), member(t)
	admins := []ed25519.PublicKey{pubOf(admin)}
	k := testKey(9, 9)

	// Sealed correctly, but signed by a member who is not an admin.
	byOther := seal(t, k, m, other)
	wantOpenErr(t, byOther, m, admins, ErrSignature, "signed by a non-admin member")

	good := seal(t, k, m, admin)
	wantOpenErr(t, good, m, nil, ErrSignature, "nil admin list")
	wantOpenErr(t, good, m, []ed25519.PublicKey{}, ErrSignature, "empty admin list")
	wantOpenErr(t, good, m, []ed25519.PublicKey{nil, pubOf(admin)[:31], append(bytes.Clone(pubOf(admin)), 0), pubOf(other)},
		ErrSignature, "admin list of wrong-length keys and another member")

	msg := good[:fmtSigOff]
	resign := func(s []byte) []byte { return append(bytes.Clone(msg), s...) }
	// The admin's signature, but for another kind, and without the domain.
	wantOpenErr(t, resign(sig.Sign(admin.Sign, "roster", msg)), m, admins, ErrSignature, "admin signature of kind roster")
	wantOpenErr(t, resign(ed25519.Sign(admin.Sign, msg)), m, admins, ErrSignature, "admin signature without the domain prefix")
	// The admin's signature over the ciphertext alone: the signer ID and
	// version must be covered too.
	wantOpenErr(t, resign(sig.Sign(admin.Sign, "epoch", msg[fmtCTOff:])), m, admins, ErrSignature, "admin signature over the ciphertext only")

	// A forgery under a small-order key: plain Ed25519 accepts it, Open must not.
	weak := mustHex(t, identityPoint)
	forged := resign(probeSig())
	if !ed25519.Verify(weak, append([]byte(fmtSigPrefix), msg...), probeSig()) {
		t.Fatal("oracle: the probe signature does not verify under the identity point")
	}
	wantOpenErr(t, forged, m, []ed25519.PublicKey{weak}, ErrSignature, "forgery under a small-order admin key")
}

func TestDeliverRejectsOtherRecipient(t *testing.T) {
	admin, a, b := member(t), member(t), member(t)
	admins := []ed25519.PublicKey{pubOf(admin)}
	blob := seal(t, testKey(9, 9), a, admin)
	wantOpenErr(t, blob, b, admins, ErrDecrypt, "delivery for a opened by b")
	if _, err := Open(blob, a, admins); err != nil {
		t.Errorf("the same delivery opened by a = %v", err)
	}
}

// TestDeliverBoundToRecipientID: the HPKE info names the recipient, so a
// delivery opens only for the member ID it was sealed for, even under the
// right receive key.
func TestDeliverBoundToRecipientID(t *testing.T) {
	admin, a, b := member(t), member(t), member(t)
	admins := []ed25519.PublicKey{pubOf(admin)}
	k := testKey(9, 9)

	// a's receive key, b's member ID.
	blob, err := Seal(k, a.Recv.PublicKey(), b.ID, admin.ID, admin.Sign)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	wantOpenErr(t, blob, a, admins, ErrDecrypt, "sealed to a's key for b's ID, opened by a")
	twin := &identity.Identity{ID: b.ID, Sign: a.Sign, Recv: a.Recv}
	if got, err := Open(blob, twin, admins); err != nil || !keysEqual(got, k) {
		t.Errorf("opened by a's receive key under b's ID = %v, want the key (the ID is the only difference)", err)
	}

	// A normal delivery to a does not open under a's receive key with b's ID.
	wantOpenErr(t, seal(t, k, a, admin), twin, admins, ErrDecrypt, "delivery for a opened under b's ID")
}

// TestDeliverWireFormat reads a sealed delivery by hand, with the format's
// values written out in this file.
func TestDeliverWireFormat(t *testing.T) {
	admin, m := member(t), member(t)
	k := Key{ID: 0x01020304, Secret: testSecret(9), NotAfter: time.Unix(0x0102030405, 0).UTC()}
	blob := seal(t, k, m, admin)

	if len(blob) != fmtBlobSize {
		t.Fatalf("blob is %d bytes, want %d", len(blob), fmtBlobSize)
	}
	if blob[0] != fmtVersion {
		t.Errorf("version byte = %d, want %d", blob[0], fmtVersion)
	}
	if !bytes.Equal(blob[fmtSignerOff:fmtCTOff], admin.ID[:]) {
		t.Errorf("signer field = %x, want the admin's member ID %x", blob[fmtSignerOff:fmtCTOff], admin.ID[:])
	}
	signed := append([]byte(fmtSigPrefix), blob[:fmtSigOff]...)
	if !ed25519.Verify(pubOf(admin), signed, blob[fmtSigOff:]) {
		t.Error("the signature is not the admin's Ed25519 signature over \"rollcall/v1/epoch\\x00\" || bytes 0..1196")
	}
	if !sig.Verify(pubOf(admin), "epoch", blob[:fmtSigOff], blob[fmtSigOff:]) {
		t.Error("sig.Verify(kind epoch) rejects the signature")
	}

	info := append([]byte(fmtInfoLabel), m.ID[:]...)
	pt, err := hpke.Open(m.Recv, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), info, blob[fmtCTOff:fmtSigOff])
	if err != nil {
		t.Fatalf("hpke.Open with info \"rollcall/v1 epoch\" || recipient ID: %v", err)
	}
	want := []byte{1, 2, 3, 4, 0, 0, 0, 1, 2, 3, 4, 5}
	want = append(want, k.Secret...)
	if !bytes.Equal(pt, want) {
		t.Errorf("plaintext = %x, want %x", pt, want)
	}
	if fmtSigOff-fmtCTOff != fmtEncSize+fmtPTSize+16 {
		t.Errorf("test constants disagree: ciphertext %d bytes", fmtSigOff-fmtCTOff)
	}
	if bytes.Contains(blob, k.Secret) || bytes.Contains(blob, k.Secret[:8]) {
		t.Error("the secret appears in the blob in the clear")
	}
}

// TestOpenHandBuiltBlob: Open reads a blob built from the documented layout
// without the package, including the edge values of NotAfter.
func TestOpenHandBuiltBlob(t *testing.T) {
	admin, m := member(t), member(t)
	admins := []ed25519.PublicKey{pubOf(admin)}
	for _, na := range []uint64{1, uint64(testNotAfter.Unix()), fmtMaxUnix} {
		pt := handPlaintext(77, na, testSecret(77))
		blob := handSeal(t, fmtVersion, pt, m.Recv.PublicKey(), m.ID, admin.ID, admin.Sign)
		got, err := Open(blob, m, admins)
		if err != nil {
			t.Errorf("NotAfter %d: Open = %v", na, err)
			continue
		}
		want := Key{ID: 77, Secret: testSecret(77), NotAfter: time.Unix(int64(na), 0).UTC()}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("NotAfter %d: Open = epoch %d, NotAfter %#v; want epoch 77, NotAfter %#v", na, got.ID, got.NotAfter, want.NotAfter)
		}
	}
}

func TestOpenRejectsMalformed(t *testing.T) {
	admin, m := member(t), member(t)
	admins := []ed25519.PublicKey{pubOf(admin)}
	good := seal(t, testKey(9, 9), m, admin)

	cases := map[string][]byte{
		"nil":                  nil,
		"empty":                {},
		"one byte":             {fmtVersion},
		"header only":          good[:fmtCTOff],
		"no signature":         good[:fmtSigOff],
		"one byte short":       good[:fmtBlobSize-1],
		"one trailing byte":    append(bytes.Clone(good), 0),
		"two blobs":            append(bytes.Clone(good), good...),
		"padded to 64 KiB":     append(bytes.Clone(good), make([]byte, 65536-fmtBlobSize)...),
		"one byte at the head": append([]byte{fmtVersion}, good...),
	}
	for name, blob := range cases {
		wantOpenErr(t, blob, m, admins, ErrFormat, name)
		wantOpenErr(t, blob, m, nil, ErrFormat, name+", no admins")
	}
	for _, v := range []byte{0, 2, 0xff} {
		b := bytes.Clone(good)
		b[0] = v
		wantOpenErr(t, b, m, admins, ErrFormat, fmt.Sprintf("version %d", v))
	}
	// A blob in another version, validly signed by the admin, is refused for its version.
	pt := handPlaintext(9, uint64(testNotAfter.Unix()), testSecret(9))
	v2 := handSeal(t, 2, pt, m.Recv.PublicKey(), m.ID, admin.ID, admin.Sign)
	wantOpenErr(t, v2, m, admins, ErrFormat, "version 2, signed by the admin")
}

// TestOpenSingleBitFlips: a single changed bit anywhere in a delivery is
// refused: in the version byte as a format error, anywhere else by the
// signature, before any decryption.
func TestOpenSingleBitFlips(t *testing.T) {
	admin, m := member(t), member(t)
	admins := []ed25519.PublicKey{pubOf(admin)}
	good := seal(t, testKey(9, 9), m, admin)
	for i := range good {
		b := bytes.Clone(good)
		b[i] ^= 1 << (i % 8)
		want := ErrSignature
		if i == 0 {
			want = ErrFormat
		}
		k, err := Open(b, m, admins)
		if err != want || !isZeroKey(k) {
			t.Errorf("bit %d of byte %d flipped: Open = %v, want %v", i%8, i, err, want)
		}
	}
}

// TestOpenCheckOrder: the arguments, then the length and version, then the
// signature, then decryption, then the plaintext's values.
func TestOpenCheckOrder(t *testing.T) {
	admin, a, b, other := member(t), member(t), member(t), member(t)
	admins := []ed25519.PublicKey{pubOf(admin)}
	k := testKey(9, 9)

	// Not decryptable by a, and not signed by an admin: the signature is
	// checked first.
	wantOpenErr(t, seal(t, k, b, other), a, admins, ErrSignature, "for b, signed by a non-admin, opened by a")
	// Signed by the admin, not decryptable by a.
	wantOpenErr(t, seal(t, k, b, admin), a, admins, ErrDecrypt, "for b, signed by the admin, opened by a")
	// An all-zero secret under a non-admin signature: the plaintext is not
	// looked at before the signature.
	zero := handSeal(t, fmtVersion, handPlaintext(9, uint64(testNotAfter.Unix()), make([]byte, 32)), a.Recv.PublicKey(), a.ID, other.ID, other.Sign)
	wantOpenErr(t, zero, a, admins, ErrSignature, "all-zero secret, signed by a non-admin")
	// Wrong length and a bad signature: the length comes first.
	wantOpenErr(t, seal(t, k, a, other)[:fmtBlobSize-1], a, admins, ErrFormat, "short and signed by a non-admin")
	// No usable self: refused before the blob is read.
	wantOpenErr(t, nil, nil, admins, ErrInvalid, "nil blob, nil self")
}

func TestOpenRejectsBadSelf(t *testing.T) {
	admin, m := member(t), member(t)
	admins := []ed25519.PublicKey{pubOf(admin)}
	blob := seal(t, testKey(9, 9), m, admin)
	dh, err := hpke.DHKEM(ecdh.X25519()).GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	for name, self := range map[string]*identity.Identity{
		"nil self":           nil,
		"no receive key":     {ID: m.ID, Sign: m.Sign},
		"zero member ID":     {Sign: m.Sign, Recv: m.Recv},
		"X25519 receive key": {ID: m.ID, Sign: m.Sign, Recv: dh},
	} {
		wantOpenErr(t, blob, self, admins, ErrInvalid, name)
	}
}

// TestOpenRejectsBadPlaintext: correctly sealed and signed by the admin, but
// carrying values a key may not have.
func TestOpenRejectsBadPlaintext(t *testing.T) {
	admin, m := member(t), member(t)
	admins := []ed25519.PublicKey{pubOf(admin)}
	open := func(na uint64, secret []byte) (Key, error) {
		blob := handSeal(t, fmtVersion, handPlaintext(9, na, secret), m.Recv.PublicKey(), m.ID, admin.ID, admin.Sign)
		return Open(blob, m, admins)
	}
	ok := uint64(testNotAfter.Unix())
	for name, c := range map[string]struct {
		na     uint64
		secret []byte
	}{
		"all-zero secret":         {ok, make([]byte, 32)},
		"NotAfter 0":              {0, testSecret(9)},
		"NotAfter after 9999":     {fmtMaxUnix + 1, testSecret(9)},
		"NotAfter 2^62":           {1 << 62, testSecret(9)},
		"NotAfter 2^63":           {1 << 63, testSecret(9)},
		"NotAfter max uint64":     {math.MaxUint64, testSecret(9)},
		"zero secret, NotAfter 0": {0, make([]byte, 32)},
	} {
		k, err := open(c.na, c.secret)
		if err != ErrInvalidKey || !isZeroKey(k) {
			t.Errorf("%s: Open = %v, want ErrInvalidKey and no key", name, err)
		}
	}
	// Only the all-zero secret is refused: one non-zero byte anywhere is a key.
	for i := 0; i < 32; i++ {
		s := make([]byte, 32)
		s[i] = 1
		if k, err := open(ok, s); err != nil || !bytes.Equal(k.Secret, s) {
			t.Errorf("secret with only byte %d set: Open = %v", i, err)
		}
	}
}

// TestDecodePlaintextLength: a plaintext that is not exactly 44 bytes is a
// format error, never a panic or a key. A BlobSize blob cannot produce one,
// so the decoder is called directly.
func TestDecodePlaintextLength(t *testing.T) {
	good := handPlaintext(9, uint64(testNotAfter.Unix()), testSecret(9))
	for _, n := range []int{0, 1, 4, 12, 43, 45, 88} {
		pt := make([]byte, n)
		copy(pt, good)
		if n > len(good) {
			copy(pt[len(good):], good)
		}
		k, err := decodePlaintext(pt)
		if err != ErrFormat || !isZeroKey(k) {
			t.Errorf("%d-byte plaintext: decodePlaintext = %v, want ErrFormat and no key", n, err)
		}
	}
	k, err := decodePlaintext(good)
	if err != nil || !keysEqual(k, testKey(9, 9)) {
		t.Errorf("44-byte plaintext: decodePlaintext = %v, want the key", err)
	}
	clear(good)
	if !bytes.Equal(k.Secret, testSecret(9)) {
		t.Error("the decoded secret shares memory with the plaintext")
	}
}

// TestOpenPlaintextSweep: 300 seeded plaintexts, biased to the edges, each
// sealed and signed correctly; Open must accept exactly the valid ones and
// return their fields unchanged.
func TestOpenPlaintextSweep(t *testing.T) {
	admin, m := member(t), member(t)
	admins := []ed25519.PublicKey{pubOf(admin)}
	rng := rand.New(rand.NewPCG(6, 2026))
	edgeIDs := []uint32{0, 1, math.MaxUint32 - 1, math.MaxUint32}
	edgeNA := []uint64{0, 1, 2, 1 << 31, 1 << 32, fmtMaxUnix - 1, fmtMaxUnix, fmtMaxUnix + 1, 1<<63 - 1, 1 << 63, math.MaxUint64}
	accepted, refused := 0, 0
	for i := 0; i < 300; i++ {
		id := rng.Uint32()
		if rng.IntN(3) == 0 {
			id = edgeIDs[rng.IntN(len(edgeIDs))]
		}
		na := rng.Uint64N(fmtMaxUnix + 1000)
		if rng.IntN(2) == 0 {
			na = edgeNA[rng.IntN(len(edgeNA))]
		}
		secret := make([]byte, 32)
		switch rng.IntN(4) {
		case 0: // all zero
		case 1:
			secret[rng.IntN(32)] = byte(1 + rng.IntN(255))
		default:
			for j := range secret {
				secret[j] = byte(rng.Uint32())
			}
		}
		blob := handSeal(t, fmtVersion, handPlaintext(id, na, secret), m.Recv.PublicKey(), m.ID, admin.ID, admin.Sign)
		got, err := Open(blob, m, admins)
		valid := !allZeroBytes(secret) && na >= 1 && na <= fmtMaxUnix
		switch {
		case valid && err != nil:
			t.Errorf("case %d (epoch %d, NotAfter %d): Open = %v, want the key", i, id, na, err)
		case valid:
			accepted++
			want := Key{ID: id, Secret: secret, NotAfter: time.Unix(int64(na), 0).UTC()}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("case %d: Open = epoch %d NotAfter %v, want epoch %d NotAfter %v", i, got.ID, got.NotAfter, id, want.NotAfter)
			}
		case err != ErrInvalidKey || !isZeroKey(got):
			t.Errorf("case %d (NotAfter %d, zero secret %v): Open = %v, want ErrInvalidKey", i, na, allZeroBytes(secret), err)
		default:
			refused++
		}
	}
	if accepted < 50 || refused < 50 {
		t.Errorf("sweep did not reach both outcomes enough: %d accepted, %d refused", accepted, refused)
	}
}

// TestNotAfterRoundTrip: NotAfter travels in whole Unix seconds and comes
// back in UTC; Seal refuses values the format cannot carry.
func TestNotAfterRoundTrip(t *testing.T) {
	admin, m := member(t), member(t)
	admins := []ed25519.PublicKey{pubOf(admin)}
	kyiv := time.FixedZone("UTC+3", 3*3600)
	for _, c := range []struct{ in, want time.Time }{
		{testNotAfter.Add(999 * time.Millisecond), testNotAfter},
		{testNotAfter.In(kyiv), testNotAfter},
		{time.Unix(1, 0), time.Unix(1, 0).UTC()},
		{time.Unix(fmtMaxUnix, 0), time.Unix(fmtMaxUnix, 0).UTC()},
	} {
		k := Key{ID: 1, Secret: testSecret(1), NotAfter: c.in}
		got, err := Open(seal(t, k, m, admin), m, admins)
		if err != nil || !reflect.DeepEqual(got.NotAfter, c.want) {
			t.Errorf("NotAfter %v: opened as %#v (%v), want %#v", c.in, got.NotAfter, err, c.want)
		}
	}
	for _, na := range []time.Time{{}, time.Unix(0, 0), time.Unix(-1, 0), time.Unix(fmtMaxUnix+1, 0), time.Unix(0, 999999999)} {
		k := Key{ID: 1, Secret: testSecret(1), NotAfter: na}
		if blob, err := Seal(k, m.Recv.PublicKey(), m.ID, admin.ID, admin.Sign); err != ErrInvalidKey || blob != nil {
			t.Errorf("Seal with NotAfter %v = (%d bytes, %v), want ErrInvalidKey", na, len(blob), err)
		}
	}
}

func TestSealRejectsBadInput(t *testing.T) {
	admin, m := member(t), member(t)
	to := m.Recv.PublicKey()
	good := testKey(9, 9)

	dh, err := hpke.DHKEM(ecdh.X25519()).GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pq, err := hpke.MLKEM768().GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	// An X-Wing key whose X25519 half is the zero point: the KEM is right,
	// the encapsulation fails.
	lowRaw := to.Bytes()
	clear(lowRaw[len(lowRaw)-32:])
	lowOrder, err := hpke.MLKEM768X25519().NewPublicKey(lowRaw)
	if err != nil {
		t.Fatalf("NewPublicKey with a zero X25519 half: %v", err)
	}
	weakAdmin := append(bytes.Clone(admin.Sign[:32]), mustHex(t, identityPoint)...)

	type args struct {
		k         Key
		to        hpke.PublicKey
		recipient ids.MemberID
		signer    ids.MemberID
		admin     ed25519.PrivateKey
	}
	ok := args{good, to, m.ID, admin.ID, admin.Sign}
	with := func(f func(*args)) args { a := ok; f(&a); return a }
	for name, c := range map[string]struct {
		a    args
		want error
	}{
		"nil secret":             {with(func(a *args) { a.k.Secret = nil }), ErrInvalidKey},
		"31-byte secret":         {with(func(a *args) { a.k.Secret = testSecret(9)[:31] }), ErrInvalidKey},
		"33-byte secret":         {with(func(a *args) { a.k.Secret = append(testSecret(9), 1) }), ErrInvalidKey},
		"all-zero secret":        {with(func(a *args) { a.k.Secret = make([]byte, 32) }), ErrInvalidKey},
		"zero NotAfter":          {with(func(a *args) { a.k.NotAfter = time.Time{} }), ErrInvalidKey},
		"nil recipient key":      {with(func(a *args) { a.to = nil }), ErrRecipientKey},
		"X25519 recipient key":   {with(func(a *args) { a.to = dh.PublicKey() }), ErrRecipientKey},
		"ML-KEM-768 only":        {with(func(a *args) { a.to = pq.PublicKey() }), ErrRecipientKey},
		"zero X25519 half":       {with(func(a *args) { a.to = lowOrder }), ErrRecipientKey},
		"zero recipient ID":      {with(func(a *args) { a.recipient = ids.MemberID{} }), ErrInvalid},
		"zero signer ID":         {with(func(a *args) { a.signer = ids.MemberID{} }), ErrInvalid},
		"nil admin key":          {with(func(a *args) { a.admin = nil }), ErrInvalid},
		"admin seed only":        {with(func(a *args) { a.admin = admin.Sign[:32] }), ErrInvalid},
		"63-byte admin key":      {with(func(a *args) { a.admin = admin.Sign[:63] }), ErrInvalid},
		"small-order admin half": {with(func(a *args) { a.admin = weakAdmin }), ErrInvalid},
	} {
		blob, err := Seal(c.a.k, c.a.to, c.a.recipient, c.a.signer, c.a.admin)
		if !errors.Is(err, c.want) || blob != nil {
			t.Errorf("%s: Seal = (%d bytes, %v), want %v", name, len(blob), err, c.want)
		}
	}
	if _, err := Seal(ok.k, ok.to, ok.recipient, ok.signer, ok.admin); err != nil {
		t.Errorf("Seal with good arguments = %v", err)
	}
}

// secretForms returns ways a formatter could print b, each from its first
// 8 bytes: hex either case, base64, decimal as fmt prints []byte, Go syntax,
// and the raw bytes.
func secretForms(b []byte) []string {
	p := b[:8]
	dec := strings.Trim(fmt.Sprint(p), "[]")
	gosyn := strings.TrimSuffix(strings.TrimPrefix(fmt.Sprintf("%#v", p), "[]byte{"), "}")
	return []string{
		hex.EncodeToString(p), strings.ToUpper(hex.EncodeToString(p)),
		base64.StdEncoding.EncodeToString(p)[:8], dec, gosyn, string(p),
	}
}

func leaks(out string, secrets ...[]byte) string {
	for _, s := range secrets {
		for _, f := range secretForms(s) {
			if strings.Contains(out, f) {
				return f
			}
		}
	}
	return ""
}

// TestKeyRedacted: no fmt verb prints a Key's secret.
func TestKeyRedacted(t *testing.T) {
	k := testKey(9, 9)
	if got, want := fmt.Sprint(k), "epoch 9 not after 2026-11-21T12:00:00Z"; got != want {
		t.Errorf("fmt.Sprint(key) = %q, want %q", got, want)
	}
	values := map[string]any{"value": k, "pointer": &k, "slice": []Key{k}, "struct": struct{ K Key }{k}, "map": map[int]Key{1: k}}
	for name, v := range values {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%d", "%x", "%X", "%q", "%o", "%b"} {
			out := fmt.Sprintf(verb, v)
			if f := leaks(out, k.Secret); f != "" {
				t.Errorf("%s with %s prints the secret (%q): %s", name, verb, f, out)
			}
		}
	}
	var nilKey *Key
	if got := fmt.Sprint(nilKey); got != "<nil>" {
		t.Errorf("fmt.Sprint(nil *Key) = %q, want <nil>", got)
	}
}

// TestRingRedacted: no fmt verb prints a Ring's packet keys.
func TestRingRedacted(t *testing.T) {
	c := &fakeClock{now: t0}
	r := &Ring{Now: c.Now}
	if got, want := fmt.Sprint(r), "epoch ring, empty"; got != want {
		t.Errorf("fmt.Sprint(empty ring) = %q, want %q", got, want)
	}
	mustInstall(t, r, testKey(6, 6), t0)
	if got, want := fmt.Sprint(r), "epoch ring, current 6"; got != want {
		t.Errorf("fmt.Sprint(ring) = %q, want %q", got, want)
	}
	mustInstall(t, r, testKey(7, 7), t0)
	if got, want := fmt.Sprint(r), "epoch ring, current 7, previous 6 until 2026-10-22T12:01:00Z"; got != want {
		t.Errorf("fmt.Sprint(ring) = %q, want %q", got, want)
	}
	pk6, pk7 := mustPacketKey(t, testSecret(6)), mustPacketKey(t, testSecret(7))
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%d", "%x", "%X", "%q"} {
		out := fmt.Sprintf(verb, r)
		if f := leaks(out, pk6, pk7, testSecret(6), testSecret(7)); f != "" {
			t.Errorf("ring with %s prints a key (%q): %s", verb, f, out)
		}
	}
	if got := fmt.Sprint(r); !strings.Contains(got, "7") {
		t.Errorf("fmt.Sprint(ring) = %q, want it to name the current epoch 7", got)
	}
}

// TestErrorsCarryNoKeyBytes: no error from Install, Seal or Open contains
// the secret, the admin's private key or the member's receive key.
func TestErrorsCarryNoKeyBytes(t *testing.T) {
	admin, m, other := member(t), member(t), member(t)
	canary := testSecret(0xc4)
	recvSeed, err := m.Recv.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	secrets := [][]byte{canary, admin.Sign.Seed(), recvSeed}

	var errs []error
	note := func(err error) {
		if err == nil {
			t.Error("expected an error, got nil")
			return
		}
		errs = append(errs, err)
	}
	var r Ring
	note(r.Install(Key{ID: 1, Secret: append(bytes.Clone(canary), 1)}, t0))
	mustInstall(t, &r, Key{ID: 5, Secret: canary}, t0)
	note(r.Install(Key{ID: 4, Secret: canary}, t0))

	k := Key{ID: 1, Secret: canary, NotAfter: testNotAfter}
	lowRaw := m.Recv.PublicKey().Bytes()
	clear(lowRaw[len(lowRaw)-32:])
	lowOrder, err := hpke.MLKEM768X25519().NewPublicKey(lowRaw)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Seal(k, lowOrder, m.ID, admin.ID, admin.Sign)
	note(err)
	_, err = Seal(Key{ID: 1, Secret: canary[:31], NotAfter: testNotAfter}, m.Recv.PublicKey(), m.ID, admin.ID, admin.Sign)
	note(err)
	_, err = Seal(k, m.Recv.PublicKey(), m.ID, admin.ID, admin.Sign[:63])
	note(err)

	admins := []ed25519.PublicKey{pubOf(admin)}
	blob := seal(t, k, m, admin)
	_, err = Open(blob[:100], m, admins)
	note(err)
	_, err = Open(blob, m, []ed25519.PublicKey{pubOf(other)})
	note(err)
	_, err = Open(blob, other, admins)
	note(err)
	zero := handSeal(t, fmtVersion, handPlaintext(1, 0, canary), m.Recv.PublicKey(), m.ID, admin.ID, admin.Sign)
	_, err = Open(zero, m, admins)
	note(err)

	for _, err := range errs {
		if f := leaks(err.Error(), secrets...); f != "" {
			t.Errorf("error %q contains key bytes (%q)", err, f)
		}
		if f := leaks(fmt.Sprintf("%#v", err), secrets...); f != "" {
			t.Errorf("error %#v contains key bytes (%q)", err, f)
		}
	}
}

// fixedIdentity is a deterministic identity, the same in every fuzz worker.
func fixedIdentity(t testing.TB, n byte) *identity.Identity {
	t.Helper()
	var id ids.MemberID
	for i := range id {
		id[i] = n
	}
	recv, err := hpke.MLKEM768X25519().NewPrivateKey(bytes.Repeat([]byte{n ^ 0x5a}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return &identity.Identity{ID: id, Sign: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{n}, 32)), Recv: recv}
}

// FuzzOpen: hostile bytes never panic Open, never yield a key other than the
// one the admin sealed, and always fail with one of the package's errors.
func FuzzOpen(f *testing.F) {
	admin, m := fixedIdentity(f, 0x11), fixedIdentity(f, 0x22)
	admins := []ed25519.PublicKey{pubOf(admin)}
	want := testKey(9, 9)
	good := seal(f, want, m, admin)
	f.Add(good)
	f.Add(good[:fmtSigOff])
	f.Add(append(bytes.Clone(good), 0))
	f.Add([]byte{})
	f.Add([]byte{fmtVersion})
	for _, i := range []int{0, 1, fmtCTOff, fmtCTOff + fmtEncSize, fmtSigOff, fmtBlobSize - 1} {
		b := bytes.Clone(good)
		b[i] ^= 0x80
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		k, err := Open(data, m, admins)
		if err == nil {
			if !keysEqual(k, want) {
				t.Fatalf("Open accepted %d bytes as epoch %d, which the admin never sealed", len(data), k.ID)
			}
			return
		}
		if !isZeroKey(k) {
			t.Fatalf("Open returned a key alongside %v", err)
		}
		switch err {
		case ErrFormat, ErrSignature, ErrDecrypt, ErrInvalidKey:
		default:
			t.Fatalf("Open = %v, not one of the package's errors", err)
		}
	})
}
