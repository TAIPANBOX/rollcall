package wire

import (
	"bytes"
	"testing"
)

// FuzzOpen feeds Open arbitrary bytes, as an outsider on the LAN can. Open
// must never panic, never modify its input, ask the lookup at most once and
// only after the length and version passed, and return a plaintext only for
// a packet that x/crypto confirms is authentic under the right key. Under a
// key nobody sealed with, or a lookup that says the epoch is unknown, nothing
// ever opens.
func FuzzOpen(f *testing.F) {
	key, other, nobody := testKey(1), testKey(2), testKey(3)
	const epoch = 0x01020304

	valid := handSeal(f, key, 1, 0, epoch, testNonce(1), canary(40))
	full := handSeal(f, key, 1, 0, epoch, testNonce(2), canary(maxPlaintext))
	f.Add(valid)
	for _, n := range []int{0, 1, 2, 5, 6, 29, 30, 31, 45, 46, len(valid) - 1} {
		f.Add(bytes.Clone(valid[:n]))
	}
	f.Add(append(bytes.Clone(valid), 0))
	f.Add(full)
	f.Add(append(bytes.Clone(full), 0))
	f.Add(make([]byte, 4096))
	f.Add(handSeal(f, key, 1, 0, epoch, testNonce(3), nil))
	f.Add(handSeal(f, key, 2, 0, epoch, testNonce(4), canary(40)))
	f.Add(handSeal(f, key, 1, 1, epoch, testNonce(5), canary(40)))
	f.Add(handSeal(f, key, 1, 0, epoch+1, testNonce(6), canary(40)))
	f.Add(handSeal(f, other, 1, 0, epoch, testNonce(7), canary(40)))

	sentinels := []error{ErrTooLarge, ErrShort, ErrVersion, ErrEpoch, ErrAuth}

	f.Fuzz(func(t *testing.T, data []byte) {
		orig := bytes.Clone(data)
		var asked int
		right := func(e uint32) ([]byte, bool) {
			asked++
			if e == epoch {
				return key, true
			}
			return nil, false
		}

		e, p, err := Open(right, data)
		if !bytes.Equal(data, orig) {
			t.Fatal("Open modified its input")
		}
		if asked > 1 {
			t.Fatalf("lookup asked %d times", asked)
		}
		if err != nil {
			if p != nil || e != 0 {
				t.Fatalf("Open returned (%d, %d bytes) with %v", e, len(p), err)
			}
			known := false
			for _, s := range sentinels {
				known = known || err == s
			}
			if !known {
				t.Fatalf("Open returned an error that is not a bare sentinel: %v", err)
			}
			early := err == ErrTooLarge || err == ErrShort || (err == ErrVersion && data[0] != 1)
			if early && asked != 0 {
				t.Fatalf("lookup asked before %v was decided", err)
			}
		} else {
			if len(data) > 1200 || data[0] != 1 || data[1] != 0 || e != epoch || p == nil {
				t.Fatalf("Open accepted a packet outside v1: %d bytes, version %d, flags %d, epoch %#x",
					len(data), data[0], data[1], e)
			}
			oracle, oerr := handOpen(t, key, data)
			if oerr != nil || !bytes.Equal(oracle, p) {
				t.Fatalf("Open returned a plaintext that x/crypto does not confirm: %v", oerr)
			}
		}

		never := map[string]KeyLookup{
			"a key nobody sealed": func(uint32) ([]byte, bool) { return nobody, true },
			"not found, with key": func(uint32) ([]byte, bool) { return key, false },
		}
		for name, lk := range never {
			if e, p, err := Open(lk, data); err == nil || p != nil || e != 0 {
				t.Fatalf("lookup %q: Open = (%d, %d bytes, %v), want an error and nothing else", name, e, len(p), err)
			}
		}
	})
}
