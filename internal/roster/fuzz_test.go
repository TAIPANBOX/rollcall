package roster

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/TAIPANBOX/rollcall/internal/ids"
)

// FuzzVerify feeds arbitrary bytes to Verify twice: as a genesis roster with
// an arbitrary signature, where the body is decoded before the signature is
// checked, and as the body of version 2 signed by the real primary of
// version 1, so that decoding, the canonical check, Check and the chain
// rules all see hostile input. Nothing may panic, an error always comes with
// a zero roster and a sentinel of the package, and a success must be a
// roster that the rules allow.
func FuzzVerify(f *testing.F) {
	ps := testParties()
	r1 := base(3)
	s1, err := SignRoster(r1, ps[0].ID, ps[0].Sign, false)
	if err != nil {
		f.Fatal(err)
	}
	r2 := next(r1, s1)
	r2.Members[2].Roles = nil
	s2, err := SignRoster(r2, ps[0].ID, ps[0].Sign, false)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(s2.Body, s2.Sig, byte(0))
	f.Add(s1.Body, s1.Sig, byte(2)) // a valid genesis by the primary
	f.Add(s1.Body, s1.Sig, byte(1))
	f.Add([]byte(`{}`), []byte{}, byte(3))
	f.Add([]byte(`null`), make([]byte, 64), byte(2))
	f.Add([]byte(`{"version":2,"members":[{"roles":["x"]}]}`), make([]byte, 64), byte(2))

	f.Fuzz(func(t *testing.T, body, rawSig []byte, flags byte) {
		s := Signed{Body: body, Sig: rawSig, Recovery: flags&1 != 0}
		if flags&2 != 0 {
			s.SignerID = ps[0].ID
		}
		got, err := s.Verify(nil)
		fuzzResult(t, got, err)
		if err == nil {
			if got.Version != 1 || got.Prev != (ids.Hash{}) || got.Check() != nil {
				t.Fatalf("genesis accepted with version %d, prev %v, Check %v", got.Version, got.Prev, got.Check())
			}
			if enc, _ := json.Marshal(got); !bytes.Equal(enc, body) {
				t.Fatal("genesis accepted for a body that is not its canonical encoding")
			}
		}

		s = handSign(ps[0].Sign, ps[0].ID, false, body)
		got, err = s.Verify(&s1)
		fuzzResult(t, got, err)
		if err == nil {
			if got.Version != 2 || got.Prev != s1.Hash() || got.Check() != nil || !bytes.Equal(got.RecoveryPub, r1.RecoveryPub) {
				t.Fatalf("version 2 accepted with version %d, prev %v, Check %v", got.Version, got.Prev, got.Check())
			}
			if enc, _ := json.Marshal(got); !bytes.Equal(enc, body) {
				t.Fatal("version 2 accepted for a body that is not its canonical encoding")
			}
		}
	})
}

// fuzzResult fails unless an error comes with a zero roster and is one of
// the package's sentinels.
func fuzzResult(t *testing.T, got Roster, err error) {
	t.Helper()
	if err == nil {
		return
	}
	if !reflect.DeepEqual(got, Roster{}) {
		t.Fatalf("error %v came with a roster", err)
	}
	for _, e := range allErrors {
		if errors.Is(err, e) {
			return
		}
	}
	t.Fatalf("error %v is not a sentinel of the package", err)
}
