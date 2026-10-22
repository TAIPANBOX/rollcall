package member

import (
	"bytes"
	"encoding/binary"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/ids"
)

// fuzzSeeds adds valid bodies and near misses to f.
func fuzzSeeds(f *testing.F) {
	m := members(2)[1]
	full := handBody(fullBeat(m))
	sparse := handBody(Heartbeat{Epoch: 1, From: m.id.ID, BootSeq: 1, Boot: bootID(1), Name: "a", Wall: time.Unix(0, 0).UTC()})
	long := fullBeat(m)
	long.Name = strings.Repeat("z", 32)
	long.Versions = [2]string{strings.Repeat("9", MaxVersionLen), strings.Repeat("v", MaxVersionLen)}
	for _, b := range [][]byte{full, sparse, handBody(long)} {
		f.Add(b)
		f.Add(b[:len(b)-1])
		f.Add(append(bytes.Clone(b), 0))
		f.Add(append(bytes.Clone(b), make([]byte, 64)...))
	}
	flags := bytes.Clone(full)
	flags[53] = 0xff
	f.Add(flags)
	neg := bytes.Clone(full)
	binary.BigEndian.PutUint64(neg[62:], 1<<63)
	f.Add(neg)
	f.Add([]byte{})
	f.Add(make([]byte, MaxEncodedLen))
}

// FuzzDecodeHeartbeat feeds the heartbeat decoder arbitrary bytes, as a
// compromised member could sign them. decodeBody must never panic, must
// refuse with ErrMalformed and the zero Heartbeat, or accept only a
// heartbeat that passes check and encodes back to exactly the same bytes:
// one heartbeat has one encoding. split, which runs on bytes nobody has
// verified yet, must never panic and must read exactly the fixed offsets.
func FuzzDecodeHeartbeat(f *testing.F) {
	fuzzSeeds(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		orig := bytes.Clone(data)
		h, err := decodeBody(data)
		if !bytes.Equal(data, orig) {
			t.Fatal("decodeBody modified its input")
		}
		if err != nil {
			if !errors.Is(err, ErrMalformed) || !reflect.DeepEqual(h, Heartbeat{}) {
				t.Fatalf("decodeBody = %+v, %v", h, err)
			}
		} else {
			if cerr := h.check(); cerr != nil {
				t.Fatalf("decoded a heartbeat that check refuses: %v", cerr)
			}
			again, aerr := appendBody(nil, h)
			if aerr != nil || !bytes.Equal(again, data) {
				t.Fatalf("not canonical: %x\nre-encodes to %x, %v", data, again, aerr)
			}
		}

		p, err := split(data)
		if !bytes.Equal(data, orig) {
			t.Fatal("split modified its input")
		}
		if err != nil {
			if !errors.Is(err, ErrMalformed) || !reflect.DeepEqual(p, packet{}) {
				t.Fatalf("split = %+v, %v", p, err)
			}
			return
		}
		if len(data) < minEncodedLen || len(data) > MaxEncodedLen || data[0] != FormatVersion {
			t.Fatalf("split accepted %d bytes starting %x", len(data), data[:1])
		}
		var from ids.MemberID
		var boot ids.BootID
		copy(from[:], data[5:21])
		copy(boot[:], data[29:45])
		want := packet{
			epoch: binary.BigEndian.Uint32(data[1:5]), from: from,
			bootSeq: binary.BigEndian.Uint64(data[21:29]), boot: boot,
			counter: binary.BigEndian.Uint64(data[45:53]),
			body:    data[:len(data)-64], sig: data[len(data)-64:],
		}
		if !reflect.DeepEqual(p, want) {
			t.Fatalf("split = %+v, want %+v", p, want)
		}
	})
}

// FuzzObserveSigned signs arbitrary bytes with a member's key and hands them
// to a table: the whole path after the signature, with hostile but signed
// content. Observe must never panic, must return only its sentinels, and
// must accept only what decodeBody accepts, returning exactly that.
func FuzzObserveSigned(f *testing.F) {
	fuzzSeeds(f)
	ms := members(3)
	fx := newFixtureOf(f, ms, start)
	r02 := ms[1]
	sentinels := []error{ErrMalformed, ErrEpoch, ErrUnknownMember, ErrReplay, ErrSignature, ErrSelf, ErrDuplicateIdentity}
	now := start
	f.Fuzz(func(t *testing.T, data []byte) {
		now += 100 * time.Millisecond
		obs, err := fx.tab.Observe(testEpoch, handSign(data, r02.id.Sign), at(now))
		if err != nil {
			known := false
			for _, s := range sentinels {
				known = known || errors.Is(err, s)
			}
			if !known {
				t.Fatalf("Observe returned %v", err)
			}
			if !errors.Is(err, ErrDuplicateIdentity) && !reflect.DeepEqual(obs, Observed{}) {
				t.Fatalf("Observe returned %+v with %v", obs, err)
			}
			return
		}
		h, derr := decodeBody(data)
		if derr != nil {
			t.Fatalf("Observe accepted what decodeBody refuses: %v", derr)
		}
		if !reflect.DeepEqual(obs.Heartbeat, h) {
			t.Fatalf("Observed.Heartbeat %+v, want %+v", obs.Heartbeat, h)
		}
		if h.From != r02.id.ID {
			t.Fatalf("accepted a heartbeat from %x signed by r02", h.From)
		}
		fx.tab.Tick(at(now))
	})
}
