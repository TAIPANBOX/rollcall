package member

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hpke"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/clock"
	"github.com/TAIPANBOX/rollcall/internal/history"
	"github.com/TAIPANBOX/rollcall/internal/identity"
	"github.com/TAIPANBOX/rollcall/internal/ids"
	"github.com/TAIPANBOX/rollcall/internal/roster"
	"github.com/TAIPANBOX/rollcall/internal/wire"
)

// t0 is the local wall clock at local monotonic 0 in every fixture.
var t0 = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)

// testEpoch is the epoch every fixture heartbeat is signed for.
const testEpoch uint32 = 0x0105

// localBoot is the boot ID of the local member in every fixture.
var localBoot = ids.BootID{0xb0, 0x07, 15: 0x01}

// testRosterHash is the hash every fixture heartbeat announces.
var testRosterHash = ids.Hash{0x52, 0x05, 31: 0x01}

// tm is one test router with deterministic keys.
type tm struct {
	id   *identity.Identity // Sign and ID only; Recv is not needed here
	pub  ed25519.PublicKey
	recv []byte // MLKEM768-X25519 public key, for the roster
	name string
}

var (
	testMembersOnce sync.Once
	testMembersAll  []tm
	recoveryKey     = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0xee}, ed25519.SeedSize))
	strangerKey     = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0xdd}, ed25519.SeedSize))
)

// members returns the first n of 40 test routers; router i has ID byte 0 =
// i+1 and name "r<i+1>", so routers sort by index.
func members(n int) []tm {
	testMembersOnce.Do(func() {
		kem := hpke.MLKEM768X25519()
		for i := 0; i < 40; i++ {
			var id ids.MemberID
			id[0], id[15] = byte(i+1), 0x5a
			seed := bytes.Repeat([]byte{byte(i + 1)}, ed25519.SeedSize)
			key := ed25519.NewKeyFromSeed(seed)
			recv, err := kem.DeriveKeyPair(append([]byte("recv"), seed...))
			if err != nil {
				panic(err)
			}
			testMembersAll = append(testMembersAll, tm{
				id:   &identity.Identity{ID: id, Sign: key},
				pub:  key.Public().(ed25519.PublicKey),
				recv: recv.PublicKey().Bytes(),
				name: fmt.Sprintf("r%02d", i+1),
			})
		}
	})
	return testMembersAll[:n]
}

// stranger returns a router that is in no fixture roster.
func stranger() tm { return members(40)[39] }

// testRoster returns a valid roster of ms with ms[0] as the primary.
func testRoster(ms []tm) roster.Roster {
	r := roster.Roster{Version: 1, Site: "home", RecoveryPub: recoveryKey.Public().(ed25519.PublicKey)}
	for i, m := range ms {
		e := roster.Member{ID: m.id.ID, Name: m.name, SignPub: bytes.Clone(m.pub), RecvPub: bytes.Clone(m.recv)}
		if i == 0 {
			e.Roles = []roster.Role{roster.RolePrimary}
		}
		r.Members = append(r.Members, e)
	}
	r.Admins = []ids.MemberID{ms[0].id.ID}
	return r
}

// bootID returns the test boot ID number n.
func bootID(n byte) ids.BootID { return ids.BootID{n, 15: 0xbb} }

// at is the local moment mono after the local boot, on a trusted clock.
func at(mono time.Duration) clock.Stamp {
	return clock.Stamp{Wall: t0.Add(mono), Mono: mono, Trusted: true, Boot: localBoot}
}

// untrustedAt is the local moment mono after the local boot, on an
// untrusted wall clock that started at 1970 at boot.
func untrustedAt(mono time.Duration) clock.Stamp {
	return clock.Stamp{Wall: time.Unix(0, 0).UTC().Add(mono), Mono: mono, Boot: localBoot}
}

// fullBeat returns a heartbeat from m with every field set to a value that
// differs from its zero value and from its neighbours.
func fullBeat(m tm) Heartbeat {
	return Heartbeat{
		Epoch:        testEpoch,
		From:         m.id.ID,
		BootSeq:      0x0102030405060708,
		Boot:         bootID(0x42),
		Counter:      0x1112131415161718,
		Name:         m.name,
		Uptime:       90*time.Minute + 7*time.Nanosecond,
		Versions:     [2]string{"24.10.4", "1.0.0-rc.1+abc"},
		WanUp:        true,
		InternetOK:   true,
		TelegramOK:   t0.Add(-41 * time.Second),
		Priority:     -7,
		Head:         history.Head{Seq: 0x2122232425262728, Hash: ids.Hash{0x31, 31: 0x32}},
		Digest:       ids.Hash{0x41, 31: 0x42},
		RosterHash:   testRosterHash,
		Wall:         t0.Add(3 * time.Nanosecond),
		Mono:         90 * time.Minute,
		ClockTrusted: true,
		GoingDown:    true,
	}
}

// handBody spells out the heartbeat layout of the package doc, independently
// of the package's encoder.
func handBody(h Heartbeat) []byte {
	var b []byte
	b = append(b, 1) // format version
	b = binary.BigEndian.AppendUint32(b, h.Epoch)
	b = append(b, h.From[:]...)
	b = binary.BigEndian.AppendUint64(b, h.BootSeq)
	b = append(b, h.Boot[:]...)
	b = binary.BigEndian.AppendUint64(b, h.Counter)
	var flags byte
	if h.WanUp {
		flags |= 1
	}
	if h.InternetOK {
		flags |= 2
	}
	if h.ClockTrusted {
		flags |= 4
	}
	if h.GoingDown {
		flags |= 8
	}
	b = append(b, flags)
	b = binary.BigEndian.AppendUint64(b, uint64(h.Uptime))
	b = binary.BigEndian.AppendUint64(b, uint64(h.Wall.UnixNano()))
	b = binary.BigEndian.AppendUint64(b, uint64(h.Mono))
	var tg int64
	if !h.TelegramOK.IsZero() {
		tg = h.TelegramOK.UnixNano()
	}
	b = binary.BigEndian.AppendUint64(b, uint64(tg))
	b = binary.BigEndian.AppendUint32(b, uint32(int32(h.Priority)))
	b = binary.BigEndian.AppendUint64(b, h.Head.Seq)
	b = append(b, h.Head.Hash[:]...)
	b = append(b, h.Digest[:]...)
	b = append(b, h.RosterHash[:]...)
	b = append(b, byte(len(h.Name)))
	b = append(b, h.Name...)
	for _, v := range h.Versions {
		b = append(b, byte(len(v)))
		b = append(b, v...)
	}
	return b
}

// handSign returns body followed by key's Ed25519 signature over
// "rollcall/v1/heartbeat\x00" || body, spelled out without package sig.
func handSign(body []byte, key ed25519.PrivateKey) []byte {
	msg := append([]byte("rollcall/v1/heartbeat\x00"), body...)
	return append(bytes.Clone(body), ed25519.Sign(key, msg)...)
}

func enc(t testing.TB, h Heartbeat, m tm) []byte {
	t.Helper()
	b, err := EncodeHeartbeat(h, m.id)
	if err != nil {
		t.Fatalf("EncodeHeartbeat: %v", err)
	}
	return b
}

func TestHeartbeatFitsWith32Members(t *testing.T) {
	ms := members(roster.MaxMembers)
	if err := testRoster(ms).Check(); err != nil {
		t.Fatalf("a full roster of %d members does not check: %v", len(ms), err)
	}
	last := ms[len(ms)-1]

	// The largest heartbeat: every variable field at its limit, every number
	// at its widest. Its size does not depend on the number of members: the
	// history goes in as one head and one digest (security spec 5.7).
	h := fullBeat(last)
	h.BootSeq, h.Counter = math.MaxUint64, math.MaxUint64
	h.Name = strings.Repeat("z", roster.MaxNameLen)
	h.Versions = [2]string{strings.Repeat("9", MaxVersionLen), strings.Repeat("v", MaxVersionLen)}
	h.Head = history.Head{Seq: math.MaxUint64, Hash: ids.Hash{0xff, 31: 0xff}}
	h.Priority = math.MinInt32
	h.Uptime, h.Mono = math.MaxInt64, math.MaxInt64
	h.Wall = time.Unix(0, math.MaxInt64).UTC()
	b := enc(t, h, last)
	if len(b) != MaxEncodedLen {
		t.Errorf("largest heartbeat is %d bytes, MaxEncodedLen is %d", len(b), MaxEncodedLen)
	}
	if MaxEncodedLen != 421 {
		t.Errorf("MaxEncodedLen = %d, want 421 (a change of the layout is a decision)", MaxEncodedLen)
	}

	key, err := wire.PacketKey(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	// One byte in front for the message type the node puts there.
	pkt, err := wire.Seal(key, testEpoch, append([]byte{0x01}, b...))
	if err != nil {
		t.Fatalf("sealing the largest heartbeat: %v", err)
	}
	if len(pkt) > wire.MaxPacket {
		t.Fatalf("sealed heartbeat is %d bytes, over %d", len(pkt), wire.MaxPacket)
	}
	t.Logf("largest heartbeat %d bytes; sealed with a type byte %d of %d bytes, %d to spare",
		len(b), len(pkt), wire.MaxPacket, wire.MaxPacket-len(pkt))

	// A table of 32 members takes it.
	f := newFixtureOf(t, ms, 0)
	if _, err := f.tab.Observe(testEpoch, b, at(time.Second)); err != nil {
		t.Fatalf("a table of 32 members refused the largest heartbeat: %v", err)
	}
}

func TestHeartbeatLayout(t *testing.T) {
	m := members(2)[1]
	full := fullBeat(m)
	sparse := Heartbeat{
		Epoch: 1, From: m.id.ID, BootSeq: 1, Boot: bootID(1), Name: "a",
		Wall: time.Unix(0, 0).UTC(),
	}
	for name, h := range map[string]Heartbeat{"full": full, "sparse": sparse} {
		got := enc(t, h, m)
		want := handSign(handBody(h), m.id.Sign)
		if !bytes.Equal(got, want) {
			t.Errorf("%s: EncodeHeartbeat =\n%x\nwant\n%x", name, got, want)
			continue
		}
		dec, err := decodeBody(got[:len(got)-ed25519.SignatureSize])
		if err != nil {
			t.Errorf("%s: decodeBody: %v", name, err)
			continue
		}
		if !reflect.DeepEqual(dec, h) {
			t.Errorf("%s: decoded\n%+v\nwant\n%+v", name, dec, h)
		}
	}

	// Each field has its own place: changing one changes the bytes.
	base := handBody(full)
	edits := map[string]func(h *Heartbeat){
		"epoch": func(h *Heartbeat) { h.Epoch++ }, "from": func(h *Heartbeat) { h.From[3]++ },
		"boot seq": func(h *Heartbeat) { h.BootSeq++ }, "boot": func(h *Heartbeat) { h.Boot[3]++ },
		"counter": func(h *Heartbeat) { h.Counter++ }, "name": func(h *Heartbeat) { h.Name = "r99" },
		"uptime": func(h *Heartbeat) { h.Uptime++ }, "openwrt": func(h *Heartbeat) { h.Versions[0] = "24.10.5" },
		"service": func(h *Heartbeat) { h.Versions[1] = "1.0.1" }, "wan": func(h *Heartbeat) { h.WanUp = false },
		"internet": func(h *Heartbeat) { h.InternetOK = false }, "telegram": func(h *Heartbeat) { h.TelegramOK = h.TelegramOK.Add(1) },
		"priority": func(h *Heartbeat) { h.Priority++ }, "head seq": func(h *Heartbeat) { h.Head.Seq++ },
		"head hash": func(h *Heartbeat) { h.Head.Hash[3]++ }, "digest": func(h *Heartbeat) { h.Digest[3]++ },
		"roster": func(h *Heartbeat) { h.RosterHash[3]++ }, "wall": func(h *Heartbeat) { h.Wall = h.Wall.Add(1) },
		"mono": func(h *Heartbeat) { h.Mono++ }, "trusted": func(h *Heartbeat) { h.ClockTrusted = false },
		"going down": func(h *Heartbeat) { h.GoingDown = false },
	}
	for name, edit := range edits {
		h := full
		edit(&h)
		b, err := appendBody(nil, h)
		if err != nil || bytes.Equal(b, base) {
			t.Errorf("changing %s does not change the encoding (%v)", name, err)
		}
	}
}

// Priorities just outside int32, as variables so that the file builds where
// int is 32 bits wide.
var over32, under32 int64 = math.MaxInt32 + 1, math.MinInt32 - 1

func TestEncodeHeartbeatRejects(t *testing.T) {
	m := members(2)[1]
	unix := func(n int64) time.Time { return time.Unix(0, n).UTC() }
	cases := map[string]func(h *Heartbeat){
		"zero from":             func(h *Heartbeat) { h.From = ids.MemberID{} },
		"from another member":   func(h *Heartbeat) { h.From = members(3)[2].id.ID },
		"zero boot":             func(h *Heartbeat) { h.Boot = ids.BootID{} },
		"boot seq 0":            func(h *Heartbeat) { h.BootSeq = 0 },
		"empty name":            func(h *Heartbeat) { h.Name = "" },
		"upper-case name":       func(h *Heartbeat) { h.Name = "OpenWrt" },
		"long name":             func(h *Heartbeat) { h.Name = strings.Repeat("a", roster.MaxNameLen+1) },
		"name with dash first":  func(h *Heartbeat) { h.Name = "-x" },
		"long openwrt version":  func(h *Heartbeat) { h.Versions[0] = strings.Repeat("1", MaxVersionLen+1) },
		"long service version":  func(h *Heartbeat) { h.Versions[1] = strings.Repeat("1", MaxVersionLen+1) },
		"space in version":      func(h *Heartbeat) { h.Versions[1] = "1.0 beta" },
		"newline in version":    func(h *Heartbeat) { h.Versions[0] = "24.10\n" },
		"slash in version":      func(h *Heartbeat) { h.Versions[0] = "24.10/4" },
		"non-ASCII in version":  func(h *Heartbeat) { h.Versions[0] = "24.10é" },
		"negative uptime":       func(h *Heartbeat) { h.Uptime = -1 },
		"negative mono":         func(h *Heartbeat) { h.Mono = -1 },
		"wall before 1970":      func(h *Heartbeat) { h.Wall = unix(-1) },
		"wall after 2262":       func(h *Heartbeat) { h.Wall = unix(math.MaxInt64).Add(1) },
		"zero wall":             func(h *Heartbeat) { h.Wall = time.Time{} },
		"telegram at 1970":      func(h *Heartbeat) { h.TelegramOK = unix(0) },
		"telegram before 1970":  func(h *Heartbeat) { h.TelegramOK = unix(-1) },
		"telegram after 2262":   func(h *Heartbeat) { h.TelegramOK = unix(math.MaxInt64).Add(1) },
		"priority over int32":   func(h *Heartbeat) { h.Priority = int(over32) },
		"priority under int32":  func(h *Heartbeat) { h.Priority = int(under32) },
		"head seq without hash": func(h *Heartbeat) { h.Head = history.Head{Seq: 1} },
		"head hash without seq": func(h *Heartbeat) { h.Head = history.Head{Hash: ids.Hash{1}} },
	}
	for name, edit := range cases {
		h := fullBeat(m)
		edit(&h)
		b, err := EncodeHeartbeat(h, m.id)
		if !errors.Is(err, ErrInvalid) || b != nil {
			t.Errorf("%s: EncodeHeartbeat = %d bytes, %v; want nil, ErrInvalid", name, len(b), err)
		}
	}

	h := fullBeat(m)
	for name, id := range map[string]*identity.Identity{
		"nil identity": nil,
		"short key":    {ID: m.id.ID, Sign: m.id.Sign[:63]},
		"no key":       {ID: m.id.ID},
	} {
		if b, err := EncodeHeartbeat(h, id); !errors.Is(err, ErrInvalid) || b != nil {
			t.Errorf("%s: EncodeHeartbeat = %d bytes, %v; want nil, ErrInvalid", name, len(b), err)
		}
	}

	// The limits themselves are accepted.
	ok := map[string]func(h *Heartbeat){
		"wall at 1970":      func(h *Heartbeat) { h.Wall = unix(0) },
		"wall at 2262":      func(h *Heartbeat) { h.Wall = unix(math.MaxInt64) },
		"telegram never":    func(h *Heartbeat) { h.TelegramOK = time.Time{} },
		"telegram 1 ns":     func(h *Heartbeat) { h.TelegramOK = unix(1) },
		"telegram at 2262":  func(h *Heartbeat) { h.TelegramOK = unix(math.MaxInt64) },
		"largest priority":  func(h *Heartbeat) { h.Priority = math.MaxInt32 },
		"smallest priority": func(h *Heartbeat) { h.Priority = math.MinInt32 },
		"empty versions":    func(h *Heartbeat) { h.Versions = [2]string{} },
		"longest versions": func(h *Heartbeat) {
			h.Versions = [2]string{strings.Repeat("a", MaxVersionLen), strings.Repeat("Z", MaxVersionLen)}
		},
		"every version symbol": func(h *Heartbeat) { h.Versions[0] = "aZ09.-+_~" },
		"longest name":         func(h *Heartbeat) { h.Name = strings.Repeat("a", roster.MaxNameLen) },
		"zero head":            func(h *Heartbeat) { h.Head = history.Head{} },
		"zero uptime and mono": func(h *Heartbeat) { h.Uptime, h.Mono = 0, 0 },
	}
	for name, edit := range ok {
		h := fullBeat(m)
		edit(&h)
		b, err := EncodeHeartbeat(h, m.id)
		if err != nil {
			t.Errorf("%s: EncodeHeartbeat: %v", name, err)
			continue
		}
		dec, err := decodeBody(b[:len(b)-ed25519.SignatureSize])
		if err != nil || !reflect.DeepEqual(dec, h) {
			t.Errorf("%s: round trip gave %+v, %v", name, dec, err)
		}
	}
}

func TestDecodeHeartbeatRejects(t *testing.T) {
	m := members(2)[1]
	valid := handBody(fullBeat(m))
	if _, err := decodeBody(valid); err != nil {
		t.Fatalf("the valid body is refused: %v", err)
	}
	set := func(off int, v ...byte) []byte {
		b := bytes.Clone(valid)
		copy(b[off:], v)
		return b
	}
	be64 := func(off int, v uint64) []byte {
		b := bytes.Clone(valid)
		binary.BigEndian.PutUint64(b[off:], v)
		return b
	}
	withName := func(name string) []byte {
		h := fullBeat(m)
		h.Name = name
		return handBody(h)
	}
	withVersion := func(v string) []byte {
		h := fullBeat(m)
		h.Versions[1] = v
		return handBody(h)
	}
	nameOff := 194
	cases := map[string][]byte{
		"empty":                  nil,
		"trailing byte":          append(bytes.Clone(valid), 0),
		"format version 0":       set(0, 0),
		"format version 2":       set(0, 2),
		"unknown flag 0x10":      set(53, valid[53]|0x10),
		"unknown flag 0x80":      set(53, valid[53]|0x80),
		"zero from":              set(5, make([]byte, 16)...),
		"boot seq 0":             be64(21, 0),
		"zero boot":              set(29, make([]byte, 16)...),
		"negative uptime":        be64(54, 1<<63),
		"negative wall":          be64(62, 1<<63|1),
		"negative mono":          be64(70, math.MaxUint64),
		"negative telegram":      be64(78, 1<<63),
		"head seq without hash":  set(98, make([]byte, 32)...),
		"head hash without seq":  be64(90, 0),
		"name length 0":          set(nameOff, 0),
		"name length 33":         withName(strings.Repeat("a", 33)),
		"name past the end":      set(nameOff, 0xff),
		"upper-case name":        withName("Rr1"),
		"name with a NUL":        withName("r\x001"),
		"version length 65":      withVersion(strings.Repeat("1", 65)),
		"version past the end":   append(bytes.Clone(valid[:len(valid)-len(fullBeat(m).Versions[1])-1]), 3, '1'),
		"version with a space":   withVersion("1 0"),
		"version with a quote":   withVersion("1\"0"),
		"version with high byte": withVersion("1\xff"),
		"versions missing":       bytes.Clone(valid[:nameOff+1+len(m.name)]),
	}
	for n := 0; n < len(valid); n++ {
		cases[fmt.Sprintf("truncated to %d", n)] = bytes.Clone(valid[:n])
	}
	for name, b := range cases {
		h, err := decodeBody(b)
		if !errors.Is(err, ErrMalformed) || !reflect.DeepEqual(h, Heartbeat{}) {
			t.Errorf("%s: decodeBody = %+v, %v; want the zero Heartbeat, ErrMalformed", name, h, err)
		}
	}
}

func TestSplitHeartbeat(t *testing.T) {
	m := members(2)[1]
	h := fullBeat(m)
	b := enc(t, h, m)
	p, err := split(b)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	want := packet{
		epoch: h.Epoch, from: h.From, bootSeq: h.BootSeq, boot: h.Boot, counter: h.Counter,
		body: b[:len(b)-64], sig: b[len(b)-64:],
	}
	if !reflect.DeepEqual(p, want) {
		t.Errorf("split =\n%+v\nwant\n%+v", p, want)
	}

	small := Heartbeat{Epoch: 1, From: m.id.ID, BootSeq: 1, Boot: bootID(1), Name: "a", Wall: time.Unix(0, 0).UTC()}
	smallest := enc(t, small, m)
	if len(smallest) != minEncodedLen {
		t.Errorf("smallest heartbeat is %d bytes, minEncodedLen %d", len(smallest), minEncodedLen)
	}
	if _, err := split(smallest); err != nil {
		t.Errorf("split refuses the smallest heartbeat: %v", err)
	}
	for name, bad := range map[string][]byte{
		"empty":            nil,
		"one short":        smallest[:len(smallest)-1],
		"one long":         append(make([]byte, MaxEncodedLen), 1),
		"format version 0": append([]byte{0}, b[1:]...),
		"format version 2": append([]byte{2}, b[1:]...),
	} {
		if p, err := split(bad); !errors.Is(err, ErrMalformed) || !reflect.DeepEqual(p, packet{}) {
			t.Errorf("%s: split = %+v, %v; want ErrMalformed", name, p, err)
		}
	}
	long := make([]byte, MaxEncodedLen)
	long[0] = FormatVersion
	if _, err := split(long); err != nil {
		t.Errorf("split refuses %d bytes: %v", MaxEncodedLen, err)
	}
}
