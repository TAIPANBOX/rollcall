package events

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/rand/v2"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/clock"
	"github.com/TAIPANBOX/rollcall/internal/ids"
)

// member returns a test member ID; n orders them.
func member(n byte) ids.MemberID {
	var m ids.MemberID
	m[0] = n
	m[15] = 0xa5
	return m
}

// boot returns a test boot ID that is never zero.
func boot(n byte) ids.BootID {
	var b ids.BootID
	b[0] = n
	b[15] = 0xb0
	return b
}

// t0 is the true wall time of the fixtures.
var t0 = time.Date(2026, 10, 22, 14, 2, 0, 0, time.UTC)

// threeYears is the clock step of Review Focus 2.
const threeYears = 3 * 365 * 24 * time.Hour

// router is a witness with its clocks: one boot, up for a while at t0, with a
// trusted wall clock unless said otherwise.
type router struct {
	id      ids.MemberID
	boot    ids.BootID
	up      time.Duration // monotonic clock at t0
	trusted bool
}

func newRouter(n byte) router {
	return router{id: member(n), boot: boot(n), up: time.Duration(n) * 1000 * time.Second, trusted: true}
}

// at stamps the moment t0+d on r's clocks.
func (r router) at(d time.Duration) clock.Stamp {
	return clock.Stamp{Wall: t0.Add(d), Mono: r.up + d, Trusted: r.trusted, Boot: r.boot}
}

// gw, the main router, has the highest ID of the fixtures, so "named first"
// is never a side effect of sorting by ID.
var (
	gw      = newRouter(0x40)
	ap2     = newRouter(2)
	ap3     = newRouter(3)
	ap4     = newRouter(4)
	ap5     = newRouter(5)
	kitchen = newRouter(6)
	office  = newRouter(7)
)

// fixture hands out events with distinct refs.
type fixture struct{ n uint32 }

func (f *fixture) ev(typ Type, subject ids.MemberID, w router, d time.Duration) Event {
	return f.stamped(typ, subject, w.id, w.at(d))
}

func (f *fixture) stamped(typ Type, subject, witness ids.MemberID, at clock.Stamp) Event {
	f.n++
	var ref ids.Hash
	binary.BigEndian.PutUint32(ref[:], f.n)
	ref[31] = 0xee
	return Event{Type: typ, Subject: subject, Witness: witness, At: at, Ref: ref}
}

// names returns the hex forms of the given members, as an incident lists them.
func names(ms ...ids.MemberID) []string {
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		out = append(out, m.String())
	}
	return out
}

// sortedNames returns the hex forms of the given members in ID order.
func sortedNames(ms ...ids.MemberID) []string {
	out := names(ms...)
	slices.Sort(out)
	return out
}

// refsOf returns the refs of evs in ascending byte order.
func refsOf(evs ...Event) []ids.Hash {
	out := make([]ids.Hash, 0, len(evs))
	for _, e := range evs {
		out = append(out, e.Ref)
	}
	slices.SortFunc(out, func(a, b ids.Hash) int { return bytes.Compare(a[:], b[:]) })
	return out
}

// wantID spells out the incident ID independently of the package: the first
// 8 bytes, in lowercase hex, of SHA-256 over "rollcall/v1 incident\x00"
// followed by one record per event in ascending byte order. A record is
// ref (32) | subject (16) | witness (16) | boot (16) | wall seconds since 1970
// (int64) | wall nanoseconds (uint32) | mono nanoseconds (int64) | trusted (1
// byte, 0 or 1) | length of the type (uint32) | type; integers big-endian.
// wantIncidentID is the ID of the incident made of evs: over its own
// accounts when it holds any, else over all of them.
func wantIncidentID(evs ...Event) string {
	var own []Event
	for _, e := range evs {
		if Own(e) {
			own = append(own, e)
		}
	}
	if len(own) > 0 {
		return wantID(own...)
	}
	return wantID(evs...)
}

func wantID(evs ...Event) string {
	var recs [][]byte
	for _, e := range evs {
		var r []byte
		r = append(r, e.Ref[:]...)
		r = append(r, e.Subject[:]...)
		r = append(r, e.Witness[:]...)
		r = append(r, e.At.Boot[:]...)
		r = binary.BigEndian.AppendUint64(r, uint64(e.At.Wall.Unix()))
		r = binary.BigEndian.AppendUint32(r, uint32(e.At.Wall.Nanosecond()))
		r = binary.BigEndian.AppendUint64(r, uint64(e.At.Mono))
		if e.At.Trusted {
			r = append(r, 1)
		} else {
			r = append(r, 0)
		}
		r = binary.BigEndian.AppendUint32(r, uint32(len(e.Type)))
		r = append(r, e.Type...)
		recs = append(recs, r)
	}
	slices.SortFunc(recs, bytes.Compare)
	h := sha256.New()
	h.Write([]byte("rollcall/v1 incident\x00"))
	for _, r := range recs {
		h.Write(r)
	}
	return hex.EncodeToString(h.Sum(nil)[:8])
}

// one coalesces evs with the default window and requires exactly one incident.
func one(t *testing.T, evs []Event) Incident {
	t.Helper()
	incs := Coalesce(evs, DefaultWindow)
	if len(incs) != 1 {
		t.Fatalf("Coalesce gave %d incidents, want 1:\n%s", len(incs), dump(incs))
	}
	return incs[0]
}

func dump(incs []Incident) string {
	var b bytes.Buffer
	for i, inc := range incs {
		fmt.Fprintf(&b, "  %d: members %v causes %d events %v witnesses %v refs %d start %v end %v approx %v\n",
			i, short(inc.Members), inc.Causes, inc.Events, short(inc.Witnesses), len(inc.Refs),
			inc.Start.Wall.Format(time.RFC3339Nano), inc.End.Wall.Format(time.RFC3339Nano), inc.Approximate)
	}
	return b.String()
}

// short cuts member hex to the two leading digits for failure output.
func short(s []string) []string {
	out := make([]string, len(s))
	for i, x := range s {
		out[i] = x[:2] + ".."
	}
	return out
}

func TestDefaultWindow(t *testing.T) {
	if DefaultWindow != 10*time.Second {
		t.Errorf("DefaultWindow = %v, want 10s (coalescing window of the plan)", DefaultWindow)
	}
}

// TestGatewayRebootIsOneIncident: the main router goes away and the four
// access points lose the internet within 10 s. That is one incident about
// the main router, never a message per router (anti-goal), whatever the
// order in which the events were stamped and whichever kind of absence it is.
func TestGatewayRebootIsOneIncident(t *testing.T) {
	causes := []Type{MemberSilent, RebootUnplanned, RebootPlanned, Upgraded, MemberBack, LinkLost}
	orders := []struct {
		name    string
		causeAt time.Duration
	}{
		{"cause first", 0},
		{"cause in the middle", 5 * time.Second},
		{"cause last, at the edge of the window", 10 * time.Second},
	}
	for _, cause := range causes {
		for _, o := range orders {
			t.Run(string(cause)+"/"+o.name, func(t *testing.T) {
				f := &fixture{}
				evs := []Event{
					f.ev(InternetLost, ap2.id, ap2, 0),
					f.ev(InternetLost, ap3.id, ap3, 3*time.Second),
					f.ev(cause, gw.id, ap2, o.causeAt), // seen by two access points
					f.ev(cause, gw.id, ap3, o.causeAt),
					f.ev(InternetLost, ap4.id, ap4, 6*time.Second),
					f.ev(InternetLost, ap5.id, ap5, 10*time.Second),
				}
				inc := one(t, evs)
				if len(inc.Members) == 0 || inc.Members[0] != gw.id.String() {
					t.Fatalf("Members = %v, want the main router %s first", short(inc.Members), gw.id.String()[:2])
				}
				if want := names(gw.id, ap2.id, ap3.id, ap4.id, ap5.id); !slices.Equal(inc.Members, want) || inc.Causes != 1 {
					t.Errorf("Members = %v, Causes %d; want %v, 1", short(inc.Members), inc.Causes, short(want))
				}
				if want := names(ap2.id, ap3.id, ap4.id, ap5.id); !slices.Equal(inc.Witnesses, want) {
					t.Errorf("Witnesses = %v, want %v", short(inc.Witnesses), short(want))
				}
				gotTypes := slices.Clone(inc.Events)
				slices.Sort(gotTypes)
				wantTypes := []Type{cause, InternetLost}
				slices.Sort(wantTypes)
				if !slices.Equal(gotTypes, wantTypes) {
					t.Errorf("Events = %v, want %v in any order", inc.Events, wantTypes)
				}
				if !inc.Start.Wall.Equal(t0) || !inc.End.Wall.Equal(t0.Add(10*time.Second)) {
					t.Errorf("Start %v End %v, want t0 and t0+10s", inc.Start.Wall, inc.End.Wall)
				}
				if inc.Approximate {
					t.Errorf("Approximate = true with every clock trusted")
				}
				if !slices.Equal(inc.Refs, refsOf(evs...)) {
					t.Errorf("Refs = %d refs, want all %d events", len(inc.Refs), len(evs))
				}
			})
		}
	}

	t.Run("every kind of link event joins the cause", func(t *testing.T) {
		f := &fixture{}
		evs := []Event{
			f.ev(WanDown, gw.id, gw, 0), // the main router's own WAN, before it went away
			f.ev(RebootUnplanned, gw.id, ap2, time.Second),
			f.ev(InternetLost, ap2.id, ap2, 2*time.Second),
			f.ev(WanDown, ap3.id, ap3, 3*time.Second),
			f.ev(UplinkSwitched, ap4.id, ap4, 4*time.Second),
			f.ev(InternetRestored, ap5.id, ap5, 5*time.Second),
			f.ev(WanUp, ap3.id, ap3, 6*time.Second),
		}
		inc := one(t, evs)
		if want := names(gw.id, ap2.id, ap3.id, ap4.id, ap5.id); !slices.Equal(inc.Members, want) {
			t.Errorf("Members = %v, want %v", short(inc.Members), short(want))
		}
		want := []Type{WanDown, RebootUnplanned, InternetLost, UplinkSwitched, InternetRestored, WanUp}
		if !slices.Equal(inc.Events, want) {
			t.Errorf("Events = %v, want %v (order of first appearance)", inc.Events, want)
		}
	})
}

// TestSiteWideOutageNamesAllWitnesses: the internet goes away for the whole
// site and no member went away. One incident names every member that saw it;
// the recovery 28 minutes later is another, naming them again.
func TestSiteWideOutageNamesAllWitnesses(t *testing.T) {
	f := &fixture{}
	down := []Event{
		f.ev(WanDown, gw.id, gw, 0),
		f.ev(InternetLost, gw.id, gw, 2*time.Second),
		f.ev(InternetLost, kitchen.id, kitchen, 4*time.Second),
		f.ev(InternetLost, office.id, office, 9*time.Second),
	}
	back := 28 * time.Minute
	up := []Event{
		f.ev(InternetRestored, office.id, office, back),
		f.ev(WanUp, gw.id, gw, back+time.Second),
		f.ev(InternetRestored, gw.id, gw, back+2*time.Second),
		f.ev(InternetRestored, kitchen.id, kitchen, back+5*time.Second),
	}
	incs := Coalesce(append(slices.Clone(up), down...), DefaultWindow)
	if len(incs) != 2 {
		t.Fatalf("Coalesce gave %d incidents, want 2 (down, up):\n%s", len(incs), dump(incs))
	}
	all := sortedNames(gw.id, kitchen.id, office.id)
	for i, c := range []struct {
		evs   []Event
		types []Type
		start time.Duration
		end   time.Duration
	}{
		{down, []Type{WanDown, InternetLost}, 0, 9 * time.Second},
		{up, []Type{InternetRestored, WanUp}, back, back + 5*time.Second},
	} {
		inc := incs[i]
		if !slices.Equal(inc.Witnesses, all) {
			t.Errorf("incident %d: Witnesses = %v, want all three %v", i, short(inc.Witnesses), short(all))
		}
		if !slices.Equal(inc.Members, all) || inc.Causes != 0 {
			t.Errorf("incident %d: Members = %v, Causes %d; want all three %v and no cause", i, short(inc.Members), inc.Causes, short(all))
		}
		if !slices.Equal(inc.Events, c.types) {
			t.Errorf("incident %d: Events = %v, want %v", i, inc.Events, c.types)
		}
		if !inc.Start.Wall.Equal(t0.Add(c.start)) || !inc.End.Wall.Equal(t0.Add(c.end)) {
			t.Errorf("incident %d: Start %v End %v, want t0+%v and t0+%v", i, inc.Start.Wall, inc.End.Wall, c.start, c.end)
		}
		if !slices.Equal(inc.Refs, refsOf(c.evs...)) {
			t.Errorf("incident %d: Refs hold %d events, want %d", i, len(inc.Refs), len(c.evs))
		}
		if inc.Approximate {
			t.Errorf("incident %d: Approximate with every clock trusted", i)
		}
	}
}

// TestUnrelatedMembersStaySeparate: events about different members with no
// shared cause are separate incidents even at the same instant, so a planned
// reboot never hides inside a crash. (The same absence of several members is
// rule (d), in TestSameAbsenceOfSeveralMembers.)
func TestUnrelatedMembersStaySeparate(t *testing.T) {
	a, b := member(0x0a), member(0x0b)
	pairs := []struct {
		name   string
		t1, t2 Type
		s1, s2 ids.MemberID
	}{
		{"planned reboot and crash", RebootPlanned, RebootUnplanned, a, b},
		{"planned reboot and upgrade", RebootPlanned, Upgraded, a, b},
		{"two link losses", LinkLost, LinkLost, a, b},
		{"upgrade and link loss", Upgraded, LinkLost, a, b},
		{"member back and member silent", MemberBack, MemberSilent, a, b},
		{"two forks", Fork, Fork, a, b},
		{"two duplicate identities", DuplicateIdentity, DuplicateIdentity, a, b},
		{"joined and left, one member", MemberJoined, MemberLeft, a, a},
		{"joined, two members", MemberJoined, MemberJoined, a, b},
		{"reboot and fork, one member", RebootUnplanned, Fork, a, a},
		{"roster changed and dropped", RosterChanged, RosterChangesDropped, a, a},
		{"flood and internet lost", UnderFlood, InternetLost, a, b},
		{"internet lost and flood", InternetLost, UnderFlood, a, b},
		{"a type from a newer version and a silence", Type("future_thing"), MemberSilent, a, a},
		{"a type from a newer version and a link event", Type("future_thing"), InternetLost, a, b},
	}
	for _, p := range pairs {
		t.Run(p.name, func(t *testing.T) {
			f := &fixture{}
			e1 := f.ev(p.t1, p.s1, ap2, 0)
			e2 := f.ev(p.t2, p.s2, ap3, 0)
			incs := Coalesce([]Event{e1, e2}, DefaultWindow)
			if len(incs) != 2 {
				t.Fatalf("Coalesce gave %d incidents, want 2:\n%s", len(incs), dump(incs))
			}
			got := map[ids.Hash]bool{}
			for _, inc := range incs {
				if len(inc.Refs) != 1 || len(inc.Events) != 1 {
					t.Fatalf("incident holds %d events (%v), want 1", len(inc.Refs), inc.Events)
				}
				got[inc.Refs[0]] = true
			}
			if !got[e1.Ref] || !got[e2.Ref] {
				t.Errorf("an event is missing from the incidents")
			}
		})
	}

	t.Run("a link event goes to the earlier of two causes", func(t *testing.T) {
		f := &fixture{}
		planned := f.ev(RebootPlanned, a, ap2, 0)
		crash := f.ev(RebootUnplanned, b, ap3, time.Second)
		lost := f.ev(InternetLost, ap4.id, ap4, 2*time.Second)
		incs := Coalesce([]Event{lost, crash, planned}, DefaultWindow)
		if len(incs) != 2 {
			t.Fatalf("Coalesce gave %d incidents, want 2:\n%s", len(incs), dump(incs))
		}
		if !slices.Equal(incs[0].Members, names(a, ap4.id)) || !slices.Equal(incs[0].Events, []Type{RebootPlanned, InternetLost}) {
			t.Errorf("first incident: members %v events %v, want the planned reboot with the link event",
				short(incs[0].Members), incs[0].Events)
		}
		if !slices.Equal(incs[1].Members, names(b)) || !slices.Equal(incs[1].Events, []Type{RebootUnplanned}) {
			t.Errorf("second incident: members %v events %v, want the crash alone", short(incs[1].Members), incs[1].Events)
		}
	})
}

// TestSameAbsenceOfSeveralMembers is rule (d): the same kind of absence of
// several members within the window of the incident's first event is one
// incident naming them all, so a power cut of the whole site, or an upgrade
// of every router, is one message. Different kinds of absence of different
// members stay apart, and no incident holds several members with several
// kinds of absence, so each member's absence can be told from the incident.
func TestSameAbsenceOfSeveralMembers(t *testing.T) {
	a, b, c := member(0x0a), member(0x0b), member(0x0c)
	type in struct {
		typ     Type
		subject ids.MemberID
		w       router
		at      time.Duration
	}
	cases := []struct {
		name   string
		evs    []in
		want   [][]string // Members of each incident, in order
		causes []int      // Causes of each incident
	}{
		{"power cut: three routers rebooted unexpectedly within 10 s",
			[]in{{RebootUnplanned, c, ap2, 0}, {RebootUnplanned, a, ap3, 4 * time.Second}, {RebootUnplanned, b, ap2, 10 * time.Second}},
			[][]string{names(a, b, c)}, []int{3}},
		{"two crashes 15 s apart",
			[]in{{RebootUnplanned, a, ap2, 0}, {RebootUnplanned, b, ap3, 15 * time.Second}},
			[][]string{names(a), names(b)}, []int{1, 1}},
		{"an upgrade and a crash of two members",
			[]in{{Upgraded, a, ap2, 0}, {RebootUnplanned, b, ap3, 2 * time.Second}},
			[][]string{names(a), names(b)}, []int{1, 1}},
		{"every router upgraded",
			[]in{{Upgraded, b, ap2, 0}, {Upgraded, a, ap3, time.Second}, {Upgraded, c, ap4, 2 * time.Second}},
			[][]string{names(a, b, c)}, []int{3}},
		{"several members silent, seen by several",
			[]in{{MemberSilent, b, ap2, 0}, {MemberSilent, a, ap2, time.Second}, {MemberSilent, b, ap3, 2 * time.Second}},
			[][]string{names(a, b)}, []int{2}},
		{"several members back",
			[]in{{MemberBack, b, ap2, 0}, {MemberBack, a, ap3, 3 * time.Second}},
			[][]string{names(a, b)}, []int{2}},
		{"planned reboots of two",
			[]in{{RebootPlanned, a, ap2, 0}, {RebootPlanned, b, ap3, 3 * time.Second}},
			[][]string{names(a, b)}, []int{2}},
		{"planned reboot and crash",
			[]in{{RebootPlanned, a, ap2, 0}, {RebootUnplanned, b, ap3, time.Second}},
			[][]string{names(a), names(b)}, []int{1, 1}},
		{"link losses of two members stay apart",
			[]in{{LinkLost, a, ap2, 0}, {LinkLost, b, ap3, time.Second}},
			[][]string{names(a), names(b)}, []int{1, 1}},
		{"several members, then another kind of absence of one of them",
			[]in{{RebootUnplanned, a, ap2, 0}, {RebootUnplanned, b, ap3, time.Second}, {MemberSilent, a, ap4, 2 * time.Second}},
			[][]string{names(a, b), names(a)}, []int{2, 1}},
		{"one member twice, then another member",
			[]in{{MemberSilent, a, ap2, 0}, {RebootUnplanned, a, ap3, time.Second}, {RebootUnplanned, b, ap4, 2 * time.Second}},
			[][]string{names(a), names(b)}, []int{1, 1}},
		{"one member twice, then another member of the first kind",
			[]in{{MemberSilent, a, ap2, 0}, {RebootUnplanned, a, ap3, time.Second}, {MemberSilent, b, ap4, 2 * time.Second}},
			[][]string{names(a), names(b)}, []int{1, 1}},
		{"the internet goes first, then two routers come back rebooted",
			[]in{{InternetLost, ap4.id, ap4, 0}, {RebootUnplanned, b, ap2, 2 * time.Second}, {RebootUnplanned, a, ap3, 4 * time.Second}},
			[][]string{names(a, b, ap4.id)}, []int{2}},
		{"power cut while a router on a UPS loses the internet",
			[]in{{RebootUnplanned, a, ap2, 0}, {InternetLost, ap4.id, ap4, time.Second}, {RebootUnplanned, b, ap2, 3 * time.Second},
				{WanDown, ap5.id, ap5, 5 * time.Second}, {RebootUnplanned, c, ap3, 9 * time.Second}},
			[][]string{names(a, b, c, ap4.id, ap5.id)}, []int{3}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := &fixture{}
			var evs []Event
			for _, e := range c.evs {
				evs = append(evs, f.ev(e.typ, e.subject, e.w, e.at))
			}
			incs := Coalesce(evs, DefaultWindow)
			var got [][]string
			var causes []int
			refs := 0
			for _, inc := range incs {
				got = append(got, inc.Members)
				causes = append(causes, inc.Causes)
				refs += len(inc.Refs)
			}
			if !reflect.DeepEqual(got, c.want) || !slices.Equal(causes, c.causes) || refs != len(evs) {
				t.Errorf("members per incident %v, causes %v (%d refs); want %v, %v (%d):\n%s",
					got, causes, refs, c.want, c.causes, len(evs), dump(incs))
			}
		})
	}
}

// TestSameFactFromSeveralWitnesses: several members reporting the same fact
// give one incident naming them all.
func TestSameFactFromSeveralWitnesses(t *testing.T) {
	x := member(0x0c)
	var site ids.MemberID
	cases := []struct {
		name      string
		build     func(f *fixture) []Event
		members   []string
		witnesses []string
		types     []Type
	}{
		{"a fork seen by three",
			func(f *fixture) []Event {
				return []Event{f.ev(Fork, x, ap2, 0), f.ev(Fork, x, ap3, time.Second), f.ev(Fork, x, ap4, 2*time.Second)}
			},
			names(x), names(ap2.id, ap3.id, ap4.id), []Type{Fork}},
		{"a silence seen by three",
			func(f *fixture) []Event {
				return []Event{f.ev(MemberSilent, x, ap4, 0), f.ev(MemberSilent, x, ap2, 0), f.ev(MemberSilent, x, ap3, 9*time.Second)}
			},
			names(x), names(ap2.id, ap3.id, ap4.id), []Type{MemberSilent}},
		{"silent, then back as an unplanned reboot",
			func(f *fixture) []Event {
				return []Event{f.ev(MemberSilent, x, ap2, 0), f.ev(RebootUnplanned, x, ap3, 4*time.Second)}
			},
			names(x), names(ap2.id, ap3.id), []Type{MemberSilent, RebootUnplanned}},
		{"a flood felt by two",
			func(f *fixture) []Event {
				return []Event{f.ev(UnderFlood, ap2.id, ap2, 0), f.ev(UnderFlood, ap3.id, ap3, 3*time.Second)}
			},
			names(ap2.id, ap3.id), names(ap2.id, ap3.id), []Type{UnderFlood}},
		{"dropped roster changes about the site, from two",
			func(f *fixture) []Event {
				return []Event{f.ev(RosterChangesDropped, site, ap2, 0), f.ev(RosterChangesDropped, site, ap3, time.Second)}
			},
			[]string{}, names(ap2.id, ap3.id), []Type{RosterChangesDropped}},
		{"a duplicate identity seen by two",
			func(f *fixture) []Event {
				return []Event{f.ev(DuplicateIdentity, x, ap3, 0), f.ev(DuplicateIdentity, x, ap2, 5*time.Second)}
			},
			names(x), names(ap2.id, ap3.id), []Type{DuplicateIdentity}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			evs := c.build(&fixture{})
			inc := one(t, evs)
			if len(inc.Members) != len(c.members) || (len(c.members) > 0 && !slices.Equal(inc.Members, c.members)) {
				t.Errorf("Members = %v, want %v", inc.Members, c.members)
			}
			if !slices.Equal(inc.Witnesses, c.witnesses) {
				t.Errorf("Witnesses = %v, want %v", short(inc.Witnesses), short(c.witnesses))
			}
			if !slices.Equal(inc.Events, c.types) {
				t.Errorf("Events = %v, want %v", inc.Events, c.types)
			}
			if len(inc.Refs) != len(evs) {
				t.Errorf("Refs hold %d events, want %d", len(inc.Refs), len(evs))
			}
		})
	}
}

// TestWindowFromFirstEvent: an incident takes events within the window of
// its first event, inclusive; it does not chain from event to event.
func TestWindowFromFirstEvent(t *testing.T) {
	x := member(0x0c)
	cases := []struct {
		name   string
		window time.Duration
		at     []time.Duration // MemberSilent of x, each seen by another router
		want   []int           // events per incident
	}{
		{"exactly the window", DefaultWindow, []time.Duration{0, 10 * time.Second}, []int{2}},
		{"one nanosecond past the window", DefaultWindow, []time.Duration{0, 10*time.Second + 1}, []int{1, 1}},
		{"no chaining from the second event", DefaultWindow, []time.Duration{0, 8 * time.Second, 16 * time.Second}, []int{2, 1}},
		{"a shorter window", 5 * time.Second, []time.Duration{0, 8 * time.Second}, []int{1, 1}},
		{"zero window, same instant", 0, []time.Duration{0, 0}, []int{2}},
		{"zero window, one nanosecond apart", 0, []time.Duration{0, 1}, []int{1, 1}},
		{"negative window", -time.Second, []time.Duration{0, 0}, []int{1, 1}},
	}
	witnesses := []router{ap2, ap3, ap4}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := &fixture{}
			var evs []Event
			for i, d := range c.at {
				evs = append(evs, f.ev(MemberSilent, x, witnesses[i], d))
			}
			incs := Coalesce(evs, c.window)
			var got []int
			for _, inc := range incs {
				got = append(got, len(inc.Refs))
			}
			if !slices.Equal(got, c.want) {
				t.Errorf("events per incident %v, want %v:\n%s", got, c.want, dump(incs))
			}
		})
	}

	t.Run("site-wide", func(t *testing.T) {
		f := &fixture{}
		evs := []Event{
			f.ev(InternetLost, ap2.id, ap2, 0),
			f.ev(InternetLost, ap3.id, ap3, 9*time.Second),
			f.ev(InternetLost, ap4.id, ap4, 11*time.Second),
		}
		incs := Coalesce(evs, DefaultWindow)
		if len(incs) != 2 || !slices.Equal(incs[0].Witnesses, names(ap2.id, ap3.id)) ||
			!slices.Equal(incs[1].Witnesses, names(ap4.id)) {
			t.Errorf("want [ap2 ap3] then [ap4]:\n%s", dump(incs))
		}
	})
}

// TestClockJumpKeepsDuration is Review Focus 2: a router's wall clock steps
// by three years when NTP answers in the middle of an incident. The events
// stay one incident, its length is the monotonic difference, its start is
// placed on the corrected clock, and it is marked approximate.
func TestClockJumpKeepsDuration(t *testing.T) {
	// ap boots after a power cut: its wall clock is three years off until NTP
	// answers between its two stamps.
	ap := router{id: member(0x20), boot: boot(0x20), up: 100 * time.Second}
	stamp := func(d time.Duration, wall time.Time, trusted bool) clock.Stamp {
		return clock.Stamp{Wall: wall, Mono: ap.up + d, Trusted: trusted, Boot: ap.boot}
	}

	cases := []struct {
		name      string
		before    time.Time // ap's wall clock at t0, before NTP
		after     time.Time // ap's wall clock at t0+6s, after NTP
		trusted   bool      // whether the second stamp is trusted
		other     time.Duration
		wantStart time.Time
		wantLen   time.Duration
	}{
		{"steps three years forward", t0.Add(-threeYears), t0.Add(6 * time.Second), true,
			3 * time.Second, t0, 6 * time.Second},
		{"steps three years back", t0.Add(threeYears), t0.Add(6 * time.Second), true,
			3 * time.Second, t0, 6 * time.Second},
		{"a trusted router's event after the step ends the incident", t0.Add(-threeYears), t0.Add(6 * time.Second), true,
			8 * time.Second, t0, 8 * time.Second},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := &fixture{}
			evs := []Event{
				f.stamped(MemberSilent, gw.id, ap.id, stamp(0, c.before, false)),
				f.stamped(InternetLost, ap.id, ap.id, stamp(6*time.Second, c.after, c.trusted)),
				f.ev(InternetLost, office.id, office, c.other),
			}
			inc := one(t, evs)
			if !inc.Approximate {
				t.Errorf("Approximate = false; an untrusted stamp was used")
			}
			if inc.Start.Mono != ap.up || inc.Start.Boot != ap.boot {
				t.Errorf("Start = %+v, want ap's first stamp", inc.Start)
			}
			if !inc.Start.Wall.Equal(c.wantStart) {
				t.Errorf("Start.Wall = %v, want %v (ap's clock corrected by its own later stamp)", inc.Start.Wall, c.wantStart)
			}
			got, _ := clock.Duration(inc.Start, inc.End)
			if got != c.wantLen {
				t.Errorf("Duration(Start, End) = %v, want %v", got, c.wantLen)
			}
		})
	}

	t.Run("one router alone: the monotonic difference, exactly", func(t *testing.T) {
		f := &fixture{}
		evs := []Event{
			f.stamped(MemberSilent, gw.id, ap.id, stamp(0, t0.Add(-threeYears), false)),
			f.stamped(InternetLost, ap.id, ap.id, stamp(6*time.Second, t0.Add(6*time.Second), true)),
		}
		inc := one(t, evs)
		got, approx := clock.Duration(inc.Start, inc.End)
		if got != 6*time.Second || approx {
			t.Errorf("Duration(Start, End) = %v, approximate %v; want 6s, exact", got, approx)
		}
		if !inc.Approximate {
			t.Errorf("Approximate = false; the start was stamped by an untrusted clock")
		}
		if !inc.End.Wall.Equal(t0.Add(6*time.Second)) || inc.End.Mono != ap.up+6*time.Second {
			t.Errorf("End = %+v, want ap's second stamp unchanged", inc.End)
		}
	})

	t.Run("no trusted stamp at all", func(t *testing.T) {
		f := &fixture{}
		wrong := t0.Add(-threeYears)
		evs := []Event{
			f.stamped(MemberSilent, gw.id, ap.id, stamp(0, wrong, false)),
			f.stamped(InternetLost, ap.id, ap.id, stamp(6*time.Second, wrong.Add(threeYears+6*time.Second), false)),
		}
		inc := one(t, evs)
		got, _ := clock.Duration(inc.Start, inc.End)
		if got != 6*time.Second || !inc.Approximate {
			t.Errorf("Duration %v, Approximate %v; want 6s, true", got, inc.Approximate)
		}
	})
}

// TestApproximate: the incident is approximate when any of its stamps is
// untrusted, not only its first or last.
func TestApproximate(t *testing.T) {
	untrusted := ap3
	untrusted.trusted = false
	cases := []struct {
		name string
		ws   []router
		want bool
	}{
		{"every clock trusted, three boots", []router{ap2, ap3, ap4}, false},
		{"an untrusted stamp in the middle", []router{ap2, untrusted, ap4}, true},
		{"an untrusted stamp at the start", []router{untrusted, ap2, ap4}, true},
		{"one trusted stamp", []router{ap2}, false},
		{"one untrusted stamp", []router{untrusted}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := &fixture{}
			var evs []Event
			for i, w := range c.ws {
				evs = append(evs, f.ev(InternetLost, w.id, w, time.Duration(i)*time.Second))
			}
			if inc := one(t, evs); inc.Approximate != c.want {
				t.Errorf("Approximate = %v, want %v", inc.Approximate, c.want)
			}
		})
	}

	t.Run("a copied boot ID makes the length approximate", func(t *testing.T) {
		// ap3 stamps with ap2's boot ID: the start and the end then look
		// like one boot whose monotonic clock ran backwards. Every clock is
		// trusted, yet the length cannot be, and is marked so.
		f := &fixture{}
		evs := []Event{
			f.ev(InternetLost, ap2.id, ap2, 0),
			f.stamped(InternetLost, ap3.id, ap3.id,
				clock.Stamp{Wall: t0.Add(time.Second), Mono: 0, Trusted: true, Boot: ap2.boot}),
		}
		inc := one(t, evs)
		if got, approx := clock.Duration(inc.Start, inc.End); got != 0 || !approx || !inc.Approximate {
			t.Errorf("Duration %v (approximate %v), Approximate %v; want 0s, true, true", got, approx, inc.Approximate)
		}
	})

	t.Run("a stamp before the start of the same boot", func(t *testing.T) {
		// Two stamps of one boot whose walls disagree with their monotonic
		// order: the incident still runs forward and is marked approximate
		// because the stamps are untrusted.
		w := router{id: member(0x30), boot: boot(0x30), up: time.Hour}
		f := &fixture{}
		evs := []Event{
			f.stamped(InternetLost, w.id, w.id, clock.Stamp{Wall: t0.Add(5 * time.Second), Mono: time.Hour, Boot: w.boot}),
			f.stamped(WanDown, w.id, w.id, clock.Stamp{Wall: t0, Mono: time.Hour + 2*time.Second, Boot: w.boot}),
		}
		inc := one(t, evs)
		if inc.Start.Mono != time.Hour || inc.End.Mono != time.Hour+2*time.Second {
			t.Errorf("Start mono %v End mono %v; want the monotonic order", inc.Start.Mono, inc.End.Mono)
		}
		if got, _ := clock.Duration(inc.Start, inc.End); got != 2*time.Second || !inc.Approximate {
			t.Errorf("Duration %v Approximate %v; want 2s, true", got, inc.Approximate)
		}
	})
}

// TestTimelineIsPerWitnessBoot: a member that stamps with another member's
// boot ID moves only its own events; the other's incident keeps its times.
func TestTimelineIsPerWitnessBoot(t *testing.T) {
	f := &fixture{}
	x := member(0x0c)
	v1 := f.ev(MemberSilent, x, ap2, 0)
	v2 := f.ev(MemberSilent, x, ap2, 2*time.Second)
	// ap3 copies ap2's boot ID, with a later monotonic reading and a wall
	// clock a year ahead.
	forged := f.stamped(Fork, ap4.id, ap3.id,
		clock.Stamp{Wall: t0.Add(365 * 24 * time.Hour), Mono: ap2.up + time.Hour, Trusted: true, Boot: ap2.boot})
	incs := Coalesce([]Event{forged, v2, v1}, DefaultWindow)
	if len(incs) != 2 {
		t.Fatalf("Coalesce gave %d incidents, want 2:\n%s", len(incs), dump(incs))
	}
	inc := incs[0]
	if !slices.Equal(inc.Refs, refsOf(v1, v2)) {
		t.Fatalf("first incident holds %d refs, want ap2's two events:\n%s", len(inc.Refs), dump(incs))
	}
	if !inc.Start.Wall.Equal(t0) || !inc.End.Wall.Equal(t0.Add(2*time.Second)) {
		t.Errorf("Start %v End %v, want t0 and t0+2s: another member's stamp moved ap2's events", inc.Start.Wall, inc.End.Wall)
	}
}

// TestUnknownBootStandsAlone: stamps without a boot ID are not put on one
// timeline, even from one witness: their monotonic readings may come from
// different boots, so only their wall clocks place them.
func TestUnknownBootStandsAlone(t *testing.T) {
	var unknown ids.BootID
	f := &fixture{}
	evs := []Event{
		f.stamped(InternetLost, ap2.id, ap2.id, clock.Stamp{Wall: t0, Mono: 100 * time.Second, Trusted: true, Boot: unknown}),
		f.stamped(WanDown, ap2.id, ap2.id, clock.Stamp{Wall: t0.Add(5 * time.Second), Mono: 0, Trusted: true, Boot: unknown}),
	}
	inc := one(t, evs)
	if !inc.Start.Wall.Equal(t0) || !inc.End.Wall.Equal(t0.Add(5*time.Second)) {
		t.Errorf("Start %v End %v, want t0 and t0+5s from the wall clocks", inc.Start.Wall, inc.End.Wall)
	}
}

// TestAnchorTie: two stamps of one boot at the same monotonic instant with
// different wall clocks (only a faulty or lying clock does that). The later
// wall clock anchors the boot, whatever the order of the events.
func TestAnchorTie(t *testing.T) {
	w := router{id: member(0x30), boot: boot(0x30), up: time.Hour}
	f := &fixture{}
	early := f.stamped(InternetLost, w.id, w.id, clock.Stamp{Wall: t0, Mono: time.Hour, Trusted: true, Boot: w.boot})
	late := f.stamped(WanDown, w.id, w.id, clock.Stamp{Wall: t0.Add(5 * time.Second), Mono: time.Hour, Trusted: true, Boot: w.boot})
	before := f.stamped(UplinkSwitched, w.id, w.id,
		clock.Stamp{Wall: t0, Mono: time.Hour - 2*time.Second, Trusted: true, Boot: w.boot})
	for i, order := range [][]Event{{early, late, before}, {late, early, before}, {before, late, early}} {
		inc := one(t, order)
		if !inc.Start.Wall.Equal(t0.Add(3*time.Second)) || !inc.End.Wall.Equal(t0.Add(5*time.Second)) {
			t.Errorf("order %d: Start %v End %v, want t0+3s and t0+5s (anchored on the later wall clock)",
				i, inc.Start.Wall, inc.End.Wall)
		}
	}
}

// TestZeroIDsAreNotNamed: a zero member ID is unknown. An absence of an
// unknown member names no cause and takes no link events; an unknown witness
// is not listed.
func TestZeroIDsAreNotNamed(t *testing.T) {
	var zero ids.MemberID
	f := &fixture{}
	crash := f.ev(RebootUnplanned, zero, ap2, 0)
	lost := f.ev(InternetLost, ap3.id, ap3, time.Second)
	incs := Coalesce([]Event{crash, lost}, DefaultWindow)
	if len(incs) != 2 {
		t.Fatalf("Coalesce gave %d incidents, want 2:\n%s", len(incs), dump(incs))
	}
	if len(incs[0].Members) != 0 || !slices.Equal(incs[0].Events, []Type{RebootUnplanned}) {
		t.Errorf("first incident: members %v events %v, want no members, the reboot alone", incs[0].Members, incs[0].Events)
	}

	f = &fixture{}
	anon := f.stamped(InternetLost, ap4.id, zero, ap4.at(0))
	seen := f.ev(InternetLost, ap5.id, ap5, time.Second)
	inc := one(t, []Event{anon, seen})
	if !slices.Equal(inc.Witnesses, names(ap5.id)) {
		t.Errorf("Witnesses = %v, want only ap5 (a zero witness is not named)", inc.Witnesses)
	}
	if !slices.Equal(inc.Members, names(ap4.id, ap5.id)) || len(inc.Refs) != 2 {
		t.Errorf("Members %v, %d refs; want ap4, ap5 and both events", short(inc.Members), len(inc.Refs))
	}
}

// TestIncidentFields: one incident written out in full.
func TestIncidentFields(t *testing.T) {
	f := &fixture{}
	lost := f.ev(InternetLost, ap2.id, ap2, 0)
	silent := f.ev(MemberSilent, gw.id, ap3, 4*time.Second)
	crash := f.ev(RebootUnplanned, gw.id, ap2, 7*time.Second)
	lost.Detail = map[string]string{"probe": "dns"}
	inc := one(t, []Event{crash, silent, lost})
	want := Incident{
		ID:          wantID(lost, silent, crash),
		Start:       ap2.at(0),
		End:         ap2.at(7 * time.Second),
		Members:     names(gw.id, ap2.id),
		Causes:      1,
		Events:      []Type{InternetLost, MemberSilent, RebootUnplanned},
		Witnesses:   names(ap2.id, ap3.id),
		Approximate: false,
		Refs:        refsOf(lost, silent, crash),
	}
	if !reflect.DeepEqual(inc, want) {
		t.Errorf("incident\n got %+v\nwant %+v", inc, want)
	}
}

// TestIncidentID: the ID is fixed by the incident's own events, so two
// routers that coalesce the same events send the same ID and a duplicate is
// recognised.
func TestIncidentID(t *testing.T) {
	x, y := member(0x0c), member(0x0d)

	t.Run("format and value", func(t *testing.T) {
		f := &fixture{}
		e1, e2 := f.ev(MemberSilent, x, ap2, 0), f.ev(MemberSilent, x, ap3, time.Second)
		inc := one(t, []Event{e2, e1})
		if inc.ID != wantID(e1, e2) {
			t.Errorf("ID = %q, want %q", inc.ID, wantID(e1, e2))
		}
		if len(inc.ID) != 16 || inc.ID != fmt.Sprintf("%016x", mustHex(t, inc.ID)) {
			t.Errorf("ID = %q, want 16 lowercase hex digits", inc.ID)
		}
	})

	t.Run("another event changes it", func(t *testing.T) {
		f := &fixture{}
		e1, e2 := f.ev(MemberSilent, x, ap2, 0), f.ev(MemberSilent, x, ap3, time.Second)
		e3 := f.ev(MemberSilent, x, ap4, 2*time.Second)
		if one(t, []Event{e1, e2}).ID == one(t, []Event{e1, e2, e3}).ID {
			t.Errorf("adding a witness kept the ID")
		}
	})

	t.Run("each field changes it", func(t *testing.T) {
		f := &fixture{}
		base := f.ev(MemberSilent, x, ap2, 0)
		id := one(t, []Event{base}).ID
		variants := map[string]func(e *Event){
			"ref":     func(e *Event) { e.Ref[5] ^= 1 },
			"type":    func(e *Event) { e.Type = RebootUnplanned },
			"subject": func(e *Event) { e.Subject = y },
			"witness": func(e *Event) { e.Witness = ap3.id },
			"boot":    func(e *Event) { e.At.Boot = boot(0x77) },
			"wall":    func(e *Event) { e.At.Wall = e.At.Wall.Add(time.Second) },
			"wall ns": func(e *Event) { e.At.Wall = e.At.Wall.Add(1) },
			"mono":    func(e *Event) { e.At.Mono++ },
			"trusted": func(e *Event) { e.At.Trusted = false },
		}
		for name, change := range variants {
			e := base
			change(&e)
			if got := one(t, []Event{e}).ID; got == id {
				t.Errorf("changing the %s kept the ID %s", name, id)
			}
		}
	})

	t.Run("events without refs still get distinct IDs", func(t *testing.T) {
		e1 := Event{Type: Fork, Subject: x, Witness: ap2.id, At: ap2.at(0)}
		e2 := Event{Type: Fork, Subject: y, Witness: ap2.id, At: ap2.at(0)}
		incs := Coalesce([]Event{e1, e2}, DefaultWindow)
		if len(incs) != 2 || incs[0].ID == incs[1].ID {
			t.Errorf("two incidents without refs share an ID:\n%s", dump(incs))
		}
	})

	t.Run("the same event given twice counts once", func(t *testing.T) {
		f := &fixture{}
		e1, e2 := f.ev(MemberSilent, x, ap2, 0), f.ev(MemberSilent, x, ap3, time.Second)
		inc := one(t, []Event{e1, e2, e1})
		if inc.ID != wantID(e1, e2) || !slices.Equal(inc.Refs, refsOf(e1, e2)) {
			t.Errorf("ID %q refs %d; want the ID and refs of the two distinct events", inc.ID, len(inc.Refs))
		}
	})

	t.Run("a member's own account names the incident", func(t *testing.T) {
		// Two routers that hold the member's own account of its return
		// and different guesses of others about it make one incident ID,
		// so an acknowledgement of either covers both.
		f := &fixture{}
		own := f.ev(RebootPlanned, kitchen.id, kitchen, 0)
		silence := f.ev(MemberSilent, kitchen.id, ap2, -time.Second)
		guess := f.ev(RebootUnplanned, kitchen.id, ap3, time.Second)
		a, b := one(t, []Event{own, silence}), one(t, []Event{own, guess, silence})
		if a.ID != wantID(own) || b.ID != a.ID {
			t.Errorf("IDs %s and %s; want both %s, fixed by the own account", a.ID, b.ID, wantID(own))
		}
	})

	t.Run("an unrelated incident in the batch does not change it", func(t *testing.T) {
		f := &fixture{}
		e1, e2 := f.ev(MemberSilent, x, ap2, 0), f.ev(MemberSilent, x, ap3, time.Second)
		other := f.ev(Fork, y, ap4, 0)
		alone := one(t, []Event{e1, e2})
		incs := Coalesce([]Event{other, e1, e2}, DefaultWindow)
		found := false
		for _, inc := range incs {
			if inc.ID == alone.ID {
				found = true
			}
		}
		if !found {
			t.Errorf("ID %s not found among %d incidents of the bigger batch", alone.ID, len(incs))
		}
	})
}

func mustHex(t *testing.T, s string) uint64 {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 8 {
		t.Fatalf("ID %q is not 8 bytes of hex: %v", s, err)
	}
	return binary.BigEndian.Uint64(b)
}

func TestCoalesceEmpty(t *testing.T) {
	if got := Coalesce(nil, DefaultWindow); len(got) != 0 {
		t.Errorf("Coalesce(nil) = %d incidents, want none", len(got))
	}
	if got := Coalesce([]Event{}, DefaultWindow); len(got) != 0 {
		t.Errorf("Coalesce(empty) = %d incidents, want none", len(got))
	}
}

// mixed is a batch with every rule in it: a gateway reboot, a site-wide
// outage, unrelated members, a clock step, a flood and a duplicate.
func mixed() []Event {
	f := &fixture{}
	ap := router{id: member(0x20), boot: boot(0x20), up: 100 * time.Second}
	var site ids.MemberID
	evs := []Event{
		f.ev(InternetLost, ap2.id, ap2, 0),
		f.ev(RebootUnplanned, gw.id, ap3, 2*time.Second),
		f.ev(InternetLost, ap3.id, ap3, 3*time.Second),
		f.ev(RebootPlanned, member(0x0a), ap4, 3*time.Second),
		f.ev(Fork, member(0x0b), ap5, 3*time.Second),
		f.ev(Fork, member(0x0b), ap4, 4*time.Second),
		f.ev(UnderFlood, ap4.id, ap4, 5*time.Second),
		f.ev(UnderFlood, ap5.id, ap5, 5*time.Second),
		f.ev(InternetLost, kitchen.id, kitchen, time.Minute),
		f.ev(WanDown, office.id, office, time.Minute+time.Second),
		f.stamped(MemberSilent, member(0x0e), ap.id, clock.Stamp{Wall: t0.Add(-threeYears), Mono: 100 * time.Second, Boot: ap.boot}),
		f.stamped(InternetLost, ap.id, ap.id, clock.Stamp{Wall: t0.Add(6 * time.Second), Mono: 106 * time.Second, Trusted: true, Boot: ap.boot}),
		f.ev(RosterChangesDropped, site, gw, 2*time.Minute),
		f.ev(RebootUnplanned, member(0x0c), ap2, 4*time.Minute),
		f.ev(RebootUnplanned, member(0x0a), ap3, 4*time.Minute+2*time.Second),
		f.ev(InternetLost, ap5.id, ap5, 4*time.Minute+3*time.Second),
		f.ev(RebootUnplanned, member(0x0b), ap2, 4*time.Minute+4*time.Second),
		f.ev(MemberSilent, member(0x0a), ap4, 4*time.Minute+5*time.Second),
		// One instant of one boot, written in two time zones: the result
		// must not depend on which of the two anchors the timeline.
		f.stamped(InternetLost, kitchen.id, kitchen.id, kitchen.at(3*time.Minute)),
		f.stamped(WanDown, kitchen.id, kitchen.id, clock.Stamp{Wall: t0.Add(3 * time.Minute).In(time.FixedZone("UTC+1", 3600)),
			Mono: kitchen.up + 3*time.Minute, Trusted: true, Boot: kitchen.boot}),
		f.ev(Type("future_thing"), ap2.id, ap2, 2*time.Minute),
	}
	evs[0].Detail = map[string]string{"probe": "dns"}
	return append(evs, evs[1]) // the same event twice
}

// TestCoalesceDeterministic: the same events in any order give the same
// incidents, IDs included, and the caller's slice is left as it was.
func TestCoalesceDeterministic(t *testing.T) {
	evs := mixed()
	before := slices.Clone(evs)
	before[0].Detail = map[string]string{"probe": "dns"}
	want := Coalesce(evs, DefaultWindow)
	if !reflect.DeepEqual(evs, before) {
		t.Fatalf("Coalesce changed its input")
	}
	if len(want) < 6 {
		t.Fatalf("the mixed batch gave %d incidents, want at least 6:\n%s", len(want), dump(want))
	}
	for seed := uint64(0); seed < 200; seed++ {
		r := rand.New(rand.NewPCG(seed, 13))
		shuffled := slices.Clone(evs)
		r.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		if got := Coalesce(shuffled, DefaultWindow); !reflect.DeepEqual(got, want) {
			t.Fatalf("seed %d: order changed the result\n got:\n%s\nwant:\n%s", seed, dump(got), dump(want))
		}
	}
}

// TestCoalesceSweep checks, over 200 random batches, what must hold for every
// input: no event lost or counted twice, IDs distinct, every incident inside
// its window and running forward, the lists exactly the events' members and
// witnesses, Approximate exactly when a stamp is untrusted or the length is,
// and never two members' absences, two different facts, or a flood mixed
// with anything else in one incident.
func TestCoalesceSweep(t *testing.T) {
	types := []Type{MemberSilent, MemberBack, RebootPlanned, RebootUnplanned, Upgraded, LinkLost,
		WanDown, WanUp, InternetLost, InternetRestored, UplinkSwitched, MemberJoined, MemberLeft,
		UnderFlood, DuplicateIdentity, Fork, RosterChanged, RosterChangesDropped, Type("future_thing")}
	absence := map[Type]bool{MemberSilent: true, MemberBack: true, RebootPlanned: true,
		RebootUnplanned: true, Upgraded: true, LinkLost: true}
	link := map[Type]bool{WanDown: true, WanUp: true, InternetLost: true, InternetRestored: true, UplinkSwitched: true}

	for seed := uint64(0); seed < 200; seed++ {
		r := rand.New(rand.NewPCG(seed, 7))
		window := []time.Duration{DefaultWindow, 3 * time.Second, 0}[r.IntN(3)]
		f := &fixture{}
		n := 1 + r.IntN(60)
		evs := make([]Event, 0, n)
		byRef := map[ids.Hash]Event{}
		for range n {
			w := byte(1 + r.IntN(6))
			var b ids.BootID
			if r.IntN(10) > 0 {
				b = boot(w*16 + byte(r.IntN(2))) // two boots per witness; never shared between witnesses
			}
			d := time.Duration(r.IntN(60_000)) * time.Millisecond
			at := clock.Stamp{Wall: t0.Add(d), Mono: time.Duration(w)*time.Hour + d, Trusted: r.IntN(4) > 0, Boot: b}
			if r.IntN(8) == 0 {
				at.Wall = at.Wall.Add(-threeYears) // a clock not yet stepped
			}
			var subject ids.MemberID
			if s := r.IntN(7); s > 0 {
				subject = member(byte(s))
			}
			e := f.stamped(types[r.IntN(len(types))], subject, member(w), at)
			evs = append(evs, e)
			byRef[e.Ref] = e
		}
		incs := Coalesce(evs, window)

		seen := map[ids.Hash]int{}
		idSeen := map[string]bool{}
		for i, inc := range incs {
			where := fmt.Sprintf("seed %d incident %d", seed, i)
			if len(inc.ID) != 16 || idSeen[inc.ID] {
				t.Fatalf("%s: ID %q malformed or repeated", where, inc.ID)
			}
			idSeen[inc.ID] = true
			if len(inc.Refs) == 0 {
				t.Fatalf("%s: no events", where)
			}
			var mine []Event
			for _, ref := range inc.Refs {
				seen[ref]++
				mine = append(mine, byRef[ref])
			}
			if inc.ID != wantIncidentID(mine...) {
				t.Fatalf("%s: ID %s, want %s", where, inc.ID, wantIncidentID(mine...))
			}
			span, spanApprox := clock.Duration(inc.Start, inc.End)
			if span > window {
				t.Fatalf("%s: spans %v, window %v", where, span, window)
			}
			if back, _ := clock.Duration(inc.End, inc.Start); back > 0 {
				t.Fatalf("%s: runs backwards by %v", where, back)
			}

			members, witnesses, typeSet := map[string]bool{}, map[string]bool{}, map[Type]bool{}
			anyUntrusted, flood, hasLink := false, false, false
			// A member's own account of its return makes the others'
			// returns about it guesses, whose types are not told.
			ownAccount := map[ids.MemberID]bool{}
			for _, e := range mine {
				if absence[e.Type] && e.Type != MemberSilent && e.Subject != (ids.MemberID{}) && e.Witness == e.Subject {
					ownAccount[e.Subject] = true
				}
			}
			absent := map[ids.MemberID]bool{}
			absentTypes := map[Type]bool{}
			facts := map[string]bool{}
			for _, e := range mine {
				if e.Subject != (ids.MemberID{}) {
					members[e.Subject.String()] = true
				}
				if e.Witness != (ids.MemberID{}) {
					witnesses[e.Witness.String()] = true
				}
				if !(absence[e.Type] && e.Type != MemberSilent && e.Witness != e.Subject && ownAccount[e.Subject]) {
					typeSet[e.Type] = true
				}
				anyUntrusted = anyUntrusted || !e.At.Trusted
				switch {
				case absence[e.Type] && e.Subject != (ids.MemberID{}):
					absent[e.Subject] = true
					absentTypes[e.Type] = true
				case link[e.Type]:
					hasLink = true
				case e.Type == UnderFlood:
					flood = true
				default:
					facts[string(e.Type)+"/"+e.Subject.String()] = true
				}
			}
			if !sameSet(inc.Members, members) || !sameSet(inc.Witnesses, witnesses) {
				t.Fatalf("%s: members %v witnesses %v do not match the events", where, inc.Members, inc.Witnesses)
			}
			if inc.Causes != len(absent) {
				t.Fatalf("%s: Causes %d, but %d members are absent", where, inc.Causes, len(absent))
			}
			if !slices.IsSorted(inc.Witnesses) || !slices.IsSorted(inc.Members[:inc.Causes]) ||
				!slices.IsSorted(inc.Members[inc.Causes:]) {
				t.Fatalf("%s: lists not in ID order: members %v (causes %d) witnesses %v", where, inc.Members, inc.Causes, inc.Witnesses)
			}
			if len(inc.Events) != len(typeSet) {
				t.Fatalf("%s: Events %v, want each of %d types once", where, inc.Events, len(typeSet))
			}
			for _, typ := range inc.Events {
				if !typeSet[typ] {
					t.Fatalf("%s: Events lists %q, which no event has", where, typ)
				}
			}
			if inc.Approximate != (anyUntrusted || spanApprox) {
				t.Fatalf("%s: Approximate %v, untrusted stamp %v, length approximate %v", where, inc.Approximate, anyUntrusted, spanApprox)
			}
			// Rule (d): several absent members only with one kind of
			// absence, and never link_lost.
			if len(absent) > 1 && (len(absentTypes) != 1 || absentTypes[LinkLost]) {
				t.Fatalf("%s: absences %v of %d members in one incident", where, inc.Events, len(absent))
			}
			for m := range absent {
				if !slices.Contains(inc.Members[:inc.Causes], m.String()) {
					t.Fatalf("%s: absent member %s not among the causes %v", where, m, inc.Members[:inc.Causes])
				}
			}
			// Exactly one kind of cause: one fact (one type about one
			// subject), or a flood, or absences and link events.
			kinds := 0
			if len(facts) > 0 {
				kinds++
			}
			if flood {
				kinds++
			}
			if len(absent) > 0 || hasLink {
				kinds++
			}
			if kinds != 1 || len(facts) > 1 {
				t.Fatalf("%s: mixes causes: facts %v flood %v absent %d link %v events %v",
					where, facts, flood, len(absent), hasLink, inc.Events)
			}
		}
		for _, e := range evs {
			if seen[e.Ref] != 1 {
				t.Fatalf("seed %d: event %x in %d incidents, want exactly 1", seed, e.Ref[:4], seen[e.Ref])
			}
		}
		if len(seen) != len(evs) {
			t.Fatalf("seed %d: incidents hold %d refs, input had %d events", seed, len(seen), len(evs))
		}
	}
}

func sameSet(list []string, set map[string]bool) bool {
	if len(list) != len(set) {
		return false
	}
	for _, s := range list {
		if !set[s] {
			return false
		}
	}
	return true
}
