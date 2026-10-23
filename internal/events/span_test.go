package events

import (
	"bytes"
	"math/rand/v2"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/clock"
	"github.com/TAIPANBOX/rollcall/internal/ids"
)

// prevBoot is r's boot before the one at, which r.at stamps: another boot
// ID and a monotonic clock that started earlier.
func prevBoot(r router) router {
	p := r
	p.boot[1] = 0xee
	p.up = r.up / 2
	return p
}

// own returns r's own account of its return: typ, stamped at d on r's
// clocks, its absence begun at since on the clocks of r's previous boot,
// trusted as given.
func (f *fixture) own(typ Type, r router, since, d time.Duration, trusted bool) Event {
	e := f.ev(typ, r.id, r, d)
	e.Since = prevBoot(r).at(since)
	e.Since.Trusted = trusted
	return e
}

// TestAbsenceSpans: a member's own account of its return carries when its
// absence began. Returns of one kind of several members whose absences
// overlap are one incident (a site-wide power cut, the routers back up to
// minutes apart); absences that do not overlap, or whose starts lie far
// apart, stay separate. The others' records of the same absence of a member
// join its own account, and its own classification is the one told.
func TestAbsenceSpans(t *testing.T) {
	a, b, c := newRouter(0x0a), newRouter(0x0b), newRouter(0x0c)
	min := time.Minute
	f := &fixture{}

	t.Run("power cut: returns 25 s apart, absences overlap", func(t *testing.T) {
		evs := []Event{
			f.own(RebootUnplanned, a, -40*time.Second, 2*min, false),
			f.own(RebootUnplanned, b, -55*time.Second, 2*min+12*time.Second, false),
			f.own(RebootUnplanned, c, -10*time.Second, 2*min+25*time.Second, true),
		}
		inc := one(t, evs)
		if !slices.Equal(inc.Members, names(a.id, b.id, c.id)) || inc.Causes != 3 {
			t.Fatalf("members %v causes %d; want all three as causes", inc.Members, inc.Causes)
		}
		if want := t0.Add(-55 * time.Second); !inc.Start.Wall.Equal(want) {
			t.Fatalf("Start %v, want the earliest start of an absence, %v", inc.Start.Wall, want)
		}
		if !inc.End.Wall.Equal(t0.Add(2*min + 25*time.Second)) {
			t.Fatalf("End %v, want the last return", inc.End.Wall)
		}
		if !inc.Approximate {
			t.Fatal("starts known only roughly, yet the incident is not approximate")
		}
	})

	t.Run("absences that do not overlap stay apart", func(t *testing.T) {
		incs := Coalesce([]Event{
			f.own(RebootUnplanned, a, -10*time.Second, time.Minute, true),
			f.own(RebootUnplanned, b, 90*time.Second, 2*min+30*time.Second, true),
		}, DefaultWindow)
		if len(incs) != 2 {
			t.Fatalf("%d incidents, want 2:\n%s", len(incs), dump(incs))
		}
	})

	t.Run("back-to-back absences with close starts share no moment", func(t *testing.T) {
		// a is back 20 s after its start; b goes 10 s later and comes back
		// 100 s after a: starts 40 s apart, but nobody was away with both.
		incs := Coalesce([]Event{
			f.own(RebootUnplanned, a, -10*time.Second, 20*time.Second, true),
			f.own(RebootUnplanned, b, 30*time.Second, 2*min, true),
		}, DefaultWindow)
		if len(incs) != 2 {
			t.Fatalf("%d incidents, want 2:\n%s", len(incs), dump(incs))
		}
	})

	t.Run("a long absence does not take in another member's short one", func(t *testing.T) {
		week := 7 * 24 * time.Hour
		incs := Coalesce([]Event{
			f.own(RebootUnplanned, a, -week, 2*min, true),
			f.own(RebootUnplanned, b, -3*24*time.Hour, -3*24*time.Hour+2*min, true),
		}, DefaultWindow)
		if len(incs) != 2 {
			t.Fatalf("%d incidents, want 2:\n%s", len(incs), dump(incs))
		}
	})

	t.Run("overlapping absences of different kinds stay apart", func(t *testing.T) {
		incs := Coalesce([]Event{
			f.own(RebootPlanned, a, -10*time.Second, 2*min, true),
			f.own(RebootUnplanned, b, -10*time.Second, 2*min+20*time.Second, true),
		}, DefaultWindow)
		if len(incs) != 2 {
			t.Fatalf("%d incidents, want 2:\n%s", len(incs), dump(incs))
		}
	})

	t.Run("the others' records of the absence join the own account", func(t *testing.T) {
		silent := f.ev(MemberSilent, a.id, ap2, 0)
		guess := f.ev(RebootUnplanned, a.id, ap3, 2*min)
		back := f.ev(MemberBack, a.id, ap4, 2*min+time.Second)
		mine := f.own(RebootPlanned, a, -3*time.Second, 2*min+25*time.Second, true)
		inc := one(t, []Event{silent, guess, back, mine})
		if inc.Causes != 1 || !slices.Equal(inc.Members, names(a.id)) {
			t.Fatalf("members %v causes %d; want a alone", inc.Members, inc.Causes)
		}
		if slices.Contains(inc.Events, RebootUnplanned) || slices.Contains(inc.Events, MemberBack) ||
			!slices.Contains(inc.Events, RebootPlanned) || !slices.Contains(inc.Events, MemberSilent) {
			t.Fatalf("Events %v; want the member's own planned reboot and the silence, not the others' guesses", inc.Events)
		}
		if !inc.Start.Wall.Equal(t0) || inc.Approximate {
			t.Fatalf("Start %v approximate %v; want the observed silence, %v, exact", inc.Start.Wall, inc.Approximate, t0)
		}
		if !slices.Equal(inc.Witnesses, sortedNames(a.id, ap2.id, ap3.id, ap4.id)) {
			t.Fatalf("witnesses %v", inc.Witnesses)
		}
	})

	t.Run("a record after the return stays apart", func(t *testing.T) {
		mine := f.own(RebootUnplanned, a, -3*time.Second, 2*min, true)
		later := f.ev(RebootUnplanned, a.id, ap3, 2*min+40*time.Second)
		incs := Coalesce([]Event{mine, later}, DefaultWindow)
		if len(incs) != 2 {
			t.Fatalf("%d incidents, want 2:\n%s", len(incs), dump(incs))
		}
	})

	t.Run("an absence nobody else saw tells its start", func(t *testing.T) {
		inc := one(t, []Event{f.own(RebootUnplanned, a, -3*time.Second, 2*min, true)})
		if !inc.Start.Wall.Equal(t0.Add(-3*time.Second)) || inc.Approximate {
			t.Fatalf("Start %v approximate %v; want %v, exact", inc.Start.Wall, inc.Approximate, t0.Add(-3*time.Second))
		}
		if d, _ := clock.Duration(inc.Start, inc.End); d != 2*min+3*time.Second {
			t.Fatalf("the absence lasted %v, want 2m3s", d)
		}
	})

	t.Run("a negative window still puts every event alone", func(t *testing.T) {
		incs := Coalesce([]Event{
			f.own(RebootUnplanned, a, -10*time.Second, 2*min, true),
			f.own(RebootUnplanned, b, -10*time.Second, 2*min+20*time.Second, true),
			f.ev(RebootUnplanned, a.id, ap3, 2*min),
		}, -1)
		if len(incs) != 3 {
			t.Fatalf("%d incidents, want 3:\n%s", len(incs), dump(incs))
		}
	})
}

// TestOwnAccountWithoutStart: a member's own account without a known start
// is still preferred over the others' guesses, and adds no start.
func TestOwnAccountWithoutStart(t *testing.T) {
	a := newRouter(0x0a)
	f := &fixture{}
	guess := f.ev(RebootUnplanned, a.id, ap3, 0)
	mine := f.ev(RebootPlanned, a.id, a, 2*time.Second)
	if !Own(mine) || Own(guess) {
		t.Fatal("Own does not tell a member's own account from another's record")
	}
	inc := one(t, []Event{guess, mine})
	if !slices.Equal(inc.Events, []Type{RebootPlanned}) || !inc.Start.Wall.Equal(t0) {
		t.Fatalf("Events %v start %v; want [reboot_planned] from %v", inc.Events, inc.Start.Wall, t0)
	}
	var zero ids.MemberID
	if Own(Event{Type: RebootPlanned, Subject: zero, Witness: zero}) || Own(Event{Type: MemberSilent, Subject: a.id, Witness: a.id}) {
		t.Fatal("Own holds for an unknown member or for a silence")
	}
}

// TestAbsenceSpansSweep checks, over 200 random batches of own accounts with
// spans and the others' records, what must hold for every input: every
// event in exactly one incident, the ID by its formula, the same result in
// any order, the start never after the end, every record of a member's
// absence that lies within the span of its own account in that account's
// incident, and an incident of several causes telling one kind of absence.
func TestAbsenceSpansSweep(t *testing.T) {
	kinds := []Type{RebootUnplanned, RebootPlanned, Upgraded, MemberBack, MemberSilent, LinkLost, InternetLost}
	for seed := uint64(0); seed < 200; seed++ {
		r := rand.New(rand.NewPCG(seed, 11))
		f := &fixture{}
		var evs []Event
		for range 1 + r.IntN(30) {
			s := newRouter(byte(1 + r.IntN(5)))
			s.trusted = r.IntN(4) > 0
			d := time.Duration(r.IntN(600)) * time.Second
			if r.IntN(3) == 0 {
				typ := []Type{RebootUnplanned, RebootPlanned, Upgraded}[r.IntN(3)]
				evs = append(evs, f.own(typ, s, d-time.Duration(r.IntN(300))*time.Second, d, r.IntN(2) == 0))
				continue
			}
			w := newRouter(byte(1 + r.IntN(5)))
			evs = append(evs, f.ev(kinds[r.IntN(len(kinds))], s.id, w, d))
		}
		incs := Coalesce(evs, DefaultWindow)
		where := map[ids.Hash]int{}
		byRef := map[ids.Hash]Event{}
		for _, e := range evs {
			byRef[e.Ref] = e
		}
		for i, inc := range incs {
			var mine []Event
			for _, ref := range inc.Refs {
				if _, dup := where[ref]; dup {
					t.Fatalf("seed %d: event %x in two incidents", seed, ref[:4])
				}
				where[ref] = i
				mine = append(mine, byRef[ref])
			}
			if inc.ID != wantIncidentID(mine...) {
				t.Fatalf("seed %d incident %d: ID %s, want %s", seed, i, inc.ID, wantIncidentID(mine...))
			}
			if inc.Start.Wall.After(inc.End.Wall) {
				t.Fatalf("seed %d incident %d: starts %v after it ends %v", seed, i, inc.Start.Wall, inc.End.Wall)
			}
			if inc.Causes > 1 {
				told := slices.DeleteFunc(slices.Clone(inc.Events), func(t Type) bool { return t == MemberSilent || t == InternetLost })
				if len(told) > 1 || slices.Contains(told, LinkLost) {
					t.Fatalf("seed %d incident %d: %d causes told as %v", seed, i, inc.Causes, inc.Events)
				}
			}
		}
		if len(where) != len(evs) {
			t.Fatalf("seed %d: %d of %d events placed", seed, len(where), len(evs))
		}
		for _, u := range evs {
			if !spanned(u) {
				continue
			}
			for _, e := range evs {
				if e.Subject != u.Subject || Own(e) || !absenceType(e.Type) ||
					e.At.Wall.Before(u.Since.Wall.Add(-DefaultWindow)) || e.At.Wall.After(u.At.Wall.Add(DefaultWindow)) {
					continue
				}
				if where[e.Ref] != where[u.Ref] && !coveredEarlier(evs, u, e) {
					t.Fatalf("seed %d: %s about %x at %v lies within the own account [%v, %v] but in another incident",
						seed, e.Type, e.Subject[:1], e.At.Wall, u.Since.Wall, u.At.Wall)
				}
			}
		}
		for k := uint64(0); k < 3; k++ {
			sh := slices.Clone(evs)
			rand.New(rand.NewPCG(seed, k)).Shuffle(len(sh), func(i, j int) { sh[i], sh[j] = sh[j], sh[i] })
			if got := Coalesce(sh, DefaultWindow); !reflect.DeepEqual(got, incs) {
				t.Fatalf("seed %d: order changed the result\n got:\n%s\nwant:\n%s", seed, dump(got), dump(incs))
			}
		}
	}
}

func absenceType(t Type) bool {
	switch t {
	case MemberSilent, MemberBack, RebootPlanned, RebootUnplanned, Upgraded, LinkLost:
		return true
	}
	return false
}

// coveredEarlier reports whether e also lies within the span of an own
// account of its subject that comes before u: it then goes with that one.
func coveredEarlier(evs []Event, u, e Event) bool {
	for _, v := range evs {
		if !spanned(v) || v.Subject != u.Subject || v.Ref == u.Ref {
			continue
		}
		if !v.At.Wall.Before(u.At.Wall) && !(v.At.Wall.Equal(u.At.Wall) && bytes.Compare(record(v), record(u)) < 0) {
			continue
		}
		if !e.At.Wall.Before(v.Since.Wall.Add(-DefaultWindow)) && !e.At.Wall.After(v.At.Wall.Add(DefaultWindow)) {
			return true
		}
	}
	return false
}
