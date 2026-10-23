package elect

import (
	"bytes"
	"math"
	"math/rand/v2"
	"slices"
	"sort"
	"testing"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/ids"
)

// at is the "now" of every test that does not say otherwise: an ordinary
// wall time without a monotonic reading, as a decoded heartbeat stamp is.
var at = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)

// id returns a MemberID whose leading bytes are b and the rest zero.
func id(b ...byte) ids.MemberID {
	var m ids.MemberID
	copy(m[:], b)
	return m
}

// ready returns the view of a member that is eligible at at: a channel, the
// internet, a Telegram call 10 s ago, heard.
func ready(m ids.MemberID, prio int) View {
	return View{ID: m, HasChannel: true, InternetOK: true, TelegramOK: at.Add(-10 * time.Second), Priority: prio}
}

// mustSend fails the test unless Sender picks want.
func mustSend(t *testing.T, views []View, now time.Time, want ids.MemberID) {
	t.Helper()
	got, ok := Sender(views, now)
	if !ok || got != want {
		t.Fatalf("Sender = %v, %v; want %v, true", got, ok, want)
	}
}

// mustNotSend fails the test unless Sender reports no sender with the zero ID.
func mustNotSend(t *testing.T, views []View, now time.Time) {
	t.Helper()
	got, ok := Sender(views, now)
	if ok || got != (ids.MemberID{}) {
		t.Fatalf("Sender = %v, %v; want the zero ID, false", got, ok)
	}
}

// TestSenderDeterministic: five members hold the same view of the group,
// each in its own order (each lists itself first, then the others, and the
// same reversed). They all name the same sender: of the eligible, the one
// with the highest priority, and of those, the lowest ID.
func TestSenderDeterministic(t *testing.T) {
	a, b, c, d, e := id(0x05), id(0x09), id(0x02), id(0x01), id(0x00, 0x01)
	group := []View{
		ready(a, 1),
		ready(b, 3),
		ready(c, 3), // the sender: priority 3, and 0x02 is below 0x09
		func() View { v := ready(d, 3); v.Silent = true; return v }(),                          // lower ID, but silent
		func() View { v := ready(e, 7); v.TelegramOK = at.Add(-61 * time.Second); return v }(), // highest, but stale
	}
	for self := range group {
		order := append(slices.Clone(group[self:]), group[:self]...)
		mustSend(t, order, at, c)
		slices.Reverse(order)
		mustSend(t, order, at, c)
	}
}

// TestSenderExcludesStaleTelegram: a member whose last successful Telegram
// call was 61 s ago is not eligible, however high its priority; the next one
// sends.
func TestSenderExcludesStaleTelegram(t *testing.T) {
	top, next := id(0x01), id(0x02)
	group := []View{ready(top, 10), ready(next, 5)}
	mustSend(t, group, at, top)

	group[0].TelegramOK = at.Add(-61 * time.Second)
	mustSend(t, group, at, next)
}

// TestSenderWindowBoundary: the 60 s window is inclusive on both sides. A
// call exactly 60 s ago counts, a nanosecond more does not; a stamp from a
// peer whose clock runs ahead counts up to exactly 60 s in the future and no
// further.
func TestSenderWindowBoundary(t *testing.T) {
	if Window != 60*time.Second {
		t.Fatalf("Window = %v, want 60s (design 4.5)", Window)
	}
	top, next := id(0x01), id(0x02)
	cases := []struct {
		name  string
		ok    time.Time
		fresh bool
	}{
		{"now", at, true},
		{"59.999999999 s ago", at.Add(-Window + time.Nanosecond), true},
		{"exactly 60 s ago", at.Add(-Window), true},
		{"60 s and 1 ns ago", at.Add(-Window - time.Nanosecond), false},
		{"61 s ago", at.Add(-61 * time.Second), false},
		{"59.999999999 s ahead", at.Add(Window - time.Nanosecond), true},
		{"exactly 60 s ahead", at.Add(Window), true},
		{"60 s and 1 ns ahead", at.Add(Window + time.Nanosecond), false},
		{"61 s ahead", at.Add(61 * time.Second), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			top := ready(top, 10)
			top.TelegramOK = c.ok
			want := next
			if c.fresh {
				want = top.ID
			}
			mustSend(t, []View{top, ready(next, 5)}, at, want)
		})
	}
}

// TestSenderFailover: the sender goes silent and the next member is chosen;
// that one loses its internet and the one after it is chosen; when the first
// is heard again with a fresh Telegram call, it sends again (the highest
// priority always wins, as in VRRP with preemption).
func TestSenderFailover(t *testing.T) {
	a, b, c := id(0x0a), id(0x0b), id(0x0c)
	group := []View{ready(a, 10), ready(b, 5), ready(c, 1)}
	mustSend(t, group, at, a)

	group[0].Silent = true
	mustSend(t, group, at, b)

	group[1].InternetOK = false
	mustSend(t, group, at, c)

	group[0].Silent = false
	mustSend(t, group, at, a)
}

// TestNoSenderWhenNobodyReaches: when no member can reach Telegram, for
// whatever reason each, there is no sender, and the ID returned is zero.
func TestNoSenderWhenNobodyReaches(t *testing.T) {
	mustNotSend(t, nil, at)
	mustNotSend(t, []View{}, at)

	noChannel := ready(id(0x01), 9)
	noChannel.HasChannel = false
	noInternet := ready(id(0x02), 8)
	noInternet.InternetOK = false
	stale := ready(id(0x03), 7)
	stale.TelegramOK = at.Add(-61 * time.Second)
	never := ready(id(0x04), 6)
	never.TelegramOK = time.Time{}
	silent := ready(id(0x05), 5)
	silent.Silent = true
	ahead := ready(id(0x06), 4)
	ahead.TelegramOK = at.Add(61 * time.Second)
	mustNotSend(t, []View{noChannel, noInternet, stale, never, silent, ahead}, at)
}

// TestSenderEligibility: each condition on its own takes the member that
// would win out of the election, and the runner-up sends.
func TestSenderEligibility(t *testing.T) {
	top, next := id(0x01), id(0x02)
	cases := []struct {
		name  string
		spoil func(*View)
	}{
		{"no channel", func(v *View) { v.HasChannel = false }},
		{"no internet", func(v *View) { v.InternetOK = false }},
		{"silent", func(v *View) { v.Silent = true }},
		{"never reached Telegram", func(v *View) { v.TelegramOK = time.Time{} }},
		{"Telegram 61 s ago", func(v *View) { v.TelegramOK = at.Add(-61 * time.Second) }},
		{"Telegram 61 s ahead", func(v *View) { v.TelegramOK = at.Add(61 * time.Second) }},
		{"Telegram in 1970", func(v *View) { v.TelegramOK = time.Unix(0, 0).UTC() }},
		{"Telegram in 2262", func(v *View) { v.TelegramOK = time.Unix(0, math.MaxInt64).UTC() }},
		{"Telegram beyond what a Duration spans", func(v *View) { v.TelegramOK = time.Unix(1<<40, 0) }},
	}
	mustSend(t, []View{ready(top, 10), ready(next, 5)}, at, top)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := ready(top, 10)
			c.spoil(&v)
			mustSend(t, []View{v, ready(next, 5)}, at, next)
			mustSend(t, []View{ready(next, 5), v}, at, next)
		})
	}
}

// TestSenderTieBreak: the highest priority wins whatever the IDs; at equal
// priority the lowest ID wins, compared as bytes from the first.
func TestSenderTieBreak(t *testing.T) {
	low := id(0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff)
	high := id(0x01)
	lastLow := id(0x07, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01)
	lastHigh := id(0x07, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02)
	cases := []struct {
		name  string
		views []View
		want  ids.MemberID
	}{
		{"equal priority: the first byte decides", []View{ready(high, 3), ready(low, 3)}, low},
		{"equal priority: the last byte decides", []View{ready(lastHigh, 3), ready(lastLow, 3)}, lastLow},
		{"higher priority beats a lower ID", []View{ready(low, 1), ready(high, 2)}, high},
		{"negative priorities: -1 beats -5", []View{ready(low, -5), ready(high, -1)}, high},
		{"zero beats negative", []View{ready(low, -1), ready(high, 0)}, high},
		{"the extremes of int", []View{ready(low, math.MinInt), ready(high, math.MaxInt)}, high},
		{"three-way tie", []View{ready(lastHigh, 4), ready(high, 4), ready(lastLow, 4)}, high},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mustSend(t, c.views, at, c.want)
			r := slices.Clone(c.views)
			slices.Reverse(r)
			mustSend(t, r, at, c.want)
		})
	}
}

// TestSenderDuplicateIDs: two entries with one ID are a caller bug. Sender
// cannot tell which of them is true, so it names no sender rather than guess,
// whichever entry would have won and whatever the other entry says.
func TestSenderDuplicateIDs(t *testing.T) {
	a, b := id(0x01), id(0x02)
	silentA := ready(a, 10)
	silentA.Silent = true
	cases := []struct {
		name  string
		views []View
	}{
		{"the same entry twice", []View{ready(a, 10), ready(a, 10)}},
		{"the winner twice, one copy silent", []View{ready(a, 10), ready(b, 5), silentA}},
		{"the winner twice, one copy silent, other order", []View{silentA, ready(b, 5), ready(a, 10)}},
		{"a loser twice, the winner once", []View{ready(a, 10), ready(b, 5), ready(b, 1)}},
		{"twice at different priorities", []View{ready(b, 1), ready(b, 7)}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mustNotSend(t, c.views, at)
		})
	}
}

// TestSenderUsesGivenNow: Sender measures the age of a Telegram call against
// the now it is given, never against the machine's clock. A group living in
// 2001, or in 2100, still has a sender.
func TestSenderUsesGivenNow(t *testing.T) {
	for _, now := range []time.Time{
		time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC),
	} {
		v := ready(id(0x01), 1)
		v.TelegramOK = now.Add(-5 * time.Second)
		mustSend(t, []View{v}, now, v.ID)
	}
}

// TestSenderNeverReachedIsNeverFresh: the zero TelegramOK means the member
// never reached Telegram. It is not eligible even when now itself is within
// 60 s of the zero time (an uninitialised clock in the caller).
func TestSenderNeverReachedIsNeverFresh(t *testing.T) {
	for _, now := range []time.Time{{}, time.Time{}.Add(30 * time.Second), time.Time{}.Add(-30 * time.Second)} {
		v := ready(id(0x01), 1)
		v.TelegramOK = time.Time{}
		mustNotSend(t, []View{v}, now)
	}
}

// TestSenderLeavesInputAlone: Sender does not reorder or change the caller's
// slice; the caller's table order is its own business.
func TestSenderLeavesInputAlone(t *testing.T) {
	group := []View{ready(id(0x03), 1), ready(id(0x01), 1), ready(id(0x02), 9)}
	group[1].Silent = true
	before := slices.Clone(group)
	mustSend(t, group, at, id(0x02))
	for i := range group {
		if group[i] != before[i] {
			t.Fatalf("views[%d] changed: %+v, was %+v", i, group[i], before[i])
		}
	}
}

// TestSenderPermutationProperty: for 1000 seeded random groups, Sender gives
// the same answer for every order of the group it is tried with (all orders
// up to 5 members, 40 random ones and the reverse above), and that answer is
// the one a separate, sort-based reading of design 4.5 gives. The generator
// aims at what can go wrong: priorities that tie, IDs that differ only in
// their first or last byte, Telegram stamps a nanosecond either side of the
// window, extreme times and priorities, and duplicate IDs. Counters at the
// end prove the generator reached each of those.
func TestSenderPermutationProperty(t *testing.T) {
	const cases = 1000
	var stats struct{ sent, none, tieByID, dup, boundary, orders int }
	for seed := range uint64(cases) {
		r := rand.New(rand.NewPCG(seed, 0x726f6c6c63616c6c))
		views := randomGroup(r)
		want, wantOK, tie := oracle(views, at)
		switch {
		case sharedID(views):
			stats.dup++
		case wantOK:
			stats.sent++
		default:
			stats.none++
		}
		if tie {
			stats.tieByID++
		}
		for _, v := range views {
			if d := at.Sub(v.TelegramOK); !v.TelegramOK.IsZero() && (d == Window || d == -Window || d == Window+1 || d == -Window-1) {
				stats.boundary++
				break
			}
		}
		check := func(order []View) {
			t.Helper()
			stats.orders++
			got, ok := Sender(order, at)
			if got != want || ok != wantOK {
				t.Fatalf("seed %d: Sender = %v, %v; want %v, %v\norder: %+v", seed, got, ok, want, wantOK, order)
			}
		}
		if len(views) <= 5 {
			permute(slices.Clone(views), len(views), check)
		} else {
			check(slices.Clone(views))
			rev := slices.Clone(views)
			slices.Reverse(rev)
			check(rev)
			for range 40 {
				p := slices.Clone(views)
				r.Shuffle(len(p), func(i, j int) { p[i], p[j] = p[j], p[i] })
				check(p)
			}
		}
	}
	t.Logf("%d groups: %d with a sender, %d without, %d with a duplicate ID, %d decided by ID at equal priority, %d with a stamp at the window edge; %d orders tried",
		cases, stats.sent, stats.none, stats.dup, stats.tieByID, stats.boundary, stats.orders)
	// The generator must keep reaching every shape it aims at.
	if stats.sent < 300 || stats.none < 50 || stats.dup < 30 || stats.tieByID < 100 || stats.boundary < 100 {
		t.Fatalf("the generator no longer covers its shapes: %+v", stats)
	}
}

// randomGroup draws a group of 0 to 12 members, or the full 32 now and then.
func randomGroup(r *rand.Rand) []View {
	n := r.IntN(13)
	if r.IntN(20) == 0 {
		n = 32
	}
	edges := []time.Duration{-Window - 1, -Window, -Window + 1, 0, Window - 1, Window, Window + 1}
	extremes := []time.Time{
		{},
		time.Unix(0, 0).UTC(),
		time.Unix(0, math.MaxInt64).UTC(),
		time.Unix(1<<40, 0),
		time.Unix(-1<<40, 0),
	}
	views := make([]View, 0, n)
	for range n {
		var v View
		for i := range v.ID {
			v.ID[i] = byte(r.Uint32())
		}
		switch r.IntN(3) {
		case 0: // a first byte of 0, 1 or 2: the first byte often decides
			v.ID[0] = byte(r.IntN(3))
		case 1: // only the last byte differs between these
			clear(v.ID[:15])
			v.ID[0] = 0x07
		}
		if len(views) > 0 && r.IntN(60) == 0 {
			v.ID = views[r.IntN(len(views))].ID // a caller bug: a duplicate
		}
		v.HasChannel = r.IntN(6) != 0
		v.InternetOK = r.IntN(6) != 0
		v.Silent = r.IntN(7) == 0
		switch k := r.IntN(10); {
		case k < 3:
			v.TelegramOK = at.Add(-edges[r.IntN(len(edges))])
		case k < 4:
			v.TelegramOK = extremes[r.IntN(len(extremes))]
		default:
			v.TelegramOK = at.Add(-time.Duration(r.Int64N(int64(140*time.Second))) + 70*time.Second)
		}
		switch k := r.IntN(20); {
		case k == 0:
			v.Priority = math.MinInt
		case k == 1:
			v.Priority = math.MaxInt
		default:
			v.Priority = r.IntN(3) - 1
		}
		views = append(views, v)
	}
	return views
}

// oracle is design 4.5 read a second way: drop a group with a duplicate ID,
// keep the eligible members (the window checked with Before and After rather
// than a duration), sort them by priority down and ID up, take the first.
// tie reports whether the first two eligible shared the priority.
func oracle(views []View, now time.Time) (ids.MemberID, bool, bool) {
	if sharedID(views) {
		return ids.MemberID{}, false, false
	}
	var el []View
	for _, v := range views {
		fresh := !v.TelegramOK.IsZero() &&
			!v.TelegramOK.Before(now.Add(-Window)) &&
			!v.TelegramOK.After(now.Add(Window))
		if v.HasChannel && v.InternetOK && !v.Silent && fresh {
			el = append(el, v)
		}
	}
	if len(el) == 0 {
		return ids.MemberID{}, false, false
	}
	sort.SliceStable(el, func(i, j int) bool {
		if el[i].Priority != el[j].Priority {
			return el[i].Priority > el[j].Priority
		}
		return bytes.Compare(el[i].ID[:], el[j].ID[:]) < 0
	})
	return el[0].ID, true, len(el) > 1 && el[0].Priority == el[1].Priority
}

// sharedID reports whether two entries carry one ID: sorted IDs, neighbours
// compared (Sender itself uses a set).
func sharedID(views []View) bool {
	all := make([]ids.MemberID, 0, len(views))
	for _, v := range views {
		all = append(all, v.ID)
	}
	slices.SortFunc(all, func(a, b ids.MemberID) int { return bytes.Compare(a[:], b[:]) })
	for i := 1; i < len(all); i++ {
		if all[i] == all[i-1] {
			return true
		}
	}
	return false
}

// permute calls f with every order of a[:k] (Heap's algorithm).
func permute(a []View, k int, f func([]View)) {
	if k <= 1 {
		f(slices.Clone(a))
		return
	}
	for i := range k - 1 {
		permute(a, k-1, f)
		if k%2 == 0 {
			a[i], a[k-1] = a[k-1], a[i]
		} else {
			a[0], a[k-1] = a[k-1], a[0]
		}
	}
	permute(a, k-1, f)
}
