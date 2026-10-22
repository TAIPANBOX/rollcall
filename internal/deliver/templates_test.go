package deliver

import (
	"encoding/hex"
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/TAIPANBOX/rollcall/internal/clock"
	"github.com/TAIPANBOX/rollcall/internal/events"
	"github.com/TAIPANBOX/rollcall/internal/ids"
)

// member returns a test member ID; n orders them.
func member(n byte) ids.MemberID {
	var m ids.MemberID
	m[0] = n
	m[15] = 0xa5
	return m
}

// hexOf is the form an incident names a member in.
func hexOf(m ids.MemberID) string { return hex.EncodeToString(m[:]) }

// The fixtures' routers, in ID order: gateway, ap-kitchen, ap-office. The
// examples of design 4.9 list witnesses in this order.
var (
	gwID      = member(1)
	kitchenID = member(2)
	officeID  = member(3)
	garageID  = member(4)
	gwHex     = hexOf(gwID)
	kitchen   = hexOf(kitchenID)
	office    = hexOf(officeID)
	garage    = hexOf(garageID)
	names     = map[string]string{gwHex: "gateway", kitchen: "ap-kitchen", office: "ap-office", garage: "ap-garage"}
	bootA     = ids.BootID{0xb0, 1}
)

// cet is the router's configured zone in the fixtures: UTC+1, so a test that
// formats in UTC by mistake shows the wrong hour.
var cet = time.FixedZone("CET", 3600)

// local returns a trusted stamp at hh:mm:ss on 22 Oct 2026 in cet, on one
// boot whose monotonic clock started at midnight UTC, so that two stamps of
// one fixture measure their distance on the monotonic clock.
func local(hh, mm, ss int) clock.Stamp {
	w := time.Date(2026, 10, 22, hh, mm, ss, 0, cet).UTC()
	return clock.Stamp{Wall: w, Mono: w.Sub(time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC)), Trusted: true, Boot: bootA}
}

// absence returns an incident about the causes, spanning start to end.
func absence(start, end clock.Stamp, causes []string, types ...events.Type) events.Incident {
	return events.Incident{
		ID:        "0123456789abcdef",
		Start:     start,
		End:       end,
		Members:   causes,
		Causes:    len(causes),
		Events:    types,
		Witnesses: []string{gwHex},
	}
}

// fact returns an incident of one fact about subject (zero for none).
func fact(at clock.Stamp, subject string, typ events.Type) events.Incident {
	var members []string
	if subject != "" {
		members = []string{subject}
	}
	return events.Incident{ID: "0123456789abcdef", Start: at, End: at, Members: members, Events: []events.Type{typ}, Witnesses: []string{gwHex}}
}

// link returns a site-wide incident of link events seen by the witnesses.
func link(start, end clock.Stamp, witnesses []string, types ...events.Type) events.Incident {
	return events.Incident{ID: "0123456789abcdef", Start: start, End: end, Members: witnesses, Events: types, Witnesses: witnesses}
}

func TestRenderExamples(t *testing.T) {
	cases := []struct {
		name string
		inc  events.Incident
		f    Facts
		want string
	}{
		{
			"crash",
			absence(local(14, 2, 0), local(14, 3, 5), []string{kitchen}, events.MemberSilent, events.RebootUnplanned),
			Facts{Names: names},
			"Home: ap-kitchen rebooted unexpectedly at 14:02, back after 1 min 5 s.",
		},
		{
			"internet outage",
			link(local(3, 12, 0), local(3, 40, 0), []string{gwHex, kitchen, office}, events.InternetLost, events.InternetRestored),
			Facts{Names: names},
			"Home: internet was down from 03:12 to 03:40 (28 min). Seen by gateway, ap-kitchen, ap-office.",
		},
		{
			"upgrade",
			absence(local(2, 0, 0), local(2, 3, 0), []string{gwHex}, events.MemberSilent, events.Upgraded),
			Facts{Names: names, From: "25.12.4", To: "25.12.5"},
			"Home: gateway upgraded 25.12.4 -> 25.12.5 at 02:00, back after 3 min.",
		},
		{
			"link lost",
			absence(local(14, 2, 0), local(14, 5, 0), []string{office}, events.MemberSilent, events.LinkLost),
			Facts{Names: names},
			"Home: ap-office lost contact 14:02 to 14:05 but stayed up: a link problem, not a reboot.",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Render(c.inc, "Home", cet, c.f)
			if got != c.want {
				t.Errorf("Render =\n  %q\nwant\n  %q", got, c.want)
			}
			if strings.ContainsAny(got, "\u2013\u2014") {
				t.Errorf("Render = %q: an en or em dash", got)
			}
		})
	}
}

func TestRenderDroppedChanges(t *testing.T) {
	inc := fact(local(14, 2, 0), "", events.RosterChangesDropped)
	cases := []struct {
		name    string
		changes []Change
		want    string
	}{
		{
			"the example",
			[]Change{{Kind: ChangeRemoved, Member: "ap-garage", By: "backup-admin"}},
			"Home: after the network healed, these changes were undone: ap-garage removed (by backup-admin). Repeat them if they are still wanted.",
		},
		{
			"each change and who made it",
			[]Change{
				{Kind: ChangeRemoved, Member: "ap-garage", By: "backup-admin"},
				{Kind: ChangeAdded, Member: "ap-attic", By: "backup-admin"},
				{Kind: ChangeRoles, Member: "ap-office", By: "gateway"},
			},
			"Home: after the network healed, these changes were undone: ap-garage removed (by backup-admin), ap-attic added (by backup-admin), ap-office roles changed (by gateway). Repeat them if they are still wanted.",
		},
		{
			"no details known",
			nil,
			"Home: after the network healed, changes made during the split were undone. Repeat them if they are still wanted.",
		},
		{
			"a name that is not a roster name is not repeated",
			[]Change{{Kind: ChangeRemoved, Member: "evil.example", By: "Visit\nhttp://x"}},
			"Home: after the network healed, these changes were undone: an unknown router removed. Repeat them if they are still wanted.",
		},
		{
			"an unknown kind",
			[]Change{{Kind: ChangeKind(99), Member: "ap-garage", By: "gateway"}},
			"Home: after the network healed, these changes were undone: ap-garage changed (by gateway). Repeat them if they are still wanted.",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Render(inc, "Home", cet, Facts{Names: names, Changes: c.changes})
			if got != c.want {
				t.Errorf("Render =\n  %q\nwant\n  %q", got, c.want)
			}
			if strings.Contains(got, "\n") {
				t.Errorf("Render = %q: more than one line", got)
			}
		})
	}
}

func TestRenderRosterChanged(t *testing.T) {
	inc := fact(local(9, 30, 0), "", events.RosterChanged)
	got := Render(inc, "Home", cet, Facts{Changes: []Change{{Kind: ChangeRemoved, Member: "ap-office", By: "gateway"}}})
	if want := "Home: the group changed: ap-office removed (by gateway)."; got != want {
		t.Errorf("Render = %q, want %q", got, want)
	}
	got = Render(inc, "Home", cet, Facts{})
	if want := "Home: the group changed at 09:30."; got != want {
		t.Errorf("Render = %q, want %q", got, want)
	}
}

func TestRenderConfirmations(t *testing.T) {
	crash := absence(local(14, 2, 0), local(14, 3, 5), []string{kitchen}, events.MemberSilent, events.RebootUnplanned)
	outage := link(local(3, 12, 0), local(3, 40, 0), []string{gwHex, kitchen, office}, events.InternetLost, events.InternetRestored)
	cases := []struct {
		name          string
		inc           events.Incident
		confirmed, of int
		want          string
	}{
		{"3 of 4", crash, 3, 4, "Home: ap-kitchen rebooted unexpectedly at 14:02, back after 1 min 5 s, confirmed by 3 of 4."},
		{"0 of 4 is said", crash, 0, 4, "Home: ap-kitchen rebooted unexpectedly at 14:02, back after 1 min 5 s, confirmed by 0 of 4."},
		{"all", crash, 4, 4, "Home: ap-kitchen rebooted unexpectedly at 14:02, back after 1 min 5 s, confirmed by 4 of 4."},
		{"on the first sentence", outage, 2, 3, "Home: internet was down from 03:12 to 03:40 (28 min), confirmed by 2 of 3. Seen by gateway, ap-kitchen, ap-office."},
		{"none possible: left out", crash, 0, 0, "Home: ap-kitchen rebooted unexpectedly at 14:02, back after 1 min 5 s."},
		{"more than possible: left out", crash, 5, 4, "Home: ap-kitchen rebooted unexpectedly at 14:02, back after 1 min 5 s."},
		{"negative: left out", crash, -1, 4, "Home: ap-kitchen rebooted unexpectedly at 14:02, back after 1 min 5 s."},
		{"negative total: left out", crash, 0, -4, "Home: ap-kitchen rebooted unexpectedly at 14:02, back after 1 min 5 s."},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Render(c.inc, "Home", cet, Facts{Names: names, Confirmed: c.confirmed, Of: c.of})
			if got != c.want {
				t.Errorf("Render =\n  %q\nwant\n  %q", got, c.want)
			}
		})
	}
}

// TestRenderEveryShape holds one line for every kind of incident Coalesce
// makes, including the ones whose start is not in the incident.
func TestRenderEveryShape(t *testing.T) {
	at, back := local(14, 2, 0), local(14, 3, 5)
	cases := []struct {
		name string
		inc  events.Incident
		f    Facts
		want string
	}{
		{"silent", absence(at, at, []string{kitchen}, events.MemberSilent), Facts{Names: names},
			"Home: ap-kitchen stopped answering at 14:02."},
		{"silent with the internet of others lost", absence(at, local(14, 2, 8), []string{gwHex}, events.MemberSilent, events.InternetLost),
			Facts{Names: names}, "Home: gateway stopped answering at 14:02."},
		{"crash, start not known", absence(back, back, []string{kitchen}, events.RebootUnplanned), Facts{Names: names},
			"Home: ap-kitchen rebooted unexpectedly, back at 14:03."},
		{"planned", absence(at, back, []string{kitchen}, events.MemberSilent, events.RebootPlanned), Facts{Names: names},
			"Home: ap-kitchen rebooted as planned at 14:02, back after 1 min 5 s."},
		{"planned, start not known", absence(back, back, []string{kitchen}, events.RebootPlanned), Facts{Names: names},
			"Home: ap-kitchen rebooted as planned, back at 14:03."},
		{"upgrade without versions", absence(at, back, []string{gwHex}, events.MemberSilent, events.Upgraded), Facts{Names: names},
			"Home: gateway upgraded at 14:02, back after 1 min 5 s."},
		{"upgrade, start not known", absence(back, back, []string{gwHex}, events.Upgraded), Facts{Names: names, From: "25.12.4", To: "25.12.5"},
			"Home: gateway upgraded 25.12.4 -> 25.12.5, back at 14:03."},
		{"upgrade with one version only", absence(at, back, []string{gwHex}, events.MemberSilent, events.Upgraded), Facts{Names: names, To: "25.12.5"},
			"Home: gateway upgraded at 14:02, back after 1 min 5 s."},
		{"link lost, start not known", absence(back, back, []string{office}, events.LinkLost), Facts{Names: names},
			"Home: ap-office lost contact until 14:03 but stayed up: a link problem, not a reboot."},
		{"back", absence(at, back, []string{kitchen}, events.MemberSilent, events.MemberBack), Facts{Names: names},
			"Home: ap-kitchen went silent at 14:02, back after 1 min 5 s."},
		{"back, start not known", absence(back, back, []string{kitchen}, events.MemberBack), Facts{Names: names},
			"Home: ap-kitchen answered again at 14:03."},
		{"several members, one absence", absence(at, at, []string{gwHex, kitchen, office}, events.MemberSilent), Facts{Names: names},
			"Home: gateway, ap-kitchen, ap-office stopped answering at 14:02."},
		{"several members rebooted", absence(back, back, []string{gwHex, kitchen}, events.RebootUnplanned), Facts{Names: names},
			"Home: gateway, ap-kitchen rebooted unexpectedly, back at 14:03."},
		{"the strongest return wins", absence(at, back, []string{gwHex}, events.MemberSilent, events.LinkLost, events.Upgraded), Facts{Names: names},
			"Home: gateway upgraded at 14:02, back after 1 min 5 s."},
		{"absence of an unknown member", events.Incident{ID: "0123456789abcdef", Start: at, End: at, Events: []events.Type{events.MemberSilent}},
			Facts{Names: names}, "Home: an unknown router stopped answering at 14:02."},
		{"internet lost", link(at, at, []string{kitchen, office}, events.InternetLost), Facts{Names: names},
			"Home: internet lost at 14:02. Seen by ap-kitchen, ap-office."},
		{"internet back", link(back, back, []string{kitchen}, events.InternetRestored), Facts{Names: names},
			"Home: internet came back at 14:03. Seen by ap-kitchen."},
		{"wan down and up", link(at, back, []string{gwHex}, events.WanDown, events.WanUp), Facts{Names: names},
			"Home: WAN was down from 14:02 to 14:03 (1 min 5 s). Seen by gateway."},
		{"wan down", link(at, at, []string{gwHex}, events.WanDown), Facts{Names: names},
			"Home: WAN went down at 14:02. Seen by gateway."},
		{"wan up", link(back, back, []string{gwHex}, events.WanUp), Facts{Names: names},
			"Home: WAN came back at 14:03. Seen by gateway."},
		{"internet outranks wan", link(at, back, []string{gwHex}, events.WanDown, events.InternetLost, events.InternetRestored), Facts{Names: names},
			"Home: internet was down from 14:02 to 14:03 (1 min 5 s). Seen by gateway."},
		{"uplink switched", link(at, at, []string{gwHex}, events.UplinkSwitched), Facts{Names: names},
			"Home: uplink switched at 14:02. Seen by gateway."},
		{"wan outranks uplink", link(at, at, []string{gwHex}, events.UplinkSwitched, events.WanDown), Facts{Names: names},
			"Home: WAN went down at 14:02. Seen by gateway."},
		{"flood", link(at, at, []string{gwHex, office}, events.UnderFlood), Facts{Names: names},
			"Home: a flood of packets that failed authentication reached the group at 14:02. Seen by gateway, ap-office."},
		{"duplicate identity", fact(at, kitchen, events.DuplicateIdentity), Facts{Names: names},
			"Home: two devices answered as ap-kitchen at 14:02."},
		{"fork", fact(at, office, events.Fork), Facts{Names: names},
			"Home: ap-office showed different histories to different routers at 14:02; the proof is kept."},
		{"joined", fact(at, garage, events.MemberJoined), Facts{Names: names},
			"Home: ap-garage joined the group at 14:02."},
		{"left", fact(at, garage, events.MemberLeft), Facts{Names: names},
			"Home: ap-garage left the group at 14:02."},
		{"a type of a newer version", fact(at, garage, events.Type("cpu_hot")), Facts{Names: names},
			"Home: event cpu_hot at 14:02."},
		{"a type that is not a plain word", fact(at, garage, events.Type("visit evil.example")), Facts{Names: names},
			"Home: an unknown event at 14:02."},
		{"no type at all", events.Incident{ID: "0123456789abcdef", Start: at, End: at}, Facts{Names: names},
			"Home: an unknown event at 14:02."},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Render(c.inc, "Home", cet, c.f)
			if got != c.want {
				t.Errorf("Render =\n  %q\nwant\n  %q", got, c.want)
			}
		})
	}
}

// TestRenderFromCoalesce renders incidents as Coalesce really makes them.
func TestRenderFromCoalesce(t *testing.T) {
	gwBoot, apBoot := ids.BootID{1}, ids.BootID{2}
	st := func(boot ids.BootID, d time.Duration) clock.Stamp {
		w := time.Date(2026, 10, 22, 13, 2, 0, 0, time.UTC).Add(d)
		return clock.Stamp{Wall: w, Mono: time.Hour + d, Trusted: true, Boot: boot}
	}
	evs := []events.Event{
		{Type: events.MemberSilent, Subject: gwID, Witness: kitchenID, At: st(apBoot, 0), Ref: ids.Hash{1}},
		{Type: events.InternetLost, Subject: kitchenID, Witness: kitchenID, At: st(apBoot, 3*time.Second), Ref: ids.Hash{2}},
		{Type: events.InternetLost, Subject: officeID, Witness: officeID, At: st(gwBoot, 4*time.Second), Ref: ids.Hash{3}},
	}
	incs := events.Coalesce(evs, events.DefaultWindow)
	if len(incs) != 1 {
		t.Fatalf("Coalesce gave %d incidents, want 1", len(incs))
	}
	got := Render(incs[0], "Home", cet, Facts{Names: names})
	if want := "Home: gateway stopped answering at 14:02."; got != want {
		t.Errorf("Render = %q, want %q", got, want)
	}
}

func TestRenderApproximate(t *testing.T) {
	inc := absence(local(14, 2, 0), local(14, 3, 5), []string{kitchen}, events.MemberSilent, events.RebootUnplanned)
	inc.Approximate = true
	got := Render(inc, "Home", cet, Facts{Names: names, Confirmed: 1, Of: 2})
	want := "Home: ap-kitchen rebooted unexpectedly at 14:02, back after 1 min 5 s, confirmed by 1 of 2. Times are approximate."
	if got != want {
		t.Errorf("Render =\n  %q\nwant\n  %q", got, want)
	}
}

// TestRenderApproximateSpan: a span the clocks cannot measure exactly is
// called approximate even when the incident does not say so, as a merged
// incident built by the node might not.
func TestRenderApproximateSpan(t *testing.T) {
	start, end := local(14, 2, 0), local(14, 3, 5)
	end.Boot, end.Trusted = ids.BootID{0xb0, 2}, false // another boot, untrusted
	inc := absence(start, end, []string{kitchen}, events.MemberSilent, events.RebootUnplanned)
	got := Render(inc, "Home", cet, Facts{Names: names})
	if want := "Home: ap-kitchen rebooted unexpectedly at 14:02, back after 1 min 5 s. Times are approximate."; got != want {
		t.Errorf("Render =\n  %q\nwant\n  %q", got, want)
	}
	// The same on one boot is exact, and says nothing.
	inc = absence(start, local(14, 3, 5), []string{kitchen}, events.MemberSilent, events.RebootUnplanned)
	if got := Render(inc, "Home", cet, Facts{Names: names}); strings.Contains(got, "approximate") {
		t.Errorf("Render = %q", got)
	}
}

func TestRenderTimeZone(t *testing.T) {
	inc := absence(local(14, 2, 0), local(14, 3, 5), []string{kitchen}, events.MemberSilent, events.RebootUnplanned)
	if got, want := Render(inc, "Home", nil, Facts{Names: names}), "Home: ap-kitchen rebooted unexpectedly at 13:02, back after 1 min 5 s."; got != want {
		t.Errorf("nil zone: Render = %q, want %q (UTC)", got, want)
	}
	east := time.FixedZone("UTC+3", 3*3600)
	if got, want := Render(inc, "Home", east, Facts{Names: names}), "Home: ap-kitchen rebooted unexpectedly at 16:02, back after 1 min 5 s."; got != want {
		t.Errorf("UTC+3: Render = %q, want %q", got, want)
	}
}

func TestRenderAcrossMidnight(t *testing.T) {
	start := local(23, 50, 0)
	end := start
	end.Wall = end.Wall.Add(20 * time.Minute)
	end.Mono += 20 * time.Minute
	inc := link(start, end, []string{gwHex}, events.InternetLost, events.InternetRestored)
	got := Render(inc, "Home", cet, Facts{Names: names})
	if want := "Home: internet was down from 22 Oct 23:50 to 23 Oct 00:10 (20 min). Seen by gateway."; got != want {
		t.Errorf("Render =\n  %q\nwant\n  %q", got, want)
	}
}

func TestDurationText(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{-time.Second, "0 s"},
		{0, "0 s"},
		{499 * time.Millisecond, "0 s"},
		{500 * time.Millisecond, "1 s"},
		{59*time.Second + 400*time.Millisecond, "59 s"},
		{59*time.Second + 500*time.Millisecond, "1 min"},
		{65 * time.Second, "1 min 5 s"},
		{3 * time.Minute, "3 min"},
		{28 * time.Minute, "28 min"},
		{59*time.Minute + 59*time.Second, "59 min 59 s"},
		{59*time.Minute + 59*time.Second + 500*time.Millisecond, "1 h"},
		{61*time.Minute + 29*time.Second, "1 h 1 min"},
		{61*time.Minute + 30*time.Second, "1 h 2 min"},
		{2 * time.Hour, "2 h"},
		{23*time.Hour + 59*time.Minute + 29*time.Second, "23 h 59 min"},
		{23*time.Hour + 59*time.Minute + 30*time.Second, "1 d"},
		{26*time.Hour + 29*time.Minute, "1 d 2 h"},
		{26*time.Hour + 30*time.Minute, "1 d 3 h"},
		{48 * time.Hour, "2 d"},
	}
	for _, c := range cases {
		if got := durationText(c.d); got != c.want {
			t.Errorf("durationText(%v) = %q, want %q", c.d, got, c.want)
		}
	}
}

func TestRenderNames(t *testing.T) {
	at := local(14, 2, 0)
	cases := []struct {
		name  string
		names map[string]string
		who   string
		want  string
	}{
		{"known", names, kitchen, "Home: ap-kitchen stopped answering at 14:02."},
		{"not in the roster", nil, kitchen, "Home: router 02000000 stopped answering at 14:02."},
		{"a roster name only", map[string]string{kitchen: "evil.example"}, kitchen, "Home: router 02000000 stopped answering at 14:02."},
		{"upper case is not a roster name", map[string]string{kitchen: "AP-Kitchen"}, kitchen, "Home: router 02000000 stopped answering at 14:02."},
		{"a line break", map[string]string{kitchen: "ap\nkitchen"}, kitchen, "Home: router 02000000 stopped answering at 14:02."},
		{"not a member ID", names, "not-hex", "Home: an unknown router stopped answering at 14:02."},
		{"a short ID", names, "0200", "Home: an unknown router stopped answering at 14:02."},
		{"upper-case hex is not the form", names, strings.ToUpper(kitchen), "Home: an unknown router stopped answering at 14:02."},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Render(absence(at, at, []string{c.who}, events.MemberSilent), "Home", cet, Facts{Names: c.names})
			if got != c.want {
				t.Errorf("Render = %q, want %q", got, c.want)
			}
		})
	}
}

func TestRenderVersions(t *testing.T) {
	inc := absence(local(2, 0, 0), local(2, 3, 0), []string{gwHex}, events.MemberSilent, events.Upgraded)
	shown := []struct{ from, to string }{
		{"25.12.4", "25.12.5"},
		{"24.10.0-rc1", "24.10.0"},
		{"SNAPSHOT", "r28427-6df0e3d02a"},
		{"23.05.5", "24.10.0_beta"},
	}
	for _, v := range shown {
		got := Render(inc, "Home", cet, Facts{Names: names, From: v.from, To: v.to})
		if want := "Home: gateway upgraded " + v.from + " -> " + v.to + " at 02:00, back after 3 min."; got != want {
			t.Errorf("versions %q -> %q: Render = %q, want %q", v.from, v.to, got, want)
		}
	}
	// A version is a peer string: anything that could become a link, a
	// mention, a command or a second line is not repeated.
	hidden := []string{
		"evil.example", "1.evil.com", "25.12.x", "25..12", ".25", "25.", "a.b",
		"@admin", "#tag", "/start", "$X", "+15551234567", "25 12", "25\n12", "25\u202e12",
		"-25", "", strings.Repeat("1", 33), "25.12.4/x", "http://x", "ab:cd",
	}
	for _, v := range hidden {
		for _, pair := range [][2]string{{v, "25.12.5"}, {"25.12.4", v}} {
			got := Render(inc, "Home", cet, Facts{Names: names, From: pair[0], To: pair[1]})
			if want := "Home: gateway upgraded at 02:00, back after 3 min."; got != want {
				t.Errorf("versions %q -> %q: Render = %q, want %q", pair[0], pair[1], got, want)
			}
		}
	}
	if got, want := Render(inc, "Home", cet, Facts{Names: names, From: strings.Repeat("1", 32), To: "2"}),
		"Home: gateway upgraded "+strings.Repeat("1", 32)+" -> 2 at 02:00, back after 3 min."; got != want {
		t.Errorf("32 characters: Render = %q, want %q", got, want)
	}
}

// TestRenderPlainText holds that a message is plain text: nothing is escaped
// for Markdown or HTML and nothing is added for them.
func TestRenderPlainText(t *testing.T) {
	inc := absence(local(14, 2, 0), local(14, 2, 0), []string{kitchen}, events.MemberSilent)
	site := `Home_1 *main* <b>&amp;</b> [x](y) \`
	got := Render(inc, site, cet, Facts{Names: names})
	if want := site + ": ap-kitchen stopped answering at 14:02."; got != want {
		t.Errorf("Render = %q, want %q", got, want)
	}
}

func TestRenderStripsControl(t *testing.T) {
	inc := absence(local(14, 2, 0), local(14, 2, 0), []string{kitchen}, events.MemberSilent)
	cases := []struct{ site, want string }{
		{"Ho\nme", "Home"},
		{"Ho\r\nme\t", "Home"},
		{"\x1b[31mHome", "[31mHome"},
		{"Home\u202e", "Home"},
		{"Ho\u200bme", "Home"},
		{"Home\x00", "Home"},
		{"Ho\xffme", "Home"},
		{"Dom\u00f4vka", "Dom\u00f4vka"},
		{"  Home  ", "Home"},
		{"\u200b Home", "Home"},
		{"", ""},
		{"\n\t", ""},
	}
	for _, c := range cases {
		got := Render(inc, c.site, cet, Facts{Names: names})
		want := "ap-kitchen stopped answering at 14:02."
		if c.want != "" {
			want = c.want + ": " + want
		}
		if got != want {
			t.Errorf("site %q: Render = %q, want %q", c.site, got, want)
		}
	}
}

func utf16Len(s string) int { return len(utf16.Encode([]rune(s))) }

// tail returns at most the last n bytes of s, for failure messages.
func tail(s string, n int) string { return s[max(0, len(s)-n):] }

func TestRenderCap(t *testing.T) {
	if MaxMessage != 4096 {
		t.Fatalf("MaxMessage = %d, want 4096 (Telegram's limit)", MaxMessage)
	}
	var many []Change
	for i := 0; i < 400; i++ {
		many = append(many, Change{Kind: ChangeRemoved, Member: "ap-garage-with-a-long-name", By: "backup-admin"})
	}
	inc := fact(local(14, 2, 0), "", events.RosterChangesDropped)
	got := Render(inc, "Home", cet, Facts{Changes: many})
	if n := utf16Len(got); n > MaxMessage {
		t.Errorf("Render gave %d UTF-16 units, at most %d", n, MaxMessage)
	}
	if n := utf16Len(got); n < MaxMessage-30 {
		t.Errorf("Render gave %d UTF-16 units; it cut far below %d", n, MaxMessage)
	}
	if !strings.HasSuffix(got, "...") {
		t.Errorf("a cut message does not end in \"...\": %q", tail(got, 40))
	}
	if !utf8.ValidString(got) {
		t.Error("the cut broke a character")
	}

	// Telegram counts UTF-16 code units: a site of characters outside the
	// BMP counts twice each.
	site := strings.Repeat("\U0001F3E0", 3000)
	got = Render(fact(local(14, 2, 0), garage, events.MemberJoined), site, cet, Facts{Names: names})
	if n := utf16Len(got); n > MaxMessage || n < MaxMessage-4 {
		t.Errorf("astral site: Render gave %d UTF-16 units, want %d or just below", n, MaxMessage)
	}
	if !utf8.ValidString(got) {
		t.Error("astral site: the cut broke a character")
	}

	// A site of 2-byte characters that fits in UTF-16 units is not cut,
	// although its bytes would not fit.
	wide := strings.Repeat("\u00e9", 3000)
	got = Render(fact(local(14, 2, 0), garage, events.MemberJoined), wide, cet, Facts{Names: names})
	if want := wide + ": ap-garage joined the group at 14:02."; got != want {
		t.Errorf("a site of 3000 2-byte characters was cut: ...%q", tail(got, 40))
	}

	short := Render(fact(local(14, 2, 0), garage, events.MemberJoined), "Home", cet, Facts{Names: names})
	if strings.HasSuffix(short, "...") {
		t.Errorf("an uncut message ends in \"...\": %q", short)
	}
}

func TestTagMessage(t *testing.T) {
	if got, want := tag("Home: ap-garage joined the group at 14:02.", "0123456789abcdef"), "Home: ap-garage joined the group at 14:02. [01234567]"; got != want {
		t.Errorf("tag = %q, want %q", got, want)
	}
	long := strings.Repeat("x", 5000)
	got := tag(long, "0123456789abcdef")
	if n := utf16Len(got); n != MaxMessage {
		t.Errorf("tag of a long text gave %d UTF-16 units, want %d", n, MaxMessage)
	}
	if !strings.HasSuffix(got, "... [01234567]") {
		t.Errorf("tag of a long text lost its ID: %q", tail(got, 30))
	}
	exact := strings.Repeat("x", MaxMessage-len(" [01234567]"))
	if got := tag(exact, "0123456789abcdef"); got != exact+" [01234567]" {
		t.Errorf("a text that fits exactly was cut: ...%q", tail(got, 30))
	}
}

// peerText is what a peer string may never put into a message: a link, an
// address, a mention, a command, a hashtag, a cashtag or a second line.
var peerText = regexp.MustCompile(`[0-9A-Za-z]\.[A-Za-z]|://|[@#/$\n\r]`)

// FuzzRender feeds hostile peer strings into every field a message takes from
// peers and checks the message stays one plain line within Telegram's limit,
// with nothing in it that Telegram would turn into a link or an entity.
func FuzzRender(f *testing.F) {
	f.Add("ap-kitchen", "25.12.4", "25.12.5", "backup-admin", uint8(0), 3, 4)
	f.Add("evil.example", "http://x", "@admin", "/start", uint8(3), -1, 0)
	f.Add("ap\n", "1.evil.com", "#x", "a\u202eb", uint8(17), 9, 2)
	types := []events.Type{
		events.MemberSilent, events.MemberBack, events.RebootPlanned, events.RebootUnplanned, events.Upgraded, events.LinkLost,
		events.WanDown, events.WanUp, events.InternetLost, events.InternetRestored, events.UplinkSwitched,
		events.MemberJoined, events.MemberLeft, events.UnderFlood, events.DuplicateIdentity, events.Fork,
		events.RosterChanged, events.RosterChangesDropped, events.Type("x.y/z"),
	}
	f.Fuzz(func(t *testing.T, name, from, to, by string, typ uint8, confirmed, of int) {
		ty := types[int(typ)%len(types)]
		inc := events.Incident{
			ID: "0123456789abcdef", Start: local(14, 2, 0), End: local(14, 3, 5),
			Members: []string{kitchen, name}, Witnesses: []string{office, name}, Events: []events.Type{events.MemberSilent, ty},
		}
		if typ&0x80 != 0 {
			inc.Causes = 2
		}
		facts := Facts{
			Names: map[string]string{kitchen: name, office: by}, From: from, To: to, Confirmed: confirmed, Of: of,
			Changes: []Change{{Kind: ChangeKind(typ % 5), Member: name, By: by}},
		}
		got := Render(inc, "Home", cet, facts)
		if !strings.HasPrefix(got, "Home: ") {
			t.Fatalf("no site prefix: %q", got)
		}
		if n := utf16Len(got); n > MaxMessage {
			t.Fatalf("%d UTF-16 units", n)
		}
		if !utf8.ValidString(got) {
			t.Fatalf("invalid UTF-8: %q", got)
		}
		for _, r := range got {
			if !unicode.IsPrint(r) {
				t.Fatalf("unprintable %U in %q", r, got)
			}
		}
		if m := peerText.FindString(got); m != "" {
			t.Fatalf("%q in %q", m, got)
		}
		if strings.ContainsAny(got, "\u2013\u2014") {
			t.Fatalf("a dash in %q", got)
		}
	})
}
