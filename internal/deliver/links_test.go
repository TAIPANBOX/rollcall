package deliver

import (
	"encoding/binary"
	"slices"
	"testing"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/clock"
	"github.com/TAIPANBOX/rollcall/internal/events"
	"github.com/TAIPANBOX/rollcall/internal/ids"
)

// linkEv is a link change of witness w at s.
func linkEv(n uint32, typ events.Type, w ids.MemberID, s clock.Stamp) events.Event {
	var ref ids.Hash
	binary.BigEndian.PutUint32(ref[:], n)
	return events.Event{Type: typ, Subject: w, Witness: w, At: s, Ref: ref}
}

// linkIncident returns the incident Coalesce would make of evs with the
// window that takes them all, with its summary.
func linkIncident(t *testing.T, evs ...events.Event) (events.Incident, Facts) {
	t.Helper()
	incs := events.Coalesce(evs, 24*time.Hour)
	if len(incs) != 1 {
		t.Fatalf("%d incidents", len(incs))
	}
	return incs[0], Facts{Names: names, Links: LinksOf(evs)}
}

// TestLinksOf: each router's records of a kind in the order of their
// stamps; a loss while down repeats a drop; a return ends one; the router
// with the most drops gives the count and the time down in all.
func TestLinksOf(t *testing.T) {
	D, U, L, R := events.WanDown, events.WanUp, events.InternetLost, events.InternetRestored
	evs := []events.Event{
		linkEv(1, D, officeID, local(12, 5, 1)), linkEv(2, L, officeID, local(12, 5, 3)),
		linkEv(3, D, officeID, local(12, 6, 2)), linkEv(4, U, officeID, local(12, 6, 4)),
		linkEv(5, D, officeID, local(12, 6, 13)), linkEv(6, U, officeID, local(12, 6, 15)),
		linkEv(7, R, officeID, local(12, 6, 50)),
		linkEv(8, D, kitchenID, local(12, 6, 30)), // another router: still down
		linkEv(9, events.UplinkSwitched, kitchenID, local(12, 6, 31)),
	}
	ls := LinksOf(evs)
	if len(ls) != 2 || ls[0].Kind != D || ls[1].Kind != L {
		t.Fatalf("links %+v, want the WAN, then the internet", ls)
	}
	wan := ls[0]
	if !wan.Lost || !wan.Back || !wan.Down || wan.Drops != 2 || wan.Of != office || !wan.Ended ||
		wan.Gone != 65*time.Second || wan.From != local(12, 5, 1) || wan.To != local(12, 6, 15) ||
		!slices.Equal(wan.Up, []string{office}) || !slices.Equal(wan.Still, []string{kitchen}) {
		t.Fatalf("WAN %+v", wan)
	}
	in := ls[1]
	if !in.Lost || !in.Back || in.Down || in.Drops != 1 || in.Gone != 107*time.Second || !in.Ended {
		t.Fatalf("internet %+v", in)
	}
	// Records out of order are read in the order of their stamps; a return
	// with no loss before it ends nothing; a drop still open counts but
	// adds no time.
	ls = LinksOf([]events.Event{
		linkEv(3, D, gwID, local(9, 0, 30)), linkEv(1, U, gwID, local(9, 0, 0)), linkEv(2, D, gwID, local(9, 0, 10)),
		linkEv(4, U, gwID, local(9, 0, 20)),
	})
	if len(ls) != 1 || ls[0].Drops != 2 || ls[0].Gone != 10*time.Second || ls[0].Ended || !ls[0].Down {
		t.Fatalf("out of order: %+v", ls)
	}
	if ls := LinksOf([]events.Event{linkEv(1, events.MemberSilent, gwID, local(9, 0, 0))}); len(ls) != 0 {
		t.Fatalf("no link change, yet %+v", ls)
	}
}

// TestRenderLinks: what a message says of a router's link changes.
func TestRenderLinks(t *testing.T) {
	D, U, L, R := events.WanDown, events.WanUp, events.InternetLost, events.InternetRestored
	DL, DR := events.DNSLost, events.DNSRestored
	o := officeID
	cases := []struct {
		name string
		evs  []events.Event
		want string
	}{
		{"start of an outage, two links", []events.Event{linkEv(1, D, o, local(14, 34, 13)), linkEv(2, L, o, local(14, 34, 13))},
			"Home: WAN and internet went down at 14:34. Seen by ap-office."},
		{"one link, its own words", []events.Event{linkEv(1, D, o, local(14, 34, 13))},
			"Home: WAN went down at 14:34. Seen by ap-office."},
		{"the internet alone", []events.Event{linkEv(1, L, o, local(14, 34, 13))},
			"Home: internet lost at 14:34. Seen by ap-office."},
		{"DNS alone", []events.Event{linkEv(1, DL, o, local(14, 3, 44))},
			"Home: DNS stopped answering at 14:03. Only name lookups failed. Seen by ap-office."},
		{"end of an outage", []events.Event{linkEv(1, D, o, local(14, 34, 13)), linkEv(2, L, o, local(14, 34, 13)),
			linkEv(3, U, o, local(16, 34, 23)), linkEv(4, R, o, local(16, 34, 34))},
			"Home: WAN and internet were down from 14:34 to 16:34 (2 h). Seen by ap-office."},
		{"a DNS cut", []events.Event{linkEv(1, DL, o, local(14, 3, 44)), linkEv(2, DR, o, local(14, 9, 3))},
			"Home: DNS was down from 14:03 to 14:09 (5 min 19 s). Only name lookups failed. Seen by ap-office."},
		{"all three", []events.Event{linkEv(1, D, o, local(9, 0, 0)), linkEv(2, L, o, local(9, 0, 5)), linkEv(3, DL, o, local(9, 0, 9))},
			"Home: WAN, internet and DNS went down at 09:00. Seen by ap-office."},
		{"returns alone", []events.Event{linkEv(1, U, o, local(9, 5, 0)), linkEv(2, R, o, local(9, 5, 9))},
			"Home: WAN and internet came back at 09:05. Seen by ap-office."},
		{"DNS back alone", []events.Event{linkEv(1, DR, o, local(9, 5, 0))},
			"Home: DNS answered again at 09:05. Only name lookups failed. Seen by ap-office."},
		{"a flapping WAN", []events.Event{linkEv(1, D, o, local(12, 6, 2)), linkEv(2, U, o, local(12, 6, 4)),
			linkEv(3, D, o, local(12, 6, 13)), linkEv(4, U, o, local(12, 6, 15)), linkEv(5, D, o, local(12, 6, 24)), linkEv(6, U, o, local(12, 6, 26))},
			"Home: WAN was down from 12:06 to 12:06 (24 s). WAN went down 3 times, 6 s in all. Seen by ap-office."},
		{"a WAN that drops and stays down", []events.Event{linkEv(1, D, o, local(12, 6, 2)), linkEv(2, U, o, local(12, 6, 4)),
			linkEv(3, D, o, local(12, 6, 13))},
			"Home: WAN went down at 12:06. WAN went down 2 times. Seen by ap-office."},
		{"the internet flaps", []events.Event{linkEv(1, L, o, local(12, 6, 2)), linkEv(2, R, o, local(12, 6, 22)),
			linkEv(3, L, o, local(12, 6, 42)), linkEv(4, R, o, local(12, 7, 2))},
			"Home: internet was down from 12:06 to 12:07 (1 min). Internet went down 2 times, 40 s in all. Seen by ap-office."},
		{"mixed: back and still down", []events.Event{linkEv(1, D, o, local(9, 0, 0)), linkEv(2, U, o, local(9, 0, 20)),
			linkEv(3, L, o, local(9, 0, 5))},
			"Home: WAN was down from 09:00 to 09:00 (20 s); internet lost at 09:00. Seen by ap-office."},
		{"mixed: a return alone and a loss", []events.Event{linkEv(1, U, o, local(9, 0, 0)), linkEv(2, L, o, local(9, 1, 0))},
			"Home: internet lost at 09:01; WAN came back at 09:00. Seen by ap-office."},
		{"mixed: two lost, the later named first", []events.Event{linkEv(1, U, o, local(9, 2, 0)), linkEv(2, L, o, local(9, 1, 0)),
			linkEv(3, DL, o, local(9, 0, 30))},
			"Home: internet and DNS went down at 09:00; WAN came back at 09:02. Seen by ap-office."},
		{"mixed: two back, at the later return", []events.Event{linkEv(1, U, o, local(9, 2, 0)), linkEv(2, R, o, local(9, 3, 0)),
			linkEv(3, DL, o, local(9, 0, 30))},
			"Home: DNS stopped answering at 09:00; WAN and internet came back at 09:03. Seen by ap-office."},
		{"links down far apart", []events.Event{linkEv(1, D, o, local(14, 0, 0)), linkEv(2, L, o, local(14, 10, 0)),
			linkEv(3, U, o, local(14, 30, 0)), linkEv(4, R, o, local(14, 30, 5))},
			"Home: WAN was down from 14:00 to 14:30 (30 min), internet was down from 14:10 to 14:30 (20 min 5 s). Seen by ap-office."},
		{"partly back", []events.Event{linkEv(1, L, o, local(9, 0, 0)), linkEv(2, L, gwID, local(9, 0, 1)),
			linkEv(3, R, gwID, local(9, 5, 0))},
			"Home: internet came back at 09:05 on gateway, still down on ap-office. Seen by gateway, ap-office."},
		{"partly back, two links alike", []events.Event{linkEv(1, L, o, local(9, 0, 0)), linkEv(2, L, gwID, local(9, 0, 1)),
			linkEv(3, D, o, local(9, 0, 0)), linkEv(4, D, gwID, local(9, 0, 1)),
			linkEv(5, R, gwID, local(9, 5, 0)), linkEv(6, U, gwID, local(9, 5, 1))},
			"Home: WAN and internet came back at 09:05 on gateway, still down on ap-office. Seen by gateway, ap-office."},
		{"several routers, one flaps", []events.Event{linkEv(1, D, o, local(12, 6, 2)), linkEv(2, U, o, local(12, 6, 4)),
			linkEv(3, D, o, local(12, 6, 13)), linkEv(4, U, o, local(12, 6, 15)), linkEv(5, D, gwID, local(12, 6, 3)), linkEv(6, U, gwID, local(12, 6, 14))},
			"Home: WAN was down from 12:06 to 12:06 (13 s). WAN went down 2 times on ap-office, 4 s in all. Seen by gateway, ap-office."},
	}
	for _, c := range cases {
		inc, f := linkIncident(t, c.evs...)
		if got := Render(inc, "Home", cet, f); got != c.want {
			t.Errorf("%s:\n got %q\nwant %q", c.name, got, c.want)
		}
	}
}

// TestRenderDNSWithoutSummary: without a summary in the facts, a DNS
// incident is told from its types, as the WAN and the internet are.
func TestRenderDNSWithoutSummary(t *testing.T) {
	at, back := local(14, 3, 44), local(14, 9, 3)
	for _, c := range []struct {
		inc  events.Incident
		want string
	}{
		{link(at, back, []string{office}, events.DNSLost, events.DNSRestored),
			"Home: DNS was down from 14:03 to 14:09 (5 min 19 s). Only name lookups failed. Seen by ap-office."},
		{link(at, at, []string{office}, events.DNSLost), "Home: DNS stopped answering at 14:03. Only name lookups failed. Seen by ap-office."},
		{link(back, back, []string{office}, events.DNSRestored), "Home: DNS answered again at 14:09. Only name lookups failed. Seen by ap-office."},
	} {
		if got := Render(c.inc, "Home", cet, Facts{Names: names}); got != c.want {
			t.Errorf("got %q\nwant %q", got, c.want)
		}
	}
}

// TestLinkNameOfOtherTypes: a type that names no kind of link is shown as
// itself; LinksOf never hands one over. Records with one wall time are read
// in the order of their monotonic clocks.
func TestLinkNameOfOtherTypes(t *testing.T) {
	if got := linkName(events.UplinkSwitched); got != "uplink_switched" {
		t.Fatalf("linkName: %q", got)
	}
	at := local(9, 0, 0)
	later := at
	later.Mono += time.Millisecond
	ls := LinksOf([]events.Event{linkEv(1, events.WanUp, gwID, later), linkEv(2, events.WanDown, gwID, at)})
	if len(ls) != 1 || ls[0].Down || ls[0].Drops != 1 || !ls[0].Ended {
		t.Fatalf("one wall time: %+v; want the loss first, then the return", ls)
	}
}
