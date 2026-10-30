package events

import (
	"math/rand/v2"
	"reflect"
	"slices"
	"testing"
	"time"
)

// typesOf returns the event types of each incident, in order.
func typesOf(incs []Incident) [][]Type {
	out := make([][]Type, len(incs))
	for i, inc := range incs {
		out[i] = inc.Events
	}
	return out
}

// TestLinkChainOneIncident (rule (f)): one router's WAN drops four times,
// each drop 2 s, 9 to 11 s apart, and the internet goes and comes back
// meanwhile: 46 s in all, beyond the 10 s window. CoalesceLinks makes one
// incident of it; Coalesce, which chains nothing, several.
func TestLinkChainOneIncident(t *testing.T) {
	var f fixture
	w := ap3
	evs := []Event{
		f.ev(WanDown, w.id, w, 0), f.ev(InternetLost, w.id, w, 2*time.Second),
		f.ev(WanUp, w.id, w, 4*time.Second), f.ev(WanDown, w.id, w, 13*time.Second),
		f.ev(WanUp, w.id, w, 15*time.Second), f.ev(WanDown, w.id, w, 26*time.Second),
		f.ev(WanUp, w.id, w, 28*time.Second), f.ev(InternetRestored, w.id, w, 46*time.Second),
	}
	incs := CoalesceLinks(evs, DefaultWindow, LinkWindow)
	if len(incs) != 1 || len(incs[0].Refs) != len(evs) {
		t.Fatalf("CoalesceLinks: %d incidents %v, want one of all %d events", len(incs), typesOf(incs), len(evs))
	}
	if inc := incs[0]; inc.ID != wantIncidentID(evs...) || inc.Start.Wall != t0 || inc.End.Wall != t0.Add(46*time.Second) ||
		!slices.Equal(inc.Witnesses, names(w.id)) || inc.Causes != 0 {
		t.Fatalf("incident %+v", inc)
	}
	if n := len(Coalesce(evs, DefaultWindow)); n < 3 {
		t.Fatalf("Coalesce made %d incidents of a 46 s chain, want several: it chains nothing", n)
	}
	// Order does not matter.
	r := rand.New(rand.NewPCG(1, 2))
	for range 20 {
		shuffled := slices.Clone(evs)
		r.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		if got := CoalesceLinks(shuffled, DefaultWindow, LinkWindow); !reflect.DeepEqual(got, incs) {
			t.Fatalf("a shuffled input gave %v", typesOf(got))
		}
	}
}

// TestLinkChainBreaks: a gap longer than the chain ends it, and so does a
// negative chain or a negative window; the chain is the gap from the
// previous link change of the same router, not from the incident's first.
func TestLinkChainBreaks(t *testing.T) {
	var f fixture
	w := ap3
	a, b := f.ev(WanDown, w.id, w, 0), f.ev(WanUp, w.id, w, 25*time.Second)
	c, d := f.ev(WanDown, w.id, w, 50*time.Second), f.ev(WanUp, w.id, w, 81*time.Second)
	incs := CoalesceLinks([]Event{a, b, c, d}, DefaultWindow, LinkWindow)
	if len(incs) != 2 || !slices.Equal(incs[0].Refs, refsOf(a, b, c)) || !slices.Equal(incs[1].Refs, refsOf(d)) {
		t.Fatalf("incidents %v; want the first three (25 s apart each) and the last (31 s after) alone", typesOf(incs))
	}
	if incs := CoalesceLinks([]Event{a, b}, DefaultWindow, -1); len(incs) != 2 {
		t.Fatalf("a negative chain chained %d", len(incs))
	}
	if incs := CoalesceLinks([]Event{a, b}, -1, LinkWindow); len(incs) != 2 {
		t.Fatalf("a negative window chained %d", len(incs))
	}
	if incs := CoalesceLinks([]Event{a, b}, DefaultWindow, 25*time.Second); len(incs) != 1 {
		t.Fatalf("a gap equal to the chain: %d incidents, want 1 (inclusive)", len(incs))
	}
}

// TestLinkChainIsPerRouter: another router's link change 20 s after the
// first router's, while the first router's chain goes on, is no part of it:
// it is beyond the window of the incident's first event and has no chain of
// its own there. Within the window it joins, as rule (b) says.
func TestLinkChainIsPerRouter(t *testing.T) {
	var f fixture
	a1, a2 := f.ev(WanDown, ap3.id, ap3, 0), f.ev(WanUp, ap3.id, ap3, 18*time.Second)
	other := f.ev(InternetLost, ap4.id, ap4, 20*time.Second)
	near := f.ev(InternetLost, ap5.id, ap5, 9*time.Second)
	incs := CoalesceLinks([]Event{a1, a2, other, near}, DefaultWindow, LinkWindow)
	if len(incs) != 2 || !slices.Equal(incs[0].Refs, refsOf(a1, a2, near)) || !slices.Equal(incs[1].Refs, refsOf(other)) {
		t.Fatalf("incidents %v; want ap3's chain with ap5's change in its window, and ap4's apart", typesOf(incs))
	}
}

// TestLinkChainEndsAtAnAbsence: once an absence joined a link incident
// (rule (a): it became the cause), the router's next link change does not
// chain into it.
func TestLinkChainEndsAtAnAbsence(t *testing.T) {
	var f fixture
	lost := f.ev(InternetLost, ap3.id, ap3, 0)
	silent := f.ev(MemberSilent, gw.id, ap2, 5*time.Second)
	back := f.ev(InternetRestored, ap3.id, ap3, 25*time.Second)
	incs := CoalesceLinks([]Event{lost, silent, back}, DefaultWindow, LinkWindow)
	if len(incs) != 2 || incs[0].Causes != 1 || !slices.Equal(incs[0].Refs, refsOf(lost, silent)) || !slices.Equal(incs[1].Refs, refsOf(back)) {
		t.Fatalf("incidents %v; want the silence with the loss as its effect, and the return apart", typesOf(incs))
	}
}

// TestLinkChainJoinsTheEarlier: a link change in reach of both its router's
// chain and the window of another link incident opened later joins the
// earlier one.
func TestLinkChainJoinsTheEarlier(t *testing.T) {
	var f fixture
	a1 := f.ev(WanDown, ap3.id, ap3, 0)
	b1 := f.ev(WanDown, ap4.id, ap4, 15*time.Second) // a new incident: beyond a1's window
	a2 := f.ev(WanUp, ap3.id, ap3, 20*time.Second)   // in b1's window and in ap3's chain
	incs := CoalesceLinks([]Event{a1, b1, a2}, DefaultWindow, LinkWindow)
	if len(incs) != 2 || !slices.Equal(incs[0].Refs, refsOf(a1, a2)) || !slices.Equal(incs[1].Refs, refsOf(b1)) {
		t.Fatalf("incidents %v; want ap3's chain whole, ap4's loss apart", typesOf(incs))
	}
	// ap3's chain began before ap4's incident, whose window x falls in too:
	// x stays with the chain.
	b0 := f.ev(WanDown, ap4.id, ap4, -12*time.Second)
	a0 := f.ev(WanDown, ap3.id, ap3, -25*time.Second) // ap3's chain starts first
	x := f.ev(WanUp, ap3.id, ap3, -5*time.Second)     // in ap3's chain and in b0's window
	incs = CoalesceLinks([]Event{a0, b0, x}, DefaultWindow, LinkWindow)
	if len(incs) != 2 || !slices.Equal(incs[0].Refs, refsOf(a0, x)) {
		t.Fatalf("incidents %v; want ap3's chain to keep its return", typesOf(incs))
	}
}

// TestDNSEventsAreLinkChanges: a router's DNS changes group with the link
// changes of the site (rule (b)), chain like them (rule (f)), and are effects
// of an absence in the window (rule (a)).
func TestDNSEventsAreLinkChanges(t *testing.T) {
	var f fixture
	lost, back := f.ev(DNSLost, ap3.id, ap3, 0), f.ev(DNSRestored, ap3.id, ap3, 25*time.Second)
	wan := f.ev(WanDown, ap4.id, ap4, 4*time.Second)
	incs := CoalesceLinks([]Event{lost, back, wan}, DefaultWindow, LinkWindow)
	if len(incs) != 1 || !slices.Equal(incs[0].Events, []Type{DNSLost, WanDown, DNSRestored}) {
		t.Fatalf("incidents %v; want one of the site's link changes", typesOf(incs))
	}
	silent := f.ev(MemberSilent, gw.id, ap2, 2*time.Second)
	incs = Coalesce([]Event{lost, silent}, DefaultWindow)
	if len(incs) != 1 || incs[0].Causes != 1 {
		t.Fatalf("incidents %v; want the silence, the DNS loss its effect", typesOf(incs))
	}
	if DNSLost != "dns_lost" || DNSRestored != "dns_restored" {
		t.Fatal("the DNS types are wire format: dns_lost and dns_restored")
	}
}
