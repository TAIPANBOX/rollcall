package events

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"slices"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/clock"
	"github.com/TAIPANBOX/rollcall/internal/ids"
)

// DefaultWindow is the coalescing window: events with one cause that fall
// within it of an incident's first event join that incident.
const DefaultWindow = 10 * time.Second

// idDomain separates incident IDs from every other hash rollcall computes.
const idDomain = "rollcall/v1 incident\x00"

// Incident is what one message reports: the events that share one cause.
type Incident struct {
	// ID is 16 lowercase hex digits fixed by the incident's events alone, so
	// two members that coalesce the same events give the same ID.
	ID string
	// Start and End are the stamps of the first and the last event, with
	// Wall placed, in UTC, on the corrected clock of their witness's boot
	// (see Coalesce). clock.Duration(Start, End) is the incident's length.
	Start, End clock.Stamp
	// Members are hex member IDs: the cause first when the incident has one
	// (it holds an absence: silent, back, rebooted, upgraded, link lost),
	// then every other member the events are about, in ID order.
	Members []string
	// Events lists each type once, in the order it first appears.
	Events []Type
	// Witnesses are the hex IDs of the members that saw the events, in ID
	// order.
	Witnesses []string
	// Approximate is true when any stamp of the incident is untrusted or
	// clock.Duration(Start, End) says the length is approximate.
	Approximate bool
	// Refs are the events' history entry hashes, one per event, in byte
	// order: the link from the incident back to what it reports.
	Refs []ids.Hash
}

// role is what an event contributes to finding its cause.
type role int

const (
	roleFact    role = iota // one fact: groups only with the same type about the same subject
	roleAbsence             // its subject went away or came back: the subject is a cause
	roleLink                // a member's own WAN or internet changed: an effect
	roleFlood               // a member is flooded: one flood across the site
)

func roleOf(e Event) role {
	switch e.Type {
	case MemberSilent, MemberBack, RebootPlanned, RebootUnplanned, Upgraded, LinkLost:
		if e.Subject == (ids.MemberID{}) {
			return roleFact // an absence of an unknown member names no cause
		}
		return roleAbsence
	case WanDown, WanUp, InternetLost, InternetRestored, UplinkSwitched:
		return roleLink
	case UnderFlood:
		return roleFlood
	default:
		return roleFact // the alarms, membership, roster, and types of newer versions
	}
}

// Coalesce groups events into incidents and returns them in time order.
// Every event ends up in exactly one incident; an event given twice (same
// ref, type, subject, witness and stamp) counts once. The result depends only
// on the set of events, not on their order, and evs is not modified.
//
// Time. Each witness's boot is one timeline: its events are placed at the
// wall time of its latest stamp (by monotonic clock, then by wall clock)
// moved by the monotonic difference. Within a boot this keeps the monotonic
// order and lengths even when the wall clock stepped by years after NTP
// answered; across boots it compares wall clocks, corrected by any later
// stamp of the same boot. Events without a boot ID keep their own wall time.
// The timelines are keyed by witness and boot, so a member that copies
// another's boot ID moves only its own events.
//
// Window. An incident takes an event only within window of the incident's
// first event (inclusive), never by chaining from event to event. A negative
// window puts every event in an incident of its own.
//
// Cause. Events share a cause when one of these holds; anything else stays
// apart, so events about different members with no shared cause are
// separate incidents:
//
//   - Absence of member X (MemberSilent, MemberBack, RebootPlanned,
//     RebootUnplanned, Upgraded, LinkLost about X): X is the cause. Further
//     absences of X join. Absences of another member never do.
//   - Link events (WanDown, WanUp, InternetLost, InternetRestored,
//     UplinkSwitched), from any member, X included, join an absence of X in
//     the window: the main router reboots and the access points lose the
//     internet. A link event that has two such causes in reach joins the
//     earlier. An absence that arrives after link events in the window
//     becomes their cause.
//   - Link events with no absence group together into one site-wide
//     incident naming every witness: the internet is gone for everyone.
//   - UnderFlood from any members groups into one site-wide flood.
//   - Any other type (alarms, membership, roster changes, types of newer
//     versions), and an absence whose subject is zero, groups only with the
//     same type about the same subject: one fact, several witnesses.
//
// Zero member IDs are unknown: they are never named in Members or
// Witnesses, though their events stay in the incident.
//
// Approximate and the ID are described on Incident. The ID is the first 8
// bytes, in hex, of SHA-256 over "rollcall/v1 incident\x00" and the
// incident's event records in byte order; a record is ref (32) | subject
// (16) | witness (16) | boot (16) | wall seconds since 1970 (int64) | wall
// nanoseconds (uint32) | monotonic nanoseconds (int64) | trusted (1 byte) |
// type length (uint32) | type, integers big-endian. Detail is not part of it;
// the ref already fixes the event.
func Coalesce(evs []Event, window time.Duration) []Incident {
	items := timeline(evs)
	var groups []*group
	open := 0 // groups before this one have closed for good
	for _, it := range items {
		// Items come in time order and groups open in time order, so the
		// groups whose window has passed are a prefix.
		for open < len(groups) && it.at.Sub(groups[open].items[0].at) > window {
			open++
		}
		var g *group
		for _, cand := range groups[open:] {
			if cand.accepts(it.ev) {
				g = cand
				break
			}
		}
		if g == nil {
			g = &group{role: roleOf(it.ev), subject: it.ev.Subject, typ: it.ev.Type}
			groups = append(groups, g)
		}
		g.add(it)
	}
	var out []Incident
	for _, g := range groups {
		out = append(out, g.incident())
	}
	return out
}

// item is one event placed on its timeline.
type item struct {
	ev  Event
	at  time.Time // the event's moment on the corrected wall clock of its timeline, UTC
	rec []byte    // the event's record: its identity, the ID input, the tie-break
}

// stamp returns the event's stamp with Wall on the corrected clock.
func (it item) stamp() clock.Stamp {
	s := it.ev.At
	s.Wall = it.at
	return s
}

// timeline returns the events in time order, each once, placed on the
// corrected clock of their witness's boot.
func timeline(evs []Event) []item {
	type key struct {
		witness ids.MemberID
		boot    ids.BootID
	}
	anchors := map[key]clock.Stamp{}
	for _, e := range evs {
		if e.At.Boot == (ids.BootID{}) {
			continue // unknown boot: the stamp stands alone
		}
		k := key{e.Witness, e.At.Boot}
		if a, ok := anchors[k]; !ok || later(e.At, a) {
			anchors[k] = e.At
		}
	}
	items := make([]item, 0, len(evs))
	for _, e := range evs {
		at := e.At.Wall
		if a, ok := anchors[key{e.Witness, e.At.Boot}]; ok {
			at = a.Wall.Add(e.At.Mono - a.Mono)
		}
		// UTC drops Go's own monotonic reading and the zone, so moments
		// compare as wall times only and the result does not depend on
		// which of two equal stamps anchored a timeline.
		items = append(items, item{ev: e, at: at.UTC(), rec: record(e)})
	}
	slices.SortFunc(items, func(a, b item) int {
		if c := a.at.Compare(b.at); c != 0 {
			return c
		}
		return bytes.Compare(a.rec, b.rec)
	})
	return slices.CompactFunc(items, func(a, b item) bool { return bytes.Equal(a.rec, b.rec) })
}

// later reports whether s is a later anchor than a for one timeline: a
// greater monotonic reading, or the same one with a later wall clock (only a
// faulty or lying clock gives one instant two wall times; the tie-break keeps
// the result independent of the order of the events).
func later(s, a clock.Stamp) bool {
	if s.Mono != a.Mono {
		return s.Mono > a.Mono
	}
	return s.Wall.After(a.Wall)
}

// record encodes the event's identity; see Coalesce.
func record(e Event) []byte {
	r := make([]byte, 0, 32+16+16+16+8+4+8+1+4+len(e.Type))
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
	return append(r, e.Type...)
}

// group is an incident being built.
type group struct {
	role    role         // roleAbsence once an absence has joined
	subject ids.MemberID // roleAbsence: the cause; roleFact: the subject of the fact
	typ     Type         // roleFact: the type of the fact
	items   []item       // in time order; items[0] opened the window
}

// accepts reports whether e shares the group's cause. The window is checked
// by the caller.
func (g *group) accepts(e Event) bool {
	switch roleOf(e) {
	case roleAbsence:
		return g.role == roleLink || g.role == roleAbsence && g.subject == e.Subject
	case roleLink:
		return g.role == roleLink || g.role == roleAbsence
	case roleFlood:
		return g.role == roleFlood
	default:
		return g.role == roleFact && g.typ == e.Type && g.subject == e.Subject
	}
}

// add puts it into the group; an absence makes its subject the cause.
func (g *group) add(it item) {
	if roleOf(it.ev) == roleAbsence {
		g.role, g.subject = roleAbsence, it.ev.Subject
	}
	g.items = append(g.items, it)
}

func (g *group) incident() Incident {
	inc := Incident{
		Start: g.items[0].stamp(),
		End:   g.items[len(g.items)-1].stamp(),
	}
	members, witnesses := map[ids.MemberID]bool{}, map[ids.MemberID]bool{}
	seen := map[Type]bool{}
	untrusted := false
	recs := make([][]byte, 0, len(g.items))
	for _, it := range g.items {
		e := it.ev
		members[e.Subject] = true
		witnesses[e.Witness] = true
		if !seen[e.Type] {
			seen[e.Type] = true
			inc.Events = append(inc.Events, e.Type)
		}
		untrusted = untrusted || !e.At.Trusted
		inc.Refs = append(inc.Refs, e.Ref)
		recs = append(recs, it.rec)
	}

	if g.role == roleAbsence {
		inc.Members = append(inc.Members, g.subject.String())
		delete(members, g.subject)
	}
	inc.Members = append(inc.Members, named(members)...)
	inc.Witnesses = named(witnesses)

	_, approx := clock.Duration(inc.Start, inc.End)
	inc.Approximate = untrusted || approx

	slices.SortFunc(inc.Refs, func(a, b ids.Hash) int { return bytes.Compare(a[:], b[:]) })
	slices.SortFunc(recs, bytes.Compare)
	h := sha256.New()
	h.Write([]byte(idDomain))
	for _, r := range recs {
		h.Write(r)
	}
	inc.ID = hex.EncodeToString(h.Sum(nil)[:8])
	return inc
}

// named returns the hex forms of the non-zero IDs in set, in ID order.
func named(set map[ids.MemberID]bool) []string {
	var out []string
	for id := range set {
		if id != (ids.MemberID{}) {
			out = append(out, id.String())
		}
	}
	slices.Sort(out) // fixed-length lowercase hex sorts like the bytes
	return out
}
