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

// startSpread bounds, beyond the window, how far apart the starts of the
// absences of several members with one cause may lie (rule (e) of
// Coalesce): a member knows its last moment up from its state on flash,
// which it writes at most once a minute, so after one power cut the starts
// the members give lie within that minute of each other.
const startSpread = time.Minute

// idDomain separates incident IDs from every other hash rollcall computes.
const idDomain = "rollcall/v1 incident\x00"

// Incident is what one message reports: the events that share one cause.
type Incident struct {
	// ID is 16 lowercase hex digits fixed by the incident's events alone, so
	// two members that coalesce the same events give the same ID. When the
	// incident holds members' own accounts of their return (Own), it is
	// fixed by those alone: members that hold the same own accounts and
	// different records of others about the same absence give the same ID,
	// and an acknowledgement of either covers both.
	ID string
	// Start and End are the stamps of the first and the last event, with
	// Wall placed, in UTC, on the corrected clock of their witness's boot
	// (see Coalesce). Start is earlier when a cause's own account of its
	// return gives the start of its absence (Event.Since) and no silence of
	// that cause is in the incident: then Start is the earliest such start.
	// clock.Duration(Start, End) is the incident's length.
	Start, End clock.Stamp
	// Began is true when the incident knows when the absence it reports
	// began: it holds the silence of a cause, or a cause's own account of
	// its return that gives its start (Event.Since), so Start is that start.
	// Otherwise the start of an absence is unknown and Start is only its
	// earliest event. It is not part of the ID.
	Began bool
	// Members are hex member IDs: first the causes, the members whose
	// absence (silent, back, rebooted, upgraded, link lost) the incident
	// reports, in ID order; then every other member the events are about, in
	// ID order.
	Members []string
	// Causes is how many of the leading Members are causes: 0 for an
	// incident without an absence, 1 for one member, more under rules (d)
	// and (e) of Coalesce. With more than one, every absence the incident
	// tells is of one type, so each cause had that one thing happen.
	Causes int
	// Events lists each type once, in the order it first appears, except
	// the others' guesses about a cause whose own account (Own) is in the
	// incident: a return another member reports about that cause stays in
	// Refs and Witnesses, but its type is not listed, so the incident tells
	// what the member itself says happened.
	Events []Type
	// Witnesses are the hex IDs of the members that saw the events, in ID
	// order.
	Witnesses []string
	// Approximate is true when any stamp of the incident is untrusted (an
	// event's At, or the Since a Start may be taken from) or
	// clock.Duration(Start, End) says the length is approximate.
	Approximate bool
	// Refs are the events' history entry hashes, one per event, in byte
	// order: the link from the incident back to what it reports.
	Refs []ids.Hash
	// Seq places the incident among incidents that start at the same
	// moment: the node sets it on a roster announcement to the version of
	// the roster it announces, so announcements queued together go out in
	// the order they were made. Coalesce leaves it 0. It is not part of the
	// ID.
	Seq uint64
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
// ref, type, subject, witness, stamp and start) counts once. The result
// depends only on the set of events, not on their order, and evs is not
// modified.
//
// Time. Each witness's boot is one timeline: its events are placed at the
// wall time of its latest stamp (by monotonic clock, then by wall clock)
// moved by the monotonic difference. Within a boot this keeps the monotonic
// order and lengths even when the wall clock stepped by years after NTP
// answered; across boots it compares wall clocks, corrected by any later
// stamp of the same boot. Events without a boot ID keep their own wall time.
// The timelines are keyed by witness and boot, so a member that copies
// another's boot ID moves only its own events. The start (Since) of an own
// account is a stamp of its witness's earlier boot and is placed, and
// anchors, the same way; it is never placed after the account's own At.
//
// Window. An incident takes an event only within window of the incident's
// first event (inclusive), never by chaining from event to event, except by
// the spans of rule (e). A negative window puts every event in an incident
// of its own.
//
// Cause. Events share a cause when one of these holds; anything else stays
// apart:
//
//   - (a) Absence of member X (MemberSilent, MemberBack, RebootPlanned,
//     RebootUnplanned, Upgraded, LinkLost about X): X is a cause. Further
//     absences of X join, of any type, while X is the only cause. Link
//     events (WanDown, WanUp, InternetLost, InternetRestored, UplinkSwitched),
//     from any member, X included, join an incident with a cause in the
//     window: the main router reboots and the access points lose the
//     internet. A link event that has two such incidents in reach joins the
//     earlier; it never merges them. An absence that arrives after link
//     events in the window becomes their cause.
//   - (b) Link events with no absence group together into one site-wide
//     incident naming every witness: the internet is gone for everyone.
//   - (c) Events about different members with no shared cause are separate
//     incidents: different kinds of absence of different members (a planned
//     reboot and a crash, an upgrade and a crash), link losses of two
//     members, alarms about two members.
//   - (d) The same kind of absence (MemberSilent, RebootUnplanned,
//     RebootPlanned, Upgraded or MemberBack, not LinkLost) of two or more
//     members, within the window of the incident's first event, is one
//     incident naming them all: a power cut of the whole site, every router
//     upgraded. Link events join it as under (a). An incident with several
//     causes takes only that one kind of absence, from new members or from
//     its causes; an incident whose one cause had two kinds of absence takes
//     no other member. So no incident tells several members with several
//     kinds of absence, and each cause's absence can be read from it (the
//     records rule (e) links to a cause's own account are of that same
//     absence, and the incident tells it by the own account).
//   - (e) A member's own account of its return (Own) with a known start
//     (Event.Since) spans its absence, from Since to At. The other members'
//     records of that member's absence (a silence, a return, their guess at
//     its cause) whose stamp lies within the span, widened by window on
//     each side, join the own account's incident wherever it is, however
//     far they are from its other events: one absence, one incident. So does
//     another member's guess at the return that names the boot the own
//     account came back in (Event.Back), with or without a start, whenever
//     the guesser heard it. An own
//     account of a kind rule (d) shares also joins, beyond the window, an
//     incident of that one kind, about other members, that holds own
//     accounts with spans, when every one of those spans and its own cover
//     one moment and their starts lie within startSpread and the window of
//     each other: after a power cut the routers of a site come back up to
//     minutes apart. A long absence does not take in a short one of another
//     member long before it (their starts lie apart), and absences that
//     share no moment stay apart. These records are told as under (d): the
//     incident tells each cause by its own account.
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
// incident's event records in byte order, only the records of its own
// accounts when it holds any; a record is ref (32) | subject
// (16) | witness (16) | boot (16) | wall seconds since 1970 (int64) | wall
// nanoseconds (uint32) | monotonic nanoseconds (int64) | trusted (1 byte) |
// type length (uint32) | type, integers big-endian. Detail and Since are not
// part of it; the ref already fixes the event.
func Coalesce(evs []Event, window time.Duration) []Incident {
	items := timeline(evs)
	link := links(items, window)
	var groups []*group
	of := make([]*group, len(items)) // the group each placed item went to
	open := 0                        // groups before this one have closed for good
	for i, it := range items {
		if link[i] >= 0 {
			continue // it goes with the own account it records (rule (e))
		}
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
		if g == nil && window >= 0 {
			for _, cand := range groups {
				if cand.overlaps(it, window) {
					g = cand
					break
				}
			}
		}
		if g == nil {
			g = &group{role: roleOf(it.ev), subject: it.ev.Subject, typ: it.ev.Type}
			groups = append(groups, g)
		}
		g.add(it)
		of[i] = g
	}
	for i, j := range link {
		if j >= 0 {
			of[j].items = append(of[j].items, items[i])
		}
	}
	var out []Incident
	for _, g := range groups {
		out = append(out, g.incident())
	}
	return out
}

// links returns, for each item, the index of the own account whose absence
// it records (rule (e)), or -1: an absence of the account's subject,
// reported by another member, stamped within the account's span widened by
// window, or a guess at its return that names the boot the account came
// back in (sameReturn). Of several such accounts it takes the earliest. A
// negative window links nothing.
func links(items []item, window time.Duration) []int {
	link := make([]int, len(items))
	for i := range link {
		link[i] = -1
	}
	if window < 0 {
		return link
	}
	for i, it := range items {
		if roleOf(it.ev) != roleAbsence || Own(it.ev) {
			continue
		}
		for j, u := range items {
			if !Own(u.ev) || u.ev.Subject != it.ev.Subject {
				continue
			}
			within := u.span && !it.at.Before(u.from.Add(-window)) && !it.at.After(u.at.Add(window))
			if !within && !sameReturn(it.ev, u.ev) {
				continue
			}
			link[i] = j
			break
		}
	}
	return link
}

// sameReturn reports whether e, another member's guess at a return of
// own's subject in a new boot, names the boot own came back in: the same
// return, whenever the guesser heard it.
func sameReturn(e, own Event) bool {
	switch e.Type {
	case RebootUnplanned, RebootPlanned, Upgraded, MemberBack:
		return e.Back != (ids.BootID{}) && e.Back == own.Back
	}
	return false
}

// item is one event placed on its timeline.
type item struct {
	ev   Event
	at   time.Time // the event's moment on the corrected wall clock of its timeline, UTC
	span bool      // an own account with a known start (rule (e))
	from time.Time // with span: when the absence began, placed like at and never after it
	rec  []byte    // the event's record: its identity, the ID input, the tie-break
	key  []byte    // rec and, with span, the start: what makes an event the same event
}

// stamp returns the event's stamp with Wall on the corrected clock.
func (it item) stamp() clock.Stamp {
	s := it.ev.At
	s.Wall = it.at
	return s
}

// since returns the start of an own account's absence with Wall on the
// corrected clock.
func (it item) since() clock.Stamp {
	s := it.ev.Since
	s.Wall = it.from
	return s
}

// spanned reports whether e is an own account with a known start.
func spanned(e Event) bool { return Own(e) && e.Since != (clock.Stamp{}) }

// timeline returns the events in time order, each once, placed on the
// corrected clock of their witness's boot.
func timeline(evs []Event) []item {
	type key struct {
		witness ids.MemberID
		boot    ids.BootID
	}
	anchors := map[key]clock.Stamp{}
	anchor := func(w ids.MemberID, s clock.Stamp) {
		if s.Boot == (ids.BootID{}) {
			return // unknown boot: the stamp stands alone
		}
		k := key{w, s.Boot}
		if a, ok := anchors[k]; !ok || later(s, a) {
			anchors[k] = s
		}
	}
	for _, e := range evs {
		anchor(e.Witness, e.At)
		if spanned(e) {
			anchor(e.Witness, e.Since)
		}
	}
	place := func(w ids.MemberID, s clock.Stamp) time.Time {
		at := s.Wall
		if a, ok := anchors[key{w, s.Boot}]; ok {
			at = a.Wall.Add(s.Mono - a.Mono)
		}
		// UTC drops Go's own monotonic reading and the zone, so moments
		// compare as wall times only and the result does not depend on
		// which of two equal stamps anchored a timeline.
		return at.UTC()
	}
	items := make([]item, 0, len(evs))
	for _, e := range evs {
		it := item{ev: e, at: place(e.Witness, e.At), rec: record(e)}
		it.key = it.rec
		if spanned(e) {
			it.span = true
			it.from = earliest(place(e.Witness, e.Since), it.at)
			it.key = appendStamp(slices.Clone(it.rec), e.Since)
		}
		items = append(items, it)
	}
	slices.SortFunc(items, byTime)
	return slices.CompactFunc(items, func(a, b item) bool { return bytes.Equal(a.key, b.key) })
}

func earliest(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}

func latest(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

// byTime orders items by their moment, then by what they are.
func byTime(a, b item) int {
	if c := a.at.Compare(b.at); c != 0 {
		return c
	}
	return bytes.Compare(a.key, b.key)
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
	r = appendStamp(r, e.At)
	r = binary.BigEndian.AppendUint32(r, uint32(len(e.Type)))
	return append(r, e.Type...)
}

// appendStamp appends s as a record holds it: boot (16) | wall seconds since
// 1970 (int64) | wall nanoseconds (uint32) | monotonic nanoseconds (int64) |
// trusted (1 byte), integers big-endian.
func appendStamp(r []byte, s clock.Stamp) []byte {
	r = append(r, s.Boot[:]...)
	r = binary.BigEndian.AppendUint64(r, uint64(s.Wall.Unix()))
	r = binary.BigEndian.AppendUint32(r, uint32(s.Wall.Nanosecond()))
	r = binary.BigEndian.AppendUint64(r, uint64(s.Mono))
	if s.Trusted {
		return append(r, 1)
	}
	return append(r, 0)
}

// group is an incident being built.
type group struct {
	role    role           // roleAbsence once an absence has joined
	causes  []ids.MemberID // roleAbsence: the absent members, in the order they joined
	subject ids.MemberID   // roleFact: the subject of the fact
	typ     Type           // roleFact: the type of the fact; roleAbsence: the one type of every absence, "" once mixed
	items   []item         // items[0] opened the window; the placed ones in time order, then those linked by rule (e)

	// The own accounts with a span that joined (rule (e)): how many, the
	// moments all their absences cover (from lo to hi; none once lo is
	// after hi), and the earliest and the latest of their starts.
	spans       int
	lo, hi      time.Time
	first, last time.Time
}

// shared reports whether absences of type t of several members are one
// incident (rule (d)). A link loss is not: two members' links break for two
// reasons as often as for one.
func shared(t Type) bool {
	switch t {
	case MemberSilent, RebootUnplanned, RebootPlanned, Upgraded, MemberBack:
		return true
	}
	return false
}

// accepts reports whether e shares the group's cause. The window is checked
// by the caller.
func (g *group) accepts(e Event) bool {
	switch roleOf(e) {
	case roleAbsence:
		switch {
		case g.role == roleLink:
			return true // the cause of the link events before it
		case g.role != roleAbsence:
			return false
		case slices.Contains(g.causes, e.Subject):
			return len(g.causes) == 1 || e.Type == g.typ // one member: any kind; several: their one kind
		default:
			return e.Type == g.typ && shared(e.Type) // rule (d)
		}
	case roleLink:
		return g.role == roleLink || g.role == roleAbsence
	case roleFlood:
		return g.role == roleFlood
	default:
		return g.role == roleFact && g.typ == e.Type && g.subject == e.Subject
	}
}

// overlaps reports whether it, an own account with a span, shares the
// group's cause beyond the window (rule (e)): an incident of its one kind
// about other members whose own accounts' spans and its own cover one
// moment, with every start within startSpread and window of the others.
func (g *group) overlaps(it item, window time.Duration) bool {
	e := it.ev
	switch {
	case !it.span || g.role != roleAbsence || g.spans == 0 || g.typ != e.Type || !shared(e.Type):
		return false
	case slices.Contains(g.causes, e.Subject):
		return false // a second absence of a cause is another absence
	case g.lo.After(g.hi) || it.from.After(g.hi) || g.lo.After(it.at):
		return false // no moment every one of them was away
	}
	return latest(g.last, it.from).Sub(earliest(g.first, it.from)) <= startSpread+window
}

// add puts it into the group; an absence makes its subject a cause.
func (g *group) add(it item) {
	if e := it.ev; roleOf(e) == roleAbsence {
		switch {
		case g.role != roleAbsence: // a new group, or link events taken over
			g.role, g.typ = roleAbsence, e.Type
		case e.Type != g.typ:
			g.typ = "" // one member, several kinds of absence
		}
		if !slices.Contains(g.causes, e.Subject) {
			g.causes = append(g.causes, e.Subject)
		}
	}
	if it.span {
		if g.spans == 0 {
			g.lo, g.hi, g.first, g.last = it.from, it.at, it.from, it.from
		} else {
			g.lo, g.hi = latest(g.lo, it.from), earliest(g.hi, it.at)
			g.first, g.last = earliest(g.first, it.from), latest(g.last, it.from)
		}
		g.spans++
	}
	g.items = append(g.items, it)
}

func (g *group) incident() Incident {
	items := slices.Clone(g.items)
	slices.SortFunc(items, byTime)
	// The causes whose own account is here, and those whose silence is.
	own, silent := map[ids.MemberID]bool{}, map[ids.MemberID]bool{}
	for _, it := range items {
		switch e := it.ev; {
		case Own(e):
			own[e.Subject] = true
		case e.Type == MemberSilent:
			silent[e.Subject] = true
		}
	}
	inc := Incident{
		Start: items[0].stamp(),
		End:   items[len(items)-1].stamp(),
	}
	members, witnesses := map[ids.MemberID]bool{}, map[ids.MemberID]bool{}
	seen := map[Type]bool{}
	untrusted := false
	recs := make([][]byte, 0, len(items))
	var ownRecs [][]byte
	for _, it := range items {
		e := it.ev
		members[e.Subject] = true
		witnesses[e.Witness] = true
		guess := roleOf(e) == roleAbsence && e.Type != MemberSilent && !Own(e) && own[e.Subject]
		if !seen[e.Type] && !guess {
			seen[e.Type] = true
			inc.Events = append(inc.Events, e.Type)
		}
		untrusted = untrusted || !e.At.Trusted
		inc.Began = inc.Began || it.span || e.Type == MemberSilent
		if it.span && !silent[e.Subject] {
			// Nobody here saw this cause go: its own start is the start.
			untrusted = untrusted || !e.Since.Trusted
			if it.from.Before(inc.Start.Wall) {
				inc.Start = it.since()
			}
		}
		inc.Refs = append(inc.Refs, e.Ref)
		recs = append(recs, it.rec)
		if Own(e) {
			ownRecs = append(ownRecs, it.rec)
		}
	}
	if len(ownRecs) > 0 {
		recs = ownRecs
	}

	causes := map[ids.MemberID]bool{}
	for _, c := range g.causes {
		causes[c] = true
		delete(members, c)
	}
	inc.Members = append(named(causes), named(members)...)
	inc.Causes = len(g.causes)
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
