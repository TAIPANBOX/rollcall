package node

import (
	"cmp"
	"encoding/json"
	"maps"
	"slices"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/clock"
	"github.com/TAIPANBOX/rollcall/internal/deliver"
	"github.com/TAIPANBOX/rollcall/internal/elect"
	"github.com/TAIPANBOX/rollcall/internal/events"
	"github.com/TAIPANBOX/rollcall/internal/history"
	"github.com/TAIPANBOX/rollcall/internal/ids"
	"github.com/TAIPANBOX/rollcall/internal/roster"
)

// # Incidents
//
// The node builds incidents from the events in its history, its own and
// every other member's (each event entry with its stamp entry), so members
// that hold the same entries make the same incidents with the same IDs.
// An event waits settle after the node first saw it, so the events of one
// cause that arrive by replication join it; then the incident is final:
// its events are taken, late ones form a new incident, and its ID never
// changes. A return of a member is merged with the incident that reported
// its silence, and an internet or WAN restore with its loss, into one
// incident that reports the whole absence with its length; once that is
// delivered, its ID and the IDs it merged are acknowledged.
//
// A router's own link changes (its WAN, its internet, its DNS) wait longer
// (@decided 2026-10-30): those of one router that follow each other within
// events.LinkWindow are one incident (events.CoalesceLinks, rule (f)), and
// an incident of link changes is final only once each of its events waited
// linkSettle, so the losses that open an outage go out in one message, the
// returns that close it in one, and a link that keeps dropping in one that
// counts the drops. A record that comes later still and belongs to a link
// incident kept here joins it (absorbLocked) instead of making a message of
// its own.
//
// Roster announcements are incidents of their own whose one event is
// fixed by the roster alone (its hash as the ref, a zero trusted stamp), so
// every member queues the same incident for one roster change and the
// group sends it once: a change is announced exactly once (invariant 16).
// The changes a lost branch made are announced the same way, from the
// entry a member records when it adopts the other branch. A roster carries
// no time, so the incident is placed, after its ID is fixed, at the moment
// this member queued it, and its Seq is the roster version:
// announcements held back together (the chat out) go out in the order the
// changes were made, and after anything that happened before them (U1).
//
// Every incident goes into the deliver.Queue; the election decides who
// sends, and acknowledgements come back as history entries.

const (
	// settle is how long an event waits for the others of its cause: the
	// coalescing window (D8). Detection stays at 30 s, so a silence reaches
	// the chat about 40 to 45 s after the last heartbeat; a record that
	// comes later only adds a witness (toldAlreadyLocked).
	settle = events.DefaultWindow
	// linkSettle is how long each event of an incident of link changes waits
	// for the others of its routers (@decided 2026-10-30): the chain of
	// rule (f), so the first message of an outage comes about 30 s later than
	// a silence's. A WAN loss is followed by the internet probe's loss, dated
	// at its first failed round, two rounds (20 s) and a probe later.
	linkSettle = events.LinkWindow
	// maxIncidentAge keeps old events, caught up after an absence, out of
	// the chat: they stay in the history only.
	maxIncidentAge = 24 * time.Hour
	// keepIncidents bounds the incidents kept for pairing and status.
	keepIncidents = 64
	// keepEvents bounds the events kept, assigned or not.
	keepEvents = 2048
	// maxChanges bounds the changes one announcement lists.
	maxChanges = 64
)

type evRec struct {
	ev       events.Event
	seen     time.Duration
	assigned bool
	single   bool         // an incident of its own: a roster announcement
	origin   ids.MemberID // the history entry it came from; zero for a roster announcement
	seq      uint64
	back     ids.BootID // for a return: the boot its subject came back in
	last     ids.BootID // the boot its subject was last heard in (or left), when known
	version  uint64     // for a roster announcement: the version of the roster it announces
}

type incRec struct {
	inc        events.Incident
	events     []events.Event
	components []string
	paired     bool
	single     bool // an incident of its own: no count of confirmations
	queuedAt   time.Time
	// held is set once the sender began holding the incident back for its
	// end (heldLocked), at heldAt; RAM only.
	held    bool
	heldAt  time.Duration
	requeue bool // restored, to be queued once its age is judged (state.go)
}

type incidents struct {
	evs        map[ids.Hash]*evRec
	changes    map[ids.Hash][]deliver.Change // by the ref of a roster event
	facts      map[string][]deliver.Change   // by incident ID
	recent     []*incRec
	byID       map[string]*incRec
	ackedIDs   map[string]bool
	ackPending map[string]bool
	alarmed    map[string]bool         // alarm incident IDs raised, one per proof
	witnessed  map[ids.Hash]bool       // events this node has stated a view on
	pending    []pendingAlarm          // falsehood alarms of others, not yet checkable
	forkChecks []forkCheck             // fork alarms of others, not yet checked
	waiting    []pendingUpdate         // updates whose claims have not arrived yet
	updates    map[ids.Hash]bool       // corrections whose update was recorded
	boots      map[ids.BootID]bool     // the boots a boot record in the log names
	ownBacks   map[ids.BootID]bool     // the boots a member's own account of its return names
	forkSeqs   map[ids.MemberID]uint64 // the lowest sequence number a fork alarm names, per forked member
	loading    bool
	restoreBy  time.Duration // when restored incidents are queued without a trusted clock (state.go)

	witnessBudget  map[ids.MemberID]*budget // statements left per origin (witness.go)
	witnessDropped uint64                   // statements not made for lack of budget

	ackNotes   []ackNote        // acknowledgements that name what they told, newest last
	named      map[ids.Hash]int // how many of ackNotes name each event (inPiecesLocked)
	coverDirty bool             // events arrived since the last look for incidents they tell
}

// ackNote is an acknowledgement of incident id by a member, with the events
// its message told (deliver.AckRefs).
type ackNote struct {
	id   string
	by   ids.MemberID
	refs []ids.Hash
}

// keepAckNotes bounds the acknowledgements with events kept: the incidents
// kept here (keepIncidents) are what they are compared with.
const keepAckNotes = 4 * keepIncidents

func (c *incidents) init() {
	c.evs = map[ids.Hash]*evRec{}
	c.changes = map[ids.Hash][]deliver.Change{}
	c.facts = map[string][]deliver.Change{}
	c.byID = map[string]*incRec{}
	c.ackedIDs = map[string]bool{}
	c.ackPending = map[string]bool{}
	c.alarmed = map[string]bool{}
	c.witnessed = map[ids.Hash]bool{}
	c.updates = map[ids.Hash]bool{}
	c.boots = map[ids.BootID]bool{}
	c.ownBacks = map[ids.BootID]bool{}
	c.forkSeqs = map[ids.MemberID]uint64{}
	c.witnessBudget = map[ids.MemberID]*budget{}
	c.named = map[ids.Hash]int{}
}

// forkAt notes that a fork alarm names seq of o's chain.
func (c *incidents) forkAt(o ids.MemberID, seq uint64) {
	if old, ok := c.forkSeqs[o]; seq > 0 && (!ok || seq < old) {
		c.forkSeqs[o] = seq
	}
}

// settleAll marks every event held as taken: what was loaded at start is
// history, not news.
func (c *incidents) settleAll() {
	for _, r := range c.evs {
		r.assigned = true
	}
}

// eventIn takes another or an own event entry with body b into the
// events incidents are made of. An event without a stamp, a flood (local
// status only) and an alarm (an incident of its own) are left out.
func (c *incidents) eventIn(e history.Entry, b EventBody, now clock.Stamp) {
	if b.At == (At{}) || b.Type == events.UnderFlood || b.Type == events.Fork {
		return
	}
	ev := eventOf(e, b)
	c.coverDirty = true
	if events.Own(ev) && ev.Back != (ids.BootID{}) {
		if len(c.ownBacks) >= keepEvents {
			clear(c.ownBacks)
		}
		c.ownBacks[ev.Back] = true
	}
	c.add(e.Hash(), &evRec{ev: ev, seen: now.Mono, origin: e.Origin, seq: e.Seq, back: b.Back.ID, last: b.Last.ID})
}

// bootIn notes the boot a boot record names.
func (c *incidents) bootIn(b BootBody) {
	if len(c.boots) >= keepEvents {
		clear(c.boots)
	}
	c.boots[b.Boot.ID] = true
}

// guessed are the returns a member guesses from another member's heartbeats
// when that member came back in a new boot.
var guessed = []events.Type{events.RebootUnplanned, events.RebootPlanned, events.Upgraded, events.MemberBack}

// ownWait bounds how long a guessed return waits for its subject's own
// account: the subject writes it once its own chain is caught up, at the
// latest ownCatchUp after its start.
const ownWait = ownCatchUp + settle

// toldByOwnLocked reports whether r is another member's guess at a return
// whose own account, which names the same boot, is already in an incident
// (D18): the account told it, and the guess would tell it again, maybe as
// another kind.
func (n *Node) toldByOwnLocked(r *evRec) bool {
	e := r.ev
	if r.back == (ids.BootID{}) || e.Witness == e.Subject || !slices.Contains(guessed, e.Type) || !n.inc.ownBacks[r.back] {
		return false
	}
	for _, o := range n.inc.evs {
		if o.assigned && events.Own(o.ev) && o.ev.Subject == e.Subject && o.ev.Back == r.back {
			return true
		}
	}
	return false
}

// inToldSpanLocked reports whether r is another member's record of a
// member's silence that came after the member's own account of that absence
// was taken into an incident: the silence names the boot the account says
// the member left (or names none), and is stamped within the absence the
// account spans, from its Since, less the coalescing window, to its At.
// Rule (e) of Coalesce would have joined it there, and the chat was told
// that absence (Q4: a router back from its own restart records a silence
// from its start, or a record held up by the network arrives after the
// incident was made). A silence that names the boot the member came back
// in, or is stamped after the account, is a new absence. An account of a
// forked origin, left out of the incidents, absorbs nothing.
func (n *Node) inToldSpanLocked(r *evRec, distrusted map[ids.MemberID]uint64) bool {
	e := r.ev
	if e.Type != events.MemberSilent || e.Subject == (ids.MemberID{}) || e.Witness == e.Subject {
		return false
	}
	at := e.At.Wall
	for _, o := range n.inc.evs {
		a := o.ev
		if !o.assigned || !events.Own(a) || a.Subject != e.Subject || a.Since == (clock.Stamp{}) ||
			(r.last != (ids.BootID{}) && r.last != o.last) ||
			(distrusted[o.origin] > 0 && o.seq >= distrusted[o.origin]) {
			continue
		}
		if !at.Before(a.Since.Wall.Add(-events.DefaultWindow)) && !at.After(a.At.Wall) {
			return true
		}
	}
	return false
}

// ownAccountOf returns x's own account of its return in evs that gives the
// start of its absence (Since), if any.
func ownAccountOf(evs []events.Event, x string) (events.Event, bool) {
	for _, e := range evs {
		if events.Own(e) && e.Subject.String() == x && e.Since != (clock.Stamp{}) {
			return e, true
		}
	}
	return events.Event{}, false
}

// withinOwnSpanLocked reports whether evs are silences of own's member that
// own's absence spans, as inToldSpanLocked judges one.
func (n *Node) withinOwnSpanLocked(evs []events.Event, own events.Event) bool {
	left := ids.BootID{}
	if o := n.inc.evs[own.Ref]; o != nil {
		left = o.last
	}
	for _, e := range evs {
		at := e.At.Wall
		if e.Type != events.MemberSilent || at.Before(own.Since.Wall.Add(-events.DefaultWindow)) || at.After(own.At.Wall) {
			return false
		}
		if r := n.inc.evs[e.Ref]; r != nil && r.last != (ids.BootID{}) && left != (ids.BootID{}) && r.last != left {
			return false
		}
	}
	return len(evs) > 0
}

// awaitsOwnLocked reports whether r is another member's guess at the return
// of a member in a new boot whose boot record is not in the log yet: the
// member's own account follows that record, tells how its boot before
// ended (planned or not, the shutdown marker), and the incident waits for
// it, so the account wins over the guess (D18).
func (n *Node) awaitsOwnLocked(r *evRec, now clock.Stamp) bool {
	e := r.ev
	return !r.single && r.back != (ids.BootID{}) && e.Witness != e.Subject && slices.Contains(guessed, e.Type) &&
		!n.inc.boots[r.back] && now.Mono-r.seen < ownWait
}

// eventOf returns the event the entry e with body b records. A start
// (Since) counts only on an entry whose origin is its subject: a member
// says when its own absence began, never another's.
func eventOf(e history.Entry, b EventBody) events.Event {
	ev := events.Event{Type: b.Type, Subject: b.Subject, Witness: e.Origin, At: b.At.Stamp(), Back: b.Back.ID, Ref: e.Hash(), Detail: b.Detail}
	if e.Origin == b.Subject && b.Since != (At{}) {
		ev.Since = b.Since.Stamp()
	}
	return ev
}

func (c *incidents) add(ref ids.Hash, r *evRec) {
	if _, ok := c.evs[ref]; ok {
		return
	}
	if len(c.evs) >= keepEvents {
		for h, old := range c.evs {
			if old.assigned {
				delete(c.evs, h)
			}
		}
	}
	r.assigned = r.assigned || c.loading
	c.evs[ref] = r
}

func (c *incidents) acked(id string) {
	if len(c.ackedIDs) >= 4*deliver.MaxDone {
		clear(c.ackedIDs)
	}
	c.ackedIDs[id] = true
	delete(c.ackPending, id)
}

// fixedStamp is the stamp of an event fixed by data alone, the same on
// every member.
var fixedStamp = clock.Stamp{Trusted: true}

// announceLocked queues the announcement of r, signed as s after prev.
func (n *Node) announceLocked(prev roster.Roster, s roster.Signed, r roster.Roster, now clock.Stamp) {
	ref := s.Hash()
	if _, ok := n.inc.evs[ref]; ok {
		return
	}
	n.inc.changes[ref] = diffRosters(prev, r, signerName(prev, s))
	n.inc.add(ref, &evRec{ev: events.Event{Type: events.RosterChanged, Ref: ref, At: fixedStamp}, seen: now.Mono, single: true, version: r.Version})
}

func signerName(prev roster.Roster, s roster.Signed) string {
	if s.Recovery {
		return ""
	}
	m, _ := memberOf(prev, s.SignerID)
	return m.Name
}

// diffRosters lists what r changed against prev, each change by.
func diffRosters(prev, r roster.Roster, by string) []deliver.Change {
	var out []deliver.Change
	for _, m := range r.Members {
		old, ok := memberOf(prev, m.ID)
		switch {
		case !ok:
			out = append(out, deliver.Change{Kind: deliver.ChangeAdded, Member: m.Name, By: by})
		case !sameRoles(old.Roles, m.Roles):
			out = append(out, deliver.Change{Kind: deliver.ChangeRoles, Member: m.Name, By: by,
				Gained: rolesNotIn(m.Roles, old.Roles), Lost: rolesNotIn(old.Roles, m.Roles)})
		}
	}
	for _, m := range prev.Members {
		if _, ok := memberOf(r, m.ID); !ok {
			out = append(out, deliver.Change{Kind: deliver.ChangeRemoved, Member: m.Name, By: by})
		}
	}
	return out
}

// rolesNotIn returns the roles of a that b lacks, in a's order; never nil.
func rolesNotIn(a, b []roster.Role) []roster.Role {
	out := []roster.Role{}
	for _, x := range a {
		if !slices.Contains(b, x) {
			out = append(out, x)
		}
	}
	return out
}

func sameRoles(a, b []roster.Role) bool {
	if len(a) != len(b) {
		return false
	}
	for _, x := range a {
		if !slices.Contains(b, x) {
			return false
		}
	}
	return true
}

// droppedBody is the body of the entry that records a roster branch this
// member adopted another branch over: what it undid and who had made it.
type droppedBody struct {
	Dropped droppedOf `json:"dropped"`
}

type droppedOf struct {
	Tip     ids.Hash    `json:"tip"`
	Changes []changeMsg `json:"changes"`
}

// changeMsg is one change of a dropped branch. Gained and Lost, on a change
// of roles only, are the roles the member gained and lost.
type changeMsg struct {
	Kind   int           `json:"kind"`
	Member string        `json:"member"`
	By     string        `json:"by"`
	Gained []roster.Role `json:"gained,omitempty"`
	Lost   []roster.Role `json:"lost,omitempty"`
}

func decodeDropped(e history.Entry) (droppedOf, bool) {
	var b droppedBody
	if e.Kind != history.KindEvent || decodeJSON(e.Body, &b, history.MaxBodySize) != nil {
		return droppedOf{}, false
	}
	d := b.Dropped
	if d.Tip == (ids.Hash{}) || len(d.Changes) > maxChanges {
		return droppedOf{}, false
	}
	for _, c := range d.Changes {
		if c.Kind < int(deliver.ChangeAdded) || c.Kind > int(deliver.ChangeRoles) ||
			roster.ValidName(c.Member) != nil || (c.By != "" && roster.ValidName(c.By) != nil) ||
			!validRoleChange(c) {
			return droppedOf{}, false
		}
	}
	return d, true
}

// validRoleChange reports whether the roles c names are fit to show: none
// on a change that is not one of roles; on one of roles, only roles this
// version knows, none named twice, in Gained and Lost together.
func validRoleChange(c changeMsg) bool {
	if c.Kind != int(deliver.ChangeRoles) {
		return len(c.Gained) == 0 && len(c.Lost) == 0
	}
	all := append(slices.Clone(c.Gained), c.Lost...)
	for i, r := range all {
		switch r {
		case roster.RolePrimary, roster.RoleBackup, roster.RoleSender:
		default:
			return false
		}
		if slices.Contains(all[:i], r) {
			return false
		}
	}
	return true
}

func (c *incidents) droppedIn(e history.Entry, d droppedOf, now clock.Stamp) {
	if _, ok := c.evs[d.Tip]; ok {
		return
	}
	var cs []deliver.Change
	for _, m := range d.Changes {
		cs = append(cs, deliver.Change{Kind: deliver.ChangeKind(m.Kind), Member: m.Member, By: m.By, Gained: m.Gained, Lost: m.Lost})
	}
	c.changes[d.Tip] = cs
	c.add(d.Tip, &evRec{ev: events.Event{Type: events.RosterChangesDropped, Ref: d.Tip, At: fixedStamp}, seen: now.Mono, single: true,
		origin: e.Origin, seq: e.Seq})
}

// droppedLocked records that the node undid ours, its own branch after
// base, for another branch.
func (n *Node) droppedLocked(base roster.Roster, ours []roster.Signed, oursR []roster.Roster, now clock.Stamp) {
	d := droppedOf{Tip: ours[len(ours)-1].Hash(), Changes: []changeMsg{}}
	before := base
	for i, s := range ours {
		for _, c := range diffRosters(before, oursR[i], signerName(before, s)) {
			if len(d.Changes) < maxChanges {
				d.Changes = append(d.Changes, changeMsg{Kind: int(c.Kind), Member: c.Member, By: c.By, Gained: c.Gained, Lost: c.Lost})
			}
		}
		before = oursR[i]
	}
	b, err := json.Marshal(droppedBody{Dropped: d})
	if err != nil {
		return
	}
	n.recordRaw(b, now)
}

// incidentsLocked turns settled events into incidents and queues them.
func (n *Node) incidentsLocked(now clock.Stamp) {
	n.queueRestoredLocked(now)
	n.coverLocked()
	var list []events.Event
	distrusted := n.distrustedLocked()
	for _, r := range n.inc.evs {
		switch {
		case r.assigned:
		case !r.single && r.origin != (ids.MemberID{}) && r.seq >= distrusted[r.origin] && distrusted[r.origin] > 0:
			// Recorded where its chain forked or after: its word differs
			// between the routers that saw its different faces, and is left
			// out (witness.go).
			r.assigned = true
		case !r.single && now.Mono-r.seen >= settle && n.cutOffViewLocked(r.ev):
			r.assigned = true
		case !r.single && n.toldByOwnLocked(r):
			// A guess at a return the member's own account told already.
			r.assigned = true
		case !r.single && n.inToldSpanLocked(r, distrusted):
			// A late silence inside an absence the member's own account told.
			r.assigned = true
		case r.single:
			r.assigned = true
			incs := events.Coalesce([]events.Event{r.ev}, events.DefaultWindow)
			if len(incs) == 1 {
				inc := incs[0]
				at := n.localStamp(now)
				inc.Start, inc.End, inc.Seq = at, at, r.version
				n.inc.facts[inc.ID] = n.inc.changes[r.ev.Ref]
				n.queueLocked(inc, []events.Event{r.ev}, nil, now)
				n.inc.byID[inc.ID].single = true
			}
		default:
			list = append(list, r.ev)
		}
	}
	if len(list) == 0 {
		return
	}
	for _, inc := range events.CoalesceLinks(list, events.DefaultWindow, events.LinkWindow) {
		var evs []events.Event
		ready := true
		wait := settle
		if linkIncident(inc) {
			wait = linkSettle
		}
		for _, ref := range inc.Refs {
			r := n.inc.evs[ref]
			if r == nil || now.Mono-r.seen < wait || n.awaitsOwnLocked(r, now) {
				ready = false
				break
			}
			evs = append(evs, r.ev)
		}
		if !ready {
			continue
		}
		for _, ref := range inc.Refs {
			n.inc.evs[ref].assigned = true
		}
		if inc.End.Trusted && now.Trusted && now.Wall.Sub(inc.End.Wall) > maxIncidentAge {
			continue
		}
		if m, parts, mev, ok := n.pairLocked(inc, evs); ok {
			n.queueLocked(m, mev, parts, now)
			// A return of links may end several starts (pairLinkLocked).
			for _, start := range parts[:len(parts)-1] {
				switch {
				case n.deliveredLocked(start):
				case n.deliveredLocked(m.ID):
					// Another member told the whole absence, from its start.
					n.ackedLocked(start, n.id.ID)
				default:
					// Not sent yet: the merged incident tells its start too,
					// in one message (D5).
					n.queue.Ack(start, n.id.ID)
				}
			}
			continue
		}
		if n.toldAlreadyLocked(evs) || n.absorbLocked(inc, evs) {
			continue
		}
		n.queueLocked(inc, evs, nil, now)
	}
}

// lossOf maps a loss to the restore that ends it.
var lossOf = map[events.Type]events.Type{
	events.InternetLost: events.InternetRestored, events.WanDown: events.WanUp, events.DNSLost: events.DNSRestored,
}

// linkKey is one kind of link, named by its loss, of one router.
type linkKey struct {
	loss events.Type
	who  ids.MemberID
}

// linkEnds returns, for each link a router recorded in evs, whether its
// last record there, in the order of the stamps, is a loss (true: the link
// is down) or a return (false).
func linkEnds(evs []events.Event) map[linkKey]bool {
	sorted := slices.Clone(evs)
	slices.SortStableFunc(sorted, func(a, b events.Event) int {
		if c := a.At.Wall.Compare(b.At.Wall); c != 0 {
			return c
		}
		return cmp.Compare(a.At.Mono, b.At.Mono)
	})
	out := map[linkKey]bool{}
	for _, e := range sorted {
		for loss, back := range lossOf {
			switch e.Type {
			case loss:
				out[linkKey{loss, e.Witness}] = true
			case back:
				out[linkKey{loss, e.Witness}] = false
			}
		}
	}
	return out
}

// anyDown reports whether ends holds a link that is down, anyBack whether
// it holds one that came back.
func anyDown(ends map[linkKey]bool) bool {
	return slices.Contains(slices.Collect(maps.Values(ends)), true)
}
func anyBack(ends map[linkKey]bool) bool {
	return slices.Contains(slices.Collect(maps.Values(ends)), false)
}

// linkOnly reports whether evs are a router's own link changes and nothing
// else.
func linkOnly(evs []events.Event) bool {
	return len(evs) > 0 && !slices.ContainsFunc(evs, func(e events.Event) bool { return !linkChange(e.Type) })
}

// linkIncident reports whether inc tells link changes alone: no absence
// and no other kind of event (rule (b) of events.Coalesce).
func linkIncident(inc events.Incident) bool {
	return inc.Causes == 0 && len(inc.Events) > 0 && !slices.ContainsFunc(inc.Events, func(t events.Type) bool { return !linkChange(t) })
}

// keptLink reports whether r is a kept incident of link changes that no
// return was merged into yet.
func keptLink(r *incRec) bool {
	return !r.paired && !r.single && r.inc.Causes == 0 && linkOnly(r.events)
}

// absorbLocked joins evs, the events of the link incident inc that no return
// paired with a start, to a kept link incident they belong to, and reports
// whether it did. The incident keeps its ID; what it tells grows, and so does
// what a return merged with it later tells. They belong to it when either
//
//   - every link evs are about ends down there, and is down in the incident
//     too: its routers' records, again, of an outage it tells that has not
//     ended. A router that restarts while its internet is still out finds it
//     out again, and a link that comes back for a few seconds within an
//     outage ends down again (D5); or
//   - every event of evs is stamped within events.LinkWindow of a record of
//     the same router in the incident: had it come in time, rule (f) would
//     have put it there (lateRecordsLocked).
//
// So the losses of one router within the window are one message, however
// late a probe records one (@decided 2026-10-30).
func (n *Node) absorbLocked(inc events.Incident, evs []events.Event) bool {
	if inc.Causes != 0 || !linkOnly(evs) {
		return false
	}
	ends := linkEnds(evs)
	for i := len(n.inc.recent) - 1; i >= 0; i-- {
		r := n.inc.recent[i]
		if !keptLink(r) {
			continue
		}
		open := linkEnds(r.events)
		if !continuesOutage(ends, open) && !n.lateRecordsLocked(evs, r, open) {
			continue
		}
		all := append(slices.Clone(r.events), evs...)
		merged := events.Coalesce(all, spanOf(all)+events.DefaultWindow)
		if len(merged) != 1 {
			continue
		}
		m := merged[0]
		m.ID, m.Seq = r.inc.ID, r.inc.Seq
		r.inc, r.events = m, all
		n.flusher.Mark()
		return true
	}
	return false
}

// continuesOutage reports whether every link in ends is down, and down in
// open, the links of a kept incident, too.
func continuesOutage(ends, open map[linkKey]bool) bool {
	if len(ends) == 0 {
		return false
	}
	for k, down := range ends {
		if !down || !open[k] {
			return false
		}
	}
	return true
}

// lateRecordsLocked reports whether every event of evs is stamped within
// events.LinkWindow of a record of the same router in r, a kept link
// incident, and may join it. While r was not delivered, every such
// record joins it and its message tells it. Once r was delivered, only
// losses join, and only while r tells an outage that has not ended: its end
// will tell them. A loss after an outage the chat was told had ended is news.
func (n *Node) lateRecordsLocked(evs []events.Event, r *incRec, open map[linkKey]bool) bool {
	delivered := n.deliveredLocked(r.inc.ID)
	if delivered && !anyDown(open) {
		return false
	}
	for _, e := range evs {
		if _, loss := lossOf[e.Type]; delivered && !loss {
			return false
		}
		if !slices.ContainsFunc(r.events, func(f events.Event) bool {
			return f.Witness == e.Witness && absDuration(f.At.Wall.Sub(e.At.Wall)) <= events.LinkWindow
		}) {
			return false
		}
	}
	return true
}

// spanOf is how far apart the first and the last stamp of evs lie.
func spanOf(evs []events.Event) time.Duration {
	var lo, hi time.Time
	for i, e := range evs {
		if i == 0 || e.At.Wall.Before(lo) {
			lo = e.At.Wall
		}
		if i == 0 || e.At.Wall.After(hi) {
			hi = e.At.Wall
		}
	}
	return hi.Sub(lo)
}

// olderIDs are the IDs of the incidents a member of an older version makes
// of the DNS events in evs. It knows no DNS event, so events.Coalesce groups
// one only with events of the same type about the same member (a fact), and
// one router's DNS losses, or returns, lie three probe rounds or more apart:
// it tells each as an incident of its own, whose ID that event alone fixes,
// the same in every version. The sender acknowledges them with what it told
// (recordAcksLocked), so an older member keeps nothing to send again; the
// other way round, the older sender's acknowledgements name the events they
// told, and inPiecesLocked counts the incident told here.
func olderIDs(evs []events.Event) []string {
	var out []string
	for _, e := range evs {
		if e.Type == events.DNSLost || e.Type == events.DNSRestored {
			out = append(out, events.Coalesce([]events.Event{e}, events.DefaultWindow)[0].ID)
		}
	}
	return out
}

// toldAlreadyLocked reports whether every event of evs, late records that
// came after their incident was made, has a twin in one incident kept here:
// an event of the same type about the same member, stamped within the
// coalescing window of it (D2). They would only add witnesses to what the
// chat was told, under another incident ID. A new absence of the same
// member is stamped when it was last heard, after its return, and has no
// such twin.
func (n *Node) toldAlreadyLocked(evs []events.Event) bool {
	win := events.DefaultWindow
	for _, r := range n.inc.recent {
		if r.single || len(r.events) == 0 {
			continue
		}
		covered := true
		for _, e := range evs {
			if !slices.ContainsFunc(r.events, func(f events.Event) bool {
				return f.Type == e.Type && f.Subject == e.Subject && absDuration(f.At.Wall.Sub(e.At.Wall)) <= win
			}) {
				covered = false
				break
			}
		}
		if covered {
			return true
		}
	}
	return false
}

// cutOffViewLocked reports whether e, a member's record of another member's
// absence, is only what a router that was cut off itself saw (D9): a third
// member recorded the witness silent over the moment of e, the subject
// itself recorded the witness silent over that moment too, and no member but
// the witness and the subject recorded the subject absent then. A router
// that loses its own link sees every other member go silent and come back;
// the others, who heard each other all along, recorded its absence, which is
// the one incident. In a group of two nobody is a third, and both views stay.
//
// The subject's own record is what tells a cut-off witness from a true
// outage that one compromised member hides (N1): in a group of three, a
// member that records the witness silent and keeps quiet about the subject
// would otherwise drop the witness's true record of the subject's outage.
// A subject that is really down records nobody silent; one that is up and
// lost the witness, as every member that heard the others did, records it.
func (n *Node) cutOffViewLocked(e events.Event) bool {
	w, x := e.Witness, e.Subject
	if !absence(e.Type) || events.Own(e) || w == x || x == (ids.MemberID{}) {
		return false
	}
	at := e.At.Wall
	from, to, cut := n.silentOverLocked(w, at, func(by ids.MemberID) bool { return by != w && by != x })
	if !cut {
		return false
	}
	if _, _, seen := n.silentOverLocked(w, at, func(by ids.MemberID) bool { return by == x }); !seen {
		return false // the subject did not lose the witness: the witness saw a true absence
	}
	win := events.DefaultWindow
	for _, f := range n.inc.evs {
		g := f.ev
		if g.Subject != x || g.Witness == w || g.Witness == x || !absence(g.Type) {
			continue
		}
		if !g.At.Wall.Before(from.Add(-win)) && (to.IsZero() || !g.At.Wall.After(to.Add(win))) {
			return false // a third member saw the subject absent too
		}
	}
	return true
}

// silentOverLocked reports whether a member that witness accepts recorded w
// silent over the moment at, within the coalescing window: a silence record
// of w stamped no later than the window after at, whose next return record
// of w by the same member, if any, is not earlier than the window before at.
// It returns the first such absence of w, from its silence to that return
// (zero if none).
func (n *Node) silentOverLocked(w ids.MemberID, at time.Time, witness func(ids.MemberID) bool) (from, to time.Time, ok bool) {
	win := events.DefaultWindow
	for _, f := range n.inc.evs {
		g := f.ev
		if g.Subject != w || g.Witness == w || !witness(g.Witness) || g.Type != events.MemberSilent || g.At.Wall.After(at.Add(win)) {
			continue
		}
		end := time.Time{}
		for _, h := range n.inc.evs {
			b := h.ev
			if b.Subject == w && b.Witness == g.Witness && b.Type != events.MemberSilent && absence(b.Type) &&
				!b.At.Wall.Before(g.At.Wall) && (end.IsZero() || b.At.Wall.Before(end)) {
				end = b.At.Wall
			}
		}
		if end.IsZero() || !end.Before(at.Add(-win)) {
			return g.At.Wall, end, true
		}
	}
	return time.Time{}, time.Time{}, false
}

// distrustedLocked returns, for every member whose chain forked in the log,
// the sequence number of the fork: its entries from there on differ
// between the routers that saw its different faces. Of the proofs this node
// and others found (their alarms name theirs), the lowest counts, so routers
// that found different proofs leave out the same events.
func (n *Node) distrustedLocked() map[ids.MemberID]uint64 {
	out := map[ids.MemberID]uint64{}
	for _, p := range n.log.Forks() {
		if o := p.A.Origin; o != n.id.ID {
			out[o] = p.A.Seq
			if s, ok := n.inc.forkSeqs[o]; ok && s < out[o] {
				out[o] = s
			}
		}
	}
	return out
}

// queueLocked keeps inc and queues it for delivery.
func (n *Node) queueLocked(inc events.Incident, evs []events.Event, components []string, now clock.Stamp) {
	r := &incRec{inc: inc, events: evs, components: components, queuedAt: now.Wall}
	n.inc.recent = append(n.inc.recent, r)
	if over := len(n.inc.recent) - keepIncidents; over > 0 {
		for _, old := range n.inc.recent[:over] {
			delete(n.inc.byID, old.inc.ID)
			delete(n.inc.facts, old.inc.ID)
		}
		n.inc.recent = slices.Clone(n.inc.recent[over:])
	}
	n.inc.byID[inc.ID] = r
	if !n.deliveredLocked(inc.ID) && !n.toldByAckLocked(r) {
		n.queue.Add(inc, now.Wall)
	}
	n.flusher.Mark()
}

// # Acknowledgements that name what they told (Q4)
//
// Members that hold the same events make the same incidents, but not
// always at once: a record that reaches one member after it made its
// incident, and another in time, or an equivocator that shows each member
// another face, leave them with incidents of one cause under different
// IDs, and an acknowledgement of one ID does not stop the other. So an
// acknowledgement names the events its message told (deliver.AckBodyRefs,
// up to deliver.MaxAckRefs, one of each kind and member first), and a kept
// incident not delivered counts as told by it when they share an event and
// every other event of it has a twin among the named ones that this member
// holds: the same type about the same member, or the same type of link
// change. A guess at a return whose member's own account is in the incident
// needs none: the incident tells the account. An incident that tells more,
// a return after a silence that was told alone, is not told by it.
//
// An incident of link changes alone also counts as told when the kept
// acknowledgements together name every one of its events (inPiecesLocked):
// a sender of an older version, whose window is 10 s, tells one router's
// outage in more messages than the window of 30 s makes here, and each of
// them names its own events (@decided 2026-10-30).

// noteAckLocked keeps the events the acknowledgement of id by by names, when
// it is the head of by's chain (entryIn hands each entry over right after
// the log took it), and counts as told every kept incident they tell.
func (n *Node) noteAckLocked(id string, by ids.MemberID) {
	hd := n.log.Head(by)
	es := n.log.Range(by, hd.Seq, hd.Seq)
	if len(es) != 1 {
		return
	}
	if aid, aby, ok := deliver.AckOf(es[0]); !ok || aid != id || aby != by {
		return
	}
	refs := deliver.AckRefs(es[0])
	if len(refs) == 0 {
		return
	}
	note := ackNote{id: id, by: by, refs: refs}
	n.inc.ackNotes = append(n.inc.ackNotes, note)
	n.inc.name(note.refs, 1)
	if over := len(n.inc.ackNotes) - keepAckNotes; over > 0 {
		for _, old := range n.inc.ackNotes[:over] {
			n.inc.name(old.refs, -1)
		}
		n.inc.ackNotes = slices.Clone(n.inc.ackNotes[over:])
	}
	for _, r := range n.inc.recent {
		if !n.deliveredLocked(r.inc.ID) && (n.coveredLocked(r, note) || n.inPiecesLocked(r)) {
			n.ackedLocked(r.inc.ID, by)
		}
	}
}

// toldByAckLocked reports whether kept acknowledgements tell r, and counts
// r as told by them then.
func (n *Node) toldByAckLocked(r *incRec) bool {
	for _, note := range n.inc.ackNotes {
		if n.coveredLocked(r, note) {
			n.ackedLocked(r.inc.ID, note.by)
			return true
		}
	}
	if n.inPiecesLocked(r) {
		n.ackedLocked(r.inc.ID, n.inc.ackNotes[len(n.inc.ackNotes)-1].by)
		return true
	}
	return false
}

// inPiecesLocked reports whether r, a kept incident of link changes alone,
// has every one of its events named by a kept acknowledgement: told, in
// pieces, by messages that were delivered.
func (n *Node) inPiecesLocked(r *incRec) bool {
	if r.single || !linkOnly(r.events) || len(n.inc.ackNotes) == 0 {
		return false
	}
	return !slices.ContainsFunc(r.events, func(e events.Event) bool { return n.inc.named[e.Ref] == 0 })
}

// name counts refs as named by one more kept acknowledgement (by d = 1), or
// by one fewer (d = -1), so that inPiecesLocked looks each event up once.
func (c *incidents) name(refs []ids.Hash, d int) {
	for _, h := range refs {
		if c.named[h] += d; c.named[h] <= 0 {
			delete(c.named, h)
		}
	}
}

// coverLocked looks again, once events arrived, for kept incidents the
// kept acknowledgements tell: an acknowledgement may name events that
// reach this member after it.
func (n *Node) coverLocked() {
	if !n.inc.coverDirty || len(n.inc.ackNotes) == 0 {
		n.inc.coverDirty = false
		return
	}
	n.inc.coverDirty = false
	for _, r := range n.inc.recent {
		if !n.deliveredLocked(r.inc.ID) {
			n.toldByAckLocked(r)
		}
	}
}

// coveredLocked reports whether note's message told what r tells, as the
// doc above says.
func (n *Node) coveredLocked(r *incRec, note ackNote) bool {
	if r.single || len(r.events) == 0 || r.inc.ID == note.id {
		return false
	}
	named := map[ids.Hash]bool{}
	var told []events.Event
	for _, h := range note.refs {
		named[h] = true
		if e := n.inc.evs[h]; e != nil {
			told = append(told, e.ev)
		}
	}
	own := map[ids.MemberID]bool{}
	for _, e := range r.events {
		if !absence(e.Type) && !linkChange(e.Type) {
			// An announcement or an alarm: its event's ref is a roster's
			// hash or its proof, shared with other announcements of it.
			return false
		}
		if events.Own(e) {
			own[e.Subject] = true
		}
	}
	shared := false
	for _, e := range r.events {
		switch {
		case named[e.Ref]:
			shared = true
		case own[e.Subject] && !events.Own(e) && e.Type != events.MemberSilent && absence(e.Type):
			// A guess the member's own account here overrides.
		case !slices.ContainsFunc(told, func(f events.Event) bool { return twin(e, f) }):
			return false
		}
	}
	return shared
}

// twin reports whether e and f tell the same thing: one type about one
// member, or one type of link change, which is told for the site.
func twin(e, f events.Event) bool {
	if e.Type != f.Type {
		return false
	}
	return linkChange(e.Type) || e.Subject == f.Subject
}

// linkChange reports whether t is a change of a member's own link, which an
// incident tells for the site.
func linkChange(t events.Type) bool {
	switch t {
	case events.WanDown, events.WanUp, events.InternetLost, events.InternetRestored, events.UplinkSwitched,
		events.DNSLost, events.DNSRestored:
		return true
	}
	return false
}

// ackRefsLocked returns the events an acknowledgement of incident id names:
// one of each type about each member (of each type of link change) first,
// then the others, up to deliver.MaxAckRefs, each by its ref.
func (n *Node) ackRefsLocked(id string) []ids.Hash {
	r := n.inc.byID[id]
	if r == nil {
		return nil
	}
	evs := slices.Clone(r.events)
	slices.SortFunc(evs, func(a, b events.Event) int { return compareHash(a.Ref, b.Ref) })
	var first, rest []ids.Hash
	for i, e := range evs {
		if slices.ContainsFunc(evs[:i], func(f events.Event) bool { return twin(e, f) }) {
			rest = append(rest, e.Ref)
		} else {
			first = append(first, e.Ref)
		}
	}
	out := append(first, rest...)
	return out[:min(len(out), deliver.MaxAckRefs)]
}

// deliveredLocked reports whether incident id was acknowledged: its own ID,
// or, for a return merged with the start it ends, every incident it merged
// (others told the start and the return apart, and the merged incident
// would tell them again).
func (n *Node) deliveredLocked(id string) bool {
	if n.inc.ackedIDs[id] {
		return true
	}
	r := n.inc.byID[id]
	if r == nil {
		return false
	}
	return len(r.components) > 1 && !slices.ContainsFunc(r.components, func(c string) bool { return !n.inc.ackedIDs[c] })
}

// ackedLocked takes the acknowledgement of incident id by member by: with a
// merged incident, the incidents it stands for, which it told; and every
// merged incident whose parts are all acknowledged now.
func (n *Node) ackedLocked(id string, by ids.MemberID) {
	n.queue.Ack(id, by)
	n.inc.acked(id)
	defer n.noteAckLocked(id, by)
	if r := n.inc.byID[id]; r != nil {
		for _, c := range r.components {
			if !n.inc.ackedIDs[c] {
				n.queue.Ack(c, by)
				n.inc.acked(c)
			}
		}
	}
	for _, r := range n.inc.recent {
		if len(r.components) > 1 && slices.Contains(r.components, id) && !n.inc.ackedIDs[r.inc.ID] && n.deliveredLocked(r.inc.ID) {
			n.queue.Ack(r.inc.ID, by)
			n.inc.acked(r.inc.ID)
		}
	}
}

// # Whose turn it is to send (D2)
//
// Every member elects the sender from its own view (elect.Sender), and two
// members whose views differ can both take themselves for it: after an
// outage both reach Telegram again within a heartbeat, or the sender of
// higher priority comes back while another sends. So a member that becomes
// the sender in its own view sends nothing until its peers have heard it
// can: until a heartbeat with its fresh Telegram call has gone out, and one
// heartbeat interval after it, in which every peer answers with its own
// state and a peer that outranks it takes the turn.
//
// When another member is eligible meanwhile (it may have been sending), or
// the node takes over from a member that was the sender in its view less
// than the delivery grace ago (it lost its internet, announced its
// shutdown, went silent), the wait after that heartbeat is handover
// instead: the other member stops within a tick of hearing it, and the wait
// keeps the two members' messages the grace apart and lets the other's
// acknowledgements arrive. Up to twice the handover, the node also waits
// while it lacks entries that a member with the sender role says, in its
// heartbeat, it holds: its acknowledgements may be among them.
//
// A member heard again (a partition healed, a router came back) starts the
// wait over: it may have been sending on its side, and the views must meet
// again. While another member's acknowledgements keep arriving, it still
// delivers in its own view: the node sends nothing until the grace after
// the last of them. A node that announced its shutdown sends nothing more.

// handover is the wait after the announcing heartbeat when another member
// may have been sending.
const handover = deliver.Grace + 2*time.Second

// senderTurn is this node's turn as the sender.
type senderTurn struct {
	prev      ids.MemberID          // the other member last seen as the sender
	prevAt    time.Duration         // when
	on        bool                  // the node is the sender in its own view
	announced bool                  // a heartbeat with its fresh Telegram call went out since
	at        time.Duration         // when it went out
	handover  bool                  // another member was eligible meanwhile
	heard     map[ids.MemberID]bool // the members heard at the last look
}

// turnLocked returns the sender the queue is to act on: sender, unless it
// is this node and its turn has not begun yet, as the doc above says.
func (n *Node) turnLocked(sender ids.MemberID, now clock.Stamp) ids.MemberID {
	n.queue.Hold(n.heldLocked(now))
	if n.goingDown {
		return ids.MemberID{}
	}
	if sender != n.id.ID {
		prev, at := n.turn.prev, n.turn.prevAt
		if sender != (ids.MemberID{}) {
			prev, at = sender, now.Mono
		}
		n.turn = senderTurn{prev: prev, prevAt: at}
		return sender
	}
	t := &n.turn
	if !t.on && t.prev != (ids.MemberID{}) && now.Mono-t.prevAt < deliver.Grace {
		t.handover = true // taking over from a sender that sent until just now
	}
	others := n.othersLocked()
	heard := map[ids.MemberID]bool{}
	for _, v := range others {
		if !v.Silent {
			heard[v.ID] = true
			if t.on && !t.heard[v.ID] {
				t.announced = false // heard again: the views must meet again
			}
		}
	}
	t.on, t.heard = true, heard
	if _, other := elect.Sender(others, now.Wall); other {
		t.handover = true
	}
	wait := n.cfg.Heartbeat
	if t.handover {
		wait = handover
	}
	if !t.announced || now.Mono < t.at+wait {
		return ids.MemberID{}
	}
	if t.handover && now.Mono < t.at+2*handover && n.behindSendersLocked() {
		return ids.MemberID{} // their acknowledgements may be among what is missing
	}
	if n.otherAck != 0 && now.Mono-n.otherAck < deliver.Grace {
		return ids.MemberID{} // another member still delivers
	}
	return sender
}

// behindSendersLocked reports whether the log lacks entries of another
// member with the sender role that its last heartbeat says it holds.
func (n *Node) behindSendersLocked() bool {
	for _, m := range n.cur().Members {
		p := n.peers[m.ID]
		if m.ID == n.id.ID || p == nil || !p.heard || p.silent || !hasRole(m, roster.RoleSender) {
			continue
		}
		if n.log.Head(m.ID).Seq < p.hb.Head.Seq {
			return true
		}
	}
	return false
}

// announceTurnLocked notes a heartbeat that tells the peers this node can
// send: it is the sender in its own view and its last Telegram call is
// fresh.
func (n *Node) announceTurnLocked(now clock.Stamp) {
	if t := &n.turn; t.on && !t.announced && !n.telegramOK.IsZero() && now.Wall.Sub(n.telegramOK) <= elect.Window {
		t.announced, t.at = true, now.Mono
	}
}

// othersLocked returns the election's view of the other members.
func (n *Node) othersLocked() []elect.View {
	return slices.DeleteFunc(n.views(), func(v elect.View) bool { return v.ID == n.id.ID })
}

// returns are the types that end a member's absence.
var returns = []events.Type{events.RebootUnplanned, events.RebootPlanned, events.Upgraded, events.LinkLost, events.MemberBack}

// maxHold bounds how long the sender holds back one incident for its end
// (heldLocked), from the first moment it held it. A true end is taken into
// an incident settle after the node first saw it, and pairs with the start
// at the next tick; the incident it makes is ready only once every event in
// it has waited settle, so a companion record seen up to settle after the
// end delays it by as much again. Two settles cover both. An end that takes
// longer either waits on something else (a guess at a return that waits for
// its member's own account, up to ownWait) or never joins at all (a
// compromised member that writes a return every few seconds): then the start
// goes out alone, and its end, if it comes, as a message of its own.
const maxHold = 2 * settle

// maxLinkHold is maxHold for an incident of link changes, whose events wait
// linkSettle each.
const maxLinkHold = 2 * linkSettle

// heldLocked returns the incidents the sender holds back now: each one that
// reports only the start of something (a silence), or link changes, was not
// sent yet, and has its end, or a record that may join it, recorded and not
// yet settled, so that both go out as one message (D5). Each is held at most
// maxHold (maxLinkHold) from the first moment it was, once (N2): ends that
// keep arriving and never join cannot hold it longer, and they never hold
// any other incident.
func (n *Node) heldLocked(now clock.Stamp) []string {
	var out []string
	for _, r := range n.inc.recent {
		if !n.endPendingLocked(r) {
			continue
		}
		if !r.held {
			r.held, r.heldAt = true, now.Mono
		}
		hold := maxHold
		if keptLink(r) {
			hold = maxLinkHold
		}
		if now.Mono-r.heldAt < hold {
			out = append(out, r.inc.ID)
		}
	}
	return out
}

// endPendingLocked reports whether r, not sent yet, has a record that would
// change its message recorded and not yet settled: for the start of a
// silence, the member's return; for link changes, a return of a link it holds
// down, or any link change of its routers stamped within events.LinkWindow of
// one of theirs in r (absorbLocked).
func (n *Node) endPendingLocked(r *incRec) bool {
	has := func(i events.Incident, t events.Type) bool { return slices.Contains(i.Events, t) }
	if r.paired || r.single || n.deliveredLocked(r.inc.ID) {
		return false
	}
	var ends func(e events.Event) bool
	switch inc := r.inc; {
	case inc.Causes == 1 && has(inc, events.MemberSilent) && !slices.ContainsFunc(returns, func(t events.Type) bool { return has(inc, t) }):
		x := inc.Members[0]
		ends = func(e events.Event) bool { return e.Subject.String() == x && slices.Contains(returns, e.Type) }
	case keptLink(r):
		open := linkEnds(r.events)
		ends = func(e events.Event) bool {
			for loss, back := range lossOf {
				if e.Type == back && open[linkKey{loss, e.Witness}] {
					return true
				}
			}
			return linkChange(e.Type) && slices.ContainsFunc(r.events, func(f events.Event) bool {
				return f.Witness == e.Witness && absDuration(f.At.Wall.Sub(e.At.Wall)) <= events.LinkWindow
			})
		}
	default:
		return false
	}
	for _, e := range n.inc.evs {
		if !e.assigned && !e.single && ends(e.ev) {
			return true
		}
	}
	return false
}

// pairLocked merges inc, a return or a restore, with the incident that
// reported its start: the silence of the same member, or the loss of the
// same link. It returns the merged incident, the IDs it stands for, and its
// events.
func (n *Node) pairLocked(inc events.Incident, evs []events.Event) (events.Incident, []string, []events.Event, bool) {
	has := func(i events.Incident, t events.Type) bool { return slices.Contains(i.Events, t) }
	match := func(r *incRec) bool { return false }
	switch {
	case inc.Causes == 1 && !has(inc, events.MemberSilent) && slices.ContainsFunc(returns, func(t events.Type) bool { return has(inc, t) }):
		x := inc.Members[0]
		match = func(r *incRec) bool {
			return r.inc.Causes == 1 && r.inc.Members[0] == x && has(r.inc, events.MemberSilent) &&
				!slices.ContainsFunc(returns, func(t events.Type) bool { return has(r.inc, t) })
		}
	case inc.Causes == 1 && slices.ContainsFunc(returns, func(t events.Type) bool { return has(inc, t) }):
		// The incident tells a whole absence, a silence and a return. A
		// silence kept on its own is that same absence only when the
		// member's own account here spans it (Q4): it then goes out once,
		// in this incident, not again on its own.
		x := inc.Members[0]
		own, ok := ownAccountOf(evs, x)
		if !ok {
			return events.Incident{}, nil, nil, false
		}
		match = func(r *incRec) bool {
			return r.inc.Causes == 1 && r.inc.Members[0] == x && has(r.inc, events.MemberSilent) &&
				!slices.ContainsFunc(returns, func(t events.Type) bool { return has(r.inc, t) }) &&
				n.withinOwnSpanLocked(r.events, own)
		}
	case inc.Causes == 0 && anyBack(linkEnds(evs)):
		return n.pairLinkLocked(inc, evs)
	default:
		return events.Incident{}, nil, nil, false
	}
	for i := len(n.inc.recent) - 1; i >= 0; i-- {
		r := n.inc.recent[i]
		if r.paired || !match(r) {
			continue
		}
		all := append(slices.Clone(r.events), evs...)
		span := inc.End.Wall.Sub(r.inc.Start.Wall)
		if span < 0 {
			span = 0
		}
		merged := events.Coalesce(all, span+events.DefaultWindow)
		if len(merged) != 1 {
			return events.Incident{}, nil, nil, false
		}
		r.paired = true
		return merged[0], []string{r.inc.ID, inc.ID}, all, true
	}
	return events.Incident{}, nil, nil, false
}

// pairLinkLocked merges inc, the link changes evs, with every kept link
// incident that holds down a link that a router's records in evs end with a
// return of (linkEnds: its last record of that link there is a return): a
// router's outage of a link ends with its own return, never with another
// router's, and the losses of routers or links that came back together end in
// one message, from the first loss to the last return. The return may follow
// drops of its own in evs: a link that kept dropping (rule (f) of
// events.CoalesceLinks) ends the outage it dropped in once it stays up. Lab
// runs: on 2026-10-29 two routers lost their WAN 88 s apart and got it back
// 2 s apart, the restores closed only the later loss, and the earlier one
// stayed open until its router's next WAN event, 11 h later; on 2026-10-30 a
// router's WAN and internet came back in one incident, which closed only the
// internet loss, and the WAN loss stayed open; and in lab cell R1.4 a WAN that
// dropped three more times left its first loss open.
func (n *Node) pairLinkLocked(inc events.Incident, evs []events.Event) (events.Incident, []string, []events.Event, bool) {
	back := map[linkKey]bool{}
	for k, down := range linkEnds(evs) {
		if !down {
			back[k] = true
		}
	}
	var rs []*incRec
	for _, r := range n.inc.recent {
		if !keptLink(r) {
			continue
		}
		for k, down := range linkEnds(r.events) {
			if down && back[k] {
				rs = append(rs, r)
				break
			}
		}
	}
	if len(rs) == 0 {
		return events.Incident{}, nil, nil, false
	}
	all, first := slices.Clone(evs), inc.Start
	var stands []string
	for _, r := range rs {
		all = append(all, r.events...)
		stands = append(stands, r.inc.ID)
		if r.inc.Start.Wall.Before(first.Wall) {
			first = r.inc.Start
		}
	}
	span := inc.End.Wall.Sub(first.Wall)
	if span < 0 {
		span = 0
	}
	merged := events.Coalesce(all, span+events.DefaultWindow)
	if len(merged) != 1 {
		return events.Incident{}, nil, nil, false
	}
	for _, r := range rs {
		r.paired = true
	}
	return merged[0], append(stands, inc.ID), all, true
}

// recordAcksLocked writes the acknowledgement of every incident this node
// delivered, and of the incidents a merged one stands for.
func (n *Node) recordAcksLocked(now clock.Stamp) {
	for _, id := range n.queue.Unrecorded() {
		if n.inc.ackPending[id] {
			continue
		}
		todo := []string{id}
		var older []string
		if r := n.inc.byID[id]; r != nil {
			todo = append(todo, r.components...)
			// What a member of an older version made of its DNS events,
			// chosen now: the acknowledgement of a merged incident counts
			// its parts acknowledged here at once, and an older member,
			// which never made the merged incident, needs each written.
			for _, a := range olderIDs(r.events) {
				if !n.inc.ackedIDs[a] && !n.inc.ackPending[a] && !slices.Contains(older, a) {
					older = append(older, a)
				}
			}
		}
		for _, a := range todo {
			if n.inc.ackedIDs[a] || n.inc.ackPending[a] {
				continue
			}
			n.recordAckLocked(a, now)
		}
		for _, a := range older {
			if !n.inc.ackPending[a] {
				n.recordAckLocked(a, now)
			}
		}
	}
}

// recordAckLocked writes the acknowledgement of incident a, with the events
// it told.
func (n *Node) recordAckLocked(a string, now clock.Stamp) {
	b, err := deliver.AckBodyRefs(a, n.ackRefsLocked(a))
	if err != nil {
		return
	}
	n.inc.ackPending[a] = true
	n.recordRaw(b, now)
}

// render is the queue's render function: it is called without the
// queue's lock, and takes the node's.
func (n *Node) render(inc events.Incident) string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.renderLocked(inc)
}

func (n *Node) renderLocked(inc events.Incident) string {
	f := deliver.Facts{Names: map[string]string{}, Changes: n.inc.facts[inc.ID]}
	if r := n.inc.byID[inc.ID]; r != nil && !r.single && r.inc.Causes == 0 && linkOnly(r.events) {
		// As it is kept: it may have taken late records since it was queued
		// (absorbLocked).
		inc = r.inc
		f.Links = deliver.LinksOf(r.events)
	}
	if len(n.rosters) > 0 {
		for _, m := range n.cur().Members {
			f.Names[m.ID.String()] = m.Name
		}
	}
	if r := n.inc.byID[inc.ID]; r != nil && !r.single && len(n.rosters) > 0 {
		f.Confirmed, f.Of = n.confirmations(inc, r.events)
	}
	if r := n.inc.byID[inc.ID]; r != nil && slices.Contains(inc.Events, events.Upgraded) {
		for _, e := range r.events {
			if e.Type != events.Upgraded {
				continue
			}
			from, to := e.Detail["from"], e.Detail["to"]
			if f.From == "" && f.To == "" {
				f.From, f.To = from, to
			} else if f.From != from || f.To != to {
				f.From, f.To = "", ""
				break
			}
		}
	}
	return deliver.Render(inc, n.site(), n.cfg.TZ, f)
}

func (n *Node) site() string {
	if n.cfg.Site != "" {
		return n.cfg.Site
	}
	if len(n.rosters) > 0 {
		return n.cur().Site
	}
	return ""
}

// views returns the election's view of the group: every roster member
// once, this router from its own state, the others from their last
// heartbeat, with TelegramOK moved onto the local clock by the peer's own
// wall clock, and a member that announced going down counted as silent.
func (n *Node) views() []elect.View {
	var vs []elect.View
	for _, m := range n.cur().Members {
		if m.ID == n.id.ID {
			vs = append(vs, elect.View{ID: m.ID, HasChannel: n.hasChannel(), InternetOK: n.internetOK,
				TelegramOK: n.telegramOK, Priority: n.cfg.Priority})
			continue
		}
		v := elect.View{ID: m.ID, Silent: true}
		if p := n.peers[m.ID]; p != nil && p.heard {
			h := p.hb
			v.HasChannel = hasRole(m, roster.RoleSender) && !h.TelegramOK.IsZero()
			v.InternetOK = h.InternetOK
			if !h.TelegramOK.IsZero() {
				v.TelegramOK = p.heardWall.Add(h.TelegramOK.Sub(h.Wall))
			}
			v.Priority = h.Priority
			v.Silent = p.silent || h.GoingDown
		}
		vs = append(vs, v)
	}
	return vs
}

// senderLocked returns the member that sends now, in this node's view.
func (n *Node) senderLocked(now clock.Stamp) (ids.MemberID, bool) {
	return elect.Sender(n.views(), now.Wall)
}
