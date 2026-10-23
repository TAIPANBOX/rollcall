package node

import (
	"encoding/json"
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
// Roster announcements are incidents of their own whose one event is
// fixed by the roster alone (its hash as the ref, a zero trusted stamp), so
// every member queues the same incident for one roster change and the
// group sends it once: a change is announced exactly once (invariant 16).
// The changes a lost branch made are announced the same way, from the
// entry a member records when it adopts the other branch.
//
// Every incident goes into the deliver.Queue; the election decides who
// sends, and acknowledgements come back as history entries.

const (
	// settle is how long an event waits for the others of its cause: the
	// coalescing window (D8). Detection stays at 30 s, so a silence reaches
	// the chat about 40 to 45 s after the last heartbeat; a record that
	// comes later only adds a witness (toldAlreadyLocked).
	settle = events.DefaultWindow
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
}

type incRec struct {
	inc        events.Incident
	events     []events.Event
	components []string
	paired     bool
	single     bool // an incident of its own: no count of confirmations
	queuedAt   time.Time
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
}

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
	if events.Own(ev) && ev.Back != (ids.BootID{}) {
		if len(c.ownBacks) >= keepEvents {
			clear(c.ownBacks)
		}
		c.ownBacks[ev.Back] = true
	}
	c.add(e.Hash(), &evRec{ev: ev, seen: now.Mono, origin: e.Origin, seq: e.Seq, back: b.Back.ID})
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
	n.inc.add(ref, &evRec{ev: events.Event{Type: events.RosterChanged, Ref: ref, At: fixedStamp}, seen: now.Mono, single: true})
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
			out = append(out, deliver.Change{Kind: deliver.ChangeRoles, Member: m.Name, By: by})
		}
	}
	for _, m := range prev.Members {
		if _, ok := memberOf(r, m.ID); !ok {
			out = append(out, deliver.Change{Kind: deliver.ChangeRemoved, Member: m.Name, By: by})
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

type changeMsg struct {
	Kind   int    `json:"kind"`
	Member string `json:"member"`
	By     string `json:"by"`
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
			roster.ValidName(c.Member) != nil || (c.By != "" && roster.ValidName(c.By) != nil) {
			return droppedOf{}, false
		}
	}
	return d, true
}

func (c *incidents) droppedIn(e history.Entry, d droppedOf, now clock.Stamp) {
	if _, ok := c.evs[d.Tip]; ok {
		return
	}
	var cs []deliver.Change
	for _, m := range d.Changes {
		cs = append(cs, deliver.Change{Kind: deliver.ChangeKind(m.Kind), Member: m.Member, By: m.By})
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
				d.Changes = append(d.Changes, changeMsg{Kind: int(c.Kind), Member: c.Member, By: c.By})
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
		case r.single:
			r.assigned = true
			incs := events.Coalesce([]events.Event{r.ev}, events.DefaultWindow)
			if len(incs) == 1 {
				n.inc.facts[incs[0].ID] = n.inc.changes[r.ev.Ref]
				n.queueLocked(incs[0], []events.Event{r.ev}, nil, now)
				n.inc.byID[incs[0].ID].single = true
			}
		default:
			list = append(list, r.ev)
		}
	}
	if len(list) == 0 {
		return
	}
	for _, inc := range events.Coalesce(list, events.DefaultWindow) {
		var evs []events.Event
		ready := true
		for _, ref := range inc.Refs {
			r := n.inc.evs[ref]
			if r == nil || now.Mono-r.seen < settle || n.awaitsOwnLocked(r, now) {
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
			switch start := parts[0]; {
			case n.deliveredLocked(start):
			case n.deliveredLocked(m.ID):
				// Another member told the whole absence, from its start.
				n.ackedLocked(start, n.id.ID)
			default:
				// Not sent yet: the merged incident tells its start too, in
				// one message (D5).
				n.queue.Ack(start, n.id.ID)
			}
			continue
		}
		if n.toldAlreadyLocked(evs) || n.continuesOutageLocked(evs) {
			continue
		}
		n.queueLocked(inc, evs, nil, now)
	}
}

// lossOf maps a loss to the restore that ends it.
var lossOf = map[events.Type]events.Type{events.InternetLost: events.InternetRestored, events.WanDown: events.WanUp}

// continuesOutageLocked reports whether evs are only losses (internet, WAN)
// that their witnesses recorded again during an outage still open here: an
// incident kept, not yet paired with its end, where each of them recorded
// that loss already. A router that restarts while the internet is still out
// finds it out again; that is the same outage, told once from its start to
// its end (D5).
func (n *Node) continuesOutageLocked(evs []events.Event) bool {
	if len(evs) == 0 {
		return false
	}
	for _, e := range evs {
		if _, ok := lossOf[e.Type]; !ok {
			return false
		}
	}
	for _, r := range n.inc.recent {
		if r.paired || r.single || r.inc.Causes != 0 {
			continue
		}
		open := !slices.ContainsFunc(r.events, func(f events.Event) bool { return f.Type == lossOf[evs[0].Type] })
		if open && !slices.ContainsFunc(evs, func(e events.Event) bool {
			return !slices.ContainsFunc(r.events, func(f events.Event) bool { return f.Type == e.Type && f.Witness == e.Witness })
		}) {
			return true
		}
	}
	return false
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
// member recorded the witness silent over the moment of e, and no member but
// the witness and the subject recorded the subject absent then. A router
// that loses its own link sees every other member go silent and come back;
// the others, who heard each other all along, recorded its absence, which is
// the one incident. In a group of two nobody is a third, and both views stay.
func (n *Node) cutOffViewLocked(e events.Event) bool {
	w, x := e.Witness, e.Subject
	if !absence(e.Type) || events.Own(e) || w == x || x == (ids.MemberID{}) {
		return false
	}
	win := events.DefaultWindow
	at := e.At.Wall
	// The witness's absence as each third member saw it: from its silence
	// record to its next return record, if any.
	var from, to time.Time
	cut := false
	for _, f := range n.inc.evs {
		g := f.ev
		if g.Subject != w || g.Witness == w || g.Witness == x || g.Type != events.MemberSilent || g.At.Wall.After(at.Add(win)) {
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
			cut, from, to = true, g.At.Wall, end
			break
		}
	}
	if !cut {
		return false
	}
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
	if !n.deliveredLocked(inc.ID) {
		n.queue.Add(inc, now.Wall)
	}
	n.flusher.Mark()
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
	return r != nil && len(r.components) > 1 && !slices.ContainsFunc(r.components, func(c string) bool { return !n.inc.ackedIDs[c] })
}

// ackedLocked takes the acknowledgement of incident id by member by: with a
// merged incident, the incidents it stands for, which it told; and every
// merged incident whose parts are all acknowledged now.
func (n *Node) ackedLocked(id string, by ids.MemberID) {
	n.queue.Ack(id, by)
	n.inc.acked(id)
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
	if n.endPendingLocked() {
		return ids.MemberID{}
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

// endPendingLocked reports whether an incident that reports only the start
// of something (a silence, an internet or WAN loss) and was not sent yet
// has its end recorded and not yet settled: the sender holds back until the
// end joins it, so both go out as one message (D5).
func (n *Node) endPendingLocked() bool {
	has := func(i events.Incident, t events.Type) bool { return slices.Contains(i.Events, t) }
	for _, r := range n.inc.recent {
		if r.paired || r.single || n.deliveredLocked(r.inc.ID) {
			continue
		}
		var ends func(e events.Event) bool
		switch inc := r.inc; {
		case inc.Causes == 1 && has(inc, events.MemberSilent) && !slices.ContainsFunc(returns, func(t events.Type) bool { return has(inc, t) }):
			x := inc.Members[0]
			ends = func(e events.Event) bool { return e.Subject.String() == x && slices.Contains(returns, e.Type) }
		case inc.Causes == 0 && has(inc, events.InternetLost) && !has(inc, events.InternetRestored):
			ends = func(e events.Event) bool { return e.Type == events.InternetRestored }
		case inc.Causes == 0 && has(inc, events.WanDown) && !has(inc, events.WanUp):
			ends = func(e events.Event) bool { return e.Type == events.WanUp }
		default:
			continue
		}
		for _, e := range n.inc.evs {
			if !e.assigned && !e.single && ends(e.ev) {
				return true
			}
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
	case inc.Causes == 0 && has(inc, events.InternetRestored) && !has(inc, events.InternetLost):
		match = func(r *incRec) bool {
			return r.inc.Causes == 0 && has(r.inc, events.InternetLost) && !has(r.inc, events.InternetRestored)
		}
	case inc.Causes == 0 && has(inc, events.WanUp) && !has(inc, events.WanDown):
		match = func(r *incRec) bool {
			return r.inc.Causes == 0 && has(r.inc, events.WanDown) && !has(r.inc, events.WanUp)
		}
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

// recordAcksLocked writes the acknowledgement of every incident this node
// delivered, and of the incidents a merged one stands for.
func (n *Node) recordAcksLocked(now clock.Stamp) {
	for _, id := range n.queue.Unrecorded() {
		if n.inc.ackPending[id] {
			continue
		}
		todo := []string{id}
		if r := n.inc.byID[id]; r != nil {
			todo = append(todo, r.components...)
		}
		for _, a := range todo {
			if n.inc.ackedIDs[a] || n.inc.ackPending[a] {
				continue
			}
			b, err := deliver.AckBody(a)
			if err != nil {
				continue
			}
			n.inc.ackPending[a] = true
			n.recordRaw(b, now)
		}
	}
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
	if len(n.rosters) > 0 {
		for _, m := range n.cur().Members {
			f.Names[m.ID.String()] = m.Name
		}
	}
	if r := n.inc.byID[inc.ID]; r != nil && !r.single && len(n.rosters) > 0 {
		f.Confirmed, f.Of = n.confirmations(r.events)
	}
	if r := n.inc.byID[inc.ID]; r != nil && !slices.Contains(inc.Events, events.MemberSilent) && ownStart(r.events) {
		// deliver tells an absence from its start when the incident holds
		// the silence that began it; a router's own account of its return
		// carries that start itself, and Start is it (events.Incident).
		inc.Events = append(slices.Clone(inc.Events), events.MemberSilent)
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
