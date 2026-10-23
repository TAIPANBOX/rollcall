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
	// settle is how long an event waits for the others of its cause.
	settle = events.DefaultWindow + 2*retryEvery
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
	single   bool // an incident of its own: a roster announcement
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
	alarmed    map[string]bool   // alarm incident IDs raised, one per proof
	witnessed  map[ids.Hash]bool // events this node has stated a view on
	pending    []pendingAlarm    // falsehood alarms of others, not yet checkable
	waiting    []pendingUpdate   // updates whose claims have not arrived yet
	updates    map[ids.Hash]bool // corrections whose update was recorded
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
	c.add(e.Hash(), &evRec{ev: eventOf(e, b), seen: now.Mono})
}

// eventOf returns the event the entry e with body b records. A start
// (Since) counts only on an entry whose origin is its subject: a member
// says when its own absence began, never another's.
func eventOf(e history.Entry, b EventBody) events.Event {
	ev := events.Event{Type: b.Type, Subject: b.Subject, Witness: e.Origin, At: b.At.Stamp(), Ref: e.Hash(), Detail: b.Detail}
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

func (c *incidents) droppedIn(d droppedOf, now clock.Stamp) {
	if _, ok := c.evs[d.Tip]; ok {
		return
	}
	var cs []deliver.Change
	for _, m := range d.Changes {
		cs = append(cs, deliver.Change{Kind: deliver.ChangeKind(m.Kind), Member: m.Member, By: m.By})
	}
	c.changes[d.Tip] = cs
	c.add(d.Tip, &evRec{ev: events.Event{Type: events.RosterChangesDropped, Ref: d.Tip, At: fixedStamp}, seen: now.Mono, single: true})
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
	for _, r := range n.inc.evs {
		switch {
		case r.assigned:
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
			if r == nil || now.Mono-r.seen < settle {
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
			continue
		}
		n.queueLocked(inc, evs, nil, now)
	}
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
	if !n.inc.ackedIDs[inc.ID] {
		n.queue.Add(inc, now.Wall)
	}
}

// returns are the types that end a member's absence.
var returns = []events.Type{events.RebootUnplanned, events.RebootPlanned, events.Upgraded, events.LinkLost, events.MemberBack}

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
