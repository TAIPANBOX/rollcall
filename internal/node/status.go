package node

import (
	"slices"
	"strconv"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/clock"
	"github.com/TAIPANBOX/rollcall/internal/epoch"
	"github.com/TAIPANBOX/rollcall/internal/events"
	"github.com/TAIPANBOX/rollcall/internal/history"
	"github.com/TAIPANBOX/rollcall/internal/ids"
	"github.com/TAIPANBOX/rollcall/internal/redact"
	"github.com/TAIPANBOX/rollcall/internal/roster"
)

// # Return after an absence
//
// Claims about this router (event entries of other members whose subject
// it is) are collected as they reach the log. Once the own chain is caught
// up and this boot's record is written, Reconcile judges them against the
// own chain (security spec 5.8): its corrections are appended at once; a
// correction that changes what the incident told (Correction.Update) also
// records one update, an own event of the corrected class about this router
// marked "update" in its Detail, which every member makes into the same
// incident of its own, so the chat gets one update; a correction that
// changes nothing told records none, and neither does one whose class this
// router's own record of the absence already told (boot.go), its account of
// the return or an update recorded for that absence before, nor one of a
// link loss that only silence claims missed, which the claimants' own record
// of its return tells (toldByReturnLocked). A claim proven false raises one
// alarm (witness.go). Nobody is expelled.

type recon struct {
	claims     []history.Entry
	dirty      bool
	boot       BootBody
	bootSeen   bool
	suspicious map[ids.MemberID]bool
}

const keepClaims = 512

func (r *recon) init() {
	r.suspicious = map[ids.MemberID]bool{}
}

func (r *recon) claim(e history.Entry) {
	r.claims = append(r.claims, e)
	if over := len(r.claims) - keepClaims; over > 0 {
		r.claims = slices.Clone(r.claims[over:])
	}
	r.dirty = true
}

func (n *Node) reconcileLocked(now clock.Stamp) {
	if !n.caughtUp || !n.rec.bootSeen || !n.rec.dirty {
		return
	}
	n.rec.dirty = false
	res, err := Reconcile(n.id, n.log.Head(n.id.ID), n.rec.boot, n.log, n.rec.claims)
	if err != nil {
		return
	}
	// Reconcile chained every correction after the head: all of them are
	// appended before any update is signed, or an update would take the
	// sequence number of a correction still to come and fork the own chain.
	var done []Correction
	for _, c := range res.Corrections {
		ok := len(c.Entries) > 0
		for _, e := range c.Entries {
			if !n.appendOwnLocked(e, now) {
				ok = false
				break
			}
		}
		if !ok {
			n.rec.dirty = true // the rest is chained after what failed: next time
			break
		}
		done = append(done, c)
	}
	for _, c := range done {
		if c.Update && !n.inc.updates[c.Entries[0].Hash()] {
			n.inc.updates[c.Entries[0].Hash()] = true
			if !n.toldOwnLocked(c) && !n.toldByReturnLocked(c) {
				n.updateLocked(c, now)
			}
		}
	}
	for _, f := range res.Falsehoods {
		n.falsehoodLocked(f, now)
	}
}

// toldByReturnLocked reports whether the absence a correction places is
// told right without an update (D1): a link loss whose corrected claims say
// only that this router went silent or answered again. Their authors
// record its return in the same boot as a link loss when they hear it again,
// and the group's message tells that, with the whole span; an update would
// tell it a second time, from the moment of the claim.
func (n *Node) toldByReturnLocked(c Correction) bool {
	if c.Class != history.ClassLinkLost {
		return false
	}
	refs := map[ids.Hash]bool{}
	for _, e := range c.Entries {
		if b, err := history.DecodeCorrection(e); err == nil {
			for _, r := range b.Refs {
				refs[r] = true
			}
		}
	}
	for _, cl := range n.rec.claims {
		if !refs[cl.Hash()] {
			continue
		}
		if b, err := DecodeEvent(cl); err != nil || !causeless(b.Type) {
			return false
		}
	}
	return true
}

// updateLocked records the update a correction that changed the incident's
// meaning sends: an event of the corrected class about this router, from
// boot From to To, stamped when the latest claim it corrects was, whose
// Detail names the correction entry ("update" its hash, "update_seq" its
// seq) so every member can check it (updateIn).
func (n *Node) updateLocked(c Correction, now clock.Stamp) {
	at := n.localStamp(now)
	latest := time.Time{}
	refs := map[ids.Hash]bool{}
	for _, e := range c.Entries {
		if b, err := history.DecodeCorrection(e); err == nil {
			for _, r := range b.Refs {
				refs[r] = true
			}
		}
	}
	for _, cl := range n.rec.claims {
		if !refs[cl.Hash()] {
			continue
		}
		if b, err := DecodeEvent(cl); err == nil && b.At != (At{}) && b.At.Wall.After(latest) {
			latest, at = b.At.Wall, b.At.Stamp()
		}
	}
	typ := events.Type(c.Class)
	first := c.Entries[0]
	n.recordEvent(events.Event{Type: typ, Subject: n.id.ID, At: at, Detail: map[string]string{
		"update": first.Hash().String(), "update_seq": strconv.FormatUint(first.Seq, 10),
	}}, EventBody{Subject: n.id.ID, Type: typ, Last: c.From, Back: c.To}, now)
}

// pendingUpdate is an update whose corrected claims this node does not
// hold yet.
type pendingUpdate struct {
	e     history.Entry
	b     EventBody
	until time.Duration
}

const updateWait = 10 * time.Minute

// correctionClass reports whether t is one of the classes a correction
// names: never an alarm, a flood or anything else.
func correctionClass(t events.Type) bool {
	switch string(t) {
	case history.ClassLinkLost, history.ClassMemberBack, history.ClassRebootPlanned,
		history.ClassRebootUnplanned, history.ClassUpgraded:
		return true
	}
	return false
}

// updateIn takes an update e with body b into the incidents, as one of its
// own, only when it is backed:
//
//   - its origin is its subject: a router correcting what was said about it;
//   - its type is a correction class (never an alarm or a flood);
//   - the origin's own chain holds, before it, the correction entry its
//     Detail names, of that same class;
//   - every claim that correction refers to is another member's event about
//     the origin, and what those claims told is not the corrected class.
//
// An update whose claims have not arrived yet waits up to updateWait;
// anything else is dropped.
func (n *Node) updateIn(e history.Entry, b EventBody, now clock.Stamp) {
	switch ok, retry := n.updateBacked(e, b); {
	case ok:
		n.inc.add(e.Hash(), &evRec{ev: eventOf(e, b), seen: now.Mono, single: true, origin: e.Origin, seq: e.Seq})
	case retry && len(n.inc.waiting) < keepPending:
		n.inc.waiting = append(n.inc.waiting, pendingUpdate{e: e, b: b, until: now.Mono + updateWait})
	}
}

func (n *Node) updateBacked(e history.Entry, b EventBody) (ok, retry bool) {
	if e.Origin != b.Subject || !correctionClass(b.Type) || b.At == (At{}) {
		return false, false
	}
	corr, held := n.entryAt(e.Origin, b.Detail["update_seq"], b.Detail["update"])
	if !held || corr.Kind != history.KindCorrection || corr.Seq >= e.Seq {
		return false, false
	}
	cb, err := history.DecodeCorrection(corr)
	if err != nil || cb.Class != string(b.Type) {
		return false, false
	}
	var types []events.Type
	for _, ref := range cb.Refs {
		r := n.inc.evs[ref]
		if r == nil {
			return false, true
		}
		if r.ev.Subject != e.Origin || r.ev.Witness == e.Origin {
			return false, false
		}
		types = append(types, r.ev.Type)
	}
	if told(types) == b.Type {
		return false, false
	}
	return true, false
}

// checkWaitingLocked takes the waiting updates that are backed now.
func (n *Node) checkWaitingLocked(now clock.Stamp) {
	n.inc.waiting = slices.DeleteFunc(n.inc.waiting, func(p pendingUpdate) bool {
		ok, retry := n.updateBacked(p.e, p.b)
		if ok {
			n.inc.add(p.e.Hash(), &evRec{ev: eventOf(p.e, p.b), seen: now.Mono, single: true, origin: p.e.Origin, seq: p.e.Seq})
		}
		return ok || !retry || now.Mono > p.until
	})
}

// # Status
//
// Status is the node's part of `rollcall status --json`, in the shape of
// luci-app-rollcall/STATUS-JSON.md (schema 1). The daemon fills the fields
// only it knows: Running, Discovery, Topology and Sandbox. Every string is
// redacted against the secrets the node holds.

// Status is a report of the node's state.
type Status struct {
	Schema        int              `json:"schema"`
	Running       bool             `json:"running"`
	Initialised   bool             `json:"initialised"`
	Error         string           `json:"error,omitempty"` // why the node does not run
	Generated     string           `json:"generated,omitempty"`
	Site          string           `json:"site,omitempty"`
	Self          *SelfStatus      `json:"self,omitempty"`
	Members       []MemberStatus   `json:"members,omitempty"`
	Sender        *string          `json:"sender"`
	Incidents     []IncidentStatus `json:"incidents,omitempty"`
	Discovery     []DiscoveryEntry `json:"discovery"`
	Topology      string           `json:"topology,omitempty"`
	Sandbox       *SandboxStatus   `json:"sandbox,omitempty"`
	Storage       StorageStatus    `json:"storage"`
	Telegram      TelegramStatus   `json:"telegram"`
	GroupKey      *GroupKeyStatus  `json:"group_key"`
	BackupWarning bool             `json:"backup_warning"`

	// For the CLI's own text and for tests; not part of the JSON contract.
	State string `json:"-"` // "running", "stopped" or "removed"
	// UnderFlood is true while a burst of packets that fail authentication
	// goes on, or while the transport says it drops packets past its read
	// rate limit (security spec 5.2); it is local status, never a chat
	// message.
	UnderFlood bool     `json:"-"`
	Epoch      uint32   `json:"-"`
	Version    uint64   `json:"-"`
	Counters   Counters `json:"-"`
	Queued     int      `json:"-"`
	Dropped    int      `json:"-"` // incidents the full queue refused (deliver.Status.Dropped)
	// WitnessesDropped counts the witness statements this router did not
	// make because their origin's events came faster than witnessEvery
	// (witness.go).
	WitnessesDropped uint64 `json:"-"`
	Delivery         string `json:"-"` // what stops delivery, from the queue
}

type SelfStatus struct {
	Name     string   `json:"name"`
	Roles    []string `json:"roles"`
	Admin    *string  `json:"admin"`
	Takeover bool     `json:"takeover"`
}

type MemberStatus struct {
	Name            string   `json:"name"`
	Roles           []string `json:"roles"`
	State           string   `json:"state"`
	LastSeen        *string  `json:"last_seen"`
	LastSeenSeconds *int64   `json:"last_seen_seconds"`
}

type IncidentStatus struct {
	ID          string `json:"id"`
	Time        string `json:"time"`
	Text        string `json:"text"`
	ConfirmedBy int    `json:"confirmed_by"`
	Members     int    `json:"members"`
	Delivered   bool   `json:"delivered"`
}

type DiscoveryEntry struct {
	Interface string `json:"interface"`
	Error     string `json:"error"`
}

type SandboxStatus struct {
	State      string `json:"state"`
	NoNewPrivs bool   `json:"no_new_privs"`
	Seccomp    bool   `json:"seccomp"`
	Jail       bool   `json:"jail"`
}

type StorageStatus struct {
	OK    bool    `json:"ok"`
	Error *string `json:"error"`
}

type TelegramStatus struct {
	State  string  `json:"state"`
	LastOK *string `json:"last_ok"`
}

type GroupKeyStatus struct {
	Created          string `json:"created"`
	AgeDays          int    `json:"age_days"`
	RotatesEveryDays int    `json:"rotates_every_days"`
}

// maxStatusIncidents is the most incidents a report lists.
const maxStatusIncidents = 20

// floodReporter is a Net that also tells whether it sees a flood of its
// own: the transport drops packets past its read rate limit before the node
// sees them (security spec 5.2).
type floodReporter interface{ UnderFlood() bool }

// Status returns the node's report, redacted.
func (n *Node) Status() Status {
	// Asked before the node's lock is taken: the transport takes its own
	// lock and calls into the node with it held. n.net never changes.
	netFlood := false
	if f, ok := n.net.(floodReporter); ok {
		netFlood = f.UnderFlood()
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	s := Status{Schema: 1, Running: true, Discovery: []DiscoveryEntry{}, UnderFlood: netFlood}
	tz := n.cfg.TZ
	if tz == nil {
		tz = time.UTC
	}
	at := func(t time.Time) string { return t.In(tz).Format(time.RFC3339) }
	now := time.Now()
	if n.clk != nil {
		now = n.clk.Now()
	}
	s.Generated = at(now)
	switch {
	case n.removed:
		s.State, s.Error = "removed", ErrRemoved.Error()
	case n.stopped != nil:
		s.State, s.Error = "stopped", n.stopped.Error()
	default:
		s.State = "running"
	}
	s.Storage.OK = true
	if n.st != nil {
		if err := n.st.LastError(); err != nil {
			e := err.Error()
			s.Storage.OK, s.Storage.Error = false, &e
		}
	}
	if n.table != nil {
		if err := n.table.StorageError(); err != nil && s.Storage.OK {
			e := err.Error()
			s.Storage.OK, s.Storage.Error = false, &e
		}
	}
	s.Telegram.State = "not_sender"
	if len(n.rosters) == 0 || n.table == nil {
		s.Initialised = false
		return n.redacted(s)
	}
	cur := n.cur()
	s.Initialised = !n.removed
	s.Site = n.site()
	s.Version = cur.Version
	s.Counters = n.counters
	s.Counters.Heartbeats = n.table.Counters()
	s.UnderFlood = s.UnderFlood || n.flood.raised
	if self, ok := memberOf(cur, n.id.ID); ok {
		ss := &SelfStatus{Name: self.Name, Roles: roleNames(self.Roles), Takeover: cur.Takeover && !cur.OwnerConfirmed}
		if a, ok := authority(cur, n.id.ID); ok {
			v := "primary"
			if a == 1 {
				v = "backup"
			}
			ss.Admin = &v
		}
		s.Self = ss
	}
	suspicious := map[ids.MemberID]bool{}
	for _, p := range n.log.Forks() {
		suspicious[p.A.Origin] = true
	}
	for id := range n.rec.suspicious {
		suspicious[id] = true
	}
	for _, m := range cur.Members {
		ms := MemberStatus{Name: m.Name, Roles: roleNames(m.Roles)}
		switch p := n.peers[m.ID]; {
		case m.ID == n.id.ID:
			ms.State = "up"
			t, zero := at(now), int64(0)
			ms.LastSeen, ms.LastSeenSeconds = &t, &zero
		case p == nil || !p.heard:
			ms.State = "unheard"
		default:
			ms.State = "up"
			if p.suspect {
				ms.State = "suspect"
			}
			if p.silent {
				ms.State = "silent"
			}
			t, ago := at(p.heardWall), int64(now.Sub(p.heardWall)/time.Second)
			ms.LastSeen, ms.LastSeenSeconds = &t, &ago
		}
		if suspicious[m.ID] {
			ms.State = "suspicious"
		}
		s.Members = append(s.Members, ms)
	}
	if n.running() {
		if id, ok := n.senderLocked(n.stamp()); ok {
			if m, ok := memberOf(cur, id); ok {
				name := m.Name
				s.Sender = &name
			}
		}
	}
	qs := n.queue.Status()
	s.Queued, s.Dropped, s.Delivery = qs.Queued, qs.Dropped, qs.Problem
	s.WitnessesDropped = n.inc.witnessDropped
	for i := len(n.inc.recent) - 1; i >= 0 && len(s.Incidents) < maxStatusIncidents; i-- {
		r := n.inc.recent[i]
		start := r.inc.Start.Wall
		if start.IsZero() {
			start = r.queuedAt
		}
		// The count the message tells (confirmations); without one, how
		// many members saw it, of the whole roster.
		confirmed, of := 0, 0
		if !r.single {
			confirmed, of = n.confirmations(r.inc, r.events)
		}
		if of == 0 {
			confirmed, of = max(len(r.inc.Witnesses), 1), len(cur.Members)
		}
		s.Incidents = append(s.Incidents, IncidentStatus{
			ID: shortID(r.inc.ID), Time: at(start), Text: n.renderLocked(r.inc),
			ConfirmedBy: confirmed, Members: of,
			Delivered: n.inc.ackedIDs[r.inc.ID],
		})
	}
	if n.hasChannel() {
		s.Telegram.State = n.telegram
		if s.Telegram.State == "" || (s.Telegram.State == "ok" && now.Sub(n.telegramOK) > time.Minute) {
			s.Telegram.State = "unreachable"
		}
	} else if n.cfg.Sender && n.ch == nil {
		s.Telegram.State = "not_configured"
	}
	if !n.telegramOK.IsZero() {
		t := at(n.telegramOK)
		s.Telegram.LastOK = &t
	}
	if len(n.keys) > 0 {
		k := n.current()
		s.Epoch = k.ID
		created := k.NotAfter.Add(-epoch.RotationPeriod)
		s.GroupKey = &GroupKeyStatus{Created: at(created), AgeDays: int(now.Sub(created) / (24 * time.Hour)),
			RotatesEveryDays: int(epoch.RotationPeriod / (24 * time.Hour))}
		s.BackupWarning = true
	}
	return n.redacted(s)
}

func roleNames(rs []roster.Role) []string {
	out := []string{}
	for _, r := range rs {
		out = append(out, string(r))
	}
	slices.Sort(out)
	return out
}

func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

// redacted returns s with the node's secrets replaced in every string.
func (n *Node) redacted(s Status) Status {
	var secrets []string
	if n.secrets.BotToken != "" {
		secrets = append(secrets, n.secrets.BotToken)
	}
	if len(secrets) == 0 {
		return s
	}
	r := func(p *string) {
		if p != nil && *p != "" {
			*p = redact.Redact(*p, secrets...)
		}
	}
	for _, p := range []*string{&s.Error, &s.Site, &s.Delivery, &s.Telegram.State, s.Storage.Error, s.Sender} {
		r(p)
	}
	if s.Self != nil {
		r(&s.Self.Name)
	}
	for i := range s.Members {
		r(&s.Members[i].Name)
	}
	for i := range s.Incidents {
		r(&s.Incidents[i].Text)
	}
	for i := range s.Discovery {
		r(&s.Discovery[i].Error)
	}
	return s
}
