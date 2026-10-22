package node

import (
	"slices"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/clock"
	"github.com/TAIPANBOX/rollcall/internal/epoch"
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
// own chain (security spec 5.8): its corrections are appended at once,
// and a claim it proves false marks its author suspicious. Nobody is
// expelled.

type recon struct {
	claims     []history.Entry
	dirty      bool
	boot       BootBody
	bootSeen   bool
	falsehoods map[ids.Hash]bool
	suspicious map[ids.MemberID]bool
}

const keepClaims = 512

func (r *recon) init() {
	r.falsehoods = map[ids.Hash]bool{}
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
	for _, c := range res.Corrections {
		for _, e := range c.Entries {
			if !n.appendLocked(e, now) {
				break
			}
		}
	}
	for _, f := range res.Falsehoods {
		h := f.Claim.Hash()
		if !n.rec.falsehoods[h] {
			n.rec.falsehoods[h] = true
			n.rec.suspicious[f.Claim.Origin] = true
		}
	}
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
	State    string   `json:"-"` // "running", "stopped" or "removed"
	Epoch    uint32   `json:"-"`
	Version  uint64   `json:"-"`
	Counters Counters `json:"-"`
	Queued   int      `json:"-"`
	Delivery string   `json:"-"` // what stops delivery, from the queue
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

// Status returns the node's report, redacted.
func (n *Node) Status() Status {
	n.mu.Lock()
	defer n.mu.Unlock()
	s := Status{Schema: 1, Running: true, Discovery: []DiscoveryEntry{}}
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
	s.Queued, s.Delivery = qs.Queued, qs.Problem
	for i := len(n.inc.recent) - 1; i >= 0 && len(s.Incidents) < maxStatusIncidents; i-- {
		r := n.inc.recent[i]
		start := r.inc.Start.Wall
		if start.IsZero() {
			start = r.queuedAt
		}
		s.Incidents = append(s.Incidents, IncidentStatus{
			ID: shortID(r.inc.ID), Time: at(start), Text: n.renderLocked(r.inc),
			ConfirmedBy: len(r.inc.Witnesses), Members: len(cur.Members),
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
