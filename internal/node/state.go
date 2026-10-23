package node

import (
	"encoding/json"
	"net/netip"
	"slices"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/clock"
	"github.com/TAIPANBOX/rollcall/internal/deliver"
	"github.com/TAIPANBOX/rollcall/internal/events"
	"github.com/TAIPANBOX/rollcall/internal/history"
	"github.com/TAIPANBOX/rollcall/internal/ids"
	"github.com/TAIPANBOX/rollcall/internal/member"
)

// # State across a restart
//
// What the node knows beyond the history, and must not lose when it
// restarts, is kept in one file of its store, state.json, written with the
// history (by the Flusher, at most once a minute) and at once on GoingDown
// and Stop:
//
//   - heads: the head of every origin's chain as the incidents had seen it;
//   - pending: the events seen and not yet taken into an incident;
//   - recent: the incidents kept, with their events, the incidents a merged
//     one stands for, the roster changes they announce, and whether a
//     return was paired with them;
//   - peers: what each peer's last heartbeat said (address, boot, version,
//     going down), when it was heard, and whether the node held it silent.
//
// At a start, after the history is loaded, an event above the head its
// origin had in the file, or pending in it, is news again; every other
// loaded event was taken. Every kept incident not acknowledged is queued
// again (D19), so an incident held while Telegram or the internet was out
// survives a restart of its sender, and a return after a restart still
// pairs with the silence it ends. A kept alarm stays raised. Without the
// file (the first start) every loaded event counts as taken.
//
// A peer known from the file is not heard until its next heartbeat. When it
// comes back from an absence the node had already seen begin, its return is
// classified against the boot and version the file names, not told as a
// bare "answered again", and a silence the node or another member already
// recorded is not recorded again from the node's start (D14).

const (
	fileState    = "state.json"
	stateVersion = 1
	maxStateFile = 1 << 20
)

type stateFile struct {
	Version int                     `json:"version"`
	Heads   map[ids.MemberID]uint64 `json:"heads"`
	Pending []ids.Hash              `json:"pending"`
	Recent  []incState              `json:"recent"`
	Peers   []peerState             `json:"peers"`
}

type incState struct {
	Inc        events.Incident  `json:"inc"`
	Events     []events.Event   `json:"events"`
	Components []string         `json:"components"`
	Paired     bool             `json:"paired"`
	Single     bool             `json:"single"`
	QueuedAt   time.Time        `json:"queued_at"`
	Changes    []deliver.Change `json:"changes"`
}

type peerState struct {
	ID        ids.MemberID `json:"id"`
	Addr      string       `json:"addr"`
	Boot      Boot         `json:"boot"`
	Version   string       `json:"version"`
	GoingDown bool         `json:"going_down"`
	Silent    bool         `json:"silent"`
	Heard     time.Time    `json:"heard"`
}

// stateLocked returns the state to keep.
func (n *Node) stateLocked() stateFile {
	f := stateFile{Version: stateVersion, Heads: map[ids.MemberID]uint64{}, Pending: []ids.Hash{}, Recent: []incState{}, Peers: []peerState{}}
	for _, m := range n.cur().Members {
		if h := n.log.Head(m.ID); h.Seq > 0 {
			f.Heads[m.ID] = h.Seq
		}
	}
	for ref, r := range n.inc.evs {
		if !r.assigned && r.origin != (ids.MemberID{}) {
			f.Pending = append(f.Pending, ref)
		}
	}
	slices.SortFunc(f.Pending, func(a, b ids.Hash) int { return compareHash(a, b) })
	for _, r := range n.inc.recent {
		f.Recent = append(f.Recent, incState{Inc: r.inc, Events: r.events, Components: r.components,
			Paired: r.paired, Single: r.single, QueuedAt: r.queuedAt, Changes: n.inc.facts[r.inc.ID]})
	}
	for _, m := range n.cur().Members {
		p := n.peers[m.ID]
		if m.ID == n.id.ID || p == nil || (!p.heard && !p.restored) {
			continue
		}
		s := peerState{ID: m.ID, Boot: Boot{ID: p.hb.Boot, Seq: p.hb.BootSeq}, Version: p.hb.Versions[0],
			GoingDown: p.hb.GoingDown, Silent: p.silent || p.toldSilent, Heard: p.heardWall}
		if p.addr.IsValid() {
			s.Addr = p.addr.String()
		}
		f.Peers = append(f.Peers, s)
	}
	return f
}

func compareHash(a, b ids.Hash) int {
	return slices.Compare(a[:], b[:])
}

// writeStateLocked writes the state file.
func (n *Node) writeStateLocked() error {
	b, err := json.Marshal(n.stateLocked())
	if err != nil {
		return err
	}
	return n.st.WriteFileAtomic(fileState, b)
}

// loadStateLocked applies the state file to what loadHistory loaded, as the
// package doc of this file describes.
func (n *Node) loadStateLocked(now clock.Stamp) {
	var f stateFile
	b, err := n.st.ReadFile(fileState)
	if err != nil || decodeJSON(b, &f, maxStateFile) != nil || f.Version != stateVersion {
		n.inc.settleAll()
		return
	}
	pending := map[ids.Hash]bool{}
	for _, h := range f.Pending {
		pending[h] = true
	}
	for ref, r := range n.inc.evs {
		if r.origin != (ids.MemberID{}) && (r.seq > f.Heads[r.origin] || pending[ref]) {
			r.assigned, r.seen = false, now.Mono
			continue
		}
		r.assigned = true
	}
	for _, s := range f.Recent {
		n.restoreIncidentLocked(s, now)
	}
}

// restoreIncidentLocked keeps the incident s again, and queues it unless it
// was acknowledged.
func (n *Node) restoreIncidentLocked(s incState, now clock.Stamp) {
	id := s.Inc.ID
	if len(id) != 16 || n.inc.byID[id] != nil {
		return
	}
	r := &incRec{inc: s.Inc, events: s.Events, components: s.Components, paired: s.Paired, single: s.Single, queuedAt: s.QueuedAt}
	n.inc.recent = append(n.inc.recent, r)
	if over := len(n.inc.recent) - keepIncidents; over > 0 {
		for _, old := range n.inc.recent[:over] {
			delete(n.inc.byID, old.inc.ID)
			delete(n.inc.facts, old.inc.ID)
		}
		n.inc.recent = slices.Clone(n.inc.recent[over:])
	}
	n.inc.byID[id] = r
	if len(s.Changes) > 0 {
		n.inc.facts[id] = s.Changes
	}
	for _, ref := range s.Inc.Refs {
		if e := n.inc.evs[ref]; e != nil {
			e.assigned = true
		}
	}
	if slices.Contains(s.Inc.Events, events.Fork) && len(s.Inc.Members) > 0 {
		var o ids.MemberID
		if o.UnmarshalText([]byte(s.Inc.Members[0])) == nil {
			n.inc.alarmed[id] = true
			n.rec.suspicious[o] = true
		}
	}
	if !n.deliveredLocked(id) {
		n.queue.Add(s.Inc, now.Wall)
	}
}

// restorePeerLocked takes what the file says of a peer of the roster.
func (n *Node) restorePeerLocked(s peerState) {
	if s.ID == n.id.ID || !n.isMember(s.ID) || !s.Boot.valid() || !validVersion(s.Version) || len(s.Version) > member.MaxVersionLen {
		return
	}
	p := n.peer(s.ID)
	if p.heard {
		return
	}
	if a, err := netip.ParseAddrPort(s.Addr); err == nil {
		p.addr = a
	}
	p.hb = member.Heartbeat{From: s.ID, Boot: s.Boot.ID, BootSeq: s.Boot.Seq, Versions: [2]string{s.Version, ""}, GoingDown: s.GoingDown}
	p.heardWall, p.restored, p.toldSilent = s.Heard, true, s.Silent
}

// openAbsenceLocked reports whether the newest record of an absence of x in
// the log, by any member, is a silence not followed by its end: the
// absence was already told before this start.
func (n *Node) openAbsenceLocked(x ids.MemberID) bool {
	var latest time.Time
	open := false
	for _, m := range n.cur().Members {
		for _, e := range n.log.Range(m.ID, 1, n.log.Head(m.ID).Seq) {
			if e.Kind != history.KindEvent {
				continue
			}
			b, err := DecodeEvent(e)
			if err != nil || b.Subject != x || !absence(b.Type) || b.At == (At{}) || b.Detail["update"] != "" {
				continue
			}
			if latest.IsZero() || !b.At.Wall.Before(latest) {
				latest, open = b.At.Wall, b.Type == events.MemberSilent
			}
		}
	}
	return open
}

// returnOfRestored classifies the return of a peer known only from the
// state file, which the Table, not knowing its boot before, reports as a
// bare member_back.
func returnOfRestored(before, h member.Heartbeat, e events.Event) events.Event {
	if e.Type != events.MemberBack || before.Boot == (ids.BootID{}) {
		return e
	}
	e.Type = events.Classify(
		events.Before{AnnouncedGoingDown: before.GoingDown, BootID: before.Boot, Version: before.Versions[0]},
		events.Return{BootID: h.Boot, Version: h.Versions[0]},
	)
	e.Detail = nil
	if e.Type == events.Upgraded {
		e.Detail = map[string]string{"from": before.Versions[0], "to": h.Versions[0]}
	}
	return e
}

// flushAllLocked writes at once everything the node keeps on flash: the
// history, the fork proofs, the state file and the alive file.
func (n *Node) flushAllLocked(now clock.Stamp) error {
	if n.flusher == nil {
		return nil
	}
	err := n.writeHistory()
	if n.rec.bootSeen {
		if !n.goingDown {
			n.aliveAt = n.localStamp(now)
		}
		if aerr := n.saveAlive(n.aliveAt, n.goingDown); err == nil {
			err = aerr
		}
	}
	return err
}

// Stop writes everything the node keeps on flash and stops the node: it
// handles and sends nothing after. The daemon calls it on a clean shutdown,
// after GoingDown when the router goes down.
func (n *Node) Stop() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.running() {
		return nil
	}
	err := n.flushAllLocked(n.stamp())
	n.stopped = ErrStopped
	return err
}
