package node

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/clock"
	"github.com/TAIPANBOX/rollcall/internal/deliver"
	"github.com/TAIPANBOX/rollcall/internal/events"
	"github.com/TAIPANBOX/rollcall/internal/history"
	"github.com/TAIPANBOX/rollcall/internal/ids"
	"github.com/TAIPANBOX/rollcall/internal/member"
	"github.com/TAIPANBOX/rollcall/internal/roster"
)

// # History
//
// The node keeps every origin's chain in a history.Log whose keys come from
// the current roster (keyOf), and writes it to the store through a
// Flusher, at most once a minute: one file per origin, history-<hex>.json,
// and the fork proofs in forks.json.
//
// An own entry (an event, a witness statement, a correction, an
// acknowledgement, a boot record) is on flash before anyone can learn of
// it: the node writes its own chain with the new entry (WriteFileAtomic,
// synced) and only then appends it to the log, from which heartbeats and
// fetches read. So the own chain on flash is never behind what any peer
// holds, and a restart after a power cut never signs a second entry at a
// sequence number it used (appendOwnLocked). Heartbeats stay in RAM. A
// write that fails keeps the record waiting and is retried at most every
// retryEvery.
//
// Own entries are signed only once the node knows the head of its own
// chain as the group holds it. After a start it asks its peers for their
// heads (the catch-up below), takes the entries of its own chain it lacks,
// and only then writes; with peers in the roster and none reachable it
// waits ownCatchUp (60 s) and then writes from what it holds. Until then
// its records wait in RAM (Node.writes).
//
// An own event is one entry, an EventBody with its stamp and details, so
// every member builds the same events from the same entries, and they
// coalesce into incidents with the same IDs.
//
// Catch-up: a heartbeat whose digest differs from the node's makes it ask
// the sender for its heads (digest_req, heads) and fetch, origin by
// origin, the entries it lacks (fetch, entries). An entry that does not
// fit its chain (history.ErrPrev) makes it fetch the origin's entry at
// Seq-1 from the same peer, which turns the mismatch into a fork proof if
// the origin signed two entries there.

// ownWrite is an own record waiting to be signed into the own chain.
type ownWrite struct {
	kind history.Kind
	body any           // EventBody, BootBody, or a json.RawMessage
	ev   *events.Event // for an event: its stamp and details
}

// recordEvent records e, which this node saw, with body in its own chain:
// at once when the own chain is caught up, else once it is.
func (n *Node) recordEvent(e events.Event, body EventBody, now clock.Stamp) {
	e.Witness = n.id.ID
	n.writes = append(n.writes, ownWrite{kind: history.KindEvent, body: body, ev: &e})
	n.flushWritesLocked(now)
}

// recordRaw records an entry of kind event with a body this package or
// deliver defines (an acknowledgement, a dropped branch).
func (n *Node) recordRaw(body json.RawMessage, now clock.Stamp) {
	n.writes = append(n.writes, ownWrite{kind: history.KindEvent, body: body})
	n.flushWritesLocked(now)
}

// caughtUpLocked marks the own chain as caught up and writes what waited.
func (n *Node) caughtUpLocked(now clock.Stamp) {
	if n.caughtUp {
		return
	}
	n.caughtUp = true
	n.flushWritesLocked(now)
}

// flushWritesLocked signs the waiting records into the own chain, once the
// own chain is caught up and the boot sequence number restored.
func (n *Node) flushWritesLocked(now clock.Stamp) {
	if !n.caughtUp || n.restoring {
		return
	}
	writes := n.writes
	n.writes = nil
	for i, w := range writes {
		head := n.log.Head(n.id.ID)
		var e history.Entry
		var err error
		var before bootBefore
		known := false
		switch b := w.body.(type) {
		case EventBody:
			if w.ev != nil {
				b.At, b.Detail = AtOf(w.ev.At), cleanDetail(w.ev.Detail)
			}
			e, err = NewEvent(n.id, head, b)
		case witnessWrite:
			e, err = history.NewWitness(n.id, head, b.ref, b.agree, "")
		case BootBody:
			before, known = n.bootBeforeLocked()
			e, err = NewBoot(n.id, head, b)
		default:
			e, err = history.NewEntry(n.id, head, w.kind, w.body)
		}
		if err != nil {
			continue
		}
		if err := n.writeOwnLocked(e); err != nil {
			// Not on flash, so not signed into the chain: it and every
			// record after it wait for the retry.
			n.writes = append(slices.Clone(writes[i:]), n.writes...)
			n.ownRetry = now.Mono + retryEvery
			return
		}
		if !n.appendLocked(e, now) {
			continue
		}
		if b, ok := w.body.(BootBody); ok {
			n.rec.boot, n.rec.bootSeen = b, true
			if known {
				n.ownReturnLocked(before, b, now)
			}
		}
	}
}

// appendOwnLocked makes e, a new entry of the own chain, durable on flash
// and then appends it, as the package doc of this file describes. It
// reports whether the log holds e now.
func (n *Node) appendOwnLocked(e history.Entry, now clock.Stamp) bool {
	if n.writeOwnLocked(e) != nil {
		return false
	}
	return n.appendLocked(e, now)
}

// writeOwnLocked writes the own chain the log holds, with next after it,
// to the own history file at once.
func (n *Node) writeOwnLocked(next history.Entry) error {
	es := append(n.log.Range(n.id.ID, 1, n.log.Head(n.id.ID).Seq), next)
	b, err := json.Marshal(es)
	if err != nil {
		return err
	}
	return n.st.WriteFileAtomic(filePrefix+n.id.ID.String()+".json", b)
}

// retryWritesLocked retries the records whose write to flash failed.
func (n *Node) retryWritesLocked(now clock.Stamp) {
	if len(n.writes) > 0 && n.ownRetry != 0 && now.Mono >= n.ownRetry {
		n.ownRetry = 0
		n.flushWritesLocked(now)
	}
}

// cleanDetail keeps the entries of d an event body allows, nil if none.
func cleanDetail(d map[string]string) map[string]string {
	var out map[string]string
	for k, v := range d {
		if validDetailKey(k) && validVersion(v) && len(out) < maxDetail {
			if out == nil {
				out = map[string]string{}
			}
			out[k] = v
		}
	}
	return out
}

// appendLocked appends e to the log and handles what it records. It
// reports whether the log holds e now.
func (n *Node) appendLocked(e history.Entry, now clock.Stamp) bool {
	err := n.log.Append(e, now.Wall)
	var fe *history.ForkError
	switch {
	case err == nil:
	case errors.As(err, &fe):
		n.forkLocked(fe.Proof, now)
		return false
	default:
		return false
	}
	n.dirty[e.Origin] = true
	n.flusher.Mark()
	n.entryIn(e, now)
	return true
}

// entryIn handles an entry the log accepted.
func (n *Node) entryIn(e history.Entry, now clock.Stamp) {
	if e.Kind == history.KindWitness {
		if w, err := history.DecodeWitness(e); err == nil && e.Origin == n.id.ID {
			n.inc.witnessed[w.Ref] = true
		}
		return
	}
	if e.Kind != history.KindEvent {
		return
	}
	if id, by, ok := deliver.AckOf(e); ok {
		n.queue.Ack(id, by)
		n.inc.acked(id)
		return
	}
	if d, ok := decodeDropped(e); ok {
		n.inc.droppedIn(d, now)
		return
	}
	b, err := DecodeEvent(e)
	if err != nil {
		return
	}
	switch {
	case b.Detail["proof"] != "":
		n.alarmIn(e, b, now)
	case b.Detail["update"] != "":
		n.updateIn(e, b, now)
	default:
		n.inc.eventIn(e, b, now)
		n.witnessLocked(e, b, now)
	}
	if b.Subject == n.id.ID && e.Origin != n.id.ID {
		n.rec.claim(e)
	}
}

// writeHistory is the Flusher's write function.
func (n *Node) writeHistory() error {
	var errs []error
	for o := range n.dirty {
		if !n.isMember(o) {
			delete(n.dirty, o)
			continue
		}
		es := n.log.Range(o, 1, n.log.Head(o).Seq)
		b, err := json.Marshal(es)
		if err == nil {
			err = n.st.WriteFileAtomic(filePrefix+o.String()+".json", b)
		}
		if err != nil {
			errs = append(errs, err)
			continue
		}
		delete(n.dirty, o)
	}
	if fs := n.log.Forks(); len(fs) > 0 {
		b, err := json.Marshal(fs)
		if err == nil {
			err = n.st.WriteFileAtomic(fileForks, b)
		}
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// loadHistory reads the stored chains of the current roster's members.
func (n *Node) loadHistory(now clock.Stamp) {
	n.inc.loading = true
	for _, m := range n.cur().Members {
		b, err := n.st.ReadFile(filePrefix + m.ID.String() + ".json")
		if err != nil {
			continue
		}
		var es []history.Entry
		if json.Unmarshal(b, &es) != nil {
			continue
		}
		for _, e := range es {
			if e.Origin == m.ID {
				n.appendLocked(e, now)
			}
		}
	}
	if b, err := n.st.ReadFile(fileForks); err == nil {
		var ps []history.ForkProof
		if json.Unmarshal(b, &ps) == nil {
			for _, p := range ps {
				n.appendLocked(p.B, now)
			}
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		_ = err // a bad proof file is rebuilt by the next flush
	}
	// What was loaded is history, not news.
	n.inc.settleAll()
	n.inc.loading = false
}

// planCatchUp asks p for its heads.
func (n *Node) planCatchUp(p ids.MemberID) {
	var hs headsMsg
	payload, _ := json.Marshal(digestReq{})
	n.plan(job{to: p, typ: msgDigestReq, reply: msgHeads, payload: payload,
		check: func(b []byte) error { return decodeJSON(b, &hs, maxReplyPayload) },
		apply: func(_ member.Admitted, now clock.Stamp) { n.headsIn(p, hs, now) }})
}

// headsIn compares p's heads with the node's and fetches what it lacks.
func (n *Node) headsIn(p ids.MemberID, hs headsMsg, now clock.Stamp) {
	ownBehind := false
	for _, h := range hs.Heads {
		if !n.isMember(h.Origin) {
			continue
		}
		mine := n.log.Head(h.Origin)
		switch {
		case h.Seq > mine.Seq:
			from := max(mine.Seq+1, h.Pruned+1)
			n.planFetch(p, h.Origin, from, h.Seq)
			if h.Origin == n.id.ID {
				ownBehind = true
			}
		case h.Seq == mine.Seq && h.Seq > 0 && h.Hash != mine.Hash:
			n.planFetch(p, h.Origin, h.Seq, h.Seq)
		}
	}
	if !ownBehind {
		n.caughtUpLocked(now)
	}
}

// planFetch asks p for origin's entries from..to.
func (n *Node) planFetch(p, origin ids.MemberID, from, to uint64) {
	var es entriesMsg
	payload, _ := json.Marshal(fetchReq{Origin: origin, From: from, To: to})
	n.plan(job{to: p, typ: msgFetch, reply: msgEntries, payload: payload,
		check: func(b []byte) error {
			if err := decodeJSON(b, &es, maxReplyPayload); err != nil {
				return err
			}
			for _, e := range es.Entries {
				if e.Origin != origin || e.Seq < from || e.Seq > to {
					return errMalformed
				}
			}
			return nil
		},
		apply: func(_ member.Admitted, now clock.Stamp) { n.entriesIn(p, origin, from, to, es.Entries, now) }})
}

// entriesIn appends fetched entries of origin, oldest first.
func (n *Node) entriesIn(p, origin ids.MemberID, from, to uint64, es []history.Entry, now clock.Stamp) {
	slices.SortFunc(es, func(a, b history.Entry) int {
		switch {
		case a.Seq < b.Seq:
			return -1
		case a.Seq > b.Seq:
			return 1
		}
		return 0
	})
	last := uint64(0)
	for _, e := range es {
		err := n.log.Append(e, now.Wall)
		var fe *history.ForkError
		switch {
		case err == nil:
			n.dirty[e.Origin] = true
			n.flusher.Mark()
			n.entryIn(e, now)
			last = e.Seq
		case errors.As(err, &fe):
			n.forkLocked(fe.Proof, now)
			return
		case errors.Is(err, history.ErrPrev) && e.Seq > 1:
			// The origin's entry at Seq-1 as p holds it is not the one the
			// log holds: fetch it, and Append shows whether that is a fork.
			n.planFetch(p, origin, e.Seq-1, e.Seq-1)
			return
		case errors.Is(err, history.ErrGap):
			if h := n.log.Head(origin); h.Seq+1 < e.Seq {
				n.planFetch(p, origin, h.Seq+1, to)
			}
			return
		default:
			last = max(last, e.Seq)
		}
	}
	if last > 0 && last < to {
		n.planFetch(p, origin, last+1, to)
		return
	}
	if origin == n.id.ID && n.log.Head(origin).Seq >= to {
		n.caughtUpLocked(now)
	}
}

// planProbe asks helper whether it hears target.
func (n *Node) planProbe(helper, target ids.MemberID) {
	var ack probeAck
	payload, _ := json.Marshal(probeReq{Target: target})
	n.plan(job{to: helper, typ: msgProbeReq, reply: msgProbeAck, payload: payload,
		check: func(b []byte) error {
			if err := decodeJSON(b, &ack, maxReplyPayload); err != nil {
				return err
			}
			if ack.Target != target || ack.Ago < 0 {
				return errMalformed
			}
			return nil
		},
		apply: func(a member.Admitted, now clock.Stamp) {
			r := member.Report{Target: ack.Target, Heartbeat: ack.Heartbeat, Ago: time.Duration(ack.Ago), BootSeq: ack.BootSeq, Boot: ack.Boot}
			evs, err := n.table.RecordReport(a, r, now)
			if err != nil {
				return
			}
			for _, e := range evs {
				n.recordEvent(e, EventBody{Subject: e.Subject, Type: e.Type}, now)
			}
			if target == n.id.ID && n.cfg.IdentityDir != "" {
				n.restoredLocked(now)
			}
		}})
}

// # Rosters
//
// A heartbeat that announces another roster hash makes the node fetch that
// peer's tip (roster, version 0). A tip one version past the node's that
// Verify accepts is adopted. A longer chain is fetched version by version
// from the node's tip on. A tip that does not continue the node's chain
// means the group split and both sides changed the roster: the node walks
// back version by version until it finds the last roster both chains hold,
// fetches the peer's branch from there, and decides with roster.Prefer
// called with the first roster of each branch after that common ancestor
// (the branch belongs to whoever started it), then adopts the winning
// branch's tip. The changes of the losing branch are announced as undone,
// once (RosterChangesDropped).
//
// A takeover (a backup naming itself primary) is adopted only if the node
// has heard nothing from the primary for roster.TakeoverAfter
// (roster.AcceptTakeover), counted from the node's start at the latest.

// rosterFetch is one roster synchronisation with a peer.
type rosterFetch struct {
	peer   ids.MemberID
	tip    roster.Signed
	tipV   uint64
	branch map[uint64]roster.Signed // the peer's rosters by the version it gave
}

// planRosterFetch asks p for its tip.
func (n *Node) planRosterFetch(p ids.MemberID) {
	f := &rosterFetch{peer: p, branch: map[uint64]roster.Signed{}}
	n.planRosterAt(f, 0)
}

// planRosterAt asks f's peer for its roster of version v (0: the tip).
func (n *Node) planRosterAt(f *rosterFetch, v uint64) {
	var (
		gotV uint64
		s    roster.Signed
	)
	payload, _ := json.Marshal(rosterReq{Version: v})
	n.plan(job{to: f.peer, typ: msgRoster, reply: msgRoster, payload: payload,
		check: func(b []byte) error {
			var err error
			gotV, s, err = decodeRosterReply(b)
			return err
		},
		apply: func(_ member.Admitted, now clock.Stamp) {
			switch {
			case v == 0:
				f.tip, f.tipV = s, gotV
			case gotV != v:
				return // not what was asked: the synchronisation stops here
			}
			f.branch[gotV] = s
			n.rosterStep(f, now)
		}})
}

// rosterStep moves a roster synchronisation one step on.
func (n *Node) rosterStep(f *rosterFetch, now clock.Stamp) {
	if n.inChain(f.tip.Hash()) >= 0 {
		return // the peer is behind or level; it fetches from us
	}
	cur := n.cur()
	if f.tipV > cur.Version {
		next, ok := f.branch[cur.Version+1]
		if !ok {
			n.planRosterAt(f, cur.Version+1)
			return
		}
		if _, err := next.Verify(&n.chain[len(n.chain)-1]); err == nil {
			if links, ok := n.branchFrom(f, cur.Version+1); ok {
				n.extendLocked(len(n.chain)-1, links, nil, now)
			}
			return
		}
	}
	// The chains diverge: find the highest version at which both hold the
	// same roster, within what the node keeps.
	for v := min(f.tipV, cur.Version); v >= max(n.rosters[0].Version, 1); v-- {
		s, ok := f.branch[v]
		if !ok {
			n.planRosterAt(f, v)
			return
		}
		if i := n.inChain(s.Hash()); i >= 0 {
			if theirs, ok := n.branchFrom(f, v+1); ok {
				n.resolveLocked(i, theirs, now)
			}
			return
		}
	}
}

// branchFrom returns the peer's rosters from version v to its tip, or
// plans the fetch of the first one missing and returns false.
func (n *Node) branchFrom(f *rosterFetch, v uint64) ([]roster.Signed, bool) {
	var out []roster.Signed
	for w := v; w <= f.tipV; w++ {
		s, ok := f.branch[w]
		if !ok {
			n.planRosterAt(f, w)
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

// inChain returns the index of the roster with hash h in the chain, or -1.
func (n *Node) inChain(h ids.Hash) int {
	for i := range n.chain {
		if n.chain[i].Hash() == h {
			return i
		}
	}
	return -1
}

// verifyLinks verifies links one by one from the chain's roster at index
// base, applying the takeover rule to each.
func (n *Node) verifyLinks(base int, links []roster.Signed) ([]roster.Roster, error) {
	prev := n.chain[base]
	prevR := n.rosters[base]
	var out []roster.Roster
	for _, s := range links {
		r, err := s.Verify(&prev)
		if err != nil {
			return nil, err
		}
		// The primary a takeover replaces takes it, and restores itself
		// (restoreLocked); every other member applies the ten-minute rule.
		if isTakeover(prevR, s, r) && prevR.Admins[0] != n.id.ID && !roster.AcceptTakeover(n.lastHeardPrimary, n.clk.Now()) {
			return nil, errTakeover
		}
		out = append(out, r)
		prev, prevR = s, r
	}
	return out, nil
}

var errTakeover = errors.New("node: a takeover while the primary is still heard")

// isTakeover reports whether r, signed as s after prev, is a takeover by a
// backup: signed by an admin other than prev's primary, naming another
// primary, with Takeover set.
func isTakeover(prev roster.Roster, s roster.Signed, r roster.Roster) bool {
	return !s.Recovery && len(prev.Admins) > 0 && s.SignerID != prev.Admins[0] &&
		len(r.Admins) > 0 && r.Admins[0] != prev.Admins[0] && r.Takeover
}

// extendLocked adopts links after the chain's roster at index base. dropped
// are the node's own rosters after base that lose to them, nil when the
// links simply extend the chain.
func (n *Node) extendLocked(base int, links []roster.Signed, dropped []roster.Signed, now clock.Stamp) bool {
	rs, err := n.verifyLinks(base, links)
	if err != nil || len(rs) == 0 {
		return false
	}
	droppedR := slices.Clone(n.rosters[base+1:])
	baseR := n.rosters[base]
	n.chain = append(slices.Clone(n.chain[:base+1]), links...)
	n.rosters = append(slices.Clone(n.rosters[:base+1]), rs...)
	if over := len(n.chain) - keepRosters; over > 0 {
		n.chain, n.rosters = n.chain[over:], n.rosters[over:]
	}
	n.curHash = n.curSigned().Hash()
	n.setKeyMap(n.cur())
	_ = n.st.WriteFileAtomic(FileRoster, encodeChain(n.chain))

	before := baseR
	for i, s := range links {
		n.announceLocked(before, s, rs[i], now)
		before = rs[i]
	}
	if len(dropped) > 0 {
		n.droppedLocked(baseR, dropped, droppedR, now)
	}
	cur := n.cur()
	if _, ok := memberOf(cur, n.id.ID); !ok {
		n.removeSelfLocked()
		return true
	}
	_ = n.table.SetRoster(cur, n.curHash, now)
	for id := range n.peers {
		if _, ok := memberOf(cur, id); !ok {
			delete(n.peers, id)
			delete(n.deliveries, id)
		}
	}
	return true
}

// resolveLocked settles a split: theirs is the peer's branch after the
// chain's roster at index base, ours the node's.
func (n *Node) resolveLocked(base int, theirs []roster.Signed, now clock.Stamp) {
	ours := slices.Clone(n.chain[base+1:])
	if len(theirs) == 0 || len(ours) == 0 {
		return
	}
	rTheirs, err := n.verifyLinks(base, theirs)
	if err != nil {
		return
	}
	if !preferTheirs(theirs, ours, rTheirs, n.rosters[base+1:], n.rosters[base]) {
		// Ours stays. The peer adopts it when it fetches from us; the
		// undone changes are announced from the history it then records.
		return
	}
	n.extendLocked(base, theirs, ours, now)
}

// preferTheirs decides between two branches that leave common, theirs
// and ours, each with its verified rosters: by the FIRST roster of each,
// since a branch belongs to whoever started it. Judged by the tips, a
// branch the primary started would rank lowest once its tip is signed by
// a member it made backup after the split.
func preferTheirs(theirs, ours []roster.Signed, rTheirs, rOurs []roster.Roster, common roster.Roster) bool {
	return roster.Prefer(theirs[0], ours[0], rTheirs[0], rOurs[0], common).Hash() == theirs[0].Hash()
}

// # Removal of self

// removeSelfLocked handles a roster without this router: it stops sending
// and clears its group secrets (security spec 5.6).
func (n *Node) removeSelfLocked() {
	n.removed = true
	n.ring = newEmptyRing(n.clk.Now)
	for i := range n.keys {
		clear(n.keys[i].Secret)
	}
	n.keys = nil
	n.secrets = secretsFile{}
	_ = writeKeys(n.st, nil, true)
	_ = SaveSecrets(n.st, "", 0)
	n.ch = nil
	n.jobs, n.out = nil, nil
	n.deliveries = map[ids.MemberID]*delivery{}
}

// # Roster changes made here

// Publish signs the next roster, as edit makes it from the current one,
// with this router's key, and adopts it. This router must be an admin of
// the current roster, and Verify must accept the result: the roster rules
// (who may sign, takeover, keys) are Verify's. A removal rotates the epoch
// key at once.
func (n *Node) Publish(edit func(r *roster.Roster) error) error {
	return n.publish(edit, nil)
}

// PublishRecovery is Publish with the recovery key instead of this
// router's admin key (rollcall admin recover).
func (n *Node) PublishRecovery(edit func(r *roster.Roster) error, recovery []byte) error {
	if len(recovery) == 0 {
		return ErrArgument
	}
	return n.publish(edit, recovery)
}

func (n *Node) publish(edit func(r *roster.Roster) error, recovery []byte) error {
	n.mu.Lock()
	if !n.running() {
		n.mu.Unlock()
		return n.why()
	}
	now := n.stamp()
	err := n.publishLocked(edit, recovery, now)
	out := n.takeOut()
	n.mu.Unlock()
	n.send(out)
	return err
}

func (n *Node) publishLocked(edit func(r *roster.Roster) error, recovery []byte, now clock.Stamp) error {
	prev := n.cur()
	r := cloneRoster(prev)
	r.Version, r.Prev = prev.Version+1, n.curHash
	if err := edit(&r); err != nil {
		return err
	}
	r.Version, r.Prev = prev.Version+1, n.curHash
	var (
		s   roster.Signed
		err error
	)
	if recovery != nil {
		s, err = roster.SignRoster(r, ids.MemberID{}, recovery, true)
	} else {
		if !slices.Contains(prev.Admins, n.id.ID) {
			return ErrNotAdmin
		}
		s, err = roster.SignRoster(r, n.id.ID, n.id.Sign, false)
	}
	if err != nil {
		return err
	}
	if !n.extendLocked(len(n.chain)-1, []roster.Signed{s}, nil, now) {
		_, err := s.Verify(&n.chain[len(n.chain)-1])
		if err == nil {
			err = errTakeover
		}
		return err
	}
	if !n.running() {
		return nil
	}
	// The members still on the old key hear the new roster in this
	// heartbeat, among them the removed ones, which may fetch it.
	n.beatLocked(now)
	if removedAny(prev, n.cur()) {
		return n.rotateLocked(now)
	}
	return nil
}

// Remove removes the member id from the roster and rotates the epoch key.
func (n *Node) Remove(id ids.MemberID) error {
	return n.Publish(func(r *roster.Roster) error {
		if id == n.id.ID {
			return fmt.Errorf("%w: a router does not remove itself", ErrArgument)
		}
		i := slices.IndexFunc(r.Members, func(m roster.Member) bool { return m.ID == id })
		if i < 0 {
			return fmt.Errorf("%w: no such member", ErrArgument)
		}
		r.Members = slices.Delete(r.Members, i, i+1)
		r.Admins = slices.DeleteFunc(r.Admins, func(a ids.MemberID) bool { return a == id })
		return nil
	})
}

func removedAny(prev, cur roster.Roster) bool {
	for _, m := range prev.Members {
		if _, ok := memberOf(cur, m.ID); !ok {
			return true
		}
	}
	return false
}

func cloneRoster(r roster.Roster) roster.Roster {
	out := r
	out.Members = make([]roster.Member, len(r.Members))
	for i, m := range r.Members {
		m.SignPub = slices.Clone(m.SignPub)
		m.RecvPub = slices.Clone(m.RecvPub)
		m.Roles = slices.Clone(m.Roles)
		out.Members[i] = m
	}
	out.Admins = slices.Clone(r.Admins)
	out.RecoveryPub = slices.Clone(r.RecoveryPub)
	return out
}

// restoreLocked restores this router as primary after a takeover it did
// not confirm, once it holds that roster (roster.ShouldRestore).
func (n *Node) restoreLocked(now clock.Stamp) {
	cur := n.cur()
	if !roster.ShouldRestore(cur, n.id.ID) || now.Mono < n.nextRestore {
		return
	}
	n.nextRestore = now.Mono + time.Minute
	_ = n.publishLocked(func(r *roster.Roster) error {
		backup := r.Admins[0]
		r.Admins = []ids.MemberID{n.id.ID, backup}
		r.Takeover, r.Replaced, r.OwnerConfirmed = false, ids.MemberID{}, false
		for i := range r.Members {
			m := &r.Members[i]
			m.Roles = slices.DeleteFunc(m.Roles, func(x roster.Role) bool { return x == roster.RolePrimary || x == roster.RoleBackup })
			switch m.ID {
			case n.id.ID:
				m.Roles = append(m.Roles, roster.RolePrimary)
			case backup:
				m.Roles = append(m.Roles, roster.RoleBackup)
			}
		}
		return nil
	}, nil, now)
}

// restoredLocked raises the stored boot sequence number past what a peer
// reported of this router, and lets the heartbeats start with it.
func (n *Node) restoredLocked(now clock.Stamp) {
	if !n.restoring {
		return
	}
	seq, raised, err := n.table.RestoreBootSeq(n.cfg.IdentityDir)
	if err != nil {
		return
	}
	if raised {
		for i, w := range n.writes {
			if b, ok := w.body.(BootBody); ok {
				b.Boot.Seq = seq
				n.writes[i].body = b
			}
		}
	}
	n.restoring = false
	n.flushWritesLocked(now)
}

func (n *Node) why() error {
	if n.stopped != nil {
		return n.stopped
	}
	return ErrRemoved
}
