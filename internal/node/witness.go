package node

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strconv"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/clock"
	"github.com/TAIPANBOX/rollcall/internal/events"
	"github.com/TAIPANBOX/rollcall/internal/history"
	"github.com/TAIPANBOX/rollcall/internal/ids"
	"github.com/TAIPANBOX/rollcall/internal/member"
	"github.com/TAIPANBOX/rollcall/internal/roster"
)

// # Witness statements (security spec 5.7)
//
// When the node accepts another member's event of a kind it can judge from
// its own view, it states once, in its own chain, whether it sees the same
// (history.NewWitness, at most one statement per event):
//
//   - member_silent about X: agree when X is suspect or silent here, or not
//     heard at all; disagree when X was heard here within the suspect time.
//   - reboot_unplanned about X: agree when the node hears X in the boot the
//     event says it came back in; disagree when it still hears X in the boot
//     the event says it left.
//   - link_lost about X: agree when the node hears X in that one boot;
//     disagree when it hears X in a later boot, or the event names two
//     boots (a reboot, not a link loss).
//   - internet_lost of the origin: agree when this node's internet probes
//     fail too, disagree when they succeed.
//
// No statement is made about this node itself (Reconcile judges those), nor
// about an event the node has no view of, nor about one whose stamp is more
// than witnessAge from the local clock (an event caught up after an
// absence). A message about a member's absence tells "confirmed by N of M"
// (confirmations): of the M members other than the absent ones, the N that
// recorded the absence themselves or whose statement agrees with such a
// record. Delivery never waits for statements: the count is what the
// sender's log holds when it renders the message.
//
// # Alarms
//
// A fork proof (two entries of one origin at one seq) and a proven falsehood
// (Reconcile: another member's claim that this node's signed chain
// contradicts) each raise one alarm incident naming the suspicious member,
// whose ID is fixed by the forked member alone for a fork (members may find
// different proofs of one equivocation) and by the proof for a falsehood,
// so every member that raises it raises the same incident and the group
// sends it once. Once a member's chain is proven forked, its events from the
// fork on are left out of the incidents still to be made (incidentsLocked):
// routers that saw its different faces hold different events of it there,
// and would otherwise make different incidents of one cause. The node also
// records the alarm in its own chain, as an event of type fork whose Detail
// names the proof ("proof": "fork" or "falsehood", "a" and "b" the entry
// hashes, "a_seq" and "b_seq" their positions). A member that reads such an
// entry raises the alarm only once it has checked the proof itself: a fork
// by fetching the origin's entry at that seq from the member that recorded
// it (whose answer carries both entries), a falsehood with
// Falsehood.Verify on the two entries from its own log. Nobody is expelled:
// removal is the owner's decision.

// witnessAge bounds how far an event's stamp may be from now for the node
// to state a view on it.
const witnessAge = 2 * time.Minute

// # How many statements (N4)
//
// A statement is an own entry, and the node writes its whole own chain to
// flash for each own entry (sync.go), up to about 300 KB at its bound. Other
// members' events are what it states views on, so a compromised member that
// wrote such an event every second would make every other router rewrite its
// chain every second. The node therefore states its view on at most
// witnessBurst events of one origin at once, and on one more each
// witnessEvery after that (a token bucket per origin). A statement over that
// is not made and is counted (Status.WitnessesDropped); it only lowers the
// "confirmed by" count of a message.
//
// witnessBurst is two events for every member of the largest roster: an
// origin that records every other member silent and then back, a whole site's
// power cycle seen from one router, gets a view stated on each. Honest
// members record events of the kinds stated on only when something changes,
// rarely more than one a minute for long. Under a member that writes one a
// second, the statements about it drop from 3600 an hour to at most
// witnessBurst+60.
const (
	witnessBurst = 2 * roster.MaxMembers
	witnessEvery = time.Minute
)

// budget is what is left of one origin's statements (witnessBurst at most),
// and when it was last refilled.
type budget struct {
	left int
	at   time.Duration
}

// spendWitnessLocked takes one statement from origin's budget at now, and
// reports whether one was left.
func (n *Node) spendWitnessLocked(origin ids.MemberID, now time.Duration) bool {
	b := n.inc.witnessBudget[origin]
	if b == nil {
		if len(n.inc.witnessBudget) >= 2*roster.MaxMembers {
			clear(n.inc.witnessBudget) // origins long removed: every budget starts full again
		}
		b = &budget{left: witnessBurst, at: now}
		n.inc.witnessBudget[origin] = b
	}
	if gain := (now - b.at) / witnessEvery; gain > 0 {
		b.left = min(witnessBurst, b.left+int(gain))
		b.at += gain * witnessEvery
	}
	if b.left == 0 {
		n.inc.witnessDropped++
		return false
	}
	b.left--
	return true
}

// witnessWrite is a witness statement waiting to be signed.
type witnessWrite struct {
	ref   ids.Hash
	agree bool
}

// witnessLocked states this node's view on another member's event e.
func (n *Node) witnessLocked(e history.Entry, b EventBody, now clock.Stamp) {
	ref := e.Hash()
	if e.Origin == n.id.ID || b.Subject == n.id.ID || n.inc.witnessed[ref] || n.inc.loading || !n.isMember(e.Origin) {
		return
	}
	at := b.At.Stamp()
	if b.At == (At{}) || !at.Trusted || !now.Trusted || absDuration(now.Wall.Sub(at.Wall)) > witnessAge {
		return
	}
	agree, ok := n.viewOf(e.Origin, b, now)
	if !ok {
		return
	}
	n.inc.witnessed[ref] = true
	if !n.spendWitnessLocked(e.Origin, now.Mono) {
		return
	}
	n.writes = append(n.writes, ownWrite{kind: history.KindWitness, body: witnessWrite{ref: ref, agree: agree}})
	n.flushWritesLocked(now)
}

// viewOf says whether this node sees what b says, and false when it has no
// view of it.
func (n *Node) viewOf(origin ids.MemberID, b EventBody, now clock.Stamp) (agree, ok bool) {
	p := n.peers[b.Subject]
	heard := p != nil && p.heard
	switch b.Type {
	case events.MemberSilent:
		if !heard || p.silent || p.suspect {
			return true, true
		}
		return now.Mono-p.heardMono >= time.Duration(member.DefaultSuspectMissed)*n.cfg.Heartbeat, true
	case events.RebootUnplanned:
		switch {
		case !heard || !b.Back.known():
			return false, false
		case p.hb.Boot == b.Back.ID:
			return true, true
		case b.Last.known() && p.hb.Boot == b.Last.ID:
			return false, true
		}
	case events.LinkLost:
		switch {
		case !heard || !b.Back.known():
			return false, false
		case b.Last.known() && b.Last.ID != b.Back.ID:
			return false, true // two boots: a reboot, not a link loss
		case p.hb.Boot == b.Back.ID:
			return true, true
		case p.hb.BootSeq > b.Back.Seq:
			return false, true
		}
	case events.InternetLost:
		if b.Subject == origin {
			return !n.internetOK, true
		}
	}
	return false, false
}

func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

// confirmations returns "confirmed by N of M" for the incident inc, made of
// evs, when it tells the absence of its causes (Incident.Causes): M is the
// members of the current roster that are not causes, the routers that could
// have seen the absence from outside, and N those of them that did, as this
// node's log tells it now: each one that recorded a cause's silence or
// return in the incident, the sender's own record included, or whose latest
// witness statement about one of those records says it saw the same
// (history.Confirmations). A cause is never counted, nor a member removed
// from the roster. For any other incident both are 0 and the message says
// nothing: a change of a router's own WAN or internet is told with the
// routers that saw it ("Seen by"), and no other router can see it; and when
// every member was a cause (a site power cut) nobody was left to see it.
//
// The count needs no trusted clock: a record is a member's own view, while a
// statement is made only on trusted stamps (witnessLocked). It used to count
// only the statements about the incident's earliest record, of the members
// other than that record's origin, the absent member among them, so on the
// lab run of 2026-10-23 a reboot both other routers saw read "confirmed by 0
// of 2" (no clock trusted, no statement made) and at best "1 of 2" (L8).
func (n *Node) confirmations(inc events.Incident, evs []events.Event) (confirmed, of int) {
	causes := map[ids.MemberID]bool{}
	for _, h := range inc.Members[:min(max(inc.Causes, 0), len(inc.Members))] {
		var x ids.MemberID
		if x.UnmarshalText([]byte(h)) == nil {
			causes[x] = true
		}
	}
	if len(causes) == 0 {
		return 0, 0
	}
	for _, m := range n.cur().Members {
		if !causes[m.ID] {
			of++
		}
	}
	saw := map[ids.MemberID]bool{}
	for _, e := range evs {
		if !absence(e.Type) || !causes[e.Subject] {
			continue
		}
		if !causes[e.Witness] && n.isMember(e.Witness) {
			saw[e.Witness] = true
		}
		agree, _ := history.Confirmations(n.log, e.Ref, n.isMember)
		for _, w := range agree {
			if !causes[w] {
				saw[w] = true
			}
		}
	}
	return len(saw), of
}

// forkAlarmID is the incident ID of the alarm about a fork of origin o's
// chain: one per forked member, whichever proof a member found.
func forkAlarmID(o ids.MemberID) string {
	h := sha256.New()
	h.Write([]byte("rollcall/v1 alarm\x00fork\x00"))
	h.Write(o[:])
	return hex.EncodeToString(h.Sum(nil)[:8])
}

// alarmID is the incident ID of the alarm about one proof: fixed by the
// proof's kind and its two entry hashes, in either order.
func alarmID(kind string, a, b ids.Hash) string {
	if string(b[:]) < string(a[:]) {
		a, b = b, a
	}
	h := sha256.New()
	h.Write([]byte("rollcall/v1 alarm\x00" + kind + "\x00"))
	h.Write(a[:])
	h.Write(b[:])
	return hex.EncodeToString(h.Sum(nil)[:8])
}

// raiseLocked queues the alarm incident id about subject, stamped at, once.
func (n *Node) raiseLocked(id string, subject ids.MemberID, at clock.Stamp, now clock.Stamp) bool {
	if n.inc.alarmed[id] {
		return false
	}
	n.inc.alarmed[id] = true
	n.rec.suspicious[subject] = true
	inc := events.Incident{ID: id, Start: at, End: at, Members: []string{subject.String()},
		Events: []events.Type{events.Fork}, Witnesses: []string{n.id.ID.String()}, Approximate: !at.Trusted}
	n.queueLocked(inc, nil, nil, now)
	n.inc.byID[id].single = true
	return true
}

// forkLocked handles a fork proof the log found: one alarm, and its record
// in the own chain.
func (n *Node) forkLocked(p history.ForkProof, now clock.Stamp) {
	o := p.A.Origin
	if n.inc.loading {
		return
	}
	if len(n.log.Forks()) > n.forksSaved {
		// On flash at once, with the forked chain up to the proof, so that
		// a restart restores the proof in the log and the node can show it
		// to a peer that checks its alarm: a proof lost in a power cut may
		// never be found again (D7). A failed write is retried by the next
		// flush.
		_ = n.writeChainLocked(o)
		_ = n.writeForksLocked()
	}
	if o == n.id.ID {
		return
	}
	at := n.localStamp(now)
	if !n.raiseLocked(forkAlarmID(o), o, at, now) {
		return
	}
	n.recordEvent(events.Event{Type: events.Fork, Subject: o, At: at, Detail: map[string]string{
		"proof": "fork", "a": p.A.Hash().String(), "b": p.B.Hash().String(), "a_seq": strconv.FormatUint(p.A.Seq, 10),
	}}, EventBody{Subject: o, Type: events.Fork}, now)
}

// falsehoodLocked handles a falsehood Reconcile proved against claimant.
func (n *Node) falsehoodLocked(f Falsehood, now clock.Stamp) {
	o := f.Claim.Origin
	ck, known := n.keyOf(o)
	if !known || f.Verify(ck, n.id.Sign.Public().(ed25519.PublicKey)) != nil {
		return
	}
	at := n.localStamp(now)
	if !n.raiseLocked(alarmID("falsehood", f.Claim.Hash(), f.Own.Hash()), o, at, now) {
		return
	}
	n.recordEvent(events.Event{Type: events.Fork, Subject: o, At: at, Detail: map[string]string{
		"proof": "falsehood", "a": f.Claim.Hash().String(), "a_seq": strconv.FormatUint(f.Claim.Seq, 10),
		"b": f.Own.Hash().String(), "b_seq": strconv.FormatUint(f.Own.Seq, 10),
	}}, EventBody{Subject: o, Type: events.Fork}, now)
}

// pendingAlarm is another member's falsehood alarm whose entries this node
// does not hold yet.
type pendingAlarm struct {
	by    ids.MemberID
	body  EventBody
	until time.Duration
}

const (
	keepPending = 64
	pendingFor  = time.Hour
)

// alarmIn handles another member's alarm entry e with body b.
func (n *Node) alarmIn(e history.Entry, b EventBody, now clock.Stamp) {
	var a, h ids.Hash
	if a.UnmarshalText([]byte(b.Detail["a"])) != nil || h.UnmarshalText([]byte(b.Detail["b"])) != nil {
		return
	}
	if e.Origin == n.id.ID {
		// The node's own record, read back after a restart: the alarm is
		// raised again, and queued unless it was acknowledged (D7).
		switch b.Detail["proof"] {
		case "fork":
			n.raiseLocked(forkAlarmID(b.Subject), b.Subject, b.At.Stamp(), now)
		case "falsehood":
			n.raiseLocked(alarmID("falsehood", a, h), b.Subject, b.At.Stamp(), now)
		}
		return
	}
	switch b.Detail["proof"] {
	case "fork":
		seq, err := strconv.ParseUint(b.Detail["a_seq"], 10, 64)
		if err != nil || seq == 0 {
			return
		}
		n.inc.forkAt(b.Subject, seq)
		if n.inc.alarmed[forkAlarmID(b.Subject)] || len(n.inc.forkChecks) >= keepPending {
			return
		}
		// Check it here: the member that recorded it answers with both
		// entries, and Append finds the fork. A fetch that fails (the
		// member cannot be reached now) is tried again (checkForksLocked).
		n.inc.forkChecks = append(n.inc.forkChecks, forkCheck{by: e.Origin, subject: b.Subject, seq: seq, until: now.Mono + pendingFor})
		n.checkForksLocked(now)
	case "falsehood":
		if n.inc.alarmed[alarmID("falsehood", a, h)] || len(n.inc.pending) >= keepPending {
			return
		}
		n.inc.pending = append(n.inc.pending, pendingAlarm{by: e.Origin, body: b, until: now.Mono + pendingFor})
		n.checkPendingLocked(now)
	}
}

// forkCheck is another member's fork alarm this node has not checked yet.
type forkCheck struct {
	by, subject ids.MemberID
	seq         uint64
	next, until time.Duration
}

// checkForksLocked asks, at most every retryEvery, the members whose fork
// alarms are unchecked for the entries of the proof, until this node holds
// the fork itself or the check expires (D7).
func (n *Node) checkForksLocked(now clock.Stamp) {
	n.inc.forkChecks = slices.DeleteFunc(n.inc.forkChecks, func(c forkCheck) bool {
		return n.inc.alarmed[forkAlarmID(c.subject)] || now.Mono > c.until
	})
	for i := range n.inc.forkChecks {
		if c := &n.inc.forkChecks[i]; now.Mono >= c.next {
			c.next = now.Mono + retryEvery
			n.planFetch(c.by, c.subject, c.seq, c.seq)
		}
	}
}

// checkPendingLocked raises every pending falsehood alarm whose proof the
// node can now check, and forgets those it cannot check in time.
func (n *Node) checkPendingLocked(now clock.Stamp) {
	n.inc.pending = slices.DeleteFunc(n.inc.pending, func(p pendingAlarm) bool {
		claim, ok1 := n.entryAt(p.body.Subject, p.body.Detail["a_seq"], p.body.Detail["a"])
		own, ok2 := n.entryAt(p.by, p.body.Detail["b_seq"], p.body.Detail["b"])
		if ok1 && ok2 {
			ck, _ := n.keyOf(claim.Origin)
			sk, _ := n.keyOf(own.Origin)
			if (Falsehood{Claim: claim, Own: own}).Verify(ck, sk) == nil {
				n.raiseLocked(alarmID("falsehood", claim.Hash(), own.Hash()), claim.Origin, p.body.At.Stamp(), now)
			}
			return true
		}
		return now.Mono > p.until
	})
}

// entryAt returns origin's entry at the seq written in seqText, if the log
// holds it with the hash written in hashText.
func (n *Node) entryAt(origin ids.MemberID, seqText, hashText string) (history.Entry, bool) {
	seq, err := strconv.ParseUint(seqText, 10, 64)
	var h ids.Hash
	if err != nil || seq == 0 || h.UnmarshalText([]byte(hashText)) != nil {
		return history.Entry{}, false
	}
	es := n.log.Range(origin, seq, seq)
	if len(es) != 1 || es[0].Hash() != h {
		return history.Entry{}, false
	}
	return es[0], true
}
