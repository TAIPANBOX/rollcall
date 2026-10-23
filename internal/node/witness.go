package node

import (
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
// absence). A message tells "confirmed by N of M" from these statements
// (not an incident of its own, which goes out before any statement can):
// history.Confirmations over the roster members, N those that agree, M the
// members other than the event's origin.
//
// # Alarms
//
// A fork proof (two entries of one origin at one seq) and a proven falsehood
// (Reconcile: another member's claim that this node's signed chain
// contradicts) each raise one alarm incident naming the suspicious member,
// whose ID is fixed by the proof alone, so every member that raises it
// raises the same incident and the group sends it once. The node also
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

// confirmations returns "confirmed by N of M" for an incident made of evs:
// the statements about its earliest event of a kind members state views
// on, N agreeing members, M the members other than its origin. Of is 0 when
// no such event is there.
func (n *Node) confirmations(evs []events.Event) (confirmed, of int) {
	var pick *events.Event
	for i, e := range evs {
		switch e.Type {
		case events.MemberSilent, events.RebootUnplanned, events.LinkLost, events.InternetLost:
		default:
			continue
		}
		if pick == nil || e.At.Wall.Before(pick.At.Wall) || (e.At.Wall.Equal(pick.At.Wall) && string(e.Ref[:]) < string(pick.Ref[:])) {
			pick = &evs[i]
		}
	}
	if pick == nil || !n.isMember(pick.Witness) {
		return 0, 0
	}
	agree, _ := history.Confirmations(n.log, pick.Ref, n.isMember)
	return len(agree), len(n.cur().Members) - 1
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
	if o == n.id.ID || n.inc.loading {
		return
	}
	at := n.localStamp(now)
	if !n.raiseLocked(alarmID("fork", p.A.Hash(), p.B.Hash()), o, at, now) {
		return
	}
	n.recordEvent(events.Event{Type: events.Fork, Subject: o, At: at, Detail: map[string]string{
		"proof": "fork", "a": p.A.Hash().String(), "b": p.B.Hash().String(), "a_seq": strconv.FormatUint(p.A.Seq, 10),
	}}, EventBody{Subject: o, Type: events.Fork}, now)
}

// falsehoodLocked handles a falsehood Reconcile proved against claimant.
func (n *Node) falsehoodLocked(f Falsehood, now clock.Stamp) {
	o := f.Claim.Origin
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
		// The node's own record, read back after a restart: that proof's
		// alarm was raised.
		n.inc.alarmed[alarmID(b.Detail["proof"], a, h)] = true
		return
	}
	switch b.Detail["proof"] {
	case "fork":
		if n.inc.alarmed[alarmID("fork", a, h)] {
			return
		}
		seq, err := strconv.ParseUint(b.Detail["a_seq"], 10, 64)
		if err != nil || seq == 0 {
			return
		}
		// Check it here: the member that recorded it answers with both
		// entries, and Append finds the fork.
		n.planFetch(e.Origin, b.Subject, seq, seq)
	case "falsehood":
		if n.inc.alarmed[alarmID("falsehood", a, h)] || len(n.inc.pending) >= keepPending {
			return
		}
		n.inc.pending = append(n.inc.pending, pendingAlarm{by: e.Origin, body: b, until: now.Mono + pendingFor})
		n.checkPendingLocked(now)
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
