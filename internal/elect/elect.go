// Package elect chooses the one member of a group that sends incidents to
// the chat (design 4.5).
//
// There is no consensus protocol. Every member runs Sender over its own view
// of the group, and members that hold the same view compute the same answer,
// the way VRRP routers agree on which of them holds an address. Members whose
// views differ (one has not yet heard the latest heartbeat, or holds a peer
// silent that another still hears) can disagree for as long as their views
// differ, which means two senders or none for that time. Delivery bounds the
// damage (design 4.5): every message carries the incident ID, so a duplicate
// is obvious, and an incident left unacknowledged by a sender that went silent
// is sent by the next eligible member after a grace period. A gap with no
// sender among members that are all alive lasts until their views converge.
// At least once is chosen on purpose.
package elect

import (
	"bytes"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/ids"
)

// Window is how close to now a member's last successful Telegram API call
// must be for the member to be eligible to send (design 4.5).
const Window = 60 * time.Second

// View is what the member running Sender knows of one member of its group,
// itself included.
type View struct {
	ID         ids.MemberID
	HasChannel bool      // it has the sender role and a channel configured
	InternetOK bool      // its internet probes succeed
	TelegramOK time.Time // its last successful Telegram API call; the zero time for never
	Priority   int       // its configured priority as a sender; higher is preferred
	Silent     bool      // the viewing member's failure detection holds it silent
}

// Sender returns the member that sends, and true; or the zero ID and false
// when there is none.
//
// views is the whole group as the caller sees it, the caller included. A
// member is eligible when all of these hold:
//
//   - HasChannel: it has the sender role and a channel configured;
//   - InternetOK: its internet probes succeed;
//   - not Silent;
//   - TelegramOK is within Window of now, inclusive: at most 60 s before now
//     (exactly 60 s still counts, 60 s and a nanosecond does not), or at most
//     60 s after it. A TelegramOK after now comes from a member whose wall
//     clock runs ahead of the caller's; up to Window of such skew is
//     tolerated, and beyond it the stamp proves nothing. The zero TelegramOK
//     means never, and never counts, whatever now is.
//
// Of the eligible members, the one with the highest Priority sends; at equal
// priority, the one with the lowest ID, compared as bytes from the first. IDs
// are unique, so that is a total order and the answer does not depend on the
// order of views.
//
// Two entries with one ID are a caller bug: there is no telling which of them
// is true, so Sender names no sender rather than guess, whichever entry would
// have won.
//
// Sender never reads the clock. It compares TelegramOK with now through
// Time.Sub only, which uses the monotonic readings when both carry one and the
// wall readings otherwise, and which saturates rather than overflows for
// stamps centuries apart. It does not modify views.
func Sender(views []View, now time.Time) (ids.MemberID, bool) {
	if hasDuplicate(views) {
		return ids.MemberID{}, false
	}
	var best *View
	for i := range views {
		v := &views[i]
		if eligible(v, now) && (best == nil || precedes(v, best)) {
			best = v
		}
	}
	if best == nil {
		return ids.MemberID{}, false
	}
	return best.ID, true
}

// eligible reports whether v may send at now.
func eligible(v *View, now time.Time) bool {
	return v.HasChannel && v.InternetOK && !v.Silent && fresh(v.TelegramOK, now)
}

// fresh reports whether a Telegram call at ok is within Window of now, on
// either side.
func fresh(ok, now time.Time) bool {
	if ok.IsZero() {
		return false
	}
	age := now.Sub(ok)
	return age <= Window && age >= -Window
}

// precedes reports whether a outranks b: a higher priority, or the same
// priority and a lower ID.
func precedes(a, b *View) bool {
	if a.Priority != b.Priority {
		return a.Priority > b.Priority
	}
	return bytes.Compare(a.ID[:], b.ID[:]) < 0
}

// hasDuplicate reports whether two entries of views carry one ID.
func hasDuplicate(views []View) bool {
	seen := make(map[ids.MemberID]struct{}, len(views))
	for i := range views {
		if _, ok := seen[views[i].ID]; ok {
			return true
		}
		seen[views[i].ID] = struct{}{}
	}
	return false
}
