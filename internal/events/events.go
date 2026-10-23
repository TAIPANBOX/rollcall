// Package events defines what rollcall reports about a group: the event
// types, the classification of a member that comes back after a silence
// (design 4.3), and the coalescing of events with one cause into one
// incident, so that one main-router reboot is one message and not one per
// router.
//
// The package is pure: no networking, no storage, no clock reads. Times come
// in on the events' stamps.
package events

import (
	"github.com/TAIPANBOX/rollcall/internal/clock"
	"github.com/TAIPANBOX/rollcall/internal/ids"
)

// Type is the kind of an event. The names travel in history entries and
// corrections, so they are part of the wire format.
type Type string

// The event types of v1: design 4.3, the alarms of the security document,
// and the announcement of roster changes undone after a network split.
const (
	MemberSilent    Type = "member_silent"    // a member stopped answering
	MemberBack      Type = "member_back"      // it answers again; nothing is claimed about the absence
	RebootPlanned   Type = "reboot_planned"   // it rebooted after announcing it
	RebootUnplanned Type = "reboot_unplanned" // it rebooted unannounced: a crash or a power cut
	Upgraded        Type = "upgraded"         // it came back with a new firmware version
	LinkLost        Type = "link_lost"        // it stayed up; the path to it broke

	WanDown          Type = "wan_down"          // a member's WAN interface went down
	WanUp            Type = "wan_up"            // and came back
	InternetLost     Type = "internet_lost"     // a member's internet probes failed
	InternetRestored Type = "internet_restored" // and succeed again
	UplinkSwitched   Type = "uplink_switched"   // a member moved to another uplink

	MemberJoined Type = "member_joined"
	MemberLeft   Type = "member_left"

	UnderFlood        Type = "under_flood"        // a burst of packets that fail authentication
	DuplicateIdentity Type = "duplicate_identity" // two live members with one identity
	Fork              Type = "fork"               // a member showed different histories to different peers

	RosterChanged        Type = "roster_changed"
	RosterChangesDropped Type = "roster_changes_dropped" // a losing roster branch, announced as undone
)

// Own reports whether e is a member's own account of its return: a return
// (RebootPlanned, RebootUnplanned, Upgraded, LinkLost or MemberBack) whose
// witness is its subject. A member knows whether it rebooted, as planned or
// not, and into which version; what the others say about the same absence
// is their guess from outside.
func Own(e Event) bool {
	switch e.Type {
	case RebootPlanned, RebootUnplanned, Upgraded, LinkLost, MemberBack:
		return e.Subject != (ids.MemberID{}) && e.Witness == e.Subject
	}
	return false
}

// Event is one thing one member saw.
//
// Since is set on a member's own account of its return (Own): the last
// moment the member knows it was up before the absence, on the clocks of
// the boot it left, or of the member that last heard it with a zero Boot.
// Its Trusted is false when that moment is only a bound (the member's last
// state on flash, written at most once a minute) or its wall clock was not
// trusted. Zero when unknown; on any other event it is ignored.
type Event struct {
	Type    Type
	Subject ids.MemberID      // the member it is about; zero when it is about no single member
	Witness ids.MemberID      // the member that saw it and stamped it
	At      clock.Stamp       // when, on the witness's clocks
	Since   clock.Stamp       // on a member's own account of its return: when its absence began (see Own)
	Back    ids.BootID        // on a return: the boot its subject came back in; zero when unknown
	Ref     ids.Hash          // the hash of the history entry that records it
	Detail  map[string]string // what the rendering needs (versions, probe target); not interpreted here
}
