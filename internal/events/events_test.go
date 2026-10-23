package events

import (
	"testing"

	"github.com/TAIPANBOX/rollcall/internal/history"
)

// TestTypeNames pins the spelling of every event type. The names travel in
// history entries and corrections, so a rename is a wire change.
func TestTypeNames(t *testing.T) {
	want := map[Type]string{
		MemberSilent:         "member_silent",
		MemberBack:           "member_back",
		RebootPlanned:        "reboot_planned",
		RebootUnplanned:      "reboot_unplanned",
		Upgraded:             "upgraded",
		LinkLost:             "link_lost",
		WanDown:              "wan_down",
		WanUp:                "wan_up",
		InternetLost:         "internet_lost",
		InternetRestored:     "internet_restored",
		UplinkSwitched:       "uplink_switched",
		MemberJoined:         "member_joined",
		MemberLeft:           "member_left",
		UnderFlood:           "under_flood",
		DuplicateIdentity:    "duplicate_identity",
		Fork:                 "fork",
		RosterChanged:        "roster_changed",
		RosterChangesDropped: "roster_changes_dropped",
	}
	if len(want) != 18 {
		t.Fatalf("%d distinct types, want 18: two constants share a value", len(want))
	}
	for typ, name := range want {
		if string(typ) != name {
			t.Errorf("type %q, want %q", typ, name)
		}
	}
}

// TestClassesMatchCorrectionClasses: a correction (history, Task 12) names
// what really happened with a class; the class must be the event type the
// classification gives, so an incident can be reclassified by it.
func TestClassesMatchCorrectionClasses(t *testing.T) {
	pairs := []struct {
		class string
		typ   Type
	}{
		{history.ClassLinkLost, LinkLost},
		{history.ClassMemberBack, MemberBack},
		{history.ClassRebootPlanned, RebootPlanned},
		{history.ClassRebootUnplanned, RebootUnplanned},
		{history.ClassUpgraded, Upgraded},
	}
	for _, p := range pairs {
		if p.class != string(p.typ) {
			t.Errorf("correction class %q differs from event type %q", p.class, p.typ)
		}
	}
}
