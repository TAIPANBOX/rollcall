package events

import (
	"testing"

	"github.com/TAIPANBOX/rollcall/internal/ids"
)

// TestClassifyTable is the classification table of design 4.3, row by row,
// plus the combinations the table leaves open and the rules for what is
// unknown. The boot ID decides whether the member rebooted; the version
// decides whether it was an upgrade; the announcement decides planned or not.
func TestClassifyTable(t *testing.T) {
	var zero ids.BootID
	old, cur := boot(1), boot(2)
	cases := []struct {
		name string
		b    Before
		r    Return
		want Type
	}{
		// The four rows of design 4.3.
		{"row 1: announced going down, new boot ID, same version",
			Before{AnnouncedGoingDown: true, BootID: old, Version: "25.12.4"},
			Return{BootID: cur, Version: "25.12.4"}, RebootPlanned},
		{"row 2: nothing announced, new boot ID, same version",
			Before{AnnouncedGoingDown: false, BootID: old, Version: "25.12.4"},
			Return{BootID: cur, Version: "25.12.4"}, RebootUnplanned},
		{"row 3: nothing announced, new boot ID, new version",
			Before{AnnouncedGoingDown: false, BootID: old, Version: "25.12.4"},
			Return{BootID: cur, Version: "25.12.5"}, Upgraded},
		{"row 3: announced going down, new boot ID, new version",
			Before{AnnouncedGoingDown: true, BootID: old, Version: "25.12.4"},
			Return{BootID: cur, Version: "25.12.5"}, Upgraded},
		{"row 4: nothing announced, same boot ID",
			Before{AnnouncedGoingDown: false, BootID: old, Version: "25.12.4"},
			Return{BootID: old, Version: "25.12.4"}, LinkLost},

		// Combinations the table leaves open.
		{"announced going down, same boot ID: it said so but never went down",
			Before{AnnouncedGoingDown: true, BootID: old, Version: "25.12.4"},
			Return{BootID: old, Version: "25.12.4"}, LinkLost},
		{"same boot ID, version changed without a reboot",
			Before{AnnouncedGoingDown: false, BootID: old, Version: "25.12.4"},
			Return{BootID: old, Version: "25.12.5"}, LinkLost},
		{"announced, same boot ID, version changed",
			Before{AnnouncedGoingDown: true, BootID: old, Version: "25.12.4"},
			Return{BootID: old, Version: "25.12.5"}, LinkLost},
		{"downgrade: new boot ID, older version",
			Before{AnnouncedGoingDown: false, BootID: old, Version: "25.12.5"},
			Return{BootID: cur, Version: "24.10.4"}, Upgraded},

		// Unknown boot IDs: neither a reboot nor a link loss can be claimed.
		{"boot ID before silence unknown",
			Before{AnnouncedGoingDown: false, BootID: zero, Version: "25.12.4"},
			Return{BootID: cur, Version: "25.12.4"}, MemberBack},
		{"boot ID on return unknown",
			Before{AnnouncedGoingDown: true, BootID: old, Version: "25.12.4"},
			Return{BootID: zero, Version: "25.12.5"}, MemberBack},
		{"both boot IDs unknown (equal, yet not the same boot)",
			Before{AnnouncedGoingDown: false, BootID: zero, Version: "25.12.4"},
			Return{BootID: zero, Version: "25.12.4"}, MemberBack},

		// Unknown versions: the reboot is certain, an upgrade is not.
		{"version before silence unknown, nothing announced",
			Before{AnnouncedGoingDown: false, BootID: old, Version: ""},
			Return{BootID: cur, Version: "25.12.5"}, RebootUnplanned},
		{"version on return unknown, nothing announced",
			Before{AnnouncedGoingDown: false, BootID: old, Version: "25.12.4"},
			Return{BootID: cur, Version: ""}, RebootUnplanned},
		{"version before silence unknown, announced",
			Before{AnnouncedGoingDown: true, BootID: old, Version: ""},
			Return{BootID: cur, Version: "25.12.5"}, RebootPlanned},
		{"both versions unknown, announced",
			Before{AnnouncedGoingDown: true, BootID: old, Version: ""},
			Return{BootID: cur, Version: ""}, RebootPlanned},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Classify(c.b, c.r); got != c.want {
				t.Errorf("Classify(%+v, %+v) = %q, want %q", c.b, c.r, got, c.want)
			}
		})
	}
}
