package events

import "github.com/TAIPANBOX/rollcall/internal/ids"

// Before is what the group knew of a member before it went silent.
type Before struct {
	AnnouncedGoingDown bool       // it said "going down" before the silence
	BootID             ids.BootID // its boot ID in its last heartbeat; zero if unknown
	Version            string     // its OpenWrt version then; empty if unknown
}

// Return is what the member says when it answers again.
type Return struct {
	BootID  ids.BootID // zero if unknown
	Version string     // empty if unknown
}

// Classify says what happened to a member that went silent and came back.
// It is the table of design 4.3:
//
//	before silence       on return                         result
//	announced going down new boot ID, same version         RebootPlanned
//	nothing announced    new boot ID, same version         RebootUnplanned
//	anything             new boot ID, new OpenWrt version  Upgraded
//	nothing announced    same boot ID                      LinkLost
//
// and these rules for what the table leaves open:
//
//   - The boot ID decides whether the member rebooted, and nothing overrides
//     it. Same boot ID means it stayed up: LinkLost, also when it had
//     announced going down and never did, and also when its version string
//     changed without a reboot.
//   - A zero boot ID on either side is unknown: neither a reboot nor a link
//     loss can be claimed, so the result is MemberBack.
//   - Upgraded needs both versions known and different. A downgrade is a
//     version change and counts as Upgraded (old -> new). With a version
//     unknown, the reboot is still certain and is classified by the
//     announcement alone.
func Classify(b Before, r Return) Type {
	switch {
	case b.BootID == (ids.BootID{}) || r.BootID == (ids.BootID{}):
		return MemberBack
	case r.BootID == b.BootID:
		return LinkLost
	case b.Version != "" && r.Version != "" && r.Version != b.Version:
		return Upgraded
	case b.AnnouncedGoingDown:
		return RebootPlanned
	default:
		return RebootUnplanned
	}
}
