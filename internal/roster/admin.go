package roster

import (
	"bytes"
	"slices"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/ids"
)

// TakeoverAfter is how long a member must have heard nothing from the
// primary before it accepts the backup's takeover (spec 6.1).
const TakeoverAfter = 10 * time.Minute

// Prefer returns the one of two rosters of a split group that every member
// keeps once the split heals (spec 6.1): the higher version; at equal
// version the one signed with the higher authority, the recovery key, then
// the primary, then a backup, then anyone else; at equal authority the one
// whose Hash is lower, compared byte by byte.
//
// a and b must each have been verified, link by link, from common, and ra
// and rb are the rosters Verify returned for them. common is the last roster
// both chains contain, the one before the split. Authority is the signer's
// place in common.Admins, Admins[0] the primary and the rest backups, not
// its place in ra or rb: a backup that took over during the split still
// ranks as the backup, and a member made admin on one side only ranks below
// both admins.
//
// Prefer orders rosters one way: Prefer(a, b, ra, rb, common) and
// Prefer(b, a, rb, ra, common) return the same roster, and folding Prefer
// over any number of candidates picks the same one in every order. It
// returns a or b as given, a when they are equal.
func Prefer(a, b Signed, ra, rb, common Roster) Signed {
	if ra.Version != rb.Version {
		if ra.Version > rb.Version {
			return a
		}
		return b
	}
	if wa, wb := authority(a, common), authority(b, common); wa != wb {
		if wa > wb {
			return a
		}
		return b
	}
	ha, hb := a.Hash(), b.Hash()
	if bytes.Compare(ha[:], hb[:]) <= 0 {
		return a
	}
	return b
}

// authority ranks the signer of s by its place in common: 3 the recovery
// key, 2 the primary, 1 a backup, 0 anyone else.
func authority(s Signed, common Roster) int {
	switch i := slices.Index(common.Admins, s.SignerID); {
	case s.Recovery:
		return 3
	case i == 0:
		return 2
	case i > 0:
		return 1
	}
	return 0
}

// AcceptTakeover reports whether a member that last heard the primary at
// lastHeardPrimary accepts, at now, a takeover by the backup (spec 6.1):
// only once it has heard nothing from the primary for at least
// TakeoverAfter. A zero lastHeardPrimary, a primary never heard, counts as
// silent. A lastHeardPrimary after now (a clock that went back) does not:
// the primary was heard, and the member keeps waiting.
//
// Pass times taken from time.Now in this process: they carry the monotonic
// clock, so setting the wall clock back or forward (a rogue NTP server, for
// instance) moves neither of them.
//
// The caller applies it to a roster that Verify accepted when the roster is
// a takeover: signed by an admin other than the previous roster's Admins[0],
// naming a new Admins[0], with Takeover set. lastHeardPrimary is when the
// member last heard that previous Admins[0].
func AcceptTakeover(lastHeardPrimary, now time.Time) bool {
	if lastHeardPrimary.IsZero() {
		return true
	}
	return now.Sub(lastHeardPrimary) >= TakeoverAfter
}

// ShouldRestore reports whether self, holding cur as its current roster,
// should restore itself as primary with the next version (spec 6.1): cur is
// a takeover the owner has not confirmed, and self is the primary it
// replaced. The restore is a roster signed by self that names self
// Admins[0] and clears Takeover; Verify accepts it without the ten-minute
// rule, since the replaced primary takes back its own role.
func ShouldRestore(cur Roster, self ids.MemberID) bool {
	return cur.Takeover && !cur.OwnerConfirmed && self != (ids.MemberID{}) && cur.Replaced == self
}

// ActingAdmin returns the admin that does the routine duties of spec 6.1,
// such as the 30-day key rotation: the first admin in r.Admins for which
// alive returns true. It returns false when no admin is alive; ordinary
// members never act. alive is asked about admins only, in order, and not
// past the first live one.
func ActingAdmin(r Roster, alive func(ids.MemberID) bool) (ids.MemberID, bool) {
	for _, id := range r.Admins {
		if alive(id) {
			return id, true
		}
	}
	return ids.MemberID{}, false
}

// checkTakeover applies the admin rules of the package comment to r, signed
// by s, following p: admin keys, then takeover. Verify calls it with p and r
// checked and s's signature verified under p's authority; it reads
// p.Admins[0] and r.Admins[0], which Check guarantees.
func checkTakeover(p, r *Roster, s Signed) error {
	if s.Recovery {
		return nil // the recovery key overrides both admins
	}
	if err := keepAdminKeys(p, r, s.SignerID); err != nil {
		return err
	}
	if s.SignerID != p.Admins[0] && r.Admins[0] != p.Admins[0] {
		// A backup names a new primary: a takeover, or a restore.
		if !r.Takeover {
			if provisional(p) && s.SignerID == p.Replaced && r.Admins[0] == s.SignerID {
				return nil // the replaced primary restores itself
			}
			return ErrTakeoverFlag
		}
		if r.Replaced != p.Admins[0] {
			return ErrTakeoverReplaced
		}
		return nil
	}
	if !p.Takeover {
		if r.Takeover {
			return ErrTakeoverFlag // only a takeover raises the flag
		}
		return nil
	}
	// p is a takeover and r takes over nothing: the takeover carries forward.
	if !r.Takeover {
		if p.OwnerConfirmed || r.Admins[0] == p.Replaced {
			return nil // confirmed, or the replaced primary is primary again
		}
		return ErrTakeoverFlag
	}
	if r.Replaced != p.Replaced {
		return ErrTakeoverReplaced
	}
	if p.OwnerConfirmed && !r.OwnerConfirmed {
		return ErrTakeoverFlag // a confirmation is not withdrawn
	}
	return nil
}

// provisional reports whether r is a takeover the owner has not confirmed.
func provisional(r *Roster) bool { return r.Takeover && !r.OwnerConfirmed }

// keepAdminKeys returns ErrAdminKeys if r, signed by the admin signer,
// gives another admin of p, still a member of r, signing or receive keys
// other than p gives it. Removing an admin is not a key change; whether it
// is allowed is decided by Check and the takeover rules. An admin of p that
// p does not list as a member fails closed.
func keepAdminKeys(p, r *Roster, signer ids.MemberID) error {
	for _, id := range p.Admins {
		if id == signer {
			continue // an admin may change its own keys
		}
		cur := memberByID(r, id)
		if cur == nil {
			continue
		}
		old := memberByID(p, id)
		if old == nil || !bytes.Equal(old.SignPub, cur.SignPub) || !bytes.Equal(old.RecvPub, cur.RecvPub) {
			return ErrAdminKeys
		}
	}
	return nil
}

// memberByID returns the member of r with id, or nil.
func memberByID(r *Roster, id ids.MemberID) *Member {
	for i := range r.Members {
		if r.Members[i].ID == id {
			return &r.Members[i]
		}
	}
	return nil
}
