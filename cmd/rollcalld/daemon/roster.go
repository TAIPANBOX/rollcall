package daemon

import (
	"errors"
	"fmt"
	"slices"

	"github.com/TAIPANBOX/rollcall/internal/ids"
	"github.com/TAIPANBOX/rollcall/internal/roster"
)

// The roster edits of the admin commands. Each takes the next roster as
// node.Publish hands it over and changes it in place; Publish signs it and
// roster.Signed.Verify decides whether the group accepts it. An edit that
// would change nothing returns errUnchanged, and the command reports that
// without signing anything.

var errUnchanged = errors.New("nothing to change")

// noMember is the error for a name the roster does not hold. The name was
// checked with roster.ValidName before, so it is safe to repeat.
func noMember(name string) error { return fmt.Errorf("no such member: %s", name) }

func memberIndex(r *roster.Roster, name string) int {
	return slices.IndexFunc(r.Members, func(m roster.Member) bool { return m.Name == name })
}

func hasRole(m roster.Member, role roster.Role) bool { return slices.Contains(m.Roles, role) }

func withoutRoles(rs []roster.Role, drop ...roster.Role) []roster.Role {
	return slices.DeleteFunc(slices.Clone(rs), func(x roster.Role) bool { return slices.Contains(drop, x) })
}

func withRole(rs []roster.Role, add roster.Role) []roster.Role {
	if slices.Contains(rs, add) {
		return rs
	}
	return append(slices.Clone(rs), add)
}

// setAdmins makes admins the admin list, Admins[0] the primary, and gives
// every member the admin role that list implies and no other.
func setAdmins(r *roster.Roster, admins ...ids.MemberID) {
	r.Admins = slices.Clone(admins)
	for i := range r.Members {
		m := &r.Members[i]
		m.Roles = withoutRoles(m.Roles, roster.RolePrimary, roster.RoleBackup)
		switch j := slices.Index(admins, m.ID); {
		case j == 0:
			m.Roles = append(m.Roles, roster.RolePrimary)
		case j > 0:
			m.Roles = append(m.Roles, roster.RoleBackup)
		}
	}
}

// removeMember deletes the member name. It reports whether that member
// held the sender role, since its bot token must then be revoked.
func removeMember(r *roster.Roster, self ids.MemberID, name string, wasSender *bool) error {
	i := memberIndex(r, name)
	switch {
	case i < 0:
		return noMember(name)
	case r.Members[i].ID == self:
		return errors.New("a router does not remove itself; run rollcall remove on an admin router")
	case len(r.Admins) > 0 && r.Admins[0] == r.Members[i].ID:
		return fmt.Errorf("%s is the primary admin; make another router primary first", name)
	}
	id := r.Members[i].ID
	*wasSender = hasRole(r.Members[i], roster.RoleSender)
	r.Members = slices.Delete(r.Members, i, i+1)
	setAdmins(r, slices.DeleteFunc(slices.Clone(r.Admins), func(a ids.MemberID) bool { return a == id })...)
	return nil
}

// setRole gives the member name the role: sender, primary, backup, or none
// (no role at all).
func setRole(r *roster.Roster, role, name string) error {
	i := memberIndex(r, name)
	if i < 0 {
		return noMember(name)
	}
	m := &r.Members[i]
	primary := len(r.Admins) > 0 && r.Admins[0] == m.ID
	backup := slices.Index(r.Admins, m.ID) > 0
	switch role {
	case "sender":
		if hasRole(*m, roster.RoleSender) {
			return errUnchanged
		}
		m.Roles = withRole(m.Roles, roster.RoleSender)
	case "none":
		if primary {
			return fmt.Errorf("%s is the primary admin; make another router primary first", name)
		}
		if !backup && !hasRole(*m, roster.RoleSender) {
			return errUnchanged
		}
		m.Roles = withoutRoles(m.Roles, roster.RoleSender)
		setAdmins(r, slices.DeleteFunc(slices.Clone(r.Admins), func(a ids.MemberID) bool { return a == m.ID })...)
	case "backup":
		switch {
		case primary:
			return fmt.Errorf("%s is the primary admin; it cannot be the backup too", name)
		case backup:
			return errUnchanged
		}
		// Appointing a backup replaces the one before (security spec 6.1).
		setAdmins(r, r.Admins[0], m.ID)
	case "primary":
		switch {
		case primary:
			return errUnchanged
		case backup:
			setAdmins(r, m.ID, r.Admins[0])
		case len(r.Admins) > 1:
			return fmt.Errorf("the group has a backup admin already; make %s the backup first, or set the backup to none", name)
		default:
			// The primary before stays an admin, as the backup.
			setAdmins(r, m.ID, r.Admins[0])
		}
	default:
		return errors.New("the role must be sender, primary, backup or none")
	}
	return nil
}

// takeOver makes self, the backup, the primary, with the takeover marked
// provisional (security spec 6.1): the primary it replaces stays a backup,
// so that it can restore itself when it comes back.
func takeOver(r *roster.Roster, self ids.MemberID) error {
	switch {
	case len(r.Admins) > 0 && r.Admins[0] == self && r.Takeover:
		return errUnchanged
	case len(r.Admins) > 0 && r.Admins[0] == self:
		return errors.New("this router is the primary admin already")
	case len(r.Admins) < 2 || r.Admins[1] != self:
		return errors.New("this router is not the backup admin")
	}
	old := r.Admins[0]
	setAdmins(r, self, old)
	r.Takeover, r.Replaced, r.OwnerConfirmed = true, old, false
	return nil
}

// confirmTakeover is the owner's confirmation of a takeover by self.
func confirmTakeover(r *roster.Roster, self ids.MemberID) error {
	switch {
	case !r.Takeover:
		return errors.New("no takeover to confirm")
	case len(r.Admins) == 0 || r.Admins[0] != self:
		return errors.New("only the router that took over can confirm it")
	case r.OwnerConfirmed:
		return errUnchanged
	}
	r.OwnerConfirmed = true
	return nil
}

// recoverAdmin makes self the only admin, as the primary, and ends any
// takeover: the roster the recovery key signs overrides both admins.
func recoverAdmin(r *roster.Roster, self ids.MemberID) error {
	if slices.IndexFunc(r.Members, func(m roster.Member) bool { return m.ID == self }) < 0 {
		return errors.New("this router is not in the roster")
	}
	setAdmins(r, self)
	r.Takeover, r.Replaced, r.OwnerConfirmed = false, ids.MemberID{}, false
	return nil
}
