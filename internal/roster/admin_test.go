package roster

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"math/rand/v2"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/ids"
)

// setAdmins makes admins the admin list of r, admins[0] the primary, and
// gives every member the primary and backup roles that agree with it; the
// sender role stays as it was.
func setAdmins(r *Roster, admins ...ids.MemberID) {
	r.Admins = slices.Clone(admins)
	for i := range r.Members {
		m := &r.Members[i]
		var roles []Role
		if m.ID == admins[0] {
			roles = append(roles, RolePrimary)
		} else if slices.Contains(admins[1:], m.ID) {
			roles = append(roles, RoleBackup)
		}
		if slices.Contains(m.Roles, RoleSender) {
			roles = append(roles, RoleSender)
		}
		m.Roles = roles
	}
}

// after returns a copy of r as the version after prev, with edit applied.
func after(r Roster, prev Signed, edit func(r *Roster)) Roster {
	n := next(r, prev)
	edit(&n)
	return n
}

// takeoverOf returns the roster after r (carried by prev) in which the
// member by takes over: by becomes the primary and r's primary its backup,
// with Takeover set, OwnerConfirmed clear and Replaced r's primary.
func takeoverOf(r Roster, prev Signed, by ids.MemberID) Roster {
	return after(r, prev, func(n *Roster) {
		setAdmins(n, by, r.Admins[0])
		n.Takeover, n.OwnerConfirmed = true, false
		n.Replaced = r.Admins[0]
	})
}

// clearTakeover clears the takeover state of r.
func clearTakeover(r *Roster) {
	r.Takeover, r.OwnerConfirmed, r.Replaced = false, false, ids.MemberID{}
}

// signRaw signs r as p without SignRoster, so a roster that Check refuses
// can still reach Verify.
func signRaw(t testing.TB, r Roster, p party) Signed {
	t.Helper()
	body, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return handSign(p.Sign, p.ID, false, body)
}

// takeoverChain is a group of three with fixed keys: P (party 0) the primary,
// B (party 1) the backup, O (party 2) an ordinary sender. s1 is its genesis,
// signed by P; t2 is B's takeover of it (B primary, P backup, Takeover set,
// Replaced P), signed by B.
type takeoverChain struct {
	P, B, O  party
	stranger party // a party that is in no roster
	r1, t2   Roster
	s1, st2  Signed
}

func newTakeoverChain(t *testing.T) takeoverChain {
	t.Helper()
	ps := testParties()
	c := takeoverChain{P: ps[0], B: ps[1], O: ps[2], stranger: ps[39]}
	c.r1 = base(3)
	c.s1 = mustSign(t, c.r1, c.P)
	c.t2 = takeoverOf(c.r1, c.s1, c.B.ID)
	c.st2 = mustSign(t, c.t2, c.B)
	return c
}

// confirmed returns version 3 of the chain: B confirms its takeover.
func (c takeoverChain) confirmed(t *testing.T) (Roster, Signed) {
	t.Helper()
	r := after(c.t2, c.st2, func(r *Roster) { r.OwnerConfirmed = true })
	return r, mustSign(t, r, c.B)
}

// addMember appends a fourth member with no roles.
func addMember(r *Roster) { r.Members = append(r.Members, base(4).Members[3]) }

// TestVerifyTakeoverFlag is the ruling: a roster signed by the backup that
// names a new primary must say it is a takeover, and Replaced names the
// primary it replaced. The flag is raised by nothing else but the recovery
// key, so the backup cannot reach the restore path of the replaced primary
// through a flag it set itself.
func TestVerifyTakeoverFlag(t *testing.T) {
	c := newTakeoverChain(t)
	P, B, O := c.P, c.B, c.O

	verifyOK(t, "takeover by the backup", c.st2, &c.s1, c.t2)

	silent := after(c.r1, c.s1, func(r *Roster) { setAdmins(r, B.ID, P.ID) })
	verifyErr(t, "backup makes itself primary without the takeover flag", mustSign(t, silent, B), &c.s1, ErrTakeoverFlag)
	alone := after(c.r1, c.s1, func(r *Roster) { setAdmins(r, B.ID) })
	verifyErr(t, "backup makes itself the only admin without the takeover flag", mustSign(t, alone, B), &c.s1, ErrTakeoverFlag)
	third := after(c.r1, c.s1, func(r *Roster) { setAdmins(r, O.ID, B.ID) })
	verifyErr(t, "backup makes an ordinary member primary without the takeover flag", mustSign(t, third, B), &c.s1, ErrTakeoverFlag)

	// The same change by the primary or by the recovery key is no takeover.
	verifyOK(t, "primary hands its role to the backup", mustSign(t, silent, P), &c.s1, silent)
	verifyOK(t, "primary makes an ordinary member primary", mustSign(t, third, P), &c.s1, third)
	verifyOK(t, "recovery key appoints the backup", mustSignRecovery(t, silent, recoveryKey), &c.s1, silent)

	// A takeover names the primary it replaced, nobody else.
	wrong := after(c.r1, c.s1, func(r *Roster) {
		setAdmins(r, B.ID, O.ID)
		r.Takeover, r.Replaced = true, O.ID
	})
	verifyErr(t, "takeover naming an ordinary member as replaced", mustSign(t, wrong, B), &c.s1, ErrTakeoverReplaced)
	stranger := after(c.r1, c.s1, func(r *Roster) {
		setAdmins(r, B.ID, P.ID)
		r.Takeover, r.OwnerConfirmed, r.Replaced = true, true, c.stranger.ID
	})
	verifyErr(t, "confirmed takeover naming a stranger as replaced", mustSign(t, stranger, B), &c.s1, ErrTakeoverReplaced)
	selfConfirmed := takeoverOf(c.r1, c.s1, B.ID)
	selfConfirmed.OwnerConfirmed = true
	verifyOK(t, "takeover confirmed in the same roster", mustSign(t, selfConfirmed, B), &c.s1, selfConfirmed)
	forOther := after(c.r1, c.s1, func(r *Roster) {
		setAdmins(r, O.ID, P.ID)
		r.Takeover, r.Replaced = true, P.ID
	})
	verifyOK(t, "takeover by the backup naming an ordinary member primary", mustSign(t, forOther, B), &c.s1, forOther)

	// The flag is raised only by a takeover.
	raised := after(c.r1, c.s1, func(r *Roster) { r.Takeover, r.Replaced = true, B.ID })
	verifyErr(t, "primary raises the flag naming the backup replaced", mustSign(t, raised, P), &c.s1, ErrTakeoverFlag)
	verifyErr(t, "backup raises the flag naming itself replaced", mustSign(t, raised, B), &c.s1, ErrTakeoverFlag)
	verifyErr(t, "primary signs the backup's takeover roster", mustSign(t, c.t2, P), &c.s1, ErrTakeoverFlag)
	verifyOK(t, "recovery key raises the flag", mustSignRecovery(t, raised, recoveryKey), &c.s1, raised)

	// At version 1 there is nothing to take over.
	g := base(3)
	g.Takeover, g.Replaced = true, B.ID
	verifyErr(t, "genesis by the primary marked as a takeover", mustSign(t, g, P), nil, ErrTakeoverFlag)
	verifyOK(t, "genesis by the recovery key marked as a takeover", mustSignRecovery(t, g, recoveryKey), nil, g)
}

// TestBackupCannotRestoreItself closes the two-step path around the
// ten-minute rule: the backup raises the flag naming itself the replaced
// primary, then "restores" itself, which members accept without the
// ten-minute check. Step 1 must be refused in every form.
func TestBackupCannotRestoreItself(t *testing.T) {
	c := newTakeoverChain(t)
	P, B := c.P, c.B
	step1 := after(c.r1, c.s1, func(r *Roster) { r.Takeover, r.Replaced = true, B.ID })
	verifyErr(t, "backup names itself the replaced primary", mustSign(t, step1, B), &c.s1, ErrTakeoverFlag)
	confirmed := step1
	confirmed.OwnerConfirmed = true
	verifyErr(t, "backup names itself the replaced primary, confirmed", mustSign(t, confirmed, B), &c.s1, ErrTakeoverFlag)
	primary := after(c.r1, c.s1, func(r *Roster) { r.Takeover, r.Replaced = true, P.ID })
	verifyErr(t, "backup names the primary replaced while it stays primary", signRaw(t, primary, B), &c.s1, ErrReplaced)
}

// TestVerifyTakeoverCarriesForward checks that a takeover stays provisional
// until the replaced primary is primary again, the owner confirms it, or the
// recovery key signs: the new primary cannot drop the flag, change Replaced,
// or take the replaced primary off the admins on its own.
func TestVerifyTakeoverCarriesForward(t *testing.T) {
	c := newTakeoverChain(t)
	P, B, O := c.P, c.B, c.O

	ok := func(name string, prev Roster, prevS Signed, signer party, edit func(r *Roster)) {
		t.Helper()
		r := after(prev, prevS, edit)
		verifyOK(t, name, mustSign(t, r, signer), &prevS, r)
	}
	bad := func(name string, prev Roster, prevS Signed, signer party, edit func(r *Roster), want error) {
		t.Helper()
		verifyErr(t, name, signRaw(t, after(prev, prevS, edit), signer), &prevS, want)
	}
	removeP := func(r *Roster) {
		r.Members = slices.Delete(r.Members, memberIndex(*r, P.ID), memberIndex(*r, P.ID)+1)
	}

	t2, st2 := c.t2, c.st2
	ok("new primary adds a member, the takeover stays", t2, st2, B, addMember)
	ok("replaced primary, now backup, adds a member", t2, st2, P, addMember)
	ok("new primary confirms", t2, st2, B, func(r *Roster) { r.OwnerConfirmed = true })
	ok("replaced primary confirms", t2, st2, P, func(r *Roster) { r.OwnerConfirmed = true })
	ok("new primary confirms and drops the replaced primary from the admins", t2, st2, B, func(r *Roster) {
		r.OwnerConfirmed = true
		setAdmins(r, B.ID)
	})
	ok("new primary confirms and removes the replaced primary", t2, st2, B, func(r *Roster) {
		r.OwnerConfirmed = true
		removeP(r)
		setAdmins(r, B.ID)
	})
	ok("new primary hands the role back", t2, st2, B, func(r *Roster) {
		setAdmins(r, P.ID, B.ID)
		clearTakeover(r)
	})
	ok("new primary hands the role on, the takeover stays", t2, st2, B, func(r *Roster) { setAdmins(r, O.ID, P.ID) })

	bad("new primary clears the flag", t2, st2, B, clearTakeover, ErrTakeoverFlag)
	bad("replaced primary clears the flag without taking the role back", t2, st2, P, clearTakeover, ErrTakeoverFlag)
	bad("new primary names another member replaced", t2, st2, B, func(r *Roster) {
		setAdmins(r, B.ID, O.ID)
		r.Replaced = O.ID
	}, ErrTakeoverReplaced)
	bad("new primary confirms naming a stranger replaced", t2, st2, B, func(r *Roster) {
		r.OwnerConfirmed, r.Replaced = true, c.stranger.ID
	}, ErrTakeoverReplaced)
	bad("new primary drops the replaced primary from the admins", t2, st2, B, func(r *Roster) { setAdmins(r, B.ID) }, ErrReplaced)
	bad("new primary swaps the replaced primary for another backup", t2, st2, B, func(r *Roster) { setAdmins(r, B.ID, O.ID) }, ErrReplaced)
	bad("new primary removes the replaced primary", t2, st2, B, func(r *Roster) {
		removeP(r)
		setAdmins(r, B.ID)
	}, ErrReplaced)

	c3, sc3 := c.confirmed(t)
	verifyOK(t, "confirmation", sc3, &st2, c3)
	ok("after confirmation the new primary ends the takeover", c3, sc3, B, clearTakeover)
	ok("after confirmation the backup ends the takeover", c3, sc3, P, clearTakeover)
	ok("after confirmation the new primary adds a member", c3, sc3, B, addMember)
	bad("new primary withdraws the confirmation", c3, sc3, B, func(r *Roster) { r.OwnerConfirmed = false }, ErrTakeoverFlag)
	bad("replaced primary withdraws the confirmation", c3, sc3, P, func(r *Roster) { r.OwnerConfirmed = false }, ErrTakeoverFlag)
	bad("after confirmation the new primary names a stranger replaced", c3, sc3, B, func(r *Roster) {
		r.Replaced = c.stranger.ID
	}, ErrTakeoverReplaced)
}

// TestVerifyTakeoverKeepsReplacedKeys follows the replaced primary's keys
// through a takeover: while it is an admin of the previous roster nobody but
// itself or the recovery key changes them, confirmed or not, so it can
// always sign its restore; once a confirmed takeover has dropped it from the
// admins it is an ordinary member.
func TestVerifyTakeoverKeepsReplacedKeys(t *testing.T) {
	c := newTakeoverChain(t)
	P, B, O := c.P, c.B, c.O
	newSign := func(id ids.MemberID) func(r *Roster) {
		return func(r *Roster) { r.Members[memberIndex(*r, id)].SignPub = pub(otherKey) }
	}
	newRecv := func(id ids.MemberID) func(r *Roster) {
		return func(r *Roster) { r.Members[memberIndex(*r, id)].RecvPub = bytes.Clone(c.stranger.Recv) }
	}

	for _, k := range []struct {
		name string
		edit func(r *Roster)
	}{{"signing key", newSign(P.ID)}, {"receive key", newRecv(P.ID)}} {
		tk := takeoverOf(c.r1, c.s1, B.ID)
		k.edit(&tk)
		verifyErr(t, "takeover that changes the replaced primary's "+k.name, mustSign(t, tk, B), &c.s1, ErrAdminKeys)
		tk.OwnerConfirmed = true
		verifyErr(t, "takeover confirmed at once that changes the replaced primary's "+k.name, mustSign(t, tk, B), &c.s1, ErrAdminKeys)

		r3 := after(c.t2, c.st2, k.edit)
		verifyErr(t, "new primary changes the replaced primary's "+k.name, mustSign(t, r3, B), &c.st2, ErrAdminKeys)
		verifyOK(t, "replaced primary changes its own "+k.name, mustSign(t, r3, P), &c.st2, r3)
		verifyOK(t, "recovery key changes the replaced primary's "+k.name, mustSignRecovery(t, r3, recoveryKey), &c.st2, r3)
		r3.OwnerConfirmed = true
		verifyErr(t, "new primary confirms and changes the replaced primary's "+k.name, mustSign(t, r3, B), &c.st2, ErrAdminKeys)
		setAdmins(&r3, B.ID)
		verifyErr(t, "new primary confirms, drops the replaced primary from the admins and changes its "+k.name,
			mustSign(t, r3, B), &c.st2, ErrAdminKeys)
	}

	// Confirmed and dropped from the admins, the replaced primary is an
	// ordinary member, whose keys an admin may change.
	c3, sc3 := c.confirmed(t)
	d4 := after(c3, sc3, func(r *Roster) { setAdmins(r, B.ID) })
	sd4 := mustSign(t, d4, B)
	verifyOK(t, "confirmed takeover drops the replaced primary from the admins", sd4, &sc3, d4)
	k5 := after(d4, sd4, newSign(P.ID))
	verifyOK(t, "then the new primary changes the former primary's signing key", mustSign(t, k5, B), &sd4, k5)
	other := after(c.t2, c.st2, newSign(O.ID))
	verifyOK(t, "new primary changes an ordinary member's signing key", mustSign(t, other, B), &c.st2, other)

	// The replaced primary listed second among the members: P takes the
	// role back from B, whose keys must stay.
	back := takeoverOf(c3, sc3, P.ID)
	newSign(B.ID)(&back)
	if memberIndex(back, B.ID) == 0 {
		t.Fatal("fixture: B must not be the first member")
	}
	verifyErr(t, "takeover back that changes the second member's signing key", mustSign(t, back, P), &sc3, ErrAdminKeys)
}

// TestVerifyAdminKeys checks that an admin's keys change only in a roster
// that admin signs, or that the recovery key signs. Otherwise the backup
// could give the primary's entry a key of its own in a roster that changes
// nothing else, then sign as the primary: a takeover past every rule above.
func TestVerifyAdminKeys(t *testing.T) {
	c := newTakeoverChain(t)
	P, B, O := c.P, c.B, c.O
	sign := func(id ids.MemberID) func(r *Roster) {
		return func(r *Roster) { r.Members[memberIndex(*r, id)].SignPub = pub(otherKey) }
	}
	recv := func(id ids.MemberID) func(r *Roster) {
		return func(r *Roster) { r.Members[memberIndex(*r, id)].RecvPub = bytes.Clone(c.stranger.Recv) }
	}

	hijack := after(c.r1, c.s1, sign(P.ID))
	verifyErr(t, "backup gives the primary's entry a signing key of its own", mustSign(t, hijack, B), &c.s1, ErrAdminKeys)
	verifyOK(t, "primary changes its own signing key", mustSign(t, hijack, P), &c.s1, hijack)
	verifyOK(t, "recovery key changes the primary's signing key", mustSignRecovery(t, hijack, recoveryKey), &c.s1, hijack)
	pRecv := after(c.r1, c.s1, recv(P.ID))
	verifyErr(t, "backup changes the primary's receive key", mustSign(t, pRecv, B), &c.s1, ErrAdminKeys)
	verifyOK(t, "primary changes its own receive key", mustSign(t, pRecv, P), &c.s1, pRecv)

	bSign := after(c.r1, c.s1, sign(B.ID))
	verifyErr(t, "primary changes the backup's signing key", mustSign(t, bSign, P), &c.s1, ErrAdminKeys)
	verifyOK(t, "backup changes its own signing key", mustSign(t, bSign, B), &c.s1, bSign)
	bRecv := after(c.r1, c.s1, recv(B.ID))
	verifyErr(t, "primary changes the backup's receive key", mustSign(t, bRecv, P), &c.s1, ErrAdminKeys)

	readd := after(c.r1, c.s1, func(r *Roster) {
		i := memberIndex(*r, P.ID)
		m := r.Members[i]
		m.SignPub = pub(otherKey)
		r.Members = append(slices.Delete(r.Members, i, i+1), m)
	})
	verifyErr(t, "backup removes the primary and adds it back with another key", mustSign(t, readd, B), &c.s1, ErrAdminKeys)

	oSign := after(c.r1, c.s1, sign(O.ID))
	verifyOK(t, "backup changes an ordinary member's signing key", mustSign(t, oSign, B), &c.s1, oSign)
	drop := after(c.r1, c.s1, func(r *Roster) {
		r.Members = slices.Delete(r.Members, memberIndex(*r, B.ID), memberIndex(*r, B.ID)+1)
		setAdmins(r, P.ID)
	})
	verifyOK(t, "primary removes the backup", mustSign(t, drop, P), &c.s1, drop)
}

// TestVerifyRecoveryOverridesTakeover checks that the recovery key is bound
// by Check alone: it may end, rewrite or raise a takeover.
func TestVerifyRecoveryOverridesTakeover(t *testing.T) {
	c := newTakeoverChain(t)
	B, O := c.B, c.O
	for _, e := range []struct {
		name string
		edit func(r *Roster)
	}{
		{"ends the takeover, the new primary stays", clearTakeover},
		{"appoints a new primary and backup", func(r *Roster) { setAdmins(r, O.ID, B.ID); clearTakeover(r) }},
		{"names another member replaced", func(r *Roster) { setAdmins(r, B.ID, O.ID); r.Replaced = O.ID }},
		{"withdraws nothing and adds a member", addMember},
	} {
		r := after(c.t2, c.st2, e.edit)
		verifyOK(t, "recovery key "+e.name, mustSignRecovery(t, r, recoveryKey), &c.st2, r)
	}
}

// TestReturningPrimaryRestores is the brief's restore test: after a
// provisional takeover the replaced primary, and only it, should restore
// itself, and its restore verifies even after the new primary has made
// changes of its own.
func TestReturningPrimaryRestores(t *testing.T) {
	c := newTakeoverChain(t)
	P, B, O := c.P, c.B, c.O
	verifyOK(t, "takeover", c.st2, &c.s1, c.t2)

	if !ShouldRestore(c.t2, P.ID) {
		t.Error("ShouldRestore(takeover, replaced primary) = false, want true")
	}
	for name, id := range map[string]ids.MemberID{"the new primary": B.ID, "an ordinary member": O.ID, "a stranger": c.stranger.ID, "the zero ID": {}} {
		if ShouldRestore(c.t2, id) {
			t.Errorf("ShouldRestore(takeover, %s) = true, want false", name)
		}
	}
	for _, id := range []ids.MemberID{P.ID, B.ID, O.ID} {
		if ShouldRestore(c.r1, id) {
			t.Errorf("ShouldRestore of a roster without a takeover = true for %v", id)
		}
	}
	if ShouldRestore(Roster{Takeover: true}, ids.MemberID{}) {
		t.Error("ShouldRestore(takeover with zero Replaced, zero ID) = true, want false")
	}
	if ShouldRestore(Roster{Replaced: P.ID}, P.ID) {
		t.Error("ShouldRestore(Replaced without the takeover flag) = true, want false")
	}

	restore := func(r *Roster) {
		setAdmins(r, P.ID, B.ID)
		clearTakeover(r)
	}
	r3 := after(c.t2, c.st2, restore)
	verifyOK(t, "replaced primary restores itself", mustSign(t, r3, P), &c.st2, r3)
	if ShouldRestore(r3, P.ID) {
		t.Error("ShouldRestore after the restore = true, want false")
	}

	// The new primary's own changes do not end the claim.
	t3 := after(c.t2, c.st2, addMember)
	st3 := mustSign(t, t3, B)
	verifyOK(t, "new primary adds a member", st3, &c.st2, t3)
	if !ShouldRestore(t3, P.ID) {
		t.Error("ShouldRestore after the new primary's change = false, want true")
	}
	r4 := after(t3, st3, restore)
	verifyOK(t, "replaced primary restores itself after the new primary's change", mustSign(t, r4, P), &st3, r4)

	// Handed on to a third member, the claim still stands.
	h3 := after(c.t2, c.st2, func(r *Roster) { setAdmins(r, O.ID, P.ID) })
	sh3 := mustSign(t, h3, B)
	verifyOK(t, "new primary hands the role on", sh3, &c.st2, h3)
	if !ShouldRestore(h3, P.ID) {
		t.Error("ShouldRestore after a hand-on = false, want true")
	}
	r4h := after(h3, sh3, func(r *Roster) { setAdmins(r, P.ID, O.ID); clearTakeover(r) })
	verifyOK(t, "replaced primary restores itself after a hand-on", mustSign(t, r4h, P), &sh3, r4h)

	alone := after(c.t2, c.st2, func(r *Roster) { setAdmins(r, P.ID); clearTakeover(r) })
	verifyOK(t, "replaced primary restores itself as the only admin", mustSign(t, alone, P), &c.st2, alone)

	// A restore makes the replaced primary primary, nobody else.
	other := after(c.t2, c.st2, func(r *Roster) { setAdmins(r, O.ID, P.ID); clearTakeover(r) })
	verifyErr(t, "replaced primary makes an ordinary member primary without the flag", mustSign(t, other, P), &c.st2, ErrTakeoverFlag)
}

// TestConfirmedTakeoverStays is the brief's confirmation test: once the
// owner confirms the takeover, or uses the recovery key, the replaced
// primary does not restore itself, and a restore it signs anyway is refused.
func TestConfirmedTakeoverStays(t *testing.T) {
	c := newTakeoverChain(t)
	P, B := c.P, c.B
	restore := func(r *Roster) {
		setAdmins(r, P.ID, B.ID)
		clearTakeover(r)
	}

	c3, sc3 := c.confirmed(t)
	verifyOK(t, "confirmation", sc3, &c.st2, c3)
	if ShouldRestore(c3, P.ID) {
		t.Error("ShouldRestore(confirmed takeover, replaced primary) = true, want false")
	}
	verifyErr(t, "replaced primary restores itself after the confirmation", mustSign(t, after(c3, sc3, restore), P), &sc3, ErrTakeoverFlag)

	once := takeoverOf(c.r1, c.s1, B.ID)
	once.OwnerConfirmed = true
	sOnce := mustSign(t, once, B)
	verifyOK(t, "takeover confirmed in the same roster", sOnce, &c.s1, once)
	if ShouldRestore(once, P.ID) {
		t.Error("ShouldRestore(takeover confirmed at once, replaced primary) = true, want false")
	}
	verifyErr(t, "replaced primary restores itself after a takeover confirmed at once", mustSign(t, after(once, sOnce, restore), P), &sOnce, ErrTakeoverFlag)

	rec := after(c.t2, c.st2, clearTakeover)
	sRec := mustSignRecovery(t, rec, recoveryKey)
	verifyOK(t, "recovery key ends the takeover", sRec, &c.st2, rec)
	if ShouldRestore(rec, P.ID) {
		t.Error("ShouldRestore after the recovery key ended the takeover = true, want false")
	}
	verifyErr(t, "replaced primary restores itself after the recovery key", mustSign(t, after(rec, sRec, restore), P), &sRec, ErrTakeoverFlag)

	// The replaced primary can still take the role back by a takeover of its
	// own, which members accept only after ten minutes of silence from B.
	back := takeoverOf(c3, sc3, P.ID)
	verifyOK(t, "replaced primary takes over from the confirmed new primary", mustSign(t, back, P), &sc3, back)
	if back.Replaced != B.ID {
		t.Errorf("takeover back replaces %v, want B", back.Replaced)
	}
}

// TestTakeoverRulesBeyondTwoAdmins drives checkTakeover with rosters that
// Check would refuse today, so that the rules that only matter when
// MaxAdmins grows, and the fail-closed lookup, are pinned.
func TestTakeoverRulesBeyondTwoAdmins(t *testing.T) {
	ps := testParties()
	P, B, Q := ps[0], ps[1], ps[2]
	mem := func(p party) Member {
		return Member{ID: p.ID, Name: p.Name, SignPub: pub(p.Sign), RecvPub: bytes.Clone(p.Recv)}
	}
	prev := Roster{
		Members:  []Member{mem(P), mem(B), mem(Q)},
		Admins:   []ids.MemberID{B.ID, P.ID, Q.ID},
		Takeover: true, Replaced: P.ID,
	}
	cur := Roster{Members: prev.Members, Admins: []ids.MemberID{P.ID, B.ID, Q.ID}}
	if err := checkTakeover(&prev, &cur, Signed{SignerID: P.ID}); err != nil {
		t.Errorf("replaced primary restores itself among three admins: %v", err)
	}
	checkErr(t, "another backup restores the replaced primary without the flag",
		checkTakeover(&prev, &cur, Signed{SignerID: Q.ID}), ErrTakeoverFlag)
	self := Roster{Members: prev.Members, Admins: []ids.MemberID{Q.ID, B.ID, P.ID}}
	checkErr(t, "another backup names itself primary without the flag during a takeover",
		checkTakeover(&prev, &self, Signed{SignerID: Q.ID}), ErrTakeoverFlag)

	// An admin of the previous roster that it does not list as a member
	// fails closed.
	from := Roster{Members: []Member{mem(B), mem(Q)}, Admins: []ids.MemberID{P.ID, B.ID}}
	to := Roster{Members: []Member{mem(P), mem(B), mem(Q)}, Admins: []ids.MemberID{P.ID, B.ID}}
	checkErr(t, "admin of the previous roster missing from its members", checkTakeover(&from, &to, Signed{SignerID: B.ID}), ErrAdminKeys)
}

// TestTakeoverNeedsTenMinutes is the brief's timing test.
func TestTakeoverNeedsTenMinutes(t *testing.T) {
	if TakeoverAfter != 10*time.Minute {
		t.Fatalf("TakeoverAfter = %v, want 10m", TakeoverAfter)
	}
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		last time.Time
		want bool
	}{
		{"heard 9m59s ago", now.Add(-(9*time.Minute + 59*time.Second)), false},
		{"heard 10m ago", now.Add(-10 * time.Minute), true},
		{"heard 10m less 1ns ago", now.Add(-10*time.Minute + 1), false},
		{"heard 10m and 1ns ago", now.Add(-10*time.Minute - 1), true},
		{"heard an hour ago", now.Add(-time.Hour), true},
		{"heard just now", now, false},
		{"heard 1s ago", now.Add(-time.Second), false},
		{"never heard", time.Time{}, true},
		{"heard in the year 1", time.Date(1, 1, 1, 0, 0, 1, 0, time.UTC), true},
		{"clock skew: heard 1s in the future", now.Add(time.Second), false},
		{"clock skew: heard 11m in the future", now.Add(11 * time.Minute), false},
		{"clock skew: heard a day in the future", now.Add(24 * time.Hour), false},
		{"clock skew: heard in the year 9999", time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC), false},
	}
	for _, c := range cases {
		if got := AcceptTakeover(c.last, now); got != c.want {
			t.Errorf("%s: AcceptTakeover = %v, want %v", c.name, got, c.want)
		}
	}
	if AcceptTakeover(now, time.Time{}) {
		t.Error("heard at a real time, now zero: AcceptTakeover = true, want false")
	}
	// Never heard is silent by rule, not because the zero time is long ago.
	if !AcceptTakeover(time.Time{}, time.Time{}.Add(time.Minute)) {
		t.Error("never heard, now a minute after the zero time: AcceptTakeover = false, want true")
	}

	// Times from time.Now carry the monotonic clock, as the daemon's will.
	start := time.Now()
	if AcceptTakeover(start, start.Add(10*time.Minute-time.Nanosecond)) {
		t.Error("monotonic: 10m less 1ns accepted")
	}
	if !AcceptTakeover(start, start.Add(10*time.Minute)) {
		t.Error("monotonic: 10m refused")
	}
}

// TestActingAdminOrder is the brief's test: the first live admin in the
// admin list acts, ordinary members never do.
func TestActingAdminOrder(t *testing.T) {
	ps := testParties()
	P, B, O := ps[0].ID, ps[1].ID, ps[2].ID
	var asked []ids.MemberID
	alive := func(set ...ids.MemberID) func(ids.MemberID) bool {
		asked = nil
		return func(id ids.MemberID) bool {
			asked = append(asked, id)
			return slices.Contains(set, id)
		}
	}
	check := func(name string, r Roster, live func(ids.MemberID) bool, want ids.MemberID, wantOK bool, wantAsked ...ids.MemberID) {
		t.Helper()
		got, ok := ActingAdmin(r, live)
		if got != want || ok != wantOK {
			t.Errorf("%s: ActingAdmin = %v, %v; want %v, %v", name, got, ok, want, wantOK)
		}
		if !slices.Equal(asked, wantAsked) {
			t.Errorf("%s: asked about %v, want %v", name, asked, wantAsked)
		}
	}
	r := base(3)
	check("both admins live", r, alive(P, B, O), P, true, P)
	check("primary silent", r, alive(B, O), B, true, P, B)
	check("only an ordinary member live", r, alive(O), ids.MemberID{}, false, P, B)
	check("nobody live", r, alive(), ids.MemberID{}, false, P, B)

	swapped := base(3)
	swapped.Members[0], swapped.Members[1] = swapped.Members[1], swapped.Members[0]
	check("backup listed first among the members", swapped, alive(P, B), P, true, P)

	c := newTakeoverChain(t)
	check("after a takeover", c.t2, alive(P, B), B, true, B)
	check("after a takeover, new primary silent", c.t2, alive(P), P, true, B, P)

	check("one admin, live", base(1), alive(P), P, true, P)
	check("one admin, silent", base(1), alive(), ids.MemberID{}, false, P)
}

// higherHash reports whether a's hash is above b's, bytewise.
func higherHash(a, b Signed) bool {
	ha, hb := a.Hash(), b.Hash()
	return bytes.Compare(ha[:], hb[:]) > 0
}

// candidate is one signed roster of a split group with its roster.
type candidate struct {
	name string
	s    Signed
	r    Roster
}

// preferBoth runs Prefer in both orders and requires want each time.
func preferBoth(t *testing.T, what string, x, y candidate, common Roster, want candidate) {
	t.Helper()
	if got := Prefer(x.s, y.s, x.r, y.r, common); !reflect.DeepEqual(got, want.s) {
		t.Errorf("%s: Prefer(%s, %s) did not pick %s", what, x.name, y.name, want.name)
	}
	if got := Prefer(y.s, x.s, y.r, x.r, common); !reflect.DeepEqual(got, want.s) {
		t.Errorf("%s: Prefer(%s, %s) did not pick %s", what, y.name, x.name, want.name)
	}
}

// forkOf signs the version after prev, renamed to site fork-k so that k
// varies the hash, as who (the recovery key when who is nil).
func forkOf(t *testing.T, name string, prev Roster, prevS Signed, who *party, k int, edit func(r *Roster)) candidate {
	t.Helper()
	r := after(prev, prevS, func(r *Roster) {
		r.Site = fmt.Sprintf("fork-%d", k)
		if edit != nil {
			edit(r)
		}
	})
	var s Signed
	if who == nil {
		s = mustSignRecovery(t, r, recoveryKey)
	} else {
		s = mustSign(t, r, *who)
	}
	if _, err := s.Verify(&prevS); err != nil {
		t.Fatalf("%s: fixture does not verify: %v", name, err)
	}
	return candidate{name, s, r}
}

// outranks requires that winner beats loser at equal version although
// winner's hash is the higher one: it varies winner (through variant) until
// the hashes disagree with the authority, so that a Prefer that ignored
// authority would pick loser.
func outranks(t *testing.T, what string, variant func(k int) candidate, loser candidate, common Roster) {
	t.Helper()
	for k := 0; k < 64; k++ {
		w := variant(k)
		if higherHash(w.s, loser.s) {
			preferBoth(t, what, w, loser, common, w)
			return
		}
	}
	t.Fatalf("%s: no variant with the higher hash in 64 tries", what)
}

// TestPreferVersion is the brief's test: the higher version wins whatever
// the authority of the signers.
func TestPreferVersion(t *testing.T) {
	c := newTakeoverChain(t)
	P, B := c.P, c.B
	a2 := forkOf(t, "primary v2", c.r1, c.s1, &P, 0, nil)
	a3 := forkOf(t, "primary v3", a2.r, a2.s, &P, 0, nil)
	b2 := forkOf(t, "backup v2", c.r1, c.s1, &B, 0, nil)
	b3 := forkOf(t, "backup v3", b2.r, b2.s, &B, 0, nil)
	rec2 := forkOf(t, "recovery v2", c.r1, c.s1, nil, 0, nil)
	t3 := forkOf(t, "backup v3 after its takeover", c.t2, c.st2, &B, 0, nil)

	preferBoth(t, "primary's v3 over backup's v2", a3, b2, c.r1, a3)
	preferBoth(t, "backup's v3 over primary's v2", b3, a2, c.r1, b3)
	preferBoth(t, "backup's v3 over recovery v2", b3, rec2, c.r1, b3)
	preferBoth(t, "backup's v3 after a takeover over primary's v2", t3, a2, c.r1, t3)

	// Versions far apart compare as numbers, not through a difference.
	lo, hi := a2, b2
	lo.r.Version, hi.r.Version = 1, math.MaxUint64
	lo.name, hi.name = "version 1", "version MaxUint64"
	preferBoth(t, "MaxUint64 over 1", lo, hi, c.r1, hi)
	lo.r.Version, hi.r.Version = math.MaxUint64-1, math.MaxUint64
	preferBoth(t, "MaxUint64 over MaxUint64-1", lo, hi, c.r1, hi)
}

// TestPreferAuthorityAtEqualVersion is the brief's test: at equal version
// the recovery key beats the primary, which beats a backup, which beats a
// signer that was no admin before the split; the rank comes from the last
// roster both sides share, not from each side's own roster.
func TestPreferAuthorityAtEqualVersion(t *testing.T) {
	c := newTakeoverChain(t)
	P, B, O := c.P, c.B, c.O
	common := c.r1
	byP := func(k int) candidate { return forkOf(t, "primary v2", c.r1, c.s1, &P, k, nil) }
	byB := func(k int) candidate { return forkOf(t, "backup v2", c.r1, c.s1, &B, k, nil) }
	byRec := func(k int) candidate { return forkOf(t, "recovery v2", c.r1, c.s1, nil, k, nil) }

	outranks(t, "recovery over primary", byRec, byP(100), common)
	outranks(t, "recovery over backup", byRec, byB(100), common)
	outranks(t, "primary over backup", byP, byB(100), common)
	outranks(t, "primary over the backup's takeover", byP, candidate{"backup's takeover", c.st2, c.t2}, common)

	// After its takeover the backup is Admins[0] of its own roster; it still
	// ranks as the backup it was before the split.
	t3 := forkOf(t, "backup v3 after its takeover", c.t2, c.st2, &B, 100, nil)
	a2 := byP(200)
	outranks(t, "primary's v3 over the backup's v3 after its takeover", func(k int) candidate {
		return forkOf(t, "primary v3", a2.r, a2.s, &P, k, nil)
	}, t3, common)

	// A member made backup after the split ranks below the backup.
	q2 := forkOf(t, "primary makes O backup", c.r1, c.s1, &P, 300, func(r *Roster) { setAdmins(r, P.ID, O.ID) })
	q3 := forkOf(t, "O v3", q2.r, q2.s, &O, 0, nil)
	b2 := byB(400)
	outranks(t, "backup over a member made backup after the split", func(k int) candidate {
		return forkOf(t, "backup v3", b2.r, b2.s, &B, k, nil)
	}, q3, common)
}

// TestPreferHashAtEqualAuthority checks the last tie-break: the lower hash.
func TestPreferHashAtEqualAuthority(t *testing.T) {
	c := newTakeoverChain(t)
	P, B := c.P, c.B
	for _, who := range []*party{&P, &B, nil} {
		x := forkOf(t, "x", c.r1, c.s1, who, 0, nil)
		y := forkOf(t, "y", c.r1, c.s1, who, 1, nil)
		want := x
		if higherHash(x.s, y.s) {
			want = y
		}
		name := "recovery"
		if who != nil {
			name = who.Name
		}
		preferBoth(t, "two forks by "+name, x, y, c.r1, want)
	}
	same := forkOf(t, "same", c.r1, c.s1, &P, 0, nil)
	if got := Prefer(same.s, same.s, same.r, same.r, c.r1); !reflect.DeepEqual(got, same.s) {
		t.Error("Prefer of a roster with itself did not return it")
	}
}

// TestPreferIsAnOrder folds Prefer over the candidates of a split in many
// orders: every member must reach the same winner whatever order its copies
// arrived in, and that winner is the first by (version down, authority down,
// hash up), computed here without the package. The top version has two
// forks by the primary, so the hash decides the winner.
func TestPreferIsAnOrder(t *testing.T) {
	c := newTakeoverChain(t)
	P, B, O := c.P, c.B, c.O
	a2 := forkOf(t, "a2", c.r1, c.s1, &P, 0, nil)
	x2 := forkOf(t, "x2", c.r1, c.s1, &P, 1, nil)
	b2 := forkOf(t, "b2", c.r1, c.s1, &B, 0, nil)
	rec2 := forkOf(t, "rec2", c.r1, c.s1, nil, 0, nil)
	q2 := forkOf(t, "q2", c.r1, c.s1, &P, 2, func(r *Roster) { setAdmins(r, P.ID, O.ID) })
	cands := []candidate{
		a2, x2, b2, rec2, q2, {"t2", c.st2, c.t2},
		forkOf(t, "a3", a2.r, a2.s, &P, 0, nil),
		forkOf(t, "t3", c.t2, c.st2, &B, 0, nil),
		forkOf(t, "q3", q2.r, q2.s, &O, 0, nil),
		forkOf(t, "x3", x2.r, x2.s, &P, 0, nil),
		forkOf(t, "b3", b2.r, b2.s, &B, 0, nil),
	}
	rank := func(s Signed) int {
		switch {
		case s.Recovery:
			return 3
		case s.SignerID == P.ID:
			return 2
		case s.SignerID == B.ID:
			return 1
		}
		return 0
	}
	before := func(x, y candidate) bool {
		if x.r.Version != y.r.Version {
			return x.r.Version > y.r.Version
		}
		if rank(x.s) != rank(y.s) {
			return rank(x.s) > rank(y.s)
		}
		return !higherHash(x.s, y.s)
	}
	want := cands[0]
	for _, x := range cands[1:] {
		if before(x, want) {
			want = x
		}
	}
	for i, x := range cands {
		for _, y := range cands[i:] {
			p, q := Prefer(x.s, y.s, x.r, y.r, c.r1), Prefer(y.s, x.s, y.r, x.r, c.r1)
			if !reflect.DeepEqual(p, q) {
				t.Errorf("Prefer(%s, %s) differs from Prefer(%s, %s)", x.name, y.name, y.name, x.name)
			}
			if !reflect.DeepEqual(p, x.s) && !reflect.DeepEqual(p, y.s) {
				t.Errorf("Prefer(%s, %s) returned neither", x.name, y.name)
			}
		}
	}
	rng := rand.New(rand.NewPCG(8, 22))
	for round := 0; round < 200; round++ {
		order := slices.Clone(cands)
		rng.Shuffle(len(order), func(i, j int) { order[i], order[j] = order[j], order[i] })
		win := order[0]
		for _, x := range order[1:] {
			s := Prefer(win.s, x.s, win.r, x.r, c.r1)
			if reflect.DeepEqual(s, x.s) {
				win = x
			}
		}
		if win.name != want.name {
			t.Fatalf("round %d: folding in another order picked %s, want %s", round, win.name, want.name)
		}
	}
	t.Logf("winner of %d candidates: %s", len(cands), want.name)
}
