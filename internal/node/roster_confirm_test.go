package node

import (
	"errors"
	"testing"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/epoch"
	"github.com/TAIPANBOX/rollcall/internal/ids"
	"github.com/TAIPANBOX/rollcall/internal/roster"
)

// takeoverBy returns the edit with which backup takes over from primary,
// as rollcall admin takeover makes it: provisional, the primary it
// replaced kept as the backup.
func takeoverBy(backup, primary ids.MemberID) func(r *roster.Roster) error {
	return func(r *roster.Roster) error {
		r.Admins = []ids.MemberID{backup, primary}
		r.Takeover, r.Replaced = true, primary
		for i := range r.Members {
			switch r.Members[i].ID {
			case primary:
				r.Members[i].Roles = []roster.Role{roster.RoleBackup}
			case backup:
				r.Members[i].Roles = []roster.Role{roster.RolePrimary}
			}
		}
		return nil
	}
}

// confirm is the owner's confirmation of the takeover in the roster.
func confirm(r *roster.Roster) error {
	r.OwnerConfirmed = true
	return nil
}

// force signs the next roster as node i, made by edit, and makes it node
// i's current roster without the checks a node applies to a roster it
// adopts: the backup as a compromised router would run it, publishing at
// once. Node i's peers fetch it when its heartbeats announce it.
func force(t testing.TB, g *group, i int, edit func(r *roster.Roster) error) {
	t.Helper()
	n := g.nodes[i]
	with(n, func() any {
		prev := n.cur()
		r := cloneRoster(prev)
		r.Version, r.Prev = prev.Version+1, n.curHash
		if err := edit(&r); err != nil {
			t.Fatal(err)
		}
		s, err := roster.SignRoster(r, n.id.ID, n.id.Sign, false)
		if err != nil {
			t.Fatal(err)
		}
		got, err := s.Verify(&n.chain[len(n.chain)-1])
		if err != nil {
			t.Fatalf("the forced roster does not verify: %v", err)
		}
		n.chain, n.rosters = append(n.chain, s), append(n.rosters, got)
		n.curHash = s.Hash()
		n.setKeyMap(got)
		_ = n.table.SetRoster(got, n.curHash, n.stamp())
		return nil
	})
}

// rosterOfNode returns node n's current roster.
func rosterOfNode(n *Node) roster.Roster { return with(n, func() roster.Roster { return n.cur() }) }

// splitTakeover starts a group of three, r01 the primary, r02 the backup,
// cuts r01 off from both others, and has r02 take over once both have
// heard nothing from r01 for eleven minutes. It returns the moment r01 was
// last heard.
func splitTakeover(t *testing.T) (*group, time.Time) {
	t.Helper()
	g := newGroup(t, setup{n: 3, admins: 2})
	g.run(15 * sec)
	g.split([]int{0}, []int{1, 2}, true)
	cut := g.clk.Now()
	g.run(11 * time.Minute)
	if err := g.nodes[1].Publish(takeoverBy(g.ids[1].ID, g.ids[0].ID)); err != nil {
		t.Fatalf("takeover after 11 min: %v", err)
	}
	g.run(30 * sec)
	if r := rosterOfNode(g.nodes[2]); r.Admins[0] != g.ids[1].ID || !r.Takeover {
		t.Fatal("r03 did not accept the takeover: the case did not happen")
	}
	return g, cut
}

// jumpTo moves the group's clock to at, ticking every node once.
func (g *group) jumpTo(at time.Time) {
	if d := at.Sub(g.clk.Now()); d > 0 {
		g.clk.advance(d)
	}
	for _, n := range g.nodes {
		if n != nil {
			n.Tick()
		}
	}
}

// TestBackupConfirmationNeedsADayOfSilence (A4): a confirmation signed by
// the backup, published at once as a compromised backup would, is refused
// by a member that heard the replaced primary less than a day ago
// (23h59m), and accepted once that member has heard nothing from it for a
// day.
func TestBackupConfirmationNeedsADayOfSilence(t *testing.T) {
	g, cut := splitTakeover(t)
	m := g.nodes[2]
	force(t, g, 1, confirm)
	g.run(time.Minute)
	if rosterOfNode(m).OwnerConfirmed {
		t.Fatal("r03 accepted the backup's confirmation twelve minutes after it last heard the primary")
	}
	g.jumpTo(cut.Add(23*time.Hour + 59*time.Minute))
	g.run(30 * sec)
	if rosterOfNode(m).OwnerConfirmed {
		t.Fatal("r03 accepted the backup's confirmation 23h59m after it last heard the primary")
	}
	g.jumpTo(cut.Add(24 * time.Hour))
	g.run(30 * sec)
	if !rosterOfNode(m).OwnerConfirmed {
		t.Fatal("r03 refused the backup's confirmation a day after it last heard the primary")
	}
}

// TestTakeoverConfirmedInOneRosterNeedsADay (A4): a backup that takes over
// and confirms in one roster is held to the same day of silence.
func TestTakeoverConfirmedInOneRosterNeedsADay(t *testing.T) {
	g := newGroup(t, setup{n: 3, admins: 2})
	g.run(15 * sec)
	g.split([]int{0}, []int{1, 2}, true)
	cut := g.clk.Now()
	g.run(11 * time.Minute)
	both := takeoverBy(g.ids[1].ID, g.ids[0].ID)
	force(t, g, 1, func(r *roster.Roster) error {
		if err := both(r); err != nil {
			return err
		}
		return confirm(r)
	})
	m := g.nodes[2]
	g.run(time.Minute)
	if r := rosterOfNode(m); r.Takeover {
		t.Fatal("r03 accepted a takeover confirmed in the same roster twelve minutes after it last heard the primary")
	}
	g.jumpTo(cut.Add(23*time.Hour + 59*time.Minute))
	g.run(30 * sec)
	if r := rosterOfNode(m); r.Takeover {
		t.Fatal("r03 accepted a takeover confirmed in the same roster 23h59m after it last heard the primary")
	}
	g.jumpTo(cut.Add(24 * time.Hour))
	g.run(30 * sec)
	if r := rosterOfNode(m); !r.Takeover || !r.OwnerConfirmed {
		t.Fatal("r03 refused a takeover confirmed in the same roster a day after it last heard the primary")
	}
}

// TestBackupHoldsConfirmationForADay (A4): the owner confirms the takeover
// on the backup twelve minutes after the primary went silent. The backup
// holds the confirmation and publishes it only once it has heard nothing
// from the primary for a day; then the member, silent from the primary as
// long, accepts it.
func TestBackupHoldsConfirmationForADay(t *testing.T) {
	g, cut := splitTakeover(t)
	b, m := g.nodes[1], g.nodes[2]
	if err := b.Publish(confirm); !errors.Is(err, ErrConfirmationHeld) {
		t.Errorf("Publish of the confirmation: %v, want ErrConfirmationHeld", err)
	}
	g.run(time.Minute)
	if rosterOfNode(b).OwnerConfirmed || rosterOfNode(m).OwnerConfirmed {
		t.Fatal("the confirmation took effect twelve minutes after the primary went silent")
	}
	if c := b.HeldConfirmation(); !c.Held || c.Of != "r01" || c.From.Before(cut.Add(23*time.Hour)) || c.From.After(cut.Add(24*time.Hour)) {
		t.Errorf("HeldConfirmation = %+v, want held, of r01, from a day after r01 was last heard", c)
	}
	g.jumpTo(cut.Add(23*time.Hour + 59*time.Minute))
	g.run(30 * sec)
	if rosterOfNode(b).OwnerConfirmed {
		t.Fatal("the backup published the confirmation before a day of silence")
	}
	g.jumpTo(cut.Add(24*time.Hour + time.Minute))
	g.run(time.Minute)
	if !rosterOfNode(b).OwnerConfirmed || !rosterOfNode(m).OwnerConfirmed {
		t.Fatal("the confirmation held by the backup did not take effect after a day of silence")
	}
	if c := b.HeldConfirmation(); c.Held || c.Lapsed {
		t.Errorf("HeldConfirmation after it was published = %+v, want neither held nor lapsed", c)
	}
	// The replaced primary restarts and comes back: it takes the
	// confirmation of its own replacement at once, as it takes a takeover,
	// and stays the backup.
	g.stop(0)
	g.reboot(0)
	g.split([]int{0}, []int{1, 2}, false)
	g.run(2 * time.Minute)
	want := rosterOfNode(b)
	for i, n := range g.nodes {
		if r := rosterOfNode(n); r.Version != want.Version || r.Admins[0] != g.ids[1].ID || !r.OwnerConfirmed {
			t.Fatalf("r%02d after the replaced primary's return: version %d, primary %s, confirmed %v; want %d, r02, true",
				i+1, r.Version, r.Admins[0], r.OwnerConfirmed, want.Version)
		}
	}
}

// TestHeldConfirmationSurvivesRestart (A4): the backup restarts while it
// holds a confirmation; it still holds it, and its day of silence starts
// again from the restart.
func TestHeldConfirmationSurvivesRestart(t *testing.T) {
	g, cut := splitTakeover(t)
	if err := g.nodes[1].Publish(confirm); !errors.Is(err, ErrConfirmationHeld) {
		t.Fatalf("Publish of the confirmation: %v, want ErrConfirmationHeld", err)
	}
	g.jumpTo(cut.Add(12 * time.Hour))
	g.stop(1)
	b := g.reboot(1)
	restarted := g.clk.Now()
	if c := b.HeldConfirmation(); !c.Held {
		t.Fatalf("after the restart the backup holds no confirmation: %+v", c)
	}
	g.jumpTo(cut.Add(24*time.Hour + time.Minute))
	g.run(time.Minute)
	if rosterOfNode(b).OwnerConfirmed {
		t.Fatal("the backup published the confirmation a day after the primary's silence began, though it restarted 12 hours in")
	}
	g.jumpTo(restarted.Add(24*time.Hour + time.Minute))
	g.run(time.Minute)
	if !rosterOfNode(b).OwnerConfirmed {
		t.Fatal("the backup did not publish the confirmation a day after its restart")
	}
}

// TestPrimaryBackWithinTheDayRestores (A4): the owner confirms on the
// backup, and the primary comes back 23 hours after it went silent. It
// restores itself, as after an unconfirmed takeover, and the confirmation
// the backup held lapses: it is never published, however long after.
func TestPrimaryBackWithinTheDayRestores(t *testing.T) {
	g, cut := splitTakeover(t)
	b := g.nodes[1]
	_ = b.Publish(confirm)
	g.run(time.Minute)
	g.jumpTo(cut.Add(23 * time.Hour))
	g.split([]int{0}, []int{1, 2}, false)
	g.run(2 * time.Minute)
	for i, n := range g.nodes {
		if r := rosterOfNode(n); r.Admins[0] != g.ids[0].ID || r.Takeover {
			t.Fatalf("r%02d after the primary's return at 23h: primary %s, takeover %v; want r01, none", i+1, r.Admins[0], r.Takeover)
		}
	}
	if c := b.HeldConfirmation(); c.Held || !c.Lapsed {
		t.Errorf("HeldConfirmation after the primary's return = %+v, want lapsed", c)
	}
	// The primary goes silent again: the lapsed confirmation stays lapsed.
	g.split([]int{0}, []int{1, 2}, true)
	g.jumpTo(cut.Add(72 * time.Hour))
	g.run(time.Minute)
	if r := rosterOfNode(b); r.OwnerConfirmed || r.Admins[0] != g.ids[0].ID {
		t.Fatalf("the lapsed confirmation was published: primary %s, confirmed %v", r.Admins[0], r.OwnerConfirmed)
	}
}

// TestRecoveryConfirmationImmediate (A4): a confirmation signed with the
// recovery key takes effect at once, twelve minutes into the silence.
func TestRecoveryConfirmationImmediate(t *testing.T) {
	g, _ := splitTakeover(t)
	b, m := g.nodes[1], g.nodes[2]
	if err := b.PublishRecovery(confirm, g.rec); err != nil {
		t.Fatalf("PublishRecovery: %v", err)
	}
	g.run(30 * sec)
	if !rosterOfNode(b).OwnerConfirmed || !rosterOfNode(m).OwnerConfirmed {
		t.Fatal("a confirmation signed with the recovery key did not take effect at once")
	}
}

// TestHeldConfirmationLapses (A4): a confirmation the backup holds lapses
// when it hears the replaced primary within the day, even before that
// primary could restore itself, and when the roster stops holding the
// backup's takeover, here through the recovery key; it is never published
// afterwards.
func TestHeldConfirmationLapses(t *testing.T) {
	t.Run("the replaced primary heard", func(t *testing.T) {
		g, cut := splitTakeover(t)
		p, b := g.nodes[0], g.nodes[1]
		if err := b.Publish(confirm); !errors.Is(err, ErrConfirmationHeld) {
			t.Fatalf("Publish of the confirmation: %v, want ErrConfirmationHeld", err)
		}
		g.jumpTo(cut.Add(23 * time.Hour))
		// One heartbeat of r01 reaches r02, under the key r02 uses; r01
		// stays cut off and cannot restore itself.
		k := with(b, func() epoch.Key { return b.current() })
		pkt := with(p, func() []byte {
			p.ring.Install(k, p.clk.Now())
			p.holdKey(k)
			pkt, err := p.heartbeat(p.stamp())
			if err != nil {
				t.Fatal(err)
			}
			return pkt
		})
		b.HandlePacket(g.addrs[0], pkt)
		if c := b.HeldConfirmation(); c.Held || !c.Lapsed {
			t.Fatalf("HeldConfirmation after hearing r01 = %+v, want lapsed", c)
		}
		g.jumpTo(cut.Add(72 * time.Hour))
		g.run(time.Minute)
		if rosterOfNode(b).OwnerConfirmed {
			t.Fatal("a lapsed confirmation was published")
		}
	})
	t.Run("the recovery key restored the primary", func(t *testing.T) {
		g, _ := splitTakeover(t)
		b, m := g.nodes[1], g.nodes[2]
		if err := b.Publish(confirm); !errors.Is(err, ErrConfirmationHeld) {
			t.Fatalf("Publish of the confirmation: %v, want ErrConfirmationHeld", err)
		}
		p, bk := g.ids[0].ID, g.ids[1].ID
		err := m.PublishRecovery(func(r *roster.Roster) error {
			if err := takeoverBy(p, bk)(r); err != nil {
				return err
			}
			r.Takeover, r.Replaced, r.OwnerConfirmed = false, ids.MemberID{}, false
			return nil
		}, g.rec)
		if err != nil {
			t.Fatalf("PublishRecovery: %v", err)
		}
		g.run(30 * sec)
		if r := rosterOfNode(b); r.Takeover || r.Admins[0] != p {
			t.Fatal("r02 did not take the recovery roster: the case did not happen")
		}
		if c := b.HeldConfirmation(); c.Held || !c.Lapsed {
			t.Fatalf("HeldConfirmation after the recovery roster = %+v, want lapsed", c)
		}
	})
}
