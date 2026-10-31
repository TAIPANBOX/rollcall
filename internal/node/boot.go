package node

import (
	"encoding/json"
	"slices"

	"github.com/TAIPANBOX/rollcall/internal/clock"
	"github.com/TAIPANBOX/rollcall/internal/events"
	"github.com/TAIPANBOX/rollcall/internal/history"
	"github.com/TAIPANBOX/rollcall/internal/ids"
)

// # The router's own return (design 4.6)
//
// At boot a router compares this boot with the one before: the boot ID, the
// OpenWrt version and the shutdown marker (Config.Planned). Once its own
// chain is caught up and this boot's record is written, a router whose boot
// before had another boot ID records one event about itself, right after
// that record: Upgraded, with Detail "from" and "to", when the version
// changed; else RebootPlanned when the boot before ended with the shutdown
// marker; else RebootUnplanned (events.Classify). Last and Back name the two
// boots, At is now, and Since when the absence began. So a reboot no other
// router saw both sides of, a power cut of the whole site or of a group of
// one, still reaches the chat; where others did see it, Coalesce makes
// their records and this one a single incident that tells the router's own
// classification (events.Coalesce, rule (e)), and the correction Reconcile
// makes of a peer's guess sends no update (toldOwnLocked).
//
// The boot before is the newer, by boot sequence number, of the latest boot
// record in the own chain and the boot the alive file names. The alive file
// is the last moment this router knew it was up, in this boot: written at
// most once a minute while it runs, through the store's Flusher, from the
// moment this boot's record is in the chain (so a restart before that still
// finds the boot before in it), and at once when the router announces its
// shutdown (GoingDown), after which it stays as written.
//
// Since is the latest of: the alive file's moment, the latest own event of
// the boot before, and the moment a peer last heard the router in that boot
// (a trusted member_silent of a peer about it that names that boot, when
// one is in the log by then). It is Trusted only when it is exact: a peer's
// stamp, or the alive moment written at the announced shutdown on a trusted
// clock. Anything else only bounds the moment from below, by up to the
// minute between two writes of the alive file or more, and makes the
// incident's times approximate.
//
// Nothing is recorded on the very first boot (no boot before is known),
// when the daemon restarted within one boot (the same boot ID), or when the
// boot ID is not the kernel's (Config.Boot zero: every start draws one, so a
// restart could not be told from a reboot).

// fileAlive is the alive file in the store.
const fileAlive = "alive.json"

// aliveFile is what fileAlive holds.
type aliveFile struct {
	Boot    Boot   `json:"boot"`    // the boot it was written in
	Version string `json:"version"` // the OpenWrt release of that boot
	At      At     `json:"at"`      // the moment, on that boot's clocks
	Down    bool   `json:"down"`    // written when the router announced its shutdown
}

func (a aliveFile) valid() bool {
	return a.Boot.known() && a.Boot.valid() && validVersion(a.Version) && a.At != (At{}) && a.At.valid()
}

// loadAlive reads the alive file the boot before left; one that does not
// decode counts as none.
func (n *Node) loadAlive() {
	b, err := n.st.ReadFile(fileAlive)
	if err != nil {
		return
	}
	var a aliveFile
	if decodeJSON(b, &a, 1024) == nil && a.valid() {
		n.prevAlive = &a
	}
}

// writeAlive is the alive Flusher's write function.
func (n *Node) writeAlive() error {
	if n.aliveAt == (clock.Stamp{}) {
		return nil
	}
	return n.saveAlive(n.aliveAt, n.goingDown)
}

func (n *Node) saveAlive(at clock.Stamp, down bool) error {
	b, err := json.Marshal(aliveFile{Boot: n.rec.boot.Boot, Version: n.cfg.Versions[0], At: AtOf(at), Down: down})
	if err != nil {
		return err
	}
	return n.st.WriteFileAtomic(fileAlive, b)
}

// aliveLocked notes that the router is up now, once this boot's record is
// written and until it announced its shutdown.
func (n *Node) aliveLocked(now clock.Stamp) {
	if n.rec.bootSeen && !n.goingDown {
		n.aliveAt = n.localStamp(now)
		n.alive.Mark()
	}
	_ = n.alive.Tick(now.Wall)
}

// announcedLocked writes the alive file at once when the router announces
// its shutdown: the last moment it speaks for.
func (n *Node) announcedLocked(now clock.Stamp) {
	if !n.rec.bootSeen {
		return
	}
	n.aliveAt = n.localStamp(now)
	_ = n.saveAlive(n.aliveAt, true)
}

// bootBefore is what the router knows of the boot before this one.
type bootBefore struct {
	boot    Boot
	version string
	alive   *aliveFile // the alive file, when it names this boot
}

// bootBeforeLocked returns the boot before this one, if any is known. It
// is called before this boot's record is appended.
func (n *Node) bootBeforeLocked() (bootBefore, bool) {
	var p bootBefore
	found := false
	es := n.log.Range(n.id.ID, 1, n.log.Head(n.id.ID).Seq)
	for i := len(es) - 1; i >= 0; i-- {
		if es[i].Kind != history.KindBoot {
			continue
		}
		if b, err := DecodeBoot(es[i]); err == nil {
			p, found = bootBefore{boot: b.Boot, version: b.Version}, true
			break
		}
	}
	if a := n.prevAlive; a != nil && (!found || a.Boot.Seq >= p.boot.Seq) {
		if !found || a.Boot != p.boot {
			p.boot, p.version = a.Boot, a.Version
		}
		p.alive, found = a, true
	}
	return p, found
}

// ownReturnLocked records this router's own return from the boot before,
// prev, into this boot, cur, whose record was just appended.
func (n *Node) ownReturnLocked(prev bootBefore, cur BootBody, now clock.Stamp) {
	if n.cfg.Boot == (ids.BootID{}) || prev.boot.ID == cur.Boot.ID {
		return
	}
	typ := events.Classify(
		events.Before{AnnouncedGoingDown: cur.Planned, BootID: prev.boot.ID, Version: prev.version},
		events.Return{BootID: cur.Boot.ID, Version: cur.Version},
	)
	var detail map[string]string
	if typ == events.Upgraded {
		detail = map[string]string{"from": prev.version, "to": cur.Version}
	}
	e, err := NewEvent(n.id, n.log.Head(n.id.ID), EventBody{
		Subject: n.id.ID, Type: typ, Last: prev.boot, Back: cur.Boot,
		At: AtOf(n.localStamp(now)), Since: n.sinceLocked(prev), Detail: detail,
	})
	if err == nil {
		n.appendOwnLocked(e, now)
	}
}

// sinceLocked returns the last moment the router knows it was up in the
// boot prev, as the package doc of this file describes; zero if none.
func (n *Node) sinceLocked(prev bootBefore) At {
	var own clock.Stamp
	exact := false
	consider := func(s clock.Stamp, ex bool) {
		if s.Boot == prev.boot.ID && (own == (clock.Stamp{}) || s.Mono > own.Mono) {
			own, exact = s, ex
		}
	}
	if a := prev.alive; a != nil && a.Boot == prev.boot {
		consider(a.At.Stamp(), a.Down)
	}
	for _, e := range n.log.Range(n.id.ID, 1, n.log.Head(n.id.ID).Seq) {
		if e.Kind != history.KindEvent {
			continue
		}
		if b, err := DecodeEvent(e); err == nil && b.At != (At{}) {
			consider(b.At.Stamp(), false)
		}
	}
	var peer clock.Stamp
	for _, c := range n.rec.claims {
		b, err := DecodeEvent(c)
		if err != nil || b.Type != events.MemberSilent || b.Subject != n.id.ID || b.Last.ID != prev.boot.ID || !b.At.Trusted {
			continue
		}
		if peer == (clock.Stamp{}) || b.At.Wall.After(peer.Wall) {
			peer = b.At.Stamp()
		}
	}
	switch {
	case peer != (clock.Stamp{}) && (own == (clock.Stamp{}) || !own.Trusted || !peer.Wall.Before(own.Wall)):
		// A moment on the peer's clock: no boot of this router's.
		return At{Wall: peer.Wall.UTC().Round(0), Trusted: true}
	case own != (clock.Stamp{}):
		s := AtOf(own)
		s.Trusted = own.Trusted && exact
		if !s.valid() {
			return At{}
		}
		return s
	}
	return At{}
}

// toldOwnLocked reports whether this router's own record of the absence a
// correction places already tells the class it corrects to: the incident
// then told it, and an update would say it a second time. The record is its
// own account of the return, or an update it recorded for that absence
// before, signed or still waiting for flash: the claims about one absence
// reach it at different times, from different members, and each
// reconciliation that finds new ones corrects them in an entry of its own,
// while the chat is told the class once (sim seeds 698 and 241, 2026-10-31).
func (n *Node) toldOwnLocked(c Correction) bool {
	tells := func(b EventBody) bool {
		return b.Subject == n.id.ID && string(b.Type) == c.Class && b.Last == c.From && b.Back == c.To
	}
	for _, e := range n.log.Range(n.id.ID, 1, n.log.Head(n.id.ID).Seq) {
		if e.Kind != history.KindEvent {
			continue
		}
		if b, err := DecodeEvent(e); err == nil && tells(b) {
			return true
		}
	}
	return slices.ContainsFunc(n.writes, func(w ownWrite) bool {
		b, ok := w.body.(EventBody)
		return ok && tells(b)
	})
}

// ownStart reports whether evs hold a member's own account of its return
// that says when its absence began.
func ownStart(evs []events.Event) bool {
	for _, e := range evs {
		if events.Own(e) && e.Since != (clock.Stamp{}) {
			return true
		}
	}
	return false
}
