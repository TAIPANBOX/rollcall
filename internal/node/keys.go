package node

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/rand"
	"fmt"
	"slices"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/clock"
	"github.com/TAIPANBOX/rollcall/internal/epoch"
	"github.com/TAIPANBOX/rollcall/internal/ids"
	"github.com/TAIPANBOX/rollcall/internal/member"
	"github.com/TAIPANBOX/rollcall/internal/roster"
	"github.com/TAIPANBOX/rollcall/internal/wire"
)

// # Epoch keys (security spec 5.5)
//
// Every epoch key is bound to the roster it was issued under, its version
// and hash (epoch.Binding), and carries its sequence number within that
// roster version and the place of the admin who issued it in that roster's
// Admins (0 the primary, 1 the backup). The delivery carries all of it,
// sealed and signed (epoch.Seal). Keys are ordered by that binding, never
// by the wire ID (epoch.Newer): a higher roster version, then a higher
// sequence number, then the primary's before the backup's. A sequence
// number runs from 1 to epoch.MaxSeq within one roster version and starts
// again at 1 with the next; at MaxSeq rotation fails until the roster
// changes. The wire ID is epoch.IDOf the binding, the sequence number and
// the authority.
//
// A key fits the node's roster (fits) when it is bound to its head, or to
// a roster before the head in its chain after which no roster removed any
// of that roster's members: everyone who can hold such a key is still a
// member. A key bound to a roster that lost a member since, or to a roster
// the chain does not hold, does not fit.
//
// A member takes a delivered key, signed by an admin of its head, only
// when it fits and the admin is the one of the bound roster whose place the
// key carries (keyIn). Of two fitting keys it keeps the newer; a current
// key that no longer fits it replaces with a fitting one, whatever the
// order. A key bound to a roster in its chain that does not fit is
// refused. A key bound to a roster the chain does not hold, a later
// version or another branch of a split, is kept aside, pending, and used
// for one thing only: to fetch the roster from its signer, which the
// member's own key may no longer reach. Once the member's chain holds that
// roster, the pending key is judged as a delivery is; a pending key never
// seals a heartbeat and the Ring never accepts it.
//
// An admin rotates at once when it signs a roster that adds or removes a
// member, so a new member's first key is bound to the roster that admitted
// it and a removed one gets no key bound to the roster without it. The
// acting admin (roster.ActingAdmin, the first live admin) rotates whenever
// its current key no longer fits its head: a removal signed elsewhere, or
// a split healed in favour of another branch, whose key replaces the
// losing branch's. It also rotates when the current key's NotAfter has
// passed (30 days), and Rotate rotates on demand. Other roster changes
// (roles, admins, a takeover and its confirmation) keep the key, so the
// two sides of a split that only changed roles still share a key when the
// split heals. A new key is installed at once, so the previous one is
// accepted for epoch.Overlap (60 s) more, and is delivered to every other
// member of the roster, a replaced primary included, sealed to its receive
// key in two TCP requests, since a delivery is larger than one packet. Each
// request is sealed under the epoch the member last spoke in a heartbeat,
// which the admin still holds, and its reply is read under the same epoch,
// so a member that missed the switch still takes it. A delivery is repeated
// every retryEvery until the member acknowledges it or is heard under the
// new epoch, and dropped once it no longer fits the admin's roster.

// delivery is one epoch key delivery still to make.
type delivery struct {
	key  epoch.Key
	blob []byte
	part int
	next time.Duration
}

// partial is a delivery being received, part by part.
type partial struct {
	epochID uint32
	parts   [deliveryParts][]byte
}

var recvKEM = hpke.MLKEM768X25519()

func newEmptyRing(now func() time.Time) *epoch.Ring { return &epoch.Ring{Now: now} }

// authority returns the place of an admin in r's admin list, the authority
// its epoch keys carry: 0 for the primary, 1 for a backup; false for
// anyone else.
func authority(r roster.Roster, id ids.MemberID) (uint32, bool) {
	switch i := slices.Index(r.Admins, id); {
	case i == 0:
		return 0, true
	case i > 0:
		return 1, true
	}
	return 0, false
}

// binding returns the node's current roster as an epoch key binds to it.
func (n *Node) binding() epoch.Binding {
	return epoch.Binding{Version: n.cur().Version, Hash: n.curHash}
}

// boundRoster returns the roster of the chain that b names, and whether
// the chain holds it.
func (n *Node) boundRoster(b epoch.Binding) (roster.Roster, int, bool) {
	i := n.inChain(b.Hash)
	if i < 0 || n.rosters[i].Version != b.Version {
		return roster.Roster{}, -1, false
	}
	return n.rosters[i], i, true
}

// fits reports whether a key bound to b fits the node's roster, as the
// section comment says.
func (n *Node) fits(b epoch.Binding) bool {
	r, i, ok := n.boundRoster(b)
	if !ok {
		return false
	}
	for _, later := range n.rosters[i+1:] {
		for _, m := range r.Members {
			if _, still := memberOf(later, m.ID); !still {
				return false
			}
		}
	}
	return true
}

// Rotate makes a new epoch key and delivers it to every other member.
// This router must be an admin.
func (n *Node) Rotate() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.running() {
		return n.why()
	}
	return n.rotateLocked(n.stamp())
}

func (n *Node) rotateLocked(now clock.Stamp) error {
	cur := n.cur()
	auth, ok := authority(cur, n.id.ID)
	if !ok {
		return ErrNotAdmin
	}
	b := n.binding()
	seq := uint16(1)
	for _, k := range n.keys {
		if k.Roster.Version == b.Version && k.Seq >= seq {
			seq = k.Seq + 1
		}
	}
	if seq > epoch.MaxSeq {
		return fmt.Errorf("%w: the epoch sequence of roster version %d is exhausted; the next roster change starts it again", ErrState, b.Version)
	}
	secret := make([]byte, epoch.SecretSize)
	if _, err := rand.Read(secret); err != nil {
		return err
	}
	k := epoch.Key{ID: epoch.IDOf(b, seq, uint8(auth)), Secret: secret,
		NotAfter: now.Wall.Add(epoch.RotationPeriod).Truncate(time.Second).UTC(),
		Roster:   b, Seq: seq, Authority: uint8(auth)}
	if err := n.ring.Install(k, now.Wall); err != nil {
		return err
	}
	n.holdKey(k)
	clear(n.deliveries)
	for _, m := range cur.Members {
		if m.ID == n.id.ID {
			continue
		}
		to, err := recvKEM.NewPublicKey(m.RecvPub)
		if err != nil {
			continue
		}
		blob, err := epoch.Seal(k, to, m.ID, n.id.ID, n.id.Sign)
		if err != nil {
			continue
		}
		n.deliveries[m.ID] = &delivery{key: k, blob: blob, next: now.Mono}
	}
	n.planDeliveries(now)
	return nil
}

// holdKey keeps k as the current key, with the one before it, and stores
// both.
func (n *Node) holdKey(k epoch.Key) {
	n.keys = append(n.keys, k)
	if len(n.keys) > 2 {
		old := n.keys[:len(n.keys)-2]
		for i := range old {
			clear(old[i].Secret)
		}
		n.keys = slices.Clone(n.keys[len(n.keys)-2:])
	}
	_ = writeKeys(n.st, n.keys, false)
}

// keysLocked does the routine key duties of a Tick.
func (n *Node) keysLocked(now clock.Stamp) {
	for id, d := range n.deliveries {
		if !n.fits(d.key.Roster) {
			delete(n.deliveries, id) // no member of this roster may take it
		}
	}
	cur := n.cur()
	acting, ok := roster.ActingAdmin(cur, func(id ids.MemberID) bool {
		if id == n.id.ID {
			return true
		}
		p := n.peers[id]
		return p != nil && p.heard && !p.silent
	})
	if ok && acting == n.id.ID && (!n.fits(n.current().Roster) || !now.Wall.Before(n.current().NotAfter)) {
		_ = n.rotateLocked(now)
	}
	n.planDeliveries(now)
}

// planDeliveries plans the deliveries that are due.
func (n *Node) planDeliveries(now clock.Stamp) {
	for id, d := range n.deliveries {
		p := n.peers[id]
		if p == nil || !p.addr.IsValid() || now.Mono < d.next {
			continue
		}
		d.next = now.Mono + retryEvery
		d.part = 0
		n.planPart(id, d)
	}
}

// planPart plans the delivery's current part to id.
func (n *Node) planPart(id ids.MemberID, d *delivery) {
	half := (len(d.blob) + 1) / deliveryParts
	data := d.blob[d.part*half : min(len(d.blob), (d.part+1)*half)]
	var seal uint32
	if p := n.peers[id]; p != nil {
		if _, held := n.keyByID(p.epoch); held {
			seal = p.epoch
		}
	}
	var ack epochAck
	n.plan(job{to: id, typ: msgEpoch, reply: msgEpoch, sealAs: seal,
		payload: encodePart(d.part, deliveryParts, d.key.ID, data),
		check: func(b []byte) error {
			if len(b) != 1 || b[0] < byte(ackPart) || b[0] > byte(ackHeld) {
				return errMalformed
			}
			ack = epochAck(b[0])
			return nil
		},
		apply: func(_ member.Admitted, _ clock.Stamp) {
			if n.deliveries[id] != d {
				return
			}
			switch ack {
			case ackPart:
				if d.part == 0 {
					d.part = 1
					n.planPart(id, d)
				}
			case ackInstalled, ackHeld:
				delete(n.deliveries, id)
			}
		}})
}

// epochSeen notes that from sent a heartbeat under epochID, its current
// key: a delivery of exactly that key is done. Only a heartbeat says which
// key a member uses; a request may be sealed under a key it keeps pending.
func (n *Node) epochSeen(from ids.MemberID, epochID uint32) {
	if d := n.deliveries[from]; d != nil && epochID == d.key.ID {
		delete(n.deliveries, from)
	}
}

// serveEpoch receives a part of an epoch key delivery from an admin.
func (n *Node) serveEpoch(ep uint32, env envelope, now clock.Stamp) []byte {
	var (
		part    int
		epochID uint32
		data    []byte
	)
	if _, err := n.admit(ep, env, func(b []byte) error {
		var err error
		part, _, epochID, data, err = decodePart(b)
		return err
	}); err != nil {
		return nil
	}
	cur := n.cur()
	if _, ok := authority(cur, env.from); !ok {
		return nil
	}
	ack, ok := n.partIn(env.from, part, epochID, data, now)
	if !ok {
		return nil
	}
	return n.reply(ep, msgEpoch, env.ref, []byte{byte(ack)})
}

// partIn takes one part of a delivery from the admin from.
func (n *Node) partIn(from ids.MemberID, part int, epochID uint32, data []byte, now clock.Stamp) (epochAck, bool) {
	if epochID == n.current().ID {
		return ackHeld, true
	}
	p := n.parts[from]
	if p == nil || p.epochID != epochID {
		p = &partial{epochID: epochID}
		n.parts[from] = p
	}
	p.parts[part] = bytes.Clone(data)
	for _, b := range p.parts {
		if b == nil {
			return ackPart, true
		}
	}
	delete(n.parts, from)
	blob := bytes.Join(p.parts[:], nil)
	cur := n.cur()
	admins := map[ids.MemberID]ed25519.PublicKey{}
	for _, a := range cur.Admins {
		if m, ok := memberOf(cur, a); ok {
			admins[a] = m.SignPub
		}
	}
	k, signer, err := epoch.Open(blob, n.id, admins)
	if err != nil || signer != from || k.ID != epochID {
		return 0, false
	}
	return n.keyIn(k, signer, now)
}

// keyIn decides on the key k, delivered by signer, an admin of the node's
// current roster, as the section comment says.
func (n *Node) keyIn(k epoch.Key, signer ids.MemberID, now clock.Stamp) (epochAck, bool) {
	switch {
	case n.fits(k.Roster):
		return n.fitIn(k, signer, now)
	case n.inChain(k.Roster.Hash) >= 0:
		// Bound to a roster this node holds and that lost a member since:
		// of use to nobody here, and the admin may stop.
		clear(k.Secret)
		return ackHeld, true
	}
	// Bound to a roster the node does not hold: kept aside, and the roster
	// fetched from its signer with it.
	if old, ok := n.pending[signer]; ok {
		clear(old.Secret)
	}
	n.pending[signer] = k
	f := &rosterFetch{peer: signer, sealAs: k.ID, branch: map[uint64]roster.Signed{}}
	n.planRosterAt(f, 0)
	return 0, false
}

// fitIn takes k, which fits the node's roster, if signer is the admin of
// the bound roster whose place k carries and k's wire ID is the one its
// binding gives, and k is newer than the current key or the current key no
// longer fits.
func (n *Node) fitIn(k epoch.Key, signer ids.MemberID, now clock.Stamp) (epochAck, bool) {
	bound, _, _ := n.boundRoster(k.Roster)
	auth, ok := authority(bound, signer)
	if !ok || uint32(k.Authority) != auth || k.ID != epoch.IDOf(k.Roster, k.Seq, k.Authority) {
		return 0, false
	}
	if have := n.current(); n.fits(have.Roster) && !epoch.Newer(k, have) {
		return ackHeld, true
	}
	if err := n.ring.Install(k, now.Wall); err != nil {
		return 0, false
	}
	n.holdKey(k)
	return ackInstalled, true
}

// pendingLocked judges again the pending keys bound to a roster the chain
// now holds, after the node took a roster.
func (n *Node) pendingLocked(now clock.Stamp) {
	for signer, k := range n.pending {
		if n.inChain(k.Roster.Hash) < 0 {
			continue // a roster not held yet: it may still come
		}
		delete(n.pending, signer)
		if _, admin := authority(n.cur(), signer); admin && n.fits(k.Roster) {
			n.fitIn(k, signer, now)
			continue
		}
		clear(k.Secret)
	}
}

// pendingKey returns the packet key of a pending key with the wire ID id.
func (n *Node) pendingKey(id uint32) ([]byte, bool) {
	for _, k := range n.pending {
		if k.ID == id {
			pk, err := wire.PacketKey(k.Secret)
			return pk, err == nil
		}
	}
	return nil, false
}
