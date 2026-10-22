package node

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/clock"
	"github.com/TAIPANBOX/rollcall/internal/epoch"
	"github.com/TAIPANBOX/rollcall/internal/ids"
	"github.com/TAIPANBOX/rollcall/internal/member"
	"github.com/TAIPANBOX/rollcall/internal/roster"
)

// # Epoch keys
//
// Epoch IDs are (sequence << 2) | authority: authority 0 for the primary,
// 1 for a backup, 2 for the recovery key, and sequence one more than the
// highest the node holds. Two admins that rotate on the two sides of a
// split never make the same ID, and the Ring orders them.
//
// The acting admin (roster.ActingAdmin, the first live admin) rotates when
// the current key's NotAfter has passed (30 days); an admin that signs a
// removal rotates at once; Rotate rotates on demand. The new key is
// installed at once, so the previous one is accepted for epoch.Overlap
// (60 s) more, and is delivered to every other member of the roster,
// a replaced primary included, sealed to its receive key (epoch.Seal) in
// two TCP requests, since a delivery is larger than one packet. Each
// request is sealed under the epoch the member last spoke, which the
// admin still holds, so a member that missed the switch still opens it.
// A delivery is repeated every retryEvery until the member acknowledges
// it or is heard under the new epoch.

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

// authority returns the authority bits of an admin's epoch IDs: 0 for the
// primary, 1 for a backup; false for anyone else.
func authority(r roster.Roster, id ids.MemberID) (uint32, bool) {
	switch i := slices.Index(r.Admins, id); {
	case i == 0:
		return 0, true
	case i > 0:
		return 1, true
	}
	return 0, false
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
	seq := uint64(n.current().ID>>2) + 1
	if seq >= 1<<30 {
		return fmt.Errorf("%w: epoch sequence exhausted", ErrState)
	}
	secret := make([]byte, epoch.SecretSize)
	if _, err := rand.Read(secret); err != nil {
		return err
	}
	k := epoch.Key{ID: uint32(seq)<<2 | auth, Secret: secret,
		NotAfter: now.Wall.Add(epoch.RotationPeriod).Truncate(time.Second).UTC()}
	if err := n.ring.Install(k, now.Wall); err != nil {
		return err
	}
	n.holdKey(k)
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
	cur := n.cur()
	acting, ok := roster.ActingAdmin(cur, func(id ids.MemberID) bool {
		if id == n.id.ID {
			return true
		}
		p := n.peers[id]
		return p != nil && p.heard && !p.silent
	})
	if ok && acting == n.id.ID && !now.Wall.Before(n.current().NotAfter) {
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

// epochSeen notes that from spoke under epochID: a delivery of that key or
// an older one is done.
func (n *Node) epochSeen(from ids.MemberID, epochID uint32) {
	if d := n.deliveries[from]; d != nil && epochID >= d.key.ID {
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
	if epochID <= n.current().ID {
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
	if auth, _ := authority(cur, signer); k.ID&3 != auth {
		return 0, false
	}
	if err := n.ring.Install(k, now.Wall); err != nil {
		if errors.Is(err, epoch.ErrStale) {
			return ackHeld, true
		}
		return 0, false
	}
	n.holdKey(k)
	return ackInstalled, true
}
