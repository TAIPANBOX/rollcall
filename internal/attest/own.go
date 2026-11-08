package attest

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/history"
	"github.com/TAIPANBOX/rollcall/internal/identity"
	"github.com/TAIPANBOX/rollcall/internal/ids"
	"github.com/TAIPANBOX/rollcall/internal/node"
	"github.com/TAIPANBOX/rollcall/internal/store"
)

// Own is what a member's state directory says about it, as a statement
// carries it.
type Own struct {
	ID      *identity.Identity // the member's identity, with the key that signs
	Head    history.Head       // the head of its own chain; zero when the chain is empty
	BootID  ids.BootID         // the boot the latest boot record names; zero without one
	BootSeq uint64             // that boot's sequence number; 0 without one
	OpenWrt string             // the OpenWrt release that record was written on
}

// ErrHistory reports an own history file that does not hold the member's
// chain: it does not decode, holds another member's entry, an entry that
// does not verify under the member's key, an entry that does not follow the
// one before it, or a latest boot record whose body is not the one form
// rollcall writes. Nothing is signed about such a chain.
var ErrHistory = errors.New("attest: the own history file does not hold this member's chain")

// ReadOwn reads, from the state directory dir (/etc/rollcall), the member's
// identity and its own chain, and returns what a statement says of them. It
// only reads: identity.Load, with the checks the daemon's start makes (the
// file 0600 at most, the directory not writable by group or others, a
// regular file whose keys match each other and its checksum), and
// store.ReadFileIn for the history file, which opens no store and so creates
// and removes nothing.
//
// The chain is verified whole before anything is taken from it: every entry
// is the member's, verifies under its key, and follows the one before it
// (seq one more, Prev its hash); the first may start past seq 1, when the
// daemon pruned older entries, and its own signature covers its Prev. A
// missing history file is an empty chain. A missing or unusable identity is
// an error, as is a history file that is not the member's chain
// (ErrHistory) or cannot be read.
func ReadOwn(dir string) (Own, error) {
	id, err := identity.Load(dir)
	if err != nil {
		return Own{}, fmt.Errorf("the member key cannot be read: %w", err)
	}
	o := Own{ID: id}
	b, err := store.ReadFileIn(dir, node.HistoryFile(id.ID))
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return o, nil
	case err != nil:
		return Own{}, fmt.Errorf("the own history cannot be read: %w", err)
	}
	var es []history.Entry
	if err := decodeChain(b, &es); err != nil {
		return Own{}, fmt.Errorf("%w: %v", ErrHistory, err)
	}
	pub := id.Sign.Public().(ed25519.PublicKey)
	for i, e := range es {
		if e.Origin != id.ID {
			return Own{}, fmt.Errorf("%w: entry %d is of member %s", ErrHistory, i, e.Origin)
		}
		if err := e.Verify(pub); err != nil {
			return Own{}, fmt.Errorf("%w: %w", ErrHistory, err)
		}
		if i > 0 && (e.Seq != es[i-1].Seq+1 || e.Prev != es[i-1].Hash()) {
			return Own{}, fmt.Errorf("%w: entry %d does not follow entry %d", ErrHistory, e.Seq, es[i-1].Seq)
		}
	}
	if len(es) == 0 {
		return o, nil
	}
	last := es[len(es)-1]
	o.Head = history.Head{Seq: last.Seq, Hash: last.Hash()}
	for i := len(es) - 1; i >= 0; i-- {
		if es[i].Kind != history.KindBoot {
			continue
		}
		bb, err := node.DecodeBoot(es[i])
		if err != nil {
			return Own{}, fmt.Errorf("%w: boot record %d: %w", ErrHistory, es[i].Seq, err)
		}
		o.BootID, o.BootSeq, o.OpenWrt = bb.Boot.ID, bb.Boot.Seq, bb.Version
		break
	}
	return o, nil
}

// decodeChain decodes the JSON array of a history file, refusing unknown
// fields and anything after the array.
func decodeChain(b []byte, es *[]history.Entry) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(es); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("data after the JSON array")
	}
	return nil
}

// Statement returns the statement o makes with the given nonce, kernel boot
// ID, rollcall version and time.
func (o Own) Statement(nonce []byte, kernelBoot ids.BootID, rollcall string, now time.Time) Statement {
	return Statement{
		Nonce: nonce, Member: o.ID.ID, Head: o.Head, KernelBoot: kernelBoot,
		BootID: o.BootID, BootSeq: o.BootSeq, OpenWrt: o.OpenWrt, Rollcall: rollcall, Time: now.UTC(),
	}
}
