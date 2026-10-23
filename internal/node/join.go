package node

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/clock"
	"github.com/TAIPANBOX/rollcall/internal/identity"
	"github.com/TAIPANBOX/rollcall/internal/pairing"
	"github.com/TAIPANBOX/rollcall/internal/roster"
	"github.com/TAIPANBOX/rollcall/internal/store"
)

// # Join (security spec 6, join)
//
// On an admin router, Invite opens a join window (pairing.Inviter, 10
// minutes, one use). While it is open, and only then, the node's
// Authenticate lets a TCP frame through that is not a wire packet but has
// the length of a join request, and HandleStream hands it to the
// Inviter: a request that does not open under the code gets no answer and
// leaves the code open. A valid one burns the code; the admin adds the new
// router to the roster (with the sender role if Invite asked for it),
// signs the roster, and answers with pairing.NewJoinResponse: the roster,
// the current epoch key and, for a sender only, the bot token. At most one
// attempt is read per joinSpacing. The request travels over TCP only: a
// UDP packet is never one.
//
// On the new router, Join sends the request and stores what the answer
// carries, so that New can start from it.

// joinSpacing is the least time between two join attempts the node reads.
const joinSpacing = time.Second

// joinWindow is an open invitation.
type joinWindow struct {
	inv    pairing.Inviter
	open   bool
	sender bool
	next   time.Duration
}

// Invite opens a join window on this admin router for one new router, to
// be reached at bootstrap, and returns its join code. The router gets the
// sender role when sender is true. Opening a window closes the one before.
func (n *Node) Invite(bootstrap netip.AddrPort, sender bool) (pairing.Code, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.running() {
		return pairing.Code{}, n.why()
	}
	if _, ok := authority(n.cur(), n.id.ID); !ok {
		return pairing.Code{}, ErrNotAdmin
	}
	c, err := n.join.inv.Open(n.clk.Now(), bootstrap, n.id)
	if err != nil {
		return pairing.Code{}, err
	}
	n.join.open, n.join.sender = true, sender
	return c, nil
}

// joinFrame reports whether b may be a join request while a window is
// open: its length is one a request can have and its version byte is 1.
func (n *Node) joinFrame(b []byte) bool {
	return n.join.open && len(b) >= pairing.MaxRequestSize-roster.MaxNameLen+1 && len(b) <= pairing.MaxRequestSize && b[0] == 1
}

// joinIn answers a join request, or returns nil.
func (n *Node) joinIn(b []byte, now clock.Stamp) []byte {
	if now.Mono < n.join.next {
		return nil
	}
	n.join.next = now.Mono + joinSpacing
	req, err := n.join.inv.Accept(b, n.clk.Now())
	if err != nil {
		return nil
	}
	n.join.open = false
	err = n.publishLocked(func(r *roster.Roster) error {
		m := roster.Member{ID: req.ID, Name: req.Name, SignPub: req.SignPub, RecvPub: req.RecvPub}
		if n.join.sender {
			m.Roles = []roster.Role{roster.RoleSender}
		}
		r.Members = append(r.Members, m)
		return nil
	}, nil, now)
	if err != nil {
		return nil
	}
	var sec *pairing.Secrets
	if n.join.sender && n.secrets.BotToken != "" {
		sec = &pairing.Secrets{BotToken: n.secrets.BotToken, ChatID: n.secrets.ChatID}
	}
	resp, err := pairing.NewJoinResponse(req, n.curSigned(), n.current(), sec, n.id)
	if err != nil {
		return nil
	}
	return resp
}

// Join sends self's join request, made with the code c under name, over nt
// to the admin the code names, and writes what the admin answers into st:
// the roster, the epoch key and, for a sender, the bot token and chat ID.
func Join(st *store.Store, nt Net, c pairing.Code, self *identity.Identity, name string) error {
	if st == nil || nt == nil {
		return ErrArgument
	}
	req, err := pairing.NewJoinRequest(c, self, name)
	if err != nil {
		return err
	}
	resp, err := nt.Stream(c.Bootstrap, req)
	if err != nil {
		return fmt.Errorf("node: the admin router did not answer the join request: %w", err)
	}
	r, k, sec, err := pairing.OpenJoinResponse(c, resp, self)
	if err != nil {
		return err
	}
	if err := Bootstrap(st, r, k); err != nil {
		return err
	}
	if sec != nil {
		return SaveSecrets(st, sec.BotToken, sec.ChatID)
	}
	return nil
}
