package node

import (
	"testing"

	"github.com/TAIPANBOX/rollcall/internal/deliver"
	"github.com/TAIPANBOX/rollcall/internal/history"
	"github.com/TAIPANBOX/rollcall/internal/identity"
)

// ackEntry returns id's acknowledgement of the incident inc, the next entry
// of its chain after head.
func ackEntry(t testing.TB, id *identity.Identity, head history.Head, inc string) history.Entry {
	t.Helper()
	b, err := deliver.AckBody(inc)
	if err != nil {
		t.Fatal(err)
	}
	e, err := history.NewEntry(id, head, history.KindEvent, b)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// TestAckOnlyFromSender (B3): an acknowledgement silences an incident only
// when its author holds the sender role in the current roster. One from a
// member without the role is kept in the history but neither marks the
// incident delivered nor pauses this router's sending for the grace; one
// from a sender does both.
func TestAckOnlyFromSender(t *testing.T) {
	g := newGroup(t, setup{n: 3, running: []bool{true, false, false}, senders: map[int]int{0: 1, 1: 2}})
	a := g.nodes[0]
	sender, plain := g.ids[1], g.ids[2]
	const byPlain, bySender = "00000000000000a1", "00000000000000b2"

	inject(a, ackEntry(t, plain, history.Head{}, byPlain))
	acked := with(a, func() bool { return a.inc.ackedIDs[byPlain] })
	paused := with(a, func() bool { return a.otherAck != 0 })
	if acked {
		t.Error("an acknowledgement from a member without the sender role marked the incident delivered")
	}
	if paused {
		t.Error("an acknowledgement from a member without the sender role paused this router's sending")
	}
	if h := with(a, func() history.Head { return a.log.Head(plain.ID) }); h.Seq != 1 {
		t.Fatalf("the plain member's acknowledgement is not in the history: head %d, want 1", h.Seq)
	}

	inject(a, ackEntry(t, sender, history.Head{}, bySender))
	if !with(a, func() bool { return a.inc.ackedIDs[bySender] }) {
		t.Error("an acknowledgement from a sender did not mark the incident delivered")
	}
	if !with(a, func() bool { return a.otherAck != 0 }) {
		t.Error("an acknowledgement from another sender did not pause this router's sending")
	}
}
