package node

import (
	"testing"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/events"
)

// TestCloneProvenThroughHelperRecorded: a clone of r03 that only a helper
// hears is proven when the helper's answer to an indirect probe carries the
// clone's heartbeat (same boot sequence number, another boot ID). The
// DuplicateIdentity event that proof raises goes into r01's own chain, as
// one proven by a heartbeat heard directly does, so it reaches the history
// and the chat.
func TestCloneProvenThroughHelperRecorded(t *testing.T) {
	g := newGroup(t, setup{n: 3, running: []bool{true, true, false}})
	a, b := g.nodes[0], g.nodes[1]
	c := g.ids[2]
	original, clone := bootN(2, 1), bootN(2, 9)
	counter := uint64(0)
	beat := func(n *Node, boot [16]byte) {
		counter++
		n.HandlePacket(g.addrs[2], sealPlain(t, g.key, heartbeatPlain(t, g.key, c, "r03", boot, counter)))
	}
	// r01 hears the original, r02 the clone, both in boot sequence 1.
	for el := time.Duration(0); el < 20*sec; el += 5 * sec {
		beat(a, original)
		beat(b, clone)
		g.run(5 * sec)
	}
	// r01 stops hearing r03 and asks r02, which still hears the clone.
	for el := time.Duration(0); el < 60*sec; el += 5 * sec {
		beat(b, clone)
		g.run(5 * sec)
	}
	if got := countType(ownTypes(a), events.DuplicateIdentity); got != 1 {
		t.Fatalf("r01 recorded %d DuplicateIdentity events, want 1 (its own chain: %v)", got, ownTypes(a))
	}
}
