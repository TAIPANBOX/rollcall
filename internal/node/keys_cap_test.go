package node

import (
	"testing"

	"github.com/TAIPANBOX/rollcall/internal/epoch"
)

// capRotate makes n, an admin, rotate to the highest sequence number its
// rotation allows under its current roster, epoch.MaxSeq, and deliver that
// key: what a compromised admin can do.
func capRotate(t testing.TB, n *Node) {
	t.Helper()
	with(n, func() any {
		n.keys[len(n.keys)-1].Seq = epoch.MaxSeq - 1
		return nil
	})
	if err := n.Rotate(); err != nil {
		t.Fatalf("rotation to the last sequence number: %v", err)
	}
	if k := currentKey(n); k.Seq != epoch.MaxSeq {
		t.Fatalf("the rotation made sequence number %d, want %d", k.Seq, epoch.MaxSeq)
	}
}
