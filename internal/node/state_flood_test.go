package node

import (
	"sync/atomic"
	"testing"
)

// floodNet is a Net that also says whether its transport is under a flood,
// as transport.Transport does.
type floodNet struct {
	*fakeNet
	flood atomic.Bool
}

func (f *floodNet) UnderFlood() bool { return f.flood.Load() }

// TestUnderFloodFromTransport: a flood the transport sees (packets it drops
// before the node, by its read rate limit) shows in the node's status like
// one the node sees itself, and stops showing once the transport's ends.
func TestUnderFloodFromTransport(t *testing.T) {
	g := newGroup(t, setup{n: 1, running: []bool{false}})
	net := &floodNet{fakeNet: g.nets[0]}
	n, err := New(g.cfgs[0], g.stores[0], g.ids[0], net, g.clk, nil)
	if err != nil {
		t.Fatal(err)
	}
	if n.Status().UnderFlood {
		t.Fatal("UnderFlood before any flood")
	}
	net.flood.Store(true)
	if !n.Status().UnderFlood {
		t.Fatal("the transport's flood does not show in the node's status")
	}
	net.flood.Store(false)
	if n.Status().UnderFlood {
		t.Fatal("UnderFlood after the transport's flood ended")
	}
}
