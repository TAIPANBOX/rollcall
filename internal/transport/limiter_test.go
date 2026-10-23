package transport

import (
	"bytes"
	"net"
	"net/netip"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// fakeClock drives a limiter: tests move it by hand.
type fakeClock struct{ at time.Duration }

func (c *fakeClock) now() time.Duration  { return c.at }
func (c *fakeClock) add(d time.Duration) { c.at += d }
func limiterAt(c *fakeClock) *limiter    { l := newLimiter(); l.now = c.now; return l }
func addrN(i int) netip.Addr {
	return netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
}
func admitN(l *limiter, a netip.Addr, n int) (admitted int) {
	for range n {
		if l.admit(a, 100) {
			admitted++
		}
	}
	return admitted
}

// TestSourceRate: one source hands on its burst at once and its rate after
// that; the rest is dropped and counted.
func TestSourceRate(t *testing.T) {
	clk := &fakeClock{}
	l := limiterAt(clk)
	a := netip.MustParseAddr("192.168.1.66")
	if got := admitN(l, a, 100); got != sourceBurst {
		t.Fatalf("a burst of 100 from one source: %d handed on, want %d", got, sourceBurst)
	}
	clk.add(time.Second)
	if got := admitN(l, a, 100); got != sourceRate {
		t.Fatalf("one second later: %d handed on, want %d", got, sourceRate)
	}
	if c := l.counters(); c.SourceLimited != 200-sourceBurst-sourceRate {
		t.Fatalf("SourceLimited = %d, want %d", c.SourceLimited, 200-sourceBurst-sourceRate)
	}
}

// TestSourcesAreIndependent: a source over its rate does not take the share
// of another; a heartbeat from a member still passes while a LAN device floods.
func TestSourcesAreIndependent(t *testing.T) {
	clk := &fakeClock{}
	l := limiterAt(clk)
	admitN(l, netip.MustParseAddr("192.168.1.66"), 1000)
	member := netip.MustParseAddr("fe80::2%br-lan")
	for i := range 6 {
		clk.add(5 * time.Second)
		admitN(l, netip.MustParseAddr("192.168.1.66"), 1000)
		if !l.admit(member, 300) {
			t.Fatalf("heartbeat %d of a member refused while another source floods", i)
		}
	}
}

// TestGlobalRate: many sources together hand on at most the global burst and
// then the global rate.
func TestGlobalRate(t *testing.T) {
	clk := &fakeClock{}
	l := limiterAt(clk)
	got := 0
	for i := range 800 {
		got += admitN(l, addrN(i), 1)
	}
	if got != globalBurst {
		t.Fatalf("800 sources at once: %d handed on, want %d", got, globalBurst)
	}
	clk.add(time.Second)
	got = 0
	for i := 800; i < 1000; i++ {
		got += admitN(l, addrN(i), 2)
	}
	if got != globalRate {
		t.Fatalf("one second later: %d handed on, want %d", got, globalRate)
	}
	if c := l.counters(); c.RateLimited != 800-globalBurst+400-globalRate {
		t.Fatalf("RateLimited = %d, want %d", c.RateLimited, 800-globalBurst+400-globalRate)
	}
}

// TestSourceTableIsBounded: a flood from ever new addresses fills the table
// to maxSources and no further; sources idle long enough to be full again are
// swept out to make room.
func TestSourceTableIsBounded(t *testing.T) {
	clk := &fakeClock{}
	l := limiterAt(clk)
	for i := range maxSources + 100 {
		l.admit(addrN(i), 100)
	}
	if n := len(l.sources); n > maxSources {
		t.Fatalf("%d sources held, want at most %d", n, maxSources)
	}
	if c := l.counters(); c.SourcesFull == 0 {
		t.Fatal("new sources past a full table were not counted")
	}
	clk.add(sourceBurst/sourceRate*time.Second + time.Second)
	if !l.admit(netip.MustParseAddr("192.168.1.2"), 100) {
		t.Fatal("a new source refused once the idle ones could be swept")
	}
	if n := len(l.sources); n > maxSources {
		t.Fatalf("%d sources held after the sweep, want at most %d", n, maxSources)
	}
}

// TestOversizeCounted: a datagram over MaxDatagram is dropped and counted.
func TestOversizeCounted(t *testing.T) {
	l := limiterAt(&fakeClock{})
	if l.admit(netip.MustParseAddr("192.168.1.66"), MaxDatagram+1) {
		t.Fatal("an oversize datagram was handed on")
	}
	if !l.admit(netip.MustParseAddr("192.168.1.66"), MaxDatagram) {
		t.Fatal("a datagram of MaxDatagram bytes was refused")
	}
	if c := l.counters(); c.Oversize != 1 {
		t.Fatalf("Oversize = %d, want 1", c.Oversize)
	}
}

// TestPaceBoundsReads: past the read burst every read waits its share of
// the read rate, so a flood costs at most readRate reads a second.
func TestPaceBoundsReads(t *testing.T) {
	clk := &fakeClock{}
	l := limiterAt(clk)
	var waited time.Duration
	for range readBurst {
		waited += l.pace()
	}
	if waited != 0 {
		t.Fatalf("the first %d reads waited %v, want none", readBurst, waited)
	}
	for range readRate {
		waited = l.pace()
	}
	if waited < 990*time.Millisecond || waited > 1010*time.Millisecond {
		t.Fatalf("after %d reads past the burst the next read waits %v, want about 1 s", readRate, waited)
	}
	if c := l.counters(); c.ReadPaced != readRate {
		t.Fatalf("ReadPaced = %d, want %d", c.ReadPaced, readRate)
	}
	clk.add(2 * time.Second)
	if d := l.pace(); d != 0 {
		t.Fatalf("after the debt is paid a read waits %v, want none", d)
	}
}

// TestFloodRaisedAndLowered: floodBurst refusals within floodWindow raise
// UnderFlood once; floodQuiet without a burst lowers it.
func TestFloodRaisedAndLowered(t *testing.T) {
	clk := &fakeClock{}
	l := limiterAt(clk)
	a := netip.MustParseAddr("192.168.1.66")
	admitN(l, a, sourceBurst+floodBurst-1)
	if l.underFlood() {
		t.Fatalf("UnderFlood after %d refusals, want it only at %d", floodBurst-1, floodBurst)
	}
	admitN(l, a, 1)
	if !l.underFlood() {
		t.Fatalf("UnderFlood not raised after %d refusals in one window", floodBurst)
	}
	admitN(l, a, 500)
	if c := l.counters(); c.Floods != 1 {
		t.Fatalf("Floods = %d during one flood, want 1", c.Floods)
	}
	clk.add(floodQuiet)
	if !l.underFlood() {
		t.Fatal("UnderFlood lowered before floodQuiet had passed")
	}
	clk.add(time.Second)
	if l.underFlood() {
		t.Fatalf("UnderFlood still raised %v after the last burst", floodQuiet+time.Second)
	}
	// Refusals spread thinner than the window never raise it.
	for range 3 * floodBurst {
		clk.add(floodWindow / floodBurst * 2)
		admitN(l, a, sourceRate*int(floodWindow/floodBurst*2/time.Second)+2)
	}
	if l.underFlood() {
		t.Fatal("UnderFlood raised by refusals spread thinner than floodBurst per window")
	}
	admitN(l, a, 1000)
	if c := l.counters(); !l.underFlood() || c.Floods != 2 {
		t.Fatalf("a second flood: UnderFlood %v, Floods %d; want true and 2", l.underFlood(), c.Floods)
	}
}

// flood sends n datagrams to ap from one socket, as fast as it can.
func flood(t *testing.T, network string, ap netip.AddrPort, n int, payload []byte) {
	t.Helper()
	c, err := net.Dial(network, ap.String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for range n {
		c.Write(payload) // a full socket buffer drops some: the point is the rate
	}
}

// TestUDPFloodFromOneSourceIsBounded is I4 at the socket: a LAN device
// flooding the port hands the node no more than one source's share, and the
// transport says it is under flood.
func TestUDPFloodFromOneSourceIsBounded(t *testing.T) {
	port := freePort(t)
	tr := listen(t, port, allowAll)
	var handed atomic.Int64
	serve(t, tr, func(netip.AddrPort, []byte) { handed.Add(1) }, echo)

	start := time.Now()
	flood(t, "udp", loop4(port), 2000, bytes.Repeat([]byte{0xee}, 64))
	time.Sleep(300 * time.Millisecond)
	elapsed := time.Since(start)
	limit := int64(sourceBurst + sourceRate*elapsed.Seconds() + 1)
	if n := handed.Load(); n > limit {
		t.Fatalf("a flood of 2000 datagrams from one source handed %d to the node in %v, want at most %d", n, elapsed, limit)
	}
	if !tr.UnderFlood() {
		t.Fatal("UnderFlood is false after a flood from one source")
	}
	if c := tr.Counters(); c.SourceLimited == 0 {
		t.Fatalf("Counters() = %+v, want the dropped datagrams counted", c)
	}
}

// TestUDPFloodSparesOtherSources: while one address floods, a member's
// datagrams from another address are all handed on.
func TestUDPFloodSparesOtherSources(t *testing.T) {
	lo := loopbackName(t)
	if !hasAddr(t, lo, netip.MustParseAddr("::1")) {
		t.Skip("no ::1 on the loopback interface")
	}
	port := freePort(t)
	tr := listen(t, port, allowAll)
	member := make(chan string, 16)
	serve(t, tr, func(from netip.AddrPort, b []byte) {
		if from.Addr().Is6() {
			member <- string(b)
		}
	}, echo)

	done := make(chan struct{})
	go func() {
		defer close(done)
		flood(t, "udp", loop4(port), 5000, bytes.Repeat([]byte{0xee}, 64))
	}()
	v6 := netip.AddrPortFrom(netip.MustParseAddr("::1"), uint16(port))
	c, err := net.Dial("udp", v6.String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for i := range 5 {
		msg := "heartbeat-" + strconv.Itoa(i)
		if _, err := c.Write([]byte(msg)); err != nil {
			t.Fatal(err)
		}
		select {
		case got := <-member:
			if got != msg {
				t.Fatalf("member datagram %q, want %q", got, msg)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("member datagram %d not handed on while another source floods", i)
		}
		time.Sleep(20 * time.Millisecond)
	}
	<-done
}
