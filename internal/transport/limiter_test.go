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

func limiterAt(c *fakeClock) *limiter { l := newLimiter(); l.now = c.now; return l }

// addrN is a distinct IPv4 source for each i.
func addrN(i int) netip.Addr {
	return netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
}

// randomSource is a distinct IPv6 source for each i, as a spoofing flood
// uses.
func randomSource(i int) netip.Addr {
	b := netip.MustParseAddr("2001:db8::").As16()
	b[12], b[13], b[14], b[15] = byte(i>>24), byte(i>>16), byte(i>>8), byte(i)
	return netip.AddrFrom16(b)
}

// A genuine datagram is one authenticate accepts: here, one that begins
// with "member". Junk is what a device without the group key can send.
var (
	heartbeat = []byte("member heartbeat")
	junk      = bytes.Repeat([]byte{0xee}, 64)
)

// authCounter is an authenticate that accepts genuine datagrams and counts
// its calls, the AEAD work the transport spends.
type authCounter struct{ calls int }

func (a *authCounter) auth(b []byte) bool {
	a.calls++
	return bytes.HasPrefix(b, []byte("member"))
}

func admitN(l *limiter, a netip.Addr, b []byte, auth func([]byte) bool, n int) (admitted int) {
	for range n {
		if l.admit(a, b, auth) {
			admitted++
		}
	}
	return admitted
}

// TestSpoofedMemberAddressKeepsItsHeartbeats: a LAN device sends 50
// datagrams a second with member X's source addresses, its link-local one
// (as to ff02::114) and its unicast one, for a minute. Every heartbeat X
// sends in that minute still reaches the node: spoofing a member's address
// at tens of packets a second must not make the group call it silent.
func TestSpoofedMemberAddressKeepsItsHeartbeats(t *testing.T) {
	clk := &fakeClock{}
	l := limiterAt(clk)
	a := &authCounter{}
	xs := []netip.Addr{netip.MustParseAddr("fe80::2%br-lan"), netip.MustParseAddr("192.168.1.2")}
	for _, x := range xs {
		if !l.admit(x, heartbeat, a.auth) {
			t.Fatalf("X's first heartbeat from %s refused", x)
		}
	}
	const step = 20 * time.Millisecond // 50 a second from each address
	for i := 1; i <= 3000; i++ {
		clk.add(step)
		for _, x := range xs {
			l.admit(x, junk, a.auth)
		}
		if i%250 == 0 { // every 5 s
			for _, x := range xs {
				if !l.admit(x, heartbeat, a.auth) {
					t.Fatalf("X's heartbeat from %s at %v dropped while its address is spoofed at 50/s", x, clk.at)
				}
			}
		}
	}
}

// TestRandomSourceFloodSparesKnownMembers: a flood of 10 000 datagrams a
// second, each from a new address, for a minute. Every heartbeat of 31 known
// members still reaches the node, and the reads never wait, so the kernel
// drops nothing for the read ceiling at that rate.
func TestRandomSourceFloodSparesKnownMembers(t *testing.T) {
	clk := &fakeClock{}
	l := limiterAt(clk)
	a := &authCounter{}
	var members []netip.Addr
	for i := range 31 {
		m := netip.MustParseAddr("fe80::1:" + strconv.Itoa(i+1) + "%br-lan")
		members = append(members, m)
		if !l.admit(m, heartbeat, a.auth) {
			t.Fatalf("member %s's first heartbeat refused", m)
		}
	}
	const perSecond = 10000
	src := 0
	for sec := range 60 {
		for i := range perSecond {
			clk.add(time.Second / perSecond)
			l.admit(randomSource(src), junk, a.auth)
			src++
			if sec%5 == 0 && i == perSecond/2 {
				for _, m := range members {
					if !l.admit(m, heartbeat, a.auth) {
						t.Fatalf("member %s's heartbeat at %v dropped by a random-source flood of %d/s", m, clk.at, perSecond)
					}
				}
			}
		}
	}
	if !l.underFlood() {
		t.Fatal("UnderFlood is false during a random-source flood")
	}
}

// TestReadCeilingAboveOldSaturation: at 10 000 datagrams a second, about
// where a small router's CPU saturated before there was a read budget, no
// read waits, so no genuine datagram is left to the kernel to drop.
func TestReadCeilingAboveOldSaturation(t *testing.T) {
	clk := &fakeClock{}
	l := limiterAt(clk)
	for i := range 20000 {
		clk.add(100 * time.Microsecond)
		if d := l.pace(); d > 0 {
			t.Fatalf("read %d at 10 000/s waits %v; the kernel would drop datagrams at that rate", i, d)
		}
	}
}

// TestUnknownSourceFloodIsBounded: junk from an address that never passed
// authenticate never reaches the node, and costs at most the unknown budget
// of authenticate calls: one address's rate, and the rate of all unknown
// addresses together. A genuine datagram from a new address passes.
func TestUnknownSourceFloodIsBounded(t *testing.T) {
	clk := &fakeClock{}
	l := limiterAt(clk)
	a := &authCounter{}
	one := netip.MustParseAddr("192.168.1.66")
	handed := 0
	for range 10 * 1000 { // 1000 a second for 10 s
		clk.add(time.Millisecond)
		if l.admit(one, junk, a.auth) {
			handed++
		}
	}
	if handed != 0 {
		t.Fatalf("%d junk datagrams from one unknown address reached the node", handed)
	}
	if max := sourceBurst + sourceRate*10 + 1; a.calls > max {
		t.Fatalf("one unknown address cost %d authenticate calls in 10 s, want at most %d", a.calls, max)
	}

	a.calls = 0
	for i := range 10 * 10000 { // 10 000 a second from new addresses for 10 s
		clk.add(100 * time.Microsecond)
		if l.admit(randomSource(i), junk, a.auth) {
			handed++
		}
	}
	if handed != 0 {
		t.Fatalf("%d junk datagrams from unknown addresses reached the node", handed)
	}
	if max := unknownBurst + unknownRate*10 + 1; a.calls > max {
		t.Fatalf("a random-source flood cost %d authenticate calls in 10 s, want at most %d", a.calls, max)
	}
	if c := l.counters(); c.Unverified == 0 || c.UnknownLimited == 0 {
		t.Fatalf("Counters() = %+v, want the failed and the unchecked datagrams counted", c)
	}

	clk.add(time.Second)
	if !l.admit(netip.MustParseAddr("192.168.1.7"), heartbeat, a.auth) {
		t.Fatal("a genuine datagram from a new address refused")
	}
}

// TestKnownSetIsBoundedAndExpires: an address is known after a datagram from
// it passed authenticate, and stays known while datagrams keep coming; after
// knownTTL of silence it is checked again. The set holds at most maxKnown
// addresses and gives up the longest unseen one.
func TestKnownSetIsBoundedAndExpires(t *testing.T) {
	clk := &fakeClock{}
	l := limiterAt(clk)
	a := &authCounter{}
	x := netip.MustParseAddr("192.168.1.2")
	l.admit(x, heartbeat, a.auth)
	if a.calls != 1 {
		t.Fatalf("the first datagram from a new address made %d authenticate calls, want 1", a.calls)
	}
	for range 2 { // each datagram keeps it known for another knownTTL
		clk.add(knownTTL - time.Second)
		l.admit(x, heartbeat, a.auth)
		if a.calls != 1 {
			t.Fatalf("a known address was checked again within knownTTL of its last datagram (%d calls)", a.calls)
		}
	}
	clk.add(knownTTL + time.Second)
	if !l.admit(x, heartbeat, a.auth) || a.calls != 2 {
		t.Fatalf("after knownTTL of silence: %d authenticate calls, want 2 (checked again, then passed)", a.calls)
	}

	for i := range maxKnown + 50 {
		clk.add(time.Second)
		l.admit(addrN(i), heartbeat, a.auth)
	}
	if n := len(l.known); n > maxKnown {
		t.Fatalf("%d known addresses, want at most %d", n, maxKnown)
	}
	calls := a.calls
	l.admit(addrN(maxKnown+49), heartbeat, a.auth) // the newest stays known
	if a.calls != calls {
		t.Fatal("the most recently learned address was given up")
	}
	l.admit(addrN(0), heartbeat, a.auth) // the oldest was given up
	if a.calls != calls+1 {
		t.Fatal("the longest unseen address is still known past maxKnown")
	}
}

// TestKnownSourceBudget: a known address hands the node its burst at once
// and its rate after that; all known addresses together hand on at most the
// known burst.
func TestKnownSourceBudget(t *testing.T) {
	clk := &fakeClock{}
	l := limiterAt(clk)
	a := &authCounter{}
	x := netip.MustParseAddr("192.168.1.2")
	if got := admitN(l, x, heartbeat, a.auth, 2*sourceBurst); got != sourceBurst {
		t.Fatalf("%d at once from a known address: %d handed on, want %d", 2*sourceBurst, got, sourceBurst)
	}
	clk.add(time.Second)
	if got := admitN(l, x, heartbeat, a.auth, 2*sourceRate); got != sourceRate {
		t.Fatalf("one second later: %d handed on, want %d", got, sourceRate)
	}
	if c := l.counters(); c.SourceLimited != sourceBurst+sourceRate {
		t.Fatalf("SourceLimited = %d, want %d", c.SourceLimited, sourceBurst+sourceRate)
	}

	clk.add(time.Hour)
	l = limiterAt(clk)
	total := 0
	for i := range 2 * knownBurst / sourceBurst {
		total += admitN(l, addrN(i), heartbeat, a.auth, sourceBurst)
	}
	if total > knownBurst+unknownBurst {
		t.Fatalf("known addresses together handed on %d at once, want at most %d", total, knownBurst+unknownBurst)
	}
	if c := l.counters(); c.KnownLimited == 0 {
		t.Fatalf("Counters() = %+v, want the datagrams over the known rate counted", c)
	}
}

// TestUntrackedSourceUsesGlobalBudget: with the source table full of active
// addresses, a datagram from a new address meets only the global budget; a
// genuine one passes.
func TestUntrackedSourceUsesGlobalBudget(t *testing.T) {
	clk := &fakeClock{}
	l := limiterAt(clk)
	a := &authCounter{}
	// A table full of addresses that have just spent their burst, right after
	// a sweep: none can be swept yet.
	l.swept = clk.at
	for i := range maxSources {
		l.sources[randomSource(i)] = &bucket{tokens: 0, last: clk.at}
	}
	if !l.admit(netip.MustParseAddr("192.168.1.9"), heartbeat, a.auth) {
		t.Fatal("a genuine datagram from a new address refused while the source table is full")
	}
	if n := len(l.sources); n > maxSources {
		t.Fatalf("%d sources held, want at most %d", n, maxSources)
	}
	if c := l.counters(); c.Untracked == 0 {
		t.Fatalf("Counters() = %+v, want the untracked datagram counted", c)
	}
	clk.add(2*sourceBurst/sourceRate*time.Second + time.Second)
	l.admit(netip.MustParseAddr("192.168.1.10"), heartbeat, a.auth)
	if _, ok := l.sources[netip.MustParseAddr("192.168.1.10")]; !ok {
		t.Fatal("idle sources were not swept to make room")
	}
}

// TestOversizeCounted: a datagram over MaxDatagram is dropped and counted,
// without an authenticate call.
func TestOversizeCounted(t *testing.T) {
	l := limiterAt(&fakeClock{})
	a := &authCounter{}
	big := append([]byte("member"), make([]byte, MaxDatagram)...)
	if l.admit(netip.MustParseAddr("192.168.1.66"), big, a.auth) {
		t.Fatal("an oversize datagram was handed on")
	}
	if c := l.counters(); c.Oversize != 1 || a.calls != 0 {
		t.Fatalf("Oversize = %d, authenticate calls %d; want 1 and 0", c.Oversize, a.calls)
	}
	if !l.admit(netip.MustParseAddr("192.168.1.66"), big[:MaxDatagram], a.auth) {
		t.Fatal("a genuine datagram of MaxDatagram bytes was refused")
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
	a := &authCounter{}
	src := netip.MustParseAddr("192.168.1.66")
	admitN(l, src, junk, a.auth, floodBurst-1)
	if l.underFlood() {
		t.Fatalf("UnderFlood after %d refusals, want it only at %d", floodBurst-1, floodBurst)
	}
	admitN(l, src, junk, a.auth, 1)
	if !l.underFlood() {
		t.Fatalf("UnderFlood not raised after %d refusals in one window", floodBurst)
	}
	admitN(l, src, junk, a.auth, 500)
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
		admitN(l, src, junk, a.auth, 1)
	}
	if l.underFlood() {
		t.Fatal("UnderFlood raised by refusals spread thinner than floodBurst per window")
	}
	admitN(l, src, junk, a.auth, 100)
	if c := l.counters(); !l.underFlood() || c.Floods != 2 {
		t.Fatalf("a second flood: UnderFlood %v, Floods %d; want true and 2", l.underFlood(), c.Floods)
	}
}

// genuineOnly is the transport's authenticate in the socket tests: a
// datagram that begins with "member" carries the group key.
func genuineOnly(b []byte) bool { return bytes.HasPrefix(b, []byte("member")) }

// flood sends n datagrams to ap from one socket, as fast as it can.
func flood(t *testing.T, network string, ap netip.AddrPort, n int, payload []byte) {
	t.Helper()
	c, err := net.Dial(network, ap.String())
	if err != nil {
		t.Error(err)
		return
	}
	defer c.Close()
	for range n {
		c.Write(payload) // a full socket buffer drops some: the point is the rate
	}
}

// TestUDPFloodFromOneSourceIsBounded is I4 at the socket: junk flooding the
// port from an address that never passed authenticate reaches the node not
// once, and the transport says it is under flood.
func TestUDPFloodFromOneSourceIsBounded(t *testing.T) {
	port := freePort(t)
	tr := listen(t, port, genuineOnly)
	var handed atomic.Int64
	serve(t, tr, func(netip.AddrPort, []byte) { handed.Add(1) }, echo)

	flood(t, "udp", loop4(port), 2000, junk)
	eventually(t, "the flood refused", func() bool { return tr.UnderFlood() })
	if n := handed.Load(); n != 0 {
		t.Fatalf("a junk flood from one unknown address handed %d datagrams to the node, want 0", n)
	}
	if c := tr.Counters(); c.Unverified == 0 {
		t.Fatalf("Counters() = %+v, want the failed datagrams counted", c)
	}
}

// TestSpoofedSourceOverUnicast: at the socket, a second sender on a member's
// own address (what spoofing it looks like to the router) sends junk at 50
// a second; every datagram of the member still reaches the node.
func TestSpoofedSourceOverUnicast(t *testing.T) {
	port := freePort(t)
	tr := listen(t, port, genuineOnly)
	got := make(chan string, 64)
	serve(t, tr, func(_ netip.AddrPort, b []byte) {
		if bytes.HasPrefix(b, []byte("member")) {
			got <- string(b)
		}
	}, echo)
	member, err := net.Dial("udp", loop4(port).String())
	if err != nil {
		t.Fatal(err)
	}
	defer member.Close()
	spoof, err := net.Dial("udp", loop4(port).String())
	if err != nil {
		t.Fatal(err)
	}
	defer spoof.Close()

	sent := 0
	for i := range 100 { // 2 s at 50 a second
		spoof.Write(junk)
		if i%5 == 0 {
			msg := "member-" + strconv.Itoa(sent)
			if _, err := member.Write([]byte(msg)); err != nil {
				t.Fatal(err)
			}
			sent++
		}
		time.Sleep(20 * time.Millisecond)
	}
	for i := range sent {
		select {
		case <-got:
		case <-time.After(3 * time.Second):
			t.Fatalf("%d of the member's %d datagrams reached the node while its address was spoofed at 50/s", i, sent)
		}
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
	tr := listen(t, port, genuineOnly)
	member := make(chan string, 16)
	serve(t, tr, func(from netip.AddrPort, b []byte) {
		if from.Addr().Is6() {
			member <- string(b)
		}
	}, echo)

	done := make(chan struct{})
	go func() {
		defer close(done)
		flood(t, "udp", loop4(port), 5000, junk)
	}()
	v6 := netip.AddrPortFrom(netip.MustParseAddr("::1"), uint16(port))
	c, err := net.Dial("udp", v6.String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for i := range 5 {
		msg := "member-heartbeat-" + strconv.Itoa(i)
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
