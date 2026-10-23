package transport

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestStreamRoundTrip(t *testing.T) {
	port := freePort(t)
	tr := listen(t, port, allowAll)
	serve(t, tr, noPacket, echo)

	reply, err := tr.Stream(loop4(port), []byte("ping"))
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	if string(reply) != "re:ping" {
		t.Fatalf("reply = %q, want %q", reply, "re:ping")
	}
	// An empty request is a valid frame.
	reply, err = tr.Stream(loop4(port), nil)
	if err != nil || string(reply) != "re:" {
		t.Fatalf("empty Stream = %q, %v; want %q", reply, err, "re:")
	}
}

func TestFrameLimit(t *testing.T) {
	port := freePort(t)
	tr := listen(t, port, allowAll)
	var calls atomic.Int32
	serve(t, tr, noPacket, func(netip.AddrPort, []byte) []byte {
		calls.Add(1)
		return []byte("ok")
	})
	addr := loop4(port)

	// A header declaring 65537 bytes: the server closes without replying and
	// never hands the body to onStream.
	c := dial(t, addr)
	if _, err := c.Write(rawFrame(make([]byte, MaxFrame+1), MaxFrame+1)); err != nil {
		// The server may reset the connection before the body is written.
		t.Logf("write of oversize frame: %v", err)
	}
	expectClosed(t, c)
	if n := calls.Load(); n != 0 {
		t.Fatalf("onStream ran %d times for an oversize frame, want 0", n)
	}

	// Exactly MaxFrame bytes is accepted.
	reply, err := tr.Stream(addr, make([]byte, MaxFrame))
	if err != nil {
		t.Fatalf("Stream at the limit: %v", err)
	}
	if string(reply) != "ok" {
		t.Fatalf("reply = %q, want %q", reply, "ok")
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("onStream ran %d times, want 1", n)
	}
}

func TestStreamRejectsOversizeWithoutDialing(t *testing.T) {
	tr := listen(t, freePort(t), allowAll)
	// Port 1 has no listener: a dial would fail with another error.
	_, err := tr.Stream(loop4(1), make([]byte, MaxFrame+1))
	if !errors.Is(err, errFrameTooLarge) {
		t.Fatalf("Stream of an oversize frame: err = %v, want errFrameTooLarge", err)
	}
}

func TestStreamToClosedPortFails(t *testing.T) {
	tr := listen(t, freePort(t), allowAll)
	if _, err := tr.Stream(loop4(freePort(t)), []byte("x")); err == nil {
		t.Fatal("Stream to a port with no listener returned no error")
	}
}

func TestOversizeReplyIsNotSent(t *testing.T) {
	port := freePort(t)
	tr := listen(t, port, allowAll)
	serve(t, tr, noPacket, func(netip.AddrPort, []byte) []byte {
		return make([]byte, MaxFrame+1)
	})
	if reply, err := tr.Stream(loop4(port), []byte("x")); err == nil {
		t.Fatalf("Stream accepted an oversize reply of %d bytes", len(reply))
	}
}

func TestConnLimit(t *testing.T) {
	port := freePort(t)
	tr := listen(t, port, allowAll)
	tr.connsPerSource = MaxConns // the loopback test has one source address
	serve(t, tr, noPacket, echo)
	addr := loop4(port)

	// Eight connections that send nothing hold every slot.
	var held []net.Conn
	for range MaxConns {
		held = append(held, dial(t, addr))
	}
	// The ninth is accepted by the kernel and closed by the server at once.
	expectClosed(t, dial(t, addr))

	for _, c := range held {
		c.Close()
	}
	// Once the held connections are gone, a new exchange gets a slot.
	deadline := time.Now().Add(5 * time.Second)
	for {
		reply, err := tr.Stream(addr, []byte("x"))
		if err == nil {
			if string(reply) != "re:x" {
				t.Fatalf("reply after slots freed = %q, want %q", reply, "re:x")
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no connection slot freed within 5 s: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestReadDeadline is M1: a connection that has not delivered its whole first
// frame within preAuthDeadline (2 s) is closed, so an idle or slow-drip
// client holds a slot for 2 s, not for the 5 s of a whole exchange.
func TestReadDeadline(t *testing.T) {
	port := freePort(t)
	tr := listen(t, port, allowAll)
	var calls atomic.Int32
	serve(t, tr, noPacket, func(netip.AddrPort, []byte) []byte {
		calls.Add(1)
		return nil
	})

	// Half a header, then silence: the server must give up at its 2 s
	// pre-authentication deadline.
	c := dial(t, loop4(port))
	if _, err := c.Write([]byte{0, 0}); err != nil {
		t.Fatalf("write: %v", err)
	}
	start := time.Now()
	if err := c.SetReadDeadline(time.Now().Add(9 * time.Second)); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(c)
	elapsed := time.Since(start)
	if err != nil && !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("server did not close the silent connection: %v", err)
	}
	if len(data) != 0 {
		t.Fatalf("server replied with %d bytes to a partial frame", len(data))
	}
	if elapsed < 1500*time.Millisecond || elapsed > 3*time.Second {
		t.Fatalf("connection closed after %v, want about 2 s", elapsed)
	}
	if n := calls.Load(); n != 0 {
		t.Fatalf("onStream ran %d times for a partial frame", n)
	}
	eventually(t, "the timed-out connection counted", func() bool { return tr.Counters().PreAuth == 1 })
}

// TestExchangeKeepsFiveSeconds: once the first frame is in, the exchange has
// the rest of the 5 s read deadline, so a reply that takes 3 s still arrives.
func TestExchangeKeepsFiveSeconds(t *testing.T) {
	port := freePort(t)
	tr := listen(t, port, allowAll)
	serve(t, tr, noPacket, func(_ netip.AddrPort, b []byte) []byte {
		time.Sleep(3 * time.Second)
		return []byte("slow")
	})
	reply, err := tr.Stream(loop4(port), []byte("x"))
	if err != nil || string(reply) != "slow" {
		t.Fatalf("a 3 s exchange = %q, %v; want the reply", reply, err)
	}
}

// TestOneSourceCannotTakeEverySlot is M1: a LAN device holding idle
// connections gets at most maxConnsPerSource slots, so a member from another
// address still gets its exchange (key rotation, roster, catch-up, join), and
// the refusals raise UnderFlood.
func TestOneSourceCannotTakeEverySlot(t *testing.T) {
	lo := loopbackName(t)
	if !hasAddr(t, lo, netip.MustParseAddr("::1")) {
		t.Skip("no ::1 on the loopback interface")
	}
	port := freePort(t)
	tr := listen(t, port, allowAll)
	serve(t, tr, noPacket, echo)

	const idle = floodBurst + maxConnsPerSource
	for range idle {
		dial(t, loop4(port)) // never sends a byte
	}
	member := netip.AddrPortFrom(netip.MustParseAddr("::1"), uint16(port))
	reply, err := tr.Stream(member, []byte("rotate"))
	if err != nil || string(reply) != "re:rotate" {
		t.Fatalf("a member's exchange while one address holds idle connections = %q, %v", reply, err)
	}
	eventually(t, "refusals counted", func() bool { return tr.Counters().ConnsSource >= idle-maxConnsPerSource })
	if !tr.UnderFlood() {
		t.Fatalf("UnderFlood is false after %d refused connections", tr.Counters().ConnsSource)
	}
}

// TestConnSlots: MaxConns in all and maxConnsPerSource per address; a
// released slot is free again.
func TestConnSlots(t *testing.T) {
	tr := &Transport{connsPerSource: maxConnsPerSource, done: make(chan struct{}), conns: map[net.Conn]netip.Addr{}, bySource: map[netip.Addr]int{}}
	var held []net.Conn
	conn := func() net.Conn {
		a, b := net.Pipe()
		t.Cleanup(func() { a.Close(); b.Close() })
		return a
	}
	for i := range MaxConns / maxConnsPerSource {
		src := addrN(i)
		for range maxConnsPerSource {
			c := conn()
			if r := tr.admitConn(c, src); r != connAdmitted {
				t.Fatalf("slot %d for %s refused: %v", len(held), src, r)
			}
			held = append(held, c)
		}
		if r := tr.admitConn(conn(), src); r != connRefusedSource {
			t.Fatalf("slot %d for %s: %v, want connRefusedSource", maxConnsPerSource+1, src, r)
		}
	}
	if r := tr.admitConn(conn(), addrN(99)); r != connRefusedFull {
		t.Fatalf("a new address with every slot taken: %v, want connRefusedFull", r)
	}
	tr.releaseConn(held[0])
	if r := tr.admitConn(conn(), addrN(99)); r != connAdmitted {
		t.Fatalf("a new address after a release: %v, want connAdmitted", r)
	}
	if r := tr.admitConn(conn(), addrN(0)); r != connRefusedFull {
		t.Fatalf("every slot taken again: %v, want connRefusedFull", r)
	}
	tr.Close()
	if r := tr.admitConn(conn(), addrN(50)); r != connRefusedClosed {
		t.Fatalf("after Close: %v, want connRefusedClosed", r)
	}
}

func TestFirstFrameMustAuthenticate(t *testing.T) {
	port := freePort(t)
	auth := func(f []byte) bool { return string(f) == "good" }
	tr := listen(t, port, auth)
	var calls atomic.Int32
	serve(t, tr, noPacket, func(_ netip.AddrPort, b []byte) []byte {
		calls.Add(1)
		return []byte("ok")
	})
	addr := loop4(port)

	// A first frame that fails authentication gets no reply, and is counted.
	c := dial(t, addr)
	if _, err := c.Write(rawFrame([]byte("bad"), 3)); err != nil {
		t.Fatalf("write: %v", err)
	}
	expectClosed(t, c)
	if n := calls.Load(); n != 0 {
		t.Fatalf("onStream ran %d times for an unauthenticated frame, want 0", n)
	}
	if n := tr.Counters().AuthFailed; n != 1 {
		t.Fatalf("AuthFailed = %d after one unauthenticated frame, want 1", n)
	}

	// The client sees the same: no reply frame, so Stream returns an error.
	if _, err := tr.Stream(addr, []byte("bad")); err == nil {
		t.Fatal("Stream of an unauthenticated frame returned no error")
	}

	// A frame that passes authentication is answered.
	reply, err := tr.Stream(addr, []byte("good"))
	if err != nil || string(reply) != "ok" {
		t.Fatalf("authenticated Stream = %q, %v; want %q", reply, err, "ok")
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("onStream ran %d times, want 1", n)
	}
}
