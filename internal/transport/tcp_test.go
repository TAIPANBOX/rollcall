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

func TestReadDeadline(t *testing.T) {
	port := freePort(t)
	tr := listen(t, port, allowAll)
	var calls atomic.Int32
	serve(t, tr, noPacket, func(netip.AddrPort, []byte) []byte {
		calls.Add(1)
		return nil
	})

	// Half a header, then silence: the server must give up after its 5 s deadline.
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
	if elapsed < 4500*time.Millisecond {
		t.Fatalf("connection closed after %v, want about 5 s", elapsed)
	}
	if n := calls.Load(); n != 0 {
		t.Fatalf("onStream ran %d times for a partial frame", n)
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

	// A first frame that fails authentication gets no reply.
	c := dial(t, addr)
	if _, err := c.Write(rawFrame([]byte("bad"), 3)); err != nil {
		t.Fatalf("write: %v", err)
	}
	expectClosed(t, c)
	if n := calls.Load(); n != 0 {
		t.Fatalf("onStream ran %d times for an unauthenticated frame, want 0", n)
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
