package transport

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"time"
)

// MaxFrame is the largest TCP frame payload in bytes.
const MaxFrame = 65536

// MaxConns is the number of TCP connections served at once. A connection past
// the limit is closed without a reply.
const MaxConns = 8

// readDeadline bounds one whole exchange on a TCP connection, from the
// accept to the end of the reply (security spec 5.4).
const readDeadline = 5 * time.Second

// preAuthDeadline bounds the wait for the whole first frame, from the accept:
// until it has passed authenticate, a connection holds a slot for nothing.
// The client (Stream) seals the frame before it dials and writes it in one
// write right after the handshake, so a slow router adds no time of its own;
// what remains is the path. The largest frame, 64 KiB, needs about three
// round trips of TCP slow start (10 segments, then 20, then 40), under 1 s on
// a 250 ms overlay path; 2 s leaves twice that, and a lost segment or two.
const preAuthDeadline = 2 * time.Second

// maxConnsPerSource is how many of the MaxConns slots one address may hold.
// A member opens one exchange at a time from its tick, and one more for a
// command (join, invite); a LAN device holding idle connections then blocks
// 2 slots, not all 8. A TCP source address has passed the handshake, so it
// cannot be spoofed to take a member's share.
const maxConnsPerSource = 2

var errFrameTooLarge = errors.New("transport: frame exceeds MaxFrame")

// Stream opens a TCP connection to to, sends b as one frame, reads one reply
// frame and closes the connection. It fails when the exchange takes longer than
// 5 s or the reply is not a complete frame.
func (t *Transport) Stream(to netip.AddrPort, b []byte) ([]byte, error) {
	if len(b) > MaxFrame {
		return nil, errFrameTooLarge
	}
	d := net.Dialer{Timeout: readDeadline}
	c, err := d.Dial("tcp", to.String())
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if err := c.SetDeadline(time.Now().Add(readDeadline)); err != nil {
		return nil, err
	}
	if err := writeFrame(c, b); err != nil {
		return nil, err
	}
	return readFrame(c)
}

// acceptLoop accepts connections on ln until ln is closed, by Close or by a
// pass that no longer wants it. A connection past the MaxConns limit, or past
// its address's maxConnsPerSource, is closed at once and counted.
func (t *Transport) acceptLoop(ln *net.TCPListener, onStream func(netip.AddrPort, []byte) []byte) {
	defer t.wg.Done()
	for {
		c, err := ln.AcceptTCP()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || !t.pause() {
				return
			}
			continue
		}
		switch t.admitConn(c, remoteAddr(c).Addr().Unmap()) {
		case connAdmitted:
			t.wg.Add(1)
			go t.serveConn(c, onStream)
		case connRefusedClosed:
			c.Close()
			return
		case connRefusedFull:
			c.Close()
			t.lim.refuse(&t.lim.c.ConnsFull)
		case connRefusedSource:
			c.Close()
			t.lim.refuse(&t.lim.c.ConnsSource)
		}
	}
}

// connVerdict is admitConn's answer.
type connVerdict int

const (
	connAdmitted      connVerdict = iota
	connRefusedFull               // every slot is taken
	connRefusedSource             // the address holds its maxConnsPerSource slots
	connRefusedClosed             // Close has begun
)

// admitConn takes a slot for c from src and records c so Close can shut it.
func (t *Transport) admitConn(c net.Conn, src netip.Addr) connVerdict {
	t.mu.Lock()
	defer t.mu.Unlock()
	switch {
	case t.closed:
		return connRefusedClosed
	case t.bySource[src] >= t.connsPerSource:
		return connRefusedSource
	case len(t.conns) >= MaxConns:
		return connRefusedFull
	}
	t.conns[c] = src
	t.bySource[src]++
	return connAdmitted
}

// releaseConn gives back the slot of c.
func (t *Transport) releaseConn(c net.Conn) {
	t.mu.Lock()
	defer t.mu.Unlock()
	src, ok := t.conns[c]
	if !ok {
		return
	}
	delete(t.conns, c)
	if t.bySource[src]--; t.bySource[src] <= 0 {
		delete(t.bySource, src)
	}
}

// serveConn answers one connection. Its whole first frame must arrive within
// preAuthDeadline and pass authenticate, or the connection closes without a
// reply and the refusal is counted. The reply must be written within
// readDeadline of the accept; one that cannot be framed is not sent.
func (t *Transport) serveConn(c net.Conn, onStream func(netip.AddrPort, []byte) []byte) {
	defer t.wg.Done()
	defer t.releaseConn(c)
	defer c.Close()
	start := time.Now()
	if err := c.SetDeadline(start.Add(preAuthDeadline)); err != nil {
		return
	}
	frame, err := readFrame(c)
	if err != nil {
		t.lim.refuse(&t.lim.c.PreAuth)
		return
	}
	if !t.authenticate(frame) {
		t.lim.refuse(&t.lim.c.AuthFailed)
		return
	}
	if err := c.SetDeadline(start.Add(readDeadline)); err != nil {
		return
	}
	reply := onStream(remoteAddr(c), frame)
	_ = writeFrame(c, reply)
}

// remoteAddr returns the peer address of c, or the zero value if it has none.
func remoteAddr(c net.Conn) netip.AddrPort {
	if ta, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		return ta.AddrPort()
	}
	return netip.AddrPort{}
}

// readFrame reads one frame: a uint32 big-endian length, then that many bytes.
// A length above MaxFrame is refused before any body byte is read.
func readFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > MaxFrame {
		return nil, errFrameTooLarge
	}
	frame := make([]byte, n)
	if _, err := io.ReadFull(r, frame); err != nil {
		return nil, err
	}
	return frame, nil
}

// writeFrame writes b as one frame, in a single write.
func writeFrame(w io.Writer, b []byte) error {
	if len(b) > MaxFrame {
		return errFrameTooLarge
	}
	buf := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(buf, uint32(len(b)))
	copy(buf[4:], b)
	_, err := w.Write(buf)
	return err
}
