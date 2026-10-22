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

// readDeadline bounds one whole exchange on a TCP connection, from the first
// byte of the request to the end of the reply.
const readDeadline = 5 * time.Second

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

// acceptLoop accepts connections on ln until the transport closes. A connection
// past the MaxConns limit is closed at once.
func (t *Transport) acceptLoop(ln *net.TCPListener, onStream func(netip.AddrPort, []byte) []byte) {
	defer t.wg.Done()
	for {
		c, err := ln.AcceptTCP()
		if err != nil {
			if !t.pause() {
				return
			}
			continue
		}
		select {
		case t.slots <- struct{}{}:
		default:
			c.Close()
			continue
		}
		if !t.track(c) {
			<-t.slots
			c.Close()
			return
		}
		t.wg.Add(1)
		go t.serveConn(c, onStream)
	}
}

// serveConn answers one connection. Its first frame must pass authenticate, or
// the connection closes without a reply. A reply that cannot be framed is not
// sent, and the connection closes.
func (t *Transport) serveConn(c net.Conn, onStream func(netip.AddrPort, []byte) []byte) {
	defer t.wg.Done()
	defer func() { <-t.slots }()
	defer t.untrack(c)
	defer c.Close()
	if err := c.SetDeadline(time.Now().Add(readDeadline)); err != nil {
		return
	}
	frame, err := readFrame(c)
	if err != nil || !t.authenticate(frame) {
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
