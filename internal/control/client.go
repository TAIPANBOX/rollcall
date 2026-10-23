package control

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

// DefaultCallTimeout bounds a Call from dial to reply. Commands such as
// join wait on the network inside the daemon, so it is generous.
const DefaultCallTimeout = 60 * time.Second

// ErrRequestTooLarge is returned before dialing when the encoded request is
// over MaxRequest.
var ErrRequestTooLarge = fmt.Errorf("control: request over %d bytes", MaxRequest)

// Error is a refusal or a command failure reported by the server. Msg is
// one of the Msg constants or the handler's (redacted) error text.
type Error struct{ Msg string }

func (e *Error) Error() string { return "rollcalld: " + e.Msg }

// Client is the path of the control socket, for the CLI:
//
//	out, err := control.Client("/var/run/rollcall.sock").Call("status")
type Client string

// Call sends one command and returns its output, within DefaultCallTimeout.
func (c Client) Call(cmd string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultCallTimeout)
	defer cancel()
	return c.CallContext(ctx, cmd, args...)
}

// CallContext is Call with the caller's context; its deadline bounds the
// whole exchange.
func (c Client) CallContext(ctx context.Context, cmd string, args ...string) ([]byte, error) {
	req, err := encodeRequest(cmd, args)
	if err != nil {
		return nil, err
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", string(c))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()

	// A server that refuses before reading may close before the write
	// lands; its reply is still there to read, and it is the better answer,
	// so a failed write is not an error by itself.
	_, _ = conn.Write(req)
	rep, err := readReply(conn)
	if err != nil {
		if errors.Is(err, os.ErrDeadlineExceeded) {
			// The connection's deadline is the context's, so the context
			// is ending too; its timer may fire a moment after the read's.
			<-ctx.Done()
		}
		if ctx.Err() != nil {
			return nil, fmt.Errorf("control: %w (%w)", ctx.Err(), err)
		}
		return nil, err
	}
	if !rep.OK {
		return nil, &Error{Msg: rep.Error}
	}
	return []byte(rep.Out), nil
}

// encodeRequest returns the framed request, or ErrRequestTooLarge.
func encodeRequest(cmd string, args []string) ([]byte, error) {
	if args == nil {
		args = []string{}
	}
	body, _ := json.Marshal(request{Cmd: cmd, Args: args}) // strings always encode
	if len(body) > MaxRequest {
		return nil, ErrRequestTooLarge
	}
	return append(binary.BigEndian.AppendUint32(make([]byte, 0, 4+len(body)), uint32(len(body))), body...), nil
}

// readReply reads one reply frame and checks that it is consistent: a
// success carries no error, a refusal carries a reason and no output.
func readReply(r io.Reader) (reply, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return reply{}, fmt.Errorf("control: read reply: %w", err)
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > MaxReply {
		return reply{}, fmt.Errorf("control: reply length %d outside 1..%d", n, MaxReply)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return reply{}, fmt.Errorf("control: read reply: %w", err)
	}
	var rep reply
	if err := decodeOne(body, &rep); err != nil {
		return reply{}, fmt.Errorf("control: decode reply: %w", err)
	}
	if rep.OK == (rep.Error != "") || (!rep.OK && rep.Out != "") {
		return reply{}, errors.New("control: inconsistent reply")
	}
	return rep, nil
}
