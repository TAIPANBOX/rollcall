package control

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestClientRoundTrip(t *testing.T) {
	rec := &recorder{}
	path := serve(t, rec.handler("line one\nline two\n", nil), withCred(fixedCred(0, nil)))
	args := []string{"", "a b", "x\x00y", "\xd0\x94\xd1\x96\xd0\xbc", `"quoted" \ back`}
	out, err := Client(path).Call("roles", args...)
	if err != nil || string(out) != "line one\nline two\n" {
		t.Fatalf("Call = %q, %v", out, err)
	}
	if _, err := Client(path).Call("status"); err != nil {
		t.Fatalf("Call without args: %v", err)
	}
	calls := rec.all()
	if len(calls) != 2 || !slices.Equal(calls[0].args, args) || calls[1].args == nil || len(calls[1].args) != 0 {
		t.Fatalf("handler saw %+v; want the args unchanged, then an empty list", calls)
	}
}

func TestClientServerError(t *testing.T) {
	path := serve(t, (&recorder{}).handler("", errors.New("no group yet")), withCred(fixedCred(0, nil)))
	out, err := Client(path).Call("status")
	var se *Error
	if !errors.As(err, &se) || se.Msg != "no group yet" || out != nil {
		t.Fatalf("Call = %q, %v; want *Error no group yet", out, err)
	}
	if !strings.Contains(err.Error(), "no group yet") {
		t.Fatalf("Error() = %q", err)
	}
}

func TestClientServerErrorWithoutText(t *testing.T) {
	path := serve(t, (&recorder{}).handler("", errors.New("")), withCred(fixedCred(0, nil)))
	_, err := Client(path).Call("status")
	wantRefusal(t, err, MsgFailed)
}

func TestClientNoServer(t *testing.T) {
	_, err := Client(filepath.Join(socketDir(t), "none")).Call("status")
	var se *Error
	if err == nil || errors.As(err, &se) {
		t.Fatalf("Call to a missing socket: %v; want a dial error", err)
	}
}

func TestClientRequestTooLarge(t *testing.T) {
	_, err := Client(filepath.Join(socketDir(t), "none")).Call("notify", strings.Repeat("a", MaxRequest))
	if !errors.Is(err, ErrRequestTooLarge) {
		t.Fatalf("Call with a request over the limit: %v; want ErrRequestTooLarge before dialing", err)
	}
}

// fakeServer accepts one connection at a time, reads whatever arrives and
// answers each with the next raw reply.
func fakeServer(t *testing.T, replies ...[]byte) string {
	t.Helper()
	path := filepath.Join(socketDir(t), "fake")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	ended := make(chan struct{})
	t.Cleanup(func() { close(ended); ln.Close() })
	go func() {
		for _, r := range replies {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			var hdr [4]byte
			if _, err := io.ReadFull(c, hdr[:]); err == nil {
				_, _ = io.CopyN(io.Discard, c, int64(binary.BigEndian.Uint32(hdr[:])))
			}
			if r == nil {
				<-ended // never answers, and keeps the connection open
			} else {
				_, _ = c.Write(r)
			}
			c.Close()
		}
	}()
	return path
}

func TestClientRefusesBadReplies(t *testing.T) {
	cases := map[string][]byte{
		"over the limit":     binary.BigEndian.AppendUint32(nil, MaxReply+1),
		"ok with an error":   frame(`{"ok":true,"out":"x","error":"e"}`),
		"refusal, no reason": frame(`{"ok":false,"out":"","error":""}`),
		"refusal with out":   frame(`{"ok":false,"out":"x","error":"e"}`),
		"unknown field":      frame(`{"ok":true,"out":"x","error":"","uid":0}`),
		"two objects":        frame(`{"ok":true,"out":"x","error":""}{}`),
		"truncated":          append(binary.BigEndian.AppendUint32(nil, 50), `{"ok":true`...),
		"empty":              frame(""),
		"not JSON":           frame("ok"),
		"closed at once":     {},
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			path := fakeServer(t, raw)
			out, err := Client(path).Call("status")
			if err == nil {
				t.Fatalf("Call accepted %q: %q", raw, out)
			}
			var se *Error
			if errors.As(err, &se) {
				t.Fatalf("a malformed reply became a server refusal: %v", err)
			}
		})
	}
	path := fakeServer(t, frame(`{"ok":true,"out":"fine","error":""}`))
	if out, err := Client(path).Call("status"); err != nil || string(out) != "fine" {
		t.Fatalf("well-formed reply: %q, %v", out, err)
	}
}

func TestClientDeadline(t *testing.T) {
	path := fakeServer(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	began := time.Now()
	_, err := Client(path).CallContext(ctx, "status")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("CallContext without a reply: %v; want the deadline", err)
	}
	if took := time.Since(began); took > 3*time.Second {
		t.Fatalf("CallContext waited %s past a 200ms deadline", took)
	}
	if DefaultCallTimeout <= 0 {
		t.Fatalf("DefaultCallTimeout = %s", DefaultCallTimeout)
	}
}
