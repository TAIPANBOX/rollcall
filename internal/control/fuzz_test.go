package control

import (
	"bytes"
	"encoding/binary"
	"errors"
	"slices"
	"testing"
)

// FuzzReadRequest feeds the server's request reader arbitrary bytes. It
// must refuse with one of its two errors, never read past the limit, and an
// accepted request must survive encoding and reading again.
func FuzzReadRequest(f *testing.F) {
	f.Add(frame(`{"cmd":"status","args":[]}`))
	f.Add(frame(`{"cmd":"roles","args":["r1","sender"]}`))
	f.Add(frame(`{"cmd":"status"}{"cmd":"remove"}`))
	f.Add(frame(`{"cmd":"status","args":[],"x":1}`))
	f.Add(frame(`null`))
	f.Add(binary.BigEndian.AppendUint32(nil, MaxRequest+1))
	f.Add([]byte{0, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		req, err := readRequest(bytes.NewReader(data))
		if err != nil {
			if !errors.Is(err, errBadRequest) && !errors.Is(err, errTooLarge) {
				t.Fatalf("unexpected error %v", err)
			}
			return
		}
		if len(data) < 4 {
			t.Fatalf("accepted %d bytes, shorter than a header", len(data))
		}
		if n := binary.BigEndian.Uint32(data); n == 0 || n > MaxRequest || int(n) > len(data)-4 {
			t.Fatalf("accepted a frame of length %d from %d bytes", n, len(data))
		}
		body, err := encodeRequest(req.Cmd, req.Args)
		if err != nil {
			return // a request at the limit may grow when re-encoded
		}
		again, err := readRequest(bytes.NewReader(body))
		if err != nil || again.Cmd != req.Cmd || !slices.Equal(again.Args, req.Args) {
			t.Fatalf("round trip: %+v, %v; want %+v", again, err, req)
		}
	})
}

// FuzzReadReply feeds the client's reply reader arbitrary bytes. An
// accepted reply is either a success without an error or a refusal with a
// reason and no output.
func FuzzReadReply(f *testing.F) {
	f.Add(frame(`{"ok":true,"out":"x","error":""}`))
	f.Add(frame(`{"ok":false,"out":"","error":"permission denied"}`))
	f.Add(frame(`{"ok":true,"out":"x","error":"e"}`))
	f.Add(binary.BigEndian.AppendUint32(nil, MaxReply+1))
	f.Fuzz(func(t *testing.T, data []byte) {
		rep, err := readReply(bytes.NewReader(data))
		if err != nil {
			return
		}
		if rep.OK == (rep.Error != "") || (!rep.OK && rep.Out != "") {
			t.Fatalf("accepted an inconsistent reply %+v", rep)
		}
		if n := binary.BigEndian.Uint32(data); n == 0 || n > MaxReply {
			t.Fatalf("accepted a frame of length %d", n)
		}
	})
}
