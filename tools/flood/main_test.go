package main

import (
	"bytes"
	"net"
	"strings"
	"testing"
	"time"
)

func TestRunSendsRandomDatagrams(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	if err := pc.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := run(pc.LocalAddr().String(), 20, 1200, &out); err != nil {
		t.Fatal(err)
	}
	var first, second []byte
	buf := make([]byte, 2048)
	for i := 0; i < 20; i++ {
		m, _, err := pc.ReadFrom(buf)
		if err != nil {
			t.Fatalf("datagram %d: %v", i+1, err)
		}
		if m != 1200 {
			t.Fatalf("datagram %d is %d bytes, want 1200", i+1, m)
		}
		switch i {
		case 0:
			first = append([]byte(nil), buf[:m]...)
		case 1:
			second = append([]byte(nil), buf[:m]...)
		}
	}
	if bytes.Equal(first, second) {
		t.Error("the first two datagrams are identical; the payload must be random")
	}
	if !strings.Contains(out.String(), "sent 20 random datagrams") {
		t.Errorf("output %q does not report 20 datagrams", out.String())
	}
}

func TestRunRefusesBadInput(t *testing.T) {
	cases := map[string]struct {
		to      string
		n, size int
	}{
		"public target": {"8.8.8.8:7432", 1, 10},
		"zero count":    {"127.0.0.1:7432", 0, 10},
		"zero size":     {"127.0.0.1:7432", 1, 0},
		"oversize":      {"127.0.0.1:7432", 1, 65508},
		"no port":       {"127.0.0.1", 1, 10},
	}
	for name, c := range cases {
		if err := run(c.to, c.n, c.size, &bytes.Buffer{}); err == nil {
			t.Errorf("%s: run returned nil, want an error", name)
		}
	}
}
