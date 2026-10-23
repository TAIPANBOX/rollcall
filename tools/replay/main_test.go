package main

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeCapture(t *testing.T, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "lan.pcap")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// readDatagrams reads n datagrams from pc, failing the test if they do not all arrive in time.
func readDatagrams(t *testing.T, pc net.PacketConn, n int) []string {
	t.Helper()
	if err := pc.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var got []string
	buf := make([]byte, 2048)
	for i := 0; i < n; i++ {
		m, _, err := pc.ReadFrom(buf)
		if err != nil {
			t.Fatalf("datagram %d: %v", i+1, err)
		}
		got = append(got, string(buf[:m]))
	}
	return got
}

func TestRunReplaysFirstN(t *testing.T) {
	path := writeCapture(t, classic(fixEthernet,
		ethernet(0x0800, ipv4UDP(rollcallPort, []byte("one"))),
		ethernet(0x0800, ipv4UDP(rollcallPort, []byte("two"))),
		ethernet(0x0800, ipv4UDP(rollcallPort, []byte("three"))),
	))
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	var out bytes.Buffer
	if err := run(path, pc.LocalAddr().String(), 2, &out); err != nil {
		t.Fatal(err)
	}
	got := readDatagrams(t, pc, 2)
	if got[0] != "one" || got[1] != "two" {
		t.Fatalf("received %q, want [one two]", got)
	}
	if err := pc.SetReadDeadline(time.Now().Add(150 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := pc.ReadFrom(make([]byte, 64)); err == nil {
		t.Error("a third datagram arrived; -count 2 must stop after two")
	}
	if !strings.Contains(out.String(), "replayed 2 payloads") {
		t.Errorf("output %q does not report two payloads", out.String())
	}
}

func TestRunRefusesBadInput(t *testing.T) {
	match := writeCapture(t, classic(fixEthernet, ethernet(0x0800, ipv4UDP(rollcallPort, []byte("x")))))
	noMatch := writeCapture(t, classic(fixEthernet, ethernet(0x0800, ipv4UDP(53, []byte("x")))))
	cases := map[string]struct {
		path, to string
		count    int
	}{
		"no port in -to":       {match, "192.168.1.1", 0},
		"port 0 in -to":        {match, "127.0.0.1:0", 0},
		"name instead of ip":   {match, "router.lan:7432", 0},
		"negative count":       {match, "127.0.0.1:7432", -1},
		"missing capture file": {filepath.Join(t.TempDir(), "absent.pcap"), "127.0.0.1:7432", 0},
		"no matching payloads": {noMatch, "127.0.0.1:7432", 0},
	}
	for name, c := range cases {
		if err := run(c.path, c.to, c.count, &bytes.Buffer{}); err == nil {
			t.Errorf("%s: run returned nil, want an error", name)
		}
	}
}
