package probe

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

// t0 is the first moment of every scripted test.
var t0 = time.Date(2026, 10, 23, 9, 0, 0, 0, time.UTC)

// at returns the moment s seconds after t0.
func at(s int) time.Time { return t0.Add(time.Duration(s) * time.Second) }

// scripted returns a probe that answers from script, one entry per call (true
// is success). It fails the test when called more often than the script allows.
func scripted(t *testing.T, script ...bool) func(context.Context) error {
	t.Helper()
	calls := 0
	return func(context.Context) error {
		t.Helper()
		if calls >= len(script) {
			t.Fatalf("probe called %d times, script has %d entries", calls+1, len(script))
		}
		ok := script[calls]
		calls++
		if ok {
			return nil
		}
		return errors.New("scripted failure")
	}
}

func TestLostAfterThreeFailures(t *testing.T) {
	p := &Prober{Probe: scripted(t, false, false, false)}
	for _, s := range []int{0, 10} {
		if lost, restored, _ := p.Tick(at(s)); lost || restored {
			t.Fatalf("Tick(%ds): lost=%v restored=%v before the third failure", s, lost, restored)
		}
	}
	lost, restored, since := p.Tick(at(20))
	if !lost || restored {
		t.Fatalf("Tick(20s): lost=%v restored=%v, want lost", lost, restored)
	}
	if !since.Equal(at(0)) {
		t.Fatalf("Tick(20s): since=%v, want the first failure at %v", since, at(0))
	}
	if !p.Down() {
		t.Fatal("Down() = false after the link was lost")
	}
}

func TestRestoredAfterOneSuccess(t *testing.T) {
	p := &Prober{Probe: scripted(t, false, false, false, true)}
	for _, s := range []int{0, 10} {
		p.Tick(at(s))
	}
	if lost, _, _ := p.Tick(at(20)); !lost {
		t.Fatal("link not lost after three failures")
	}
	lost, restored, since := p.Tick(at(30))
	if lost || !restored {
		t.Fatalf("Tick(30s): lost=%v restored=%v, want restored", lost, restored)
	}
	if !since.Equal(at(30)) {
		t.Fatalf("Tick(30s): since=%v, want the first success at %v", since, at(30))
	}
	if p.Down() {
		t.Fatal("Down() = true after the link was restored")
	}
}

func TestSuccessResetsFailureStreak(t *testing.T) {
	// Fail, fail, succeed, fail, fail, fail: the streak restarts after the success.
	p := &Prober{Probe: scripted(t, false, false, true, false, false, false)}
	for _, s := range []int{0, 10, 20, 30, 40} {
		if lost, _, _ := p.Tick(at(s)); lost {
			t.Fatalf("Tick(%ds): lost before three consecutive failures", s)
		}
	}
	lost, _, since := p.Tick(at(50))
	if !lost {
		t.Fatal("Tick(50s): not lost after three consecutive failures since the success")
	}
	if !since.Equal(at(30)) {
		t.Fatalf("Tick(50s): since=%v, want the first failure of the new streak at %v", since, at(30))
	}
}

func TestRestoredNeedsConsecutiveSuccesses(t *testing.T) {
	// RestoredAfter is 2: a failure between two successes restarts the count.
	p := &Prober{
		RestoredAfter: 2,
		Probe:         scripted(t, false, false, false, true, false, true, true),
	}
	for _, s := range []int{0, 10} {
		p.Tick(at(s))
	}
	if lost, _, _ := p.Tick(at(20)); !lost {
		t.Fatal("link not lost after three failures")
	}
	for _, s := range []int{30, 40} {
		if _, restored, _ := p.Tick(at(s)); restored {
			t.Fatalf("Tick(%ds): restored before two consecutive successes", s)
		}
	}
	if lost, restored, _ := p.Tick(at(50)); lost || restored {
		// One success after a failure: still waiting for the second.
		t.Fatalf("Tick(50s): lost=%v restored=%v after a single success, want nothing", lost, restored)
	}
	_, restored, since := p.Tick(at(60))
	if !restored {
		t.Fatal("Tick(60s): not restored after two consecutive successes")
	}
	if !since.Equal(at(50)) {
		t.Fatalf("Tick(60s): since=%v, want the first success of the streak at %v", since, at(50))
	}
}

func TestTickWaitsForPeriod(t *testing.T) {
	calls := 0
	p := &Prober{Probe: func(context.Context) error { calls++; return nil }}
	for _, s := range []int{0, 5, 10} {
		p.Tick(at(s))
	}
	// The probe runs at 0 s and at 10 s (the default period), not at 5 s.
	if calls != 2 {
		t.Fatalf("probe ran %d times over 0, 5 and 10 s, want 2", calls)
	}
}

func TestProbeGetsDeadline(t *testing.T) {
	var deadline time.Time
	p := &Prober{Probe: func(ctx context.Context) error {
		dl, ok := ctx.Deadline()
		if !ok {
			t.Fatal("probe context has no deadline")
		}
		deadline = dl
		return nil
	}}
	p.Tick(at(0))
	left := time.Until(deadline)
	if left <= 0 || left > DefaultTimeout {
		t.Fatalf("probe deadline is %v away, want within %v", left, DefaultTimeout)
	}
}

func TestNilProbeNeverReportsEvents(t *testing.T) {
	// Positive control first: the same prober type reports a loss with a probe set.
	withProbe := &Prober{Probe: scripted(t, false, false, false)}
	withProbe.Tick(at(0))
	withProbe.Tick(at(10))
	if lost, _, _ := withProbe.Tick(at(20)); !lost {
		t.Fatal("positive control: no loss from three failures")
	}
	var none Prober
	for _, s := range []int{0, 10, 20, 30} {
		if lost, restored, _ := none.Tick(at(s)); lost || restored {
			t.Fatalf("Tick(%ds) with no probe: lost=%v restored=%v", s, lost, restored)
		}
	}
}

// dnsQuery is one question a fakeDNS server saw.
type dnsQuery struct {
	name  string
	qtype uint16
}

// fakeDNS starts a UDP DNS responder on 127.0.0.1 and returns its address and a
// channel of the questions it saw. With silent set it never answers. Otherwise
// it answers an A query for openwrt.org with 192.0.2.7 (TEST-NET-1) and answers
// every other question with NXDOMAIN.
func fakeDNS(t *testing.T, silent bool) (string, <-chan dnsQuery) {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	seen := make(chan dnsQuery, 16)
	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			q, end, ok := parseDNSQuestion(buf[:n])
			if !ok {
				continue
			}
			select {
			case seen <- q:
			default:
			}
			if silent {
				continue
			}
			conn.WriteTo(dnsAnswer(buf[:n], end, q), from)
		}
	}()
	return conn.LocalAddr().String(), seen
}

// parseDNSQuestion reads the single question of a query and returns it with the
// offset just past it.
func parseDNSQuestion(msg []byte) (dnsQuery, int, bool) {
	if len(msg) < 12 || binary.BigEndian.Uint16(msg[4:6]) != 1 {
		return dnsQuery{}, 0, false
	}
	var labels []string
	i := 12
	for {
		if i >= len(msg) {
			return dnsQuery{}, 0, false
		}
		l := int(msg[i])
		i++
		if l == 0 {
			break
		}
		if l > 63 || i+l > len(msg) {
			return dnsQuery{}, 0, false
		}
		labels = append(labels, string(msg[i:i+l]))
		i += l
	}
	if i+4 > len(msg) {
		return dnsQuery{}, 0, false
	}
	q := dnsQuery{
		name:  strings.ToLower(strings.Join(labels, ".")),
		qtype: binary.BigEndian.Uint16(msg[i : i+2]),
	}
	return q, i + 4, true
}

// dnsAnswer builds the response to query, echoing its question section.
func dnsAnswer(query []byte, end int, q dnsQuery) []byte {
	rcode := byte(3) // NXDOMAIN
	var answer []byte
	if q.name == "openwrt.org" && q.qtype == 1 {
		rcode = 0
		// Name pointer to the question, type A, class IN, TTL 60, RDLENGTH 4, 192.0.2.7.
		answer = []byte{0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 7}
	}
	resp := make([]byte, 0, end+len(answer))
	resp = append(resp, query[0], query[1])
	resp = append(resp, 0x80|(query[2]&0x01), 0x80|rcode)
	ancount := byte(0)
	if answer != nil {
		ancount = 1
	}
	resp = append(resp, 0, 1, 0, ancount, 0, 0, 0, 0)
	resp = append(resp, query[12:end]...)
	return append(resp, answer...)
}

func TestDNSProbeQueriesFixedNameAtServer(t *testing.T) {
	addr, queries := fakeDNS(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := DNS(ctx, addr, "openwrt.org"); err != nil {
		t.Fatalf("DNS(openwrt.org) against a server that answers: %v", err)
	}
	select {
	case q := <-queries:
		if q.name != "openwrt.org" || q.qtype != 1 {
			t.Fatalf("server saw %+v, want an A query for openwrt.org", q)
		}
	default:
		t.Fatal("server saw no query")
	}
}

func TestDNSProbeFailsWhenServerRefusesName(t *testing.T) {
	addr, _ := fakeDNS(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := DNS(ctx, addr, "openwrt.org"); err != nil {
		t.Fatalf("positive control: DNS(openwrt.org) failed: %v", err)
	}
	if err := DNS(ctx, addr, "nothing-here.invalid"); err == nil {
		t.Fatal("DNS of a name the server answers NXDOMAIN for returned no error")
	}
}

func TestDNSProbeHonoursDeadlineOnSilentServer(t *testing.T) {
	answering, _ := fakeDNS(t, false)
	silent, _ := fakeDNS(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if err := DNS(ctx, answering, "openwrt.org"); err != nil {
		t.Fatalf("positive control: DNS against an answering server: %v", err)
	}
	start := time.Now()
	if err := DNS(ctx, silent, "openwrt.org"); err == nil {
		t.Fatal("DNS against a silent server returned no error")
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("DNS took %v with a 200 ms deadline", took)
	}
}

func TestTCPProbeConnectsAndFailsOnClosedPort(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := l.Addr().String()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := TCP(ctx, addr); err != nil {
		t.Fatalf("TCP(%s) to an open listener: %v", addr, err)
	}
	l.Close()
	if err := TCP(ctx, addr); err == nil {
		t.Fatalf("TCP(%s) to a closed port returned no error", addr)
	}
}

func TestHostPortAddsDefaultPort(t *testing.T) {
	cases := []struct{ in, want string }{
		{"192.0.2.1", "192.0.2.1:443"},
		{"example.test", "example.test:443"},
		{"example.test:8443", "example.test:8443"},
		{"2001:db8::1", "[2001:db8::1]:443"},
		{"[2001:db8::1]", "[2001:db8::1]:443"},
		{"[2001:db8::1]:8443", "[2001:db8::1]:8443"},
	}
	for _, c := range cases {
		if got := hostPort(c.in, "443"); got != c.want {
			t.Errorf("hostPort(%q, 443) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestICMPRequiresIPv4LiteralAndEchoesLoopback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	// A hostname would need a DNS lookup, so it is refused before any socket opens.
	if err := ICMP(ctx, "openwrt.org"); err == nil {
		t.Fatal("ICMP accepted a hostname")
	}
	err := ICMP(ctx, "127.0.0.1")
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
		t.Skipf("raw ICMP socket needs CAP_NET_RAW: %v", err)
	}
	if err != nil {
		t.Fatalf("ICMP(127.0.0.1): %v", err)
	}
}

func TestChecksumMatchesRFC1071Example(t *testing.T) {
	// RFC 1071 section 3: the sum of these words is 0xddf2, so the checksum is 0x220d.
	if got := checksum([]byte{0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7}); got != 0x220d {
		t.Fatalf("checksum = %#04x, want 0x220d", got)
	}
}

func TestEchoMessageLayoutAndChecksum(t *testing.T) {
	payload := []byte("rollcall")
	m := echoMessage(0x1234, 7, payload)
	if len(m) != 8+len(payload) {
		t.Fatalf("echo message is %d bytes, want %d", len(m), 8+len(payload))
	}
	if m[0] != 8 || m[1] != 0 {
		t.Fatalf("type/code = %d/%d, want echo request 8/0", m[0], m[1])
	}
	if id := binary.BigEndian.Uint16(m[4:6]); id != 0x1234 {
		t.Fatalf("identifier = %#x, want 0x1234", id)
	}
	if seq := binary.BigEndian.Uint16(m[6:8]); seq != 7 {
		t.Fatalf("sequence = %d, want 7", seq)
	}
	// A message whose checksum is correct sums to zero.
	if checksum(m) != 0 {
		t.Fatal("echo message checksum does not verify")
	}
}

// replyBytes builds an echo reply for id and seq, optionally with a 20-byte IPv4 header in front.
func replyBytes(id, seq uint16, withIPHeader bool) []byte {
	m := make([]byte, 16)
	m[0] = 0 // echo reply
	binary.BigEndian.PutUint16(m[4:], id)
	binary.BigEndian.PutUint16(m[6:], seq)
	copy(m[8:], "rollcall")
	binary.BigEndian.PutUint16(m[2:], checksum(m))
	if !withIPHeader {
		return m
	}
	h := make([]byte, 20)
	h[0] = 0x45 // IPv4, header length 5 words
	h[8] = 64   // TTL
	h[9] = 1    // ICMP
	return append(h, m...)
}

func TestIsEchoReply(t *testing.T) {
	cases := []struct {
		name string
		b    []byte
		want bool
	}{
		{"reply without IP header", replyBytes(0x1234, 7, false), true},
		{"reply behind IPv4 header", replyBytes(0x1234, 7, true), true},
		{"wrong identifier", replyBytes(0x1235, 7, false), false},
		{"wrong sequence", replyBytes(0x1234, 8, false), false},
		{"corrupt checksum", func() []byte { b := replyBytes(0x1234, 7, false); b[2] ^= 0xff; return b }(), false},
		{"echo request, not reply", func() []byte { b := replyBytes(0x1234, 7, false); b[0] = 8; return b }(), false},
		{"too short", []byte{0, 0, 0}, false},
	}
	for _, c := range cases {
		if got := isEchoReply(c.b, 0x1234, 7); got != c.want {
			t.Errorf("%s: isEchoReply = %v, want %v", c.name, got, c.want)
		}
	}
}

// fakeICMPConn stands in for the raw socket. Each WriteTo queues the replies
// the script builds from the identifier and sequence of the request; each
// ReadFrom returns the next queued packet, or a deadline error when none is left.
type fakeICMPConn struct {
	net.PacketConn
	script []func(id, seq uint16) []byte
	queue  [][]byte
}

func (c *fakeICMPConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	id := binary.BigEndian.Uint16(b[4:6])
	seq := binary.BigEndian.Uint16(b[6:8])
	for _, reply := range c.script {
		c.queue = append(c.queue, reply(id, seq))
	}
	c.script = nil
	return len(b), nil
}

func (c *fakeICMPConn) ReadFrom(b []byte) (int, net.Addr, error) {
	if len(c.queue) == 0 {
		return 0, nil, os.ErrDeadlineExceeded
	}
	m := c.queue[0]
	c.queue = c.queue[1:]
	return copy(b, m), nil, nil
}

func (c *fakeICMPConn) SetDeadline(time.Time) error { return nil }

func TestICMPRoundMatchesOwnReply(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	dst := &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)}
	matching := func(id, seq uint16) []byte { return replyBytes(id, seq, true) }
	otherID := func(_, seq uint16) []byte { return replyBytes(0xffff, seq, false) }
	otherSeq := func(id, seq uint16) []byte { return replyBytes(id, seq+1, false) }
	badSum := func(id, seq uint16) []byte {
		b := replyBytes(id, seq, false)
		b[2] ^= 0xff
		return b
	}

	cases := []struct {
		name    string
		script  []func(id, seq uint16) []byte
		wantErr bool
	}{
		{"matching reply", []func(uint16, uint16) []byte{matching}, false},
		{"noise then matching reply", []func(uint16, uint16) []byte{otherID, matching}, false},
		{"reply to another sequence only", []func(uint16, uint16) []byte{otherSeq}, true},
		{"reply with a bad checksum only", []func(uint16, uint16) []byte{badSum}, true},
		{"no reply at all", nil, true},
	}
	for _, c := range cases {
		conn := &fakeICMPConn{script: c.script}
		err := icmpRound(ctx, conn, dst, "127.0.0.1")
		if c.wantErr && err == nil {
			t.Errorf("%s: icmpRound returned no error", c.name)
		}
		if !c.wantErr && err != nil {
			t.Errorf("%s: icmpRound: %v", c.name, err)
		}
	}
}

// Added after the implementation to cover the configured-field branches. These
// tests were not run red first, which the report states.
func TestConfiguredPeriodTimeoutAndThreshold(t *testing.T) {
	calls := 0
	p := &Prober{
		Period:    5 * time.Second,
		Timeout:   time.Second,
		LostAfter: 1,
		Probe: func(ctx context.Context) error {
			calls++
			dl, ok := ctx.Deadline()
			if !ok || time.Until(dl) > time.Second {
				t.Errorf("probe deadline is not within the configured 1 s timeout")
			}
			return errors.New("down")
		},
	}
	lost, _, since := p.Tick(at(0))
	if !lost || !since.Equal(at(0)) {
		t.Fatalf("Tick(0s) with LostAfter 1: lost=%v since=%v, want lost since %v", lost, since, at(0))
	}
	p.Tick(at(3))
	if calls != 1 {
		t.Fatalf("probe ran %d times by 3 s, want 1 within the 5 s period", calls)
	}
	p.Tick(at(5))
	if calls != 2 {
		t.Fatalf("probe ran %d times by 5 s, want 2", calls)
	}
}

func TestTCPProbeWithoutDeadlineAddsOne(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()
	// The context has no deadline; the probe must add the default one itself.
	if err := TCP(context.Background(), l.Addr().String()); err != nil {
		t.Fatalf("TCP with a context that has no deadline: %v", err)
	}
}
