// Package probe checks whether a router can reach the internet and reports
// when that changes.
//
// Three probes measure the link: DNS (one query for a fixed name to a given
// server, which counts any answer), TCP (a connection to host:443) and ICMP
// (an echo to an IPv4 address over a raw socket, which needs CAP_NET_RAW; the
// caller enables it only where that is granted). Each probe takes a context
// and never runs without a deadline.
//
// An ICMP reply counts only when it comes from the probed address and
// carries back the random payload of its request. The identifier and the
// sequence number alone are 32 bits a device on the LAN can sweep by
// spraying forged replies, which would hide a lost internet connection.
//
// Prober turns a stream of probe results into lost and restored events. Each
// event carries the time its condition started, the first failed probe or
// the first success, so one outage keeps one timestamp however long the
// detection took.
package probe

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"time"
)

// Defaults for the internet probe. Each applies when the matching Prober
// field is left at zero.
const (
	DefaultPeriod        = 10 * time.Second // time between two probes
	DefaultTimeout       = 3 * time.Second  // deadline of one probe
	DefaultLostAfter     = 3                // consecutive failed probes that mean lost
	DefaultRestoredAfter = 1                // consecutive successful probes that mean restored
)

// Ports used when an address does not name one.
const (
	dnsPort = "53"
	tcpPort = "443"
)

// ICMP message types used by the echo probe.
const (
	icmpEchoReply   = 0
	icmpEchoRequest = 8
)

// icmpTag starts the payload of each echo request; icmpNonceSize random
// bytes follow it, new for every request, and the reply must carry them back.
const (
	icmpTag       = "rollcall"
	icmpNonceSize = 16
)

// ErrSkip is what a probe returns when it cannot judge the link this round:
// Prober.Tick counts the round neither way, and a streak against the state
// starts over.
var ErrSkip = errors.New("probe: nothing to judge this round")

// dnsRetry is how long DNS waits for an answer before it sends its query
// again, within the probe's deadline: one lost packet does not fail a round.
const dnsRetry = time.Second

// DNS response codes the probe tells apart.
const (
	rcodeNoError  = 0
	rcodeNXDomain = 3
)

// DNS asks server, over UDP, for the A record of name and reports whether
// the server answered. Any answer counts, that the name does not exist
// (NXDOMAIN) as much as an address: the probe asks whether the server
// answers, not what. A reply with any other response code (SERVFAIL,
// REFUSED), a refused port, and no reply before the deadline are failures.
// A reply counts only when it carries the query's random ID and repeats its
// question; the socket is connected to server, so the kernel drops what
// another address sends. The query goes again every dnsRetry until the
// deadline. server is an IP address or IP:port; the port defaults to 53.
// The query goes to server alone: DNS never reads resolv.conf and starts no
// lookup of its own.
func DNS(ctx context.Context, server string, name string) error {
	ctx, cancel := withDeadline(ctx)
	defer cancel()
	addr := hostPort(server, dnsPort)
	fail := func(format string, args ...any) error {
		return fmt.Errorf("dns probe of %s via %s: %s", name, addr, fmt.Sprintf(format, args...))
	}
	query, err := newDNSQuery(name)
	if err != nil {
		return fail("%v", err)
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		return fail("%v", err)
	}
	defer conn.Close()
	// Closing the socket unblocks a read when the context ends first.
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	buf := make([]byte, 1500)
	for {
		if _, err := conn.Write(query); err != nil {
			if ctx.Err() != nil {
				return fail("no answer: %v", ctx.Err())
			}
			return fail("send: %v", err)
		}
		if err := conn.SetReadDeadline(earlier(time.Now().Add(dnsRetry), deadline)); err != nil {
			return fail("set deadline: %v", err)
		}
		for {
			n, err := conn.Read(buf)
			if err != nil {
				var ne net.Error
				switch {
				case ctx.Err() != nil || !time.Now().Before(deadline):
					return fail("no answer: %v", context.DeadlineExceeded)
				case errors.As(err, &ne) && ne.Timeout():
				default:
					return fail("%v", err) // a refused port, an unreachable network
				}
				break // send it again
			}
			switch rcode, ok := dnsReply(buf[:n], query); {
			case !ok:
				continue // not a reply to this query
			case rcode == rcodeNoError, rcode == rcodeNXDomain:
				return nil
			default:
				return fail("the server answered with response code %d", rcode)
			}
		}
	}
}

func earlier(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}

// newDNSQuery builds a query for the A record of name, class IN, recursion
// desired, with a random ID. name is a host name of letters, digits and
// inner hyphens, at most 253 bytes, an optional final dot.
func newDNSQuery(name string) ([]byte, error) {
	name = strings.TrimSuffix(name, ".")
	if name == "" || len(name) > 253 {
		return nil, fmt.Errorf("%q is not a host name", name)
	}
	q := make([]byte, 12, 12+len(name)+6)
	if _, err := rand.Read(q[:2]); err != nil {
		return nil, fmt.Errorf("random query ID: %w", err)
	}
	q[2] = 0x01                           // RD
	binary.BigEndian.PutUint16(q[4:6], 1) // QDCOUNT
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return nil, fmt.Errorf("%q is not a host name", name)
		}
		for i := 0; i < len(label); i++ {
			if c := label[i]; !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '-') {
				return nil, fmt.Errorf("%q is not a host name", name)
			}
		}
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	return append(q, 0, 0, 1, 0, 1), nil // root, QTYPE A, QCLASS IN
}

// dnsReply returns the response code of b when b is a reply to query: the
// same ID, the response bit set, a standard query, and the same one question,
// its name in any case (a server may change the case of letters).
func dnsReply(b, query []byte) (rcode int, ok bool) {
	if len(b) < len(query) || b[0] != query[0] || b[1] != query[1] || b[2]&0x80 == 0 || b[2]&0x78 != 0 ||
		binary.BigEndian.Uint16(b[4:6]) != 1 || !bytes.EqualFold(b[12:len(query)], query[12:]) {
		return 0, false
	}
	return int(b[3] & 0x0f), true
}

// ResolvConfServers returns the name servers a resolv.conf lists, each once,
// in their order, at most max: the address of every nameserver line, which
// may carry a zone (fe80::1%wan). It leaves out what is not an IP address,
// and loopback and unspecified addresses: the router's own resolver, whose
// cache would answer for a server that does not.
func ResolvConfServers(b []byte, max int) []string {
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || f[0] != "nameserver" || len(out) >= max {
			continue
		}
		a, err := netip.ParseAddr(f[1])
		if err != nil || a.IsLoopback() || a.IsUnspecified() || a.IsMulticast() {
			continue
		}
		if s := a.String(); !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

// TCP connects to addr and closes the connection. addr is a host or
// host:port; the port defaults to 443.
func TCP(ctx context.Context, addr string) error {
	ctx, cancel := withDeadline(ctx)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", hostPort(addr, tcpPort))
	if err != nil {
		return fmt.Errorf("tcp probe of %s: %w", addr, err)
	}
	return conn.Close()
}

// ICMP sends one echo request to addr and waits for the matching reply. addr
// must be an IPv4 literal: a hostname would need a lookup, and the probe
// refuses to start one. The raw socket needs CAP_NET_RAW; without it the
// error wraps the permission error.
func ICMP(ctx context.Context, addr string) error {
	ip, err := netip.ParseAddr(addr)
	if err != nil || !ip.Is4() {
		return fmt.Errorf("icmp probe needs an IPv4 literal, got %q", addr)
	}
	ctx, cancel := withDeadline(ctx)
	defer cancel()
	conn, err := net.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return fmt.Errorf("icmp probe: raw socket: %w", err)
	}
	defer conn.Close()
	// Closing the socket unblocks the read when the context ends first.
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	return icmpRound(ctx, conn, &net.IPAddr{IP: ip.AsSlice()}, addr)
}

// Prober runs one probe per period and reports when the link is lost and
// when it is restored. Set Probe; the other fields may stay zero.
type Prober struct {
	// Probe runs one probe. A nil error means the link answered. The context
	// it receives carries a deadline.
	Probe func(ctx context.Context) error
	// Period is the time between two probes; zero means DefaultPeriod.
	Period time.Duration
	// Timeout bounds one probe; zero means DefaultTimeout.
	Timeout time.Duration
	// LostAfter is the number of failures in a row that mean lost; zero means DefaultLostAfter.
	LostAfter int
	// RestoredAfter is the number of successes in a row that mean restored; zero means DefaultRestoredAfter.
	RestoredAfter int

	started  bool
	next     time.Time
	down     bool
	streak   int
	since    time.Time
	answered bool
}

// Tick runs the probe when a period has passed since the last one, with now as
// the time of the probe. It returns lost on the probe that made the link lost,
// or restored on the probe that brought it back. since is the time of the first
// probe in the streak that caused the change: the first failure for a loss, the
// first success for a restore. Tick returns zero values when it did not probe,
// or when the probe changed nothing. Without a Probe it never reports anything.
// A probe that returns ErrSkip changes nothing and ends any streak.
func (p *Prober) Tick(now time.Time) (lost, restored bool, since time.Time) {
	if p.Probe == nil || (p.started && now.Before(p.next)) {
		return false, false, time.Time{}
	}
	p.started = true
	p.next = now.Add(p.period())
	ctx, cancel := context.WithTimeout(context.Background(), p.timeout())
	err := p.Probe(ctx)
	cancel()
	p.answered = err == nil
	if errors.Is(err, ErrSkip) {
		p.streak = 0
		return false, false, time.Time{}
	}
	return p.record(err == nil, now)
}

// Down reports whether the link is currently considered lost.
func (p *Prober) Down() bool { return p.down }

// Answered reports whether the last probe got an answer.
func (p *Prober) Answered() bool { return p.answered }

// record folds one probe result into the state. A result that agrees with the
// state ends any streak against it. A result that contradicts the state
// extends the streak, and the state changes when the streak reaches its
// threshold.
func (p *Prober) record(ok bool, now time.Time) (lost, restored bool, since time.Time) {
	contradicts := ok == p.down
	if !contradicts {
		p.streak = 0
		return false, false, time.Time{}
	}
	if p.streak == 0 {
		p.since = now
	}
	p.streak++
	if p.streak < p.threshold() {
		return false, false, time.Time{}
	}
	p.down = !p.down
	p.streak = 0
	if p.down {
		return true, false, p.since
	}
	return false, true, p.since
}

// threshold is the streak length that changes the state: LostAfter while the
// link is up, RestoredAfter while it is down.
func (p *Prober) threshold() int {
	if p.down {
		if p.RestoredAfter > 0 {
			return p.RestoredAfter
		}
		return DefaultRestoredAfter
	}
	if p.LostAfter > 0 {
		return p.LostAfter
	}
	return DefaultLostAfter
}

func (p *Prober) period() time.Duration {
	if p.Period > 0 {
		return p.Period
	}
	return DefaultPeriod
}

func (p *Prober) timeout() time.Duration {
	if p.Timeout > 0 {
		return p.Timeout
	}
	return DefaultTimeout
}

// withDeadline keeps the caller's context when it has a deadline and adds the
// default one when it does not, so a probe never runs without one.
func withDeadline(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, DefaultTimeout)
}

// checksum is the ones' complement Internet checksum of b (RFC 1071).
func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

// echoMessage builds an ICMP echo request with a valid checksum.
func echoMessage(id, seq uint16, payload []byte) []byte {
	m := make([]byte, 8+len(payload))
	m[0] = icmpEchoRequest
	binary.BigEndian.PutUint16(m[4:6], id)
	binary.BigEndian.PutUint16(m[6:8], seq)
	copy(m[8:], payload)
	binary.BigEndian.PutUint16(m[2:4], checksum(m))
	return m
}

// isEchoReply reports whether b is a valid ICMP echo reply for id and seq
// that carries exactly payload. A raw socket may deliver the IPv4 header in
// front of the ICMP message; a leading byte of 0x4x marks one, and an echo
// reply never starts with it.
func isEchoReply(b []byte, id, seq uint16, payload []byte) bool {
	if len(b) >= 20 && b[0]>>4 == 4 {
		ihl := int(b[0]&0x0f) * 4
		if ihl < 20 || ihl > len(b) {
			return false
		}
		b = b[ihl:]
	}
	if len(b) < 8 || b[0] != icmpEchoReply || b[1] != 0 {
		return false
	}
	if checksum(b) != 0 {
		return false
	}
	return binary.BigEndian.Uint16(b[4:6]) == id && binary.BigEndian.Uint16(b[6:8]) == seq && bytes.Equal(b[8:], payload)
}

// fromAddr reports whether from, the sender a raw socket reports, is dst.
func fromAddr(from net.Addr, dst *net.IPAddr) bool {
	a, ok := from.(*net.IPAddr)
	return ok && a != nil && a.IP.Equal(dst.IP)
}

// hostPort adds defPort to addr when addr names no port. A bare IPv6 literal
// gets brackets.
func hostPort(addr, defPort string) string {
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	return net.JoinHostPort(strings.TrimSuffix(strings.TrimPrefix(addr, "["), "]"), defPort)
}

// icmpRound sends one echo request over conn to dst and reads until the reply
// to that request arrives, the context deadline passes, or the read fails.
// The reply must come from dst and carry the request's random payload. It is
// the part of ICMP that needs no privilege, so tests drive it with a fake
// connection. addr is only used in error messages.
func icmpRound(ctx context.Context, conn net.PacketConn, dst *net.IPAddr, addr string) error {
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return fmt.Errorf("icmp probe: set deadline: %w", err)
	}
	id := uint16(os.Getpid())
	r := make([]byte, 2+icmpNonceSize)
	rand.Read(r)
	seq := binary.BigEndian.Uint16(r)
	payload := append([]byte(icmpTag), r[2:]...)
	if _, err := conn.WriteTo(echoMessage(id, seq, payload), dst); err != nil {
		return fmt.Errorf("icmp probe of %s: send: %w", addr, err)
	}
	buf := make([]byte, 1500)
	for {
		n, from, err := conn.ReadFrom(buf)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return fmt.Errorf("icmp probe of %s: no echo reply: %w", addr, ctxErr)
			}
			return fmt.Errorf("icmp probe of %s: no echo reply: %w", addr, err)
		}
		if fromAddr(from, dst) && isEchoReply(buf[:n], id, seq, payload) {
			return nil
		}
	}
}
