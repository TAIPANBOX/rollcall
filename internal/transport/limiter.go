package transport

import (
	"net/netip"
	"sync"
	"time"
)

// The read budget (security spec 5.2 and threat 4).
//
// What it must hold. Every datagram the node is handed is opened under the
// node's lock, about 0.1 ms on a small MIPS router (estimated, not measured;
// it is the figure at which ~10 000 a second saturated such a router before
// there was any budget). So the budget gives that work a ceiling. But a LAN
// device can put any source address on a UDP datagram, a member's included,
// and a budget that drops by address before the AEAD lets it drop that
// member's heartbeats; six missed in 30 s and the group reports the member
// silent. The rule: making a genuine member's heartbeat be dropped must not
// cost an attacker much less than saturating the CPU did, thousands of
// datagrams a second, not tens.
//
// How. An address is known once a datagram from it passed authenticate (the
// AEAD under the group's key). Junk from an address that is not known is
// checked by the transport itself, within its own budget, and never reaches
// the node; a datagram that passes makes its address known. A datagram from
// a known address goes to the node, within a budget large enough that
// spoofing that address costs thousands a second before its heartbeats are
// dropped. So an attacker spoofing a known member pays per-address rates, an
// attacker spraying new addresses only uses up the budget for unknown ones,
// and neither touches the other. Nothing is blocked by address: a bucket
// refills.
//
// The sizes. A real group is at most 32 members, each sending one heartbeat
// every 5 s on each path to this router and four at a planned shutdown.
const (
	// sourceRate and sourceBurst bound one address, known or not. A member
	// sends 0.2 a second per path. Spoofing its address at 2560 a second still
	// lets one heartbeat in ten through, so six missed in a row is a coin
	// toss only at that rate; at 50 a second nothing of the member is lost.
	// The same rate for unknown addresses keeps a member whose address is not
	// known yet (after a restart of this router) from being kept out by tens a
	// second of junk under its address.
	sourceRate  = 256
	sourceBurst = 512
	// knownRate and knownBurst bound what all known addresses hand the node
	// together: 2048 a second is about 20% of one core at 0.1 ms each; 31
	// peers on two paths send about 12 a second. Using it up needs eight or
	// more spoofed members' addresses at full rate, thousands a second.
	knownRate  = 2048
	knownBurst = 4096
	// unknownRate and unknownBurst bound the authenticate calls for datagrams
	// from addresses that are not known: about 10% of one core. A flood from
	// new addresses uses it up and nothing else.
	unknownRate  = 1024
	unknownBurst = 1024
	// readRate and readBurst bound the reads, handed on or dropped. Past it the
	// read loops wait and the kernel drops what does not fit the socket
	// buffer, genuine datagrams included, so it sits above the ~10 000 a
	// second that saturated the CPU before: at about 15 µs a read (estimated)
	// it is near a quarter of one core.
	readRate  = 16384
	readBurst = 4096
	// maxSources bounds the table of per-address buckets: 32 members with a
	// few addresses each is about 128. A datagram from a new address while the
	// table is full of active ones meets only the global budgets.
	maxSources = 1024
	// sweepEvery spaces the sweeps of idle addresses out of a full table.
	sweepEvery = time.Second
	// maxKnown bounds the known addresses: 32 members with up to 8 addresses
	// each (IPv4, global and link-local IPv6, on two interfaces) is 256. Only
	// a datagram under a group key adds one; past the bound the longest unseen
	// is given up and is checked again on its next datagram.
	maxKnown = 512
	// knownTTL is how long an address stays known without a datagram from it.
	// Any datagram handed on keeps it known, a spoofed one too: that only lets
	// the spoofer use that address's budget, which it could do anyway.
	knownTTL = 10 * time.Minute
	// floodBurst refusals within floodWindow raise UnderFlood; floodQuiet
	// without a burst lowers it. The node uses the same window and quiet for
	// AEAD failures. A real group refuses nothing, since its traffic is far
	// below every limit, so 32 in 10 s is someone over them.
	floodBurst  = 32
	floodWindow = 10 * time.Second
	floodQuiet  = 60 * time.Second
)

// Counters counts what the transport refused before the node saw it.
type Counters struct {
	Oversize       uint64 // UDP datagrams over MaxDatagram
	SourceLimited  uint64 // UDP datagrams over their address's rate
	KnownLimited   uint64 // UDP datagrams from known addresses over the rate of all of them
	UnknownLimited uint64 // UDP datagrams from unknown addresses over the rate of checks
	Unverified     uint64 // UDP datagrams from unknown addresses that failed authenticate
	Untracked      uint64 // UDP datagrams from a new address while the address table was full (not refused)
	ReadPaced      uint64 // reads that waited for the read rate
	Floods         uint64 // times UnderFlood was raised
	ConnsFull      uint64 // TCP connections refused: every slot taken
	ConnsSource    uint64 // TCP connections refused: the address holds its share of slots
	PreAuth        uint64 // TCP connections closed without a whole first frame in time
	AuthFailed     uint64 // TCP first frames that failed authenticate
}

// UnderFlood reports whether the transport has refused a burst of traffic
// (floodBurst refusals within 10 s) in the last minute: datagrams over the
// read budget or failing authenticate, and, for TCP, connections refused. It
// is local status, like the node's own flood of AEAD failures.
func (t *Transport) UnderFlood() bool { return t.lim.underFlood() }

// Counters reports what the transport refused before the node saw it.
func (t *Transport) Counters() Counters { return t.lim.counters() }

// bucket is a token bucket: rate tokens a second, up to burst.
type bucket struct {
	tokens float64
	last   time.Duration
}

func fullBucket(now time.Duration, burst float64) *bucket {
	return &bucket{tokens: burst, last: now}
}

func (b *bucket) refill(now time.Duration, rate, burst float64) {
	if now > b.last {
		b.tokens = min(burst, b.tokens+rate*(now-b.last).Seconds())
		b.last = now
	}
}

// take spends one token if there is one.
func (b *bucket) take(now time.Duration, rate, burst float64) bool {
	b.refill(now, rate, burst)
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// spend spends one token even when there is none, and returns how long the
// caller waits for the debt to be paid.
func (b *bucket) spend(now time.Duration, rate, burst float64) time.Duration {
	b.refill(now, rate, burst)
	b.tokens--
	if b.tokens >= 0 {
		return 0
	}
	return time.Duration(-b.tokens / rate * float64(time.Second))
}

// floodWatch raises a flood at floodBurst refusals within floodWindow and
// lowers it after floodQuiet without one.
type floodWatch struct {
	start, last time.Duration
	count       int
	raised      bool
}

// note records one refusal and reports whether it raised the flood.
func (f *floodWatch) note(now time.Duration) bool {
	if now-f.start > floodWindow || now < f.start || f.count == 0 {
		f.start, f.count = now, 0
	}
	f.count++
	if f.count < floodBurst {
		return false
	}
	f.last = now
	if f.raised {
		return false
	}
	f.raised = true
	return true
}

func (f *floodWatch) active(now time.Duration) bool {
	if f.raised && now-f.last > floodQuiet {
		f.raised = false
	}
	return f.raised
}

// limiter holds the read budget, the known addresses and the flood signal of
// one transport.
type limiter struct {
	mu      sync.Mutex
	now     func() time.Duration // monotonic; tests replace it
	read    *bucket
	known   map[netip.Addr]time.Duration // address: when a datagram from it was last handed on
	kAll    *bucket                      // all known addresses
	uAll    *bucket                      // authenticate calls for unknown addresses
	sources map[netip.Addr]*bucket
	swept   time.Duration
	flood   floodWatch
	c       Counters
}

func newLimiter() *limiter {
	start := time.Now()
	return &limiter{
		now:     func() time.Duration { return time.Since(start) },
		read:    fullBucket(0, readBurst),
		known:   make(map[netip.Addr]time.Duration),
		kAll:    fullBucket(0, knownBurst),
		uAll:    fullBucket(0, unknownBurst),
		sources: make(map[netip.Addr]*bucket),
		swept:   -sweepEvery,
	}
}

// pace spends one read and returns how long the read loop waits before it
// looks at what it read.
func (l *limiter) pace() time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	d := l.read.spend(l.now(), readRate, readBurst)
	if d > 0 {
		l.c.ReadPaced++
	}
	return d
}

// verdict is what check decides for one datagram.
type verdict int

const (
	drop   verdict = iota
	pass           // from a known address, within budget: to the node
	verify         // from an unknown address, within budget: authenticate first
)

// admit decides whether datagram b from src goes to the node: check, then
// for an unknown address, auth (outside the limiter's lock), whose success
// makes the address known.
func (l *limiter) admit(src netip.Addr, b []byte, auth func([]byte) bool) bool {
	switch l.check(src, len(b)) {
	case pass:
		return true
	case verify:
		ok := auth(b)
		l.verified(src, ok)
		return ok
	}
	return false
}

// check decides a datagram of size bytes from src before any cryptography:
// over MaxDatagram, or over its address's rate, it is dropped; from a known
// address it goes to the node within the rate of known addresses; from an
// unknown one it is checked within the rate of checks. A datagram refused by
// its address spends nothing of the global rates, so one address cannot use
// up the others' share.
func (l *limiter) check(src netip.Addr, size int) verdict {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if size > MaxDatagram {
		l.c.Oversize++
		l.refusedLocked(now)
		return drop
	}
	src = src.Unmap()
	if b := l.bucketLocked(src, now); b != nil && !b.take(now, sourceRate, sourceBurst) {
		l.c.SourceLimited++
		l.refusedLocked(now)
		return drop
	}
	if l.knownLocked(src, now) {
		if !l.kAll.take(now, knownRate, knownBurst) {
			l.c.KnownLimited++
			l.refusedLocked(now)
			return drop
		}
		l.known[src] = now
		return pass
	}
	if !l.uAll.take(now, unknownRate, unknownBurst) {
		l.c.UnknownLimited++
		l.refusedLocked(now)
		return drop
	}
	return verify
}

// verified records what authenticate said of a datagram from the unknown
// address src: a pass makes src known, a failure is a refusal.
func (l *limiter) verified(src netip.Addr, ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if !ok {
		l.c.Unverified++
		l.refusedLocked(now)
		return
	}
	l.learnLocked(src.Unmap(), now)
}

// bucketLocked returns src's bucket, making one when the table has room. It
// returns nil when the table is full of active addresses: the datagram then
// meets only the global rates.
func (l *limiter) bucketLocked(src netip.Addr, now time.Duration) *bucket {
	if b := l.sources[src]; b != nil {
		return b
	}
	if len(l.sources) >= maxSources && !l.sweepLocked(now) {
		l.c.Untracked++
		return nil
	}
	b := fullBucket(now, sourceBurst)
	l.sources[src] = b
	return b
}

// sweepLocked drops the addresses idle long enough for their bucket to be
// full again, at most once per sweepEvery, and reports whether there is room.
func (l *limiter) sweepLocked(now time.Duration) bool {
	if now-l.swept >= sweepEvery {
		l.swept = now
		for a, b := range l.sources {
			b.refill(now, sourceRate, sourceBurst)
			if b.tokens >= sourceBurst {
				delete(l.sources, a)
			}
		}
	}
	return len(l.sources) < maxSources
}

// knownLocked reports whether src is known now; an entry past knownTTL is
// given up.
func (l *limiter) knownLocked(src netip.Addr, now time.Duration) bool {
	at, ok := l.known[src]
	if ok && now-at > knownTTL {
		delete(l.known, src)
		return false
	}
	return ok
}

// learnLocked makes src known; past maxKnown the longest unseen address is
// given up.
func (l *limiter) learnLocked(src netip.Addr, now time.Duration) {
	if _, ok := l.known[src]; !ok && len(l.known) >= maxKnown {
		var oldest netip.Addr
		at := now + 1
		for a, seen := range l.known {
			if seen < at {
				oldest, at = a, seen
			}
		}
		delete(l.known, oldest)
	}
	l.known[src] = now
}

// refuse counts one refusal outside the read loops (a TCP connection) in
// counter, a field of l.c, and towards the flood signal.
func (l *limiter) refuse(counter *uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	*counter++
	l.refusedLocked(l.now())
}

// refusedLocked counts one refusal towards the flood signal.
func (l *limiter) refusedLocked(now time.Duration) {
	if l.flood.note(now) {
		l.c.Floods++
	}
}

func (l *limiter) underFlood() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.flood.active(l.now())
}

func (l *limiter) counters() Counters {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.c
}
