package transport

import (
	"net/netip"
	"sync"
	"time"
)

// The read budget (security spec 5.2 and threat 4): what the read loops hand
// the node, where every datagram is opened under the node's lock, has a
// ceiling, and so do the reads themselves. A real group is at most 32 members;
// each sends one heartbeat every 5 s on each path to this router (multicast on
// a shared segment, unicast to a static peer) and four at once when it
// announces a shutdown. Every number below leaves ten times that or more.
// Nothing is blocked by address: a bucket refills, so a spoofed member's
// address only shares that member's bucket, never mutes it for good.
const (
	// sourceRate and sourceBurst bound one source address: 0.2 heartbeats a
	// second per path, 4 at a shutdown; 8 a second and 32 at once is forty
	// and eight times that.
	sourceRate  = 8
	sourceBurst = 32
	// globalRate and globalBurst bound all sources together: 31 peers on two
	// paths send about 12 a second, and all their shutdown bursts at once are
	// 248. At about 0.1 ms to open 1200 bytes on a small MIPS router
	// (estimated, not measured), 256 a second is near 3% of one core.
	globalRate  = 256
	globalBurst = 512
	// readRate and readBurst bound the reads, handed on or dropped, so a flood
	// costs at most this many system calls a second; past it the read loops
	// wait, and the kernel drops what does not fit the socket buffer.
	readRate  = 2048
	readBurst = 256
	// maxSources bounds the table of source buckets: 32 members with a few
	// addresses each (IPv4, global and link-local IPv6) is about 128.
	maxSources = 1024
	// sweepEvery spaces the sweeps of idle sources out of a full table.
	sweepEvery = time.Second
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
	Oversize      uint64 // UDP datagrams over MaxDatagram
	SourceLimited uint64 // UDP datagrams over their source's rate
	SourcesFull   uint64 // UDP datagrams from a new source while the source table was full
	RateLimited   uint64 // UDP datagrams over the rate of all sources together
	ReadPaced     uint64 // reads that waited for the read rate
	Floods        uint64 // times UnderFlood was raised
	ConnsFull     uint64 // TCP connections refused: every slot taken
	ConnsSource   uint64 // TCP connections refused: the address holds its share of slots
	PreAuth       uint64 // TCP connections closed without a whole first frame in time
	AuthFailed    uint64 // TCP first frames that failed authenticate
}

// UnderFlood reports whether the transport has refused a burst of traffic
// (floodBurst refusals within 10 s) in the last minute: datagrams over the
// read budget, and, for TCP, connections refused. It is local status, like
// the node's own flood of AEAD failures.
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

// limiter holds the read budget and the flood signal of one transport.
type limiter struct {
	mu      sync.Mutex
	now     func() time.Duration // monotonic; tests replace it
	read    *bucket
	global  *bucket
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
		global:  fullBucket(0, globalBurst),
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

// admit decides whether a datagram of size bytes from src goes to the node:
// not over MaxDatagram, within its source's rate, then within the rate of
// all sources. A datagram refused by its source spends nothing of the global
// rate, so one source cannot use up the others' share.
func (l *limiter) admit(src netip.Addr, size int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if size > MaxDatagram {
		l.c.Oversize++
		l.refusedLocked(now)
		return false
	}
	src = src.Unmap()
	b := l.sources[src]
	if b == nil {
		if len(l.sources) >= maxSources && !l.sweepLocked(now) {
			l.c.SourcesFull++
			l.refusedLocked(now)
			return false
		}
		b = fullBucket(now, sourceBurst)
		l.sources[src] = b
	}
	if !b.take(now, sourceRate, sourceBurst) {
		l.c.SourceLimited++
		l.refusedLocked(now)
		return false
	}
	if !l.global.take(now, globalRate, globalBurst) {
		l.c.RateLimited++
		l.refusedLocked(now)
		return false
	}
	return true
}

// sweepLocked drops the sources idle long enough for their bucket to be full
// again, at most once per sweepEvery, and reports whether there is room now.
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
