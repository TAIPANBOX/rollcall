package sim

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/node"
)

// # The fake network
//
// Every router has one address on the site and one or more faces: the
// node.Node instances that run with its identity (one for an honest
// router, two for an equivocator). A face is the node.Net of its node.
//
// UDP. Multicast reaches every other router on the sender's segment (one
// segment for the whole site unless Options.Separate puts each router on
// its own LAN); unicast reaches the router with that address, on any
// segment (routed). A datagram is lost with the site's loss probability,
// is delayed by one to SetDelay's steps, and is delivered only if the link
// is still up when it arrives: both routers powered, in the same group of
// a partition, neither cut off. It reaches every face of the router it is
// for; an equivocator's face sends only to the routers that see it.
//
// TCP. Stream is synchronous: the request reaches the face the caller sees
// (Authenticate, then HandleStream, as the transport does), and the reply
// comes back at once. A lossy link drops the request or the reply with the
// loss probability, as a TCP connection that times out.
//
// Nothing here sleeps: time moves only in Site.Run.

var (
	errUnreachable = errors.New("sim: no route to the router")
	errRefused     = errors.New("sim: connection refused")
	errClosed      = errors.New("sim: connection closed without an answer")
	errNoInternet  = errors.New("sim: no internet")
)

// maxFrame is the transport's largest TCP frame.
const maxFrame = 1 << 16

// datagram is a UDP packet on its way.
type datagram struct {
	due       int64          // the step it arrives at
	src       netip.AddrPort // the source address
	from      *router        // nil for an unpaired device
	to        *router
	multicast bool
	b         []byte
}

// face is one node.Node running with a router's identity, and its Net.
type face struct {
	r    *router
	idx  int
	dir  string // its store directory
	node *node.Node
}

// serves reports whether the router to sees this face.
func (f *face) serves(to *router) bool {
	return len(f.r.faces) == 1 || f.r.sees[to] == f.idx
}

// Multicast sends b to every other router on the segment.
func (f *face) Multicast(b []byte) error {
	s := f.r.s
	s.record(f.r, b)
	for _, to := range s.routers {
		if to != f.r && to.segment == f.r.segment {
			s.emit(f, to, true, b)
		}
	}
	return nil
}

// Unicast sends b to the router at to; to an address nobody has, it is
// lost, as UDP is.
func (f *face) Unicast(to netip.AddrPort, b []byte) error {
	s := f.r.s
	s.record(f.r, b)
	if r := s.byAddr[to]; r != nil && r != f.r {
		s.emit(f, r, false, b)
	}
	return nil
}

// Stream makes one TCP exchange with the router at to.
func (f *face) Stream(to netip.AddrPort, b []byte) ([]byte, error) {
	s := f.r.s
	r := s.byAddr[to]
	switch {
	case r == nil || r == f.r:
		return nil, errUnreachable
	case !f.serves(r) || !s.linkUp(f.r, r) || s.lose():
		return nil, errUnreachable
	}
	return s.stream(f.r.addr, f.r, r, b)
}

// stream hands the request b from src (the router from, or nil for an
// unpaired device) to the face of r that from sees, and returns its reply.
func (s *Site) stream(src netip.AddrPort, from, r *router, b []byte) ([]byte, error) {
	if r == s.broken.deaf {
		return nil, errUnreachable
	}
	t := r.faceFor(from)
	if t == nil || t.node == nil {
		return nil, errRefused
	}
	if len(b) > maxFrame || !t.node.Authenticate(b) {
		return nil, errClosed
	}
	// The TCP source port is an ephemeral one.
	reply := t.node.HandleStream(netip.AddrPortFrom(src.Addr(), 40000), bytes.Clone(b))
	if reply == nil {
		return nil, errClosed
	}
	if from != nil && (from == s.broken.deaf || s.lose()) {
		return nil, errUnreachable
	}
	s.stats.Streams++
	return reply, nil
}

// emit puts b from face f to the router to on the air.
func (s *Site) emit(f *face, to *router, multicast bool, b []byte) {
	if !f.serves(to) || !s.linkUp(f.r, to) || s.lose() {
		return
	}
	s.air = append(s.air, datagram{due: s.step + s.delaySteps(), src: f.r.addr, from: f.r, to: to, multicast: multicast, b: bytes.Clone(b)})
}

// deliverDue delivers the datagrams due at this step.
func (s *Site) deliverDue() {
	if len(s.air) == 0 {
		return
	}
	var now, later []datagram
	for _, d := range s.air {
		if d.due <= s.step {
			now = append(now, d)
		} else {
			later = append(later, d)
		}
	}
	s.air = later
	for _, d := range now {
		switch {
		case !d.to.powered || d.to == s.broken.deaf:
			continue
		case d.from != nil && !s.linkUp(d.from, d.to):
			continue // the link went down on the way
		}
		s.stats.UDP++
		if d.multicast {
			s.stats.Multicast++
		}
		for _, f := range d.to.faces {
			if f.node != nil {
				f.node.HandlePacket(d.src, bytes.Clone(d.b))
			}
		}
	}
}

// linkUp reports whether a and b can reach each other now.
func (s *Site) linkUp(a, b *router) bool {
	return a.powered && b.powered && a.group == b.group && !a.cut && !b.cut
}

func (s *Site) lose() bool {
	return s.loss > 0 && s.rng.Float64() < s.loss
}

func (s *Site) delaySteps() int64 {
	n := int64(s.delay / Step)
	if n <= 1 {
		return 1
	}
	return 1 + s.rng.Int64N(n)
}

// record keeps b, sent by r, while capturing.
func (s *Site) record(r *router, b []byte) {
	if s.capture {
		s.captured[r] = append(s.captured[r], bytes.Clone(b))
	}
}

// # The fake clock
//
// The site's true time is start plus the elapsed steps. A router's wall
// clock is the true time plus its skew: zero while it is NTP-synced, and
// after a power cut the time sysfixtime leaves (the newest file under
// /etc: about when the router last wrote its state) until it reaches the
// internet again. Its monotonic clock counts from its boot.

type clockOf struct{ r *router }

func (c clockOf) Now() time.Time      { return c.r.now() }
func (c clockOf) Mono() time.Duration { return c.r.mono() }

// # The fake chat
//
// Every sender's channel writes to the one chat of the site. A router
// reaches Telegram while it is powered, has internet, and Telegram is up.

type channel struct{ r *router }

func (c *channel) Send(_ context.Context, text string, _ bool) error {
	s := c.r.s
	if !s.reachesTelegram(c.r) {
		return errNoInternet
	}
	if s.broken.loseChat {
		return nil
	}
	m := Message{At: s.el, Wall: s.wall(), By: c.r.name, Text: text}
	s.chat = append(s.chat, m)
	if s.broken.doubleChat {
		s.chat = append(s.chat, m)
	}
	return nil
}

func (c *channel) Ping(context.Context) error {
	if !c.r.s.reachesTelegram(c.r) {
		return errNoInternet
	}
	return nil
}

func (s *Site) reachesTelegram(r *router) bool {
	return r.powered && r.internet && s.telegram
}

// Message is one message the chat received.
type Message struct {
	At   time.Duration // since the site started
	Wall time.Time     // the site's true time then
	By   string        // the router that sent it
	Text string
}

func (m Message) String() string {
	return fmt.Sprintf("%7s %s: %s", m.At.Round(time.Second), m.By, m.Text)
}

// # Writes
//
// The store writes files directly, so writes are counted the way a flash
// would see them: a file whose modification time changed since the last
// look, once a simulated minute (the node writes at most once a minute).

func (s *Site) countWrites() {
	for _, r := range s.routers {
		for _, f := range r.faces {
			es, err := os.ReadDir(f.dir)
			if err != nil {
				continue
			}
			for _, e := range es {
				info, err := e.Info()
				if err != nil || strings.HasPrefix(e.Name(), ".") {
					continue
				}
				p := filepath.Join(f.dir, e.Name())
				if t := info.ModTime(); !t.Equal(s.mtimes[p]) {
					s.mtimes[p] = t
					s.stats.Writes++
				}
			}
		}
	}
}
