// Package sim runs a whole rollcall site in one process: several node.Node
// instances on a fake network (net.go) under a fake clock, with a fake
// chat that records every message. It drives the nodes only through their
// exported API, as the daemon does, and proves the behaviour of
// features/group.feature scenario by scenario (scenarios_test.go) and under
// random faults (sweep_test.go).
//
// # Time
//
// The site moves in steps of 100 ms (Step); nothing sleeps in real time. A
// datagram arrives one or more steps after it was sent. Every running
// router is ticked once a simulated second, at its own phase within the
// second: first the internet probe (probe.Prober, the daemon's, lost after
// 3 failures 10 s apart), then node.Tick.
//
// # Routers
//
// Router i is called r01, r02, ... and has the address 10.0.0.(i+1):7432.
// Each has its own store directory (and an identity directory for its boot
// sequence numbers) in a temporary directory that Close removes. The stores
// are opened with store.OpenNoSync: what a node writes is what a router
// writes, without the fsyncs that would make the sweep wait on the disk. A power
// cut drops the node with everything it held in RAM; power on starts a new
// node from what the store holds, with a new boot ID, the next boot
// sequence number, and a wall clock that is wrong until the router reaches
// the internet (NTP).
//
// # Determinism
//
// One seed drives every random choice of the site: identities, keys, boot
// IDs, tick phases, loss and delay. The nodes draw their nonces and request
// IDs from crypto/rand, which changes bytes only, and they iterate Go maps,
// whose order Go varies from run to run: a replay repeats the faults and
// the network exactly, and the nodes' decisions nearly always.
package sim

import (
	"context"
	"crypto/ed25519"
	"crypto/hpke"
	"fmt"
	mrand "math/rand/v2"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/clock"
	"github.com/TAIPANBOX/rollcall/internal/deliver"
	"github.com/TAIPANBOX/rollcall/internal/epoch"
	"github.com/TAIPANBOX/rollcall/internal/events"
	"github.com/TAIPANBOX/rollcall/internal/identity"
	"github.com/TAIPANBOX/rollcall/internal/ids"
	"github.com/TAIPANBOX/rollcall/internal/node"
	"github.com/TAIPANBOX/rollcall/internal/probe"
	"github.com/TAIPANBOX/rollcall/internal/roster"
	"github.com/TAIPANBOX/rollcall/internal/store"
)

const (
	// Step is how far the clock moves at a time.
	Step = 100 * time.Millisecond
	// Port is the rollcall port of every router.
	Port = 7432
	// Version is the OpenWrt release every router starts with.
	Version = "24.10.4"
	// UpgradeTime is how long a router is away for an upgrade.
	UpgradeTime = 3 * time.Minute

	siteName    = "Home"
	stepsPerSec = int64(time.Second / Step)
	// bootUptime is the router's uptime when the daemon starts.
	bootUptime = 25 * time.Second
	// ntpAfter is how long after the daemon's start NTP answers, once
	// the router reaches the internet.
	ntpAfter = 5 * time.Second
	// shutdownTime is how long a planned shutdown takes after the router
	// announced it.
	shutdownTime = 2 * time.Second
)

// start is when every site starts: 09:00:00 UTC.
var start = time.Date(2026, 10, 23, 9, 0, 0, 0, time.UTC)

// intruder is the address of a device on the LAN that was never paired.
var intruder = netip.MustParseAddrPort("10.0.0.200:7432")

// Options says how a site is made.
type Options struct {
	// N is the number of routers, at least 1.
	N int
	// Seed drives every random choice of the site.
	Seed int64
	// Senders maps a router index to its priority as a sender, for the
	// routers with the sender role and the bot token. Nil means router 0
	// with priority 2 and, with two or more routers, router 1 with 1.
	Senders map[int]int
	// Separate puts every router on its own LAN: multicast reaches nobody
	// else, and every router has the others as static peers.
	Separate bool
	// Equivocator, when not nil, makes the last router equivocate: it runs
	// twice with one identity and one boot, and the routers listed here
	// see its second face, the others its first. It never sends and is
	// never power-cycled.
	Equivocator []int
}

// Cycle is one power cycle of a router: when it went off, when it came
// back (-1 while it is off), and why: "crash", "planned reboot" or
// "upgrade".
type Cycle struct {
	Member  int
	Kind    string
	Off, On time.Duration
}

// Stats counts what the fake network carried and the store wrote.
type Stats struct {
	UDP       int // datagrams delivered
	Multicast int // of them multicast
	Streams   int // TCP exchanges answered
	Writes    int // store files written, summed over every router
}

// Site is one simulated site. It is not safe for concurrent use; sites are
// independent of each other.
type Site struct {
	o    Options
	rng  *mrand.Rand
	root string

	el   time.Duration // since the site started
	step int64

	routers []*router
	byAddr  map[netip.AddrPort]*router
	eq      *router
	key     epoch.Key

	air      []datagram
	todo     []scheduled
	loss     float64
	delay    time.Duration
	telegram bool

	chat        []Message
	cycles      []Cycle
	partitioned bool               // a partition or a cut link happened
	split       bool               // one is in force now
	splits      [][2]time.Duration // when one was in force; -1 for an end still open
	stats       Stats
	mtimes      map[string]time.Time
	capture     bool
	captured    map[*router][][]byte

	broken breaks
}

// breaks are faults planted in the fake itself, to show that the sweep
// sees them (TestSweepHasTeeth).
type breaks struct {
	loseChat   bool    // the chat accepts messages and loses them
	doubleChat bool    // the chat shows every message twice
	deaf       *router // nothing reaches this router
}

type scheduled struct {
	at time.Duration
	do func()
}

// router is one router of the site.
type router struct {
	s     *Site
	i     int
	name  string
	id    *identity.Identity
	addr  netip.AddrPort
	dir   string // its directory; the stores and the identity directory are under it
	idDir string
	faces []*face
	sees  map[*router]int // for an equivocator: the face each router sees

	sender  bool
	prio    int
	version string
	peers   []netip.AddrPort // static peers

	powered  bool
	planned  bool // the shutdown marker: the next boot follows an announced shutdown
	internet bool
	trusted  bool
	skew     time.Duration
	bootAt   time.Duration // when its monotonic clock was 0
	started  time.Duration // when its daemon started
	offAt    time.Duration
	boot     ids.BootID
	bootSeq  uint64
	prober   *probe.Prober
	phase    int64

	group   int
	cut     bool
	segment int
}

func (r *router) now() time.Time      { return r.s.wall().Add(r.skew) }
func (r *router) mono() time.Duration { return r.s.el - r.bootAt }
func (r *router) running() bool       { return r.powered && r.faces[0].node != nil }
func (r *router) stamp() clock.Stamp {
	return clock.Stamp{Wall: r.now(), Mono: r.mono(), Trusted: r.trusted, Boot: r.boot}
}

func (r *router) faceFor(from *router) *face {
	if len(r.faces) == 1 || from == nil {
		return r.faces[0]
	}
	return r.faces[r.sees[from]]
}

// NewSite returns a site of n routers made from seed, with the default
// senders.
func NewSite(n int, seed int64) *Site { return New(Options{N: n, Seed: seed}) }

// New returns the site o describes: every router paired into one group,
// powered, with internet, its clock synced, and its node started. It
// panics if the site cannot be made (a temporary directory, a node that
// does not start): it is a test harness.
func New(o Options) *Site {
	if o.N < 1 || o.N > roster.MaxMembers {
		panic(fmt.Sprintf("sim: %d routers", o.N))
	}
	if o.Senders == nil {
		o.Senders = map[int]int{0: 1}
		if o.N > 1 {
			o.Senders = map[int]int{0: 2, 1: 1}
		}
	}
	root, err := os.MkdirTemp("", "rollcall-sim-")
	must(err)
	s := &Site{o: o, rng: mrand.New(mrand.NewPCG(uint64(o.Seed), 0x73696d)), root: root,
		byAddr: map[netip.AddrPort]*router{}, telegram: true, delay: Step,
		mtimes: map[string]time.Time{}, captured: map[*router][][]byte{}}
	for i := 0; i < o.N; i++ {
		prio, sender := o.Senders[i]
		s.add(sender, prio)
	}
	if o.Equivocator != nil {
		s.eq = s.routers[o.N-1]
		if s.eq.sender || o.N < 3 {
			panic("sim: the equivocator must be a third router without the sender role")
		}
		s.eq.faces = append(s.eq.faces, &face{r: s.eq, idx: 1, dir: filepath.Join(s.eq.dir, "store-b")})
		for _, j := range o.Equivocator {
			s.eq.sees[s.routers[j]] = 1
		}
	}
	if o.Separate {
		for _, r := range s.routers {
			for _, p := range s.routers {
				if p != r {
					r.peers = append(r.peers, p.addr)
				}
			}
		}
	}

	rec := ed25519.NewKeyFromSeed(s.bytes(ed25519.SeedSize))
	r := roster.Roster{Version: 1, Site: "home", RecoveryPub: rec.Public().(ed25519.PublicKey)}
	for _, x := range s.routers {
		r.Members = append(r.Members, x.member(x.i == 0))
	}
	r.Admins = []ids.MemberID{s.routers[0].id.ID}
	first, err := roster.SignRoster(r, s.routers[0].id.ID, s.routers[0].id.Sign, false)
	must(err)
	s.key = epoch.Key{ID: 4, Secret: s.bytes(epoch.SecretSize), NotAfter: start.Add(epoch.RotationPeriod)}
	for _, x := range s.routers {
		for _, f := range x.faces {
			st, err := store.OpenNoSync(f.dir)
			must(err)
			must(node.Bootstrap(st, first, s.key))
			if x.sender {
				must(node.SaveSecrets(st, "CANARY-123:abc", 42))
			}
		}
		x.powered, x.trusted, x.bootAt = true, true, -10*time.Minute
		s.start(x, true)
	}
	return s
}

// add makes router len(s.routers): identity, address, directories.
func (s *Site) add(sender bool, prio int) *router {
	i := len(s.routers)
	r := &router{s: s, i: i, name: fmt.Sprintf("r%02d", i+1), id: s.identity(),
		addr:   netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, 0, byte(i + 1)}), Port),
		sender: sender, prio: prio, version: Version, internet: true, sees: map[*router]int{},
		phase: s.rng.Int64N(stepsPerSec)}
	r.dir = filepath.Join(s.root, r.name)
	r.idDir = filepath.Join(r.dir, "id")
	r.faces = []*face{{r: r, dir: filepath.Join(r.dir, "store")}}
	if s.o.Separate {
		r.segment = i
	}
	must(os.MkdirAll(r.idDir, 0o700))
	s.routers = append(s.routers, r)
	s.byAddr[r.addr] = r
	return r
}

func (r *router) member(primary bool) roster.Member {
	m := roster.Member{ID: r.id.ID, Name: r.name, SignPub: r.id.Sign.Public().(ed25519.PublicKey), RecvPub: r.id.Recv.PublicKey().Bytes()}
	if primary {
		m.Roles = append(m.Roles, roster.RolePrimary)
	}
	if r.sender {
		m.Roles = append(m.Roles, roster.RoleSender)
	}
	return m
}

func (s *Site) bytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(s.rng.Uint32())
	}
	return b
}

func (s *Site) identity() *identity.Identity {
	id := &identity.Identity{Sign: ed25519.NewKeyFromSeed(s.bytes(ed25519.SeedSize))}
	copy(id.ID[:], s.bytes(len(id.ID)))
	recv, err := hpke.MLKEM768X25519().NewPrivateKey(s.bytes(32))
	must(err)
	id.Recv = recv
	return id
}

func must(err error) {
	if err != nil {
		panic(fmt.Sprintf("sim: %v", err))
	}
}

// start starts r's daemon: one node per face, from the store. newBoot is
// false for a daemon restart, which keeps the kernel's boot ID.
func (s *Site) start(r *router, newBoot bool) {
	if newBoot {
		copy(r.boot[:], s.bytes(len(r.boot)))
	}
	if r == s.eq {
		r.bootSeq = 1
	} else {
		seq, err := identity.NextBootSeq(r.idDir)
		must(err)
		r.bootSeq = seq
	}
	cfg := node.Config{Site: siteName, Heartbeat: 5 * time.Second, SilentAfter: 30 * time.Second,
		Sender: r.sender, Priority: r.prio, TZ: time.UTC, Boot: r.boot, BootSeq: r.bootSeq,
		Planned: r.planned, Peers: slices.Clone(r.peers), Versions: [2]string{r.version, "1.0.0"}}
	if r != s.eq {
		cfg.IdentityDir = r.idDir
	}
	r.planned, r.started = false, s.el
	r.prober = &probe.Prober{Probe: func(context.Context) error {
		if r.internet {
			return nil
		}
		return errNoInternet
	}}
	for _, f := range r.faces {
		st, err := store.OpenNoSync(f.dir)
		must(err)
		var ch deliver.Channel
		if r.sender {
			ch = &channel{r: r}
		}
		n, err := node.New(cfg, st, r.id, f, clockOf{r}, ch)
		if err != nil {
			panic(fmt.Sprintf("sim: %s does not start: %v", r.name, err))
		}
		n.SetClockTrusted(r.trusted)
		f.node = n
	}
}

// Close removes the site's directories.
func (s *Site) Close() { os.RemoveAll(s.root) }

// # Running

// Run moves the site d on, step by step.
func (s *Site) Run(d time.Duration) {
	for end := s.el + d; s.el < end; {
		s.el += Step
		s.step++
		s.deliverDue()
		s.runTodo()
		for _, r := range s.routers {
			if r.running() && s.step%stepsPerSec == r.phase {
				s.tick(r)
			}
		}
		if s.step%(60*stepsPerSec) == 0 {
			s.countWrites()
		}
	}
}

// RunUntil runs the site until cond holds, checking once a second, at
// most max. It returns the time cond first held, and whether it did.
func (s *Site) RunUntil(cond func() bool, max time.Duration) (time.Duration, bool) {
	for end := s.el + max; s.el < end; {
		s.Run(time.Second)
		if cond() {
			return s.el, true
		}
	}
	return s.el, false
}

func (s *Site) runTodo() {
	if len(s.todo) == 0 {
		return
	}
	var due []scheduled
	s.todo = slices.DeleteFunc(s.todo, func(a scheduled) bool {
		if a.at <= s.el {
			due = append(due, a)
			return true
		}
		return false
	})
	for _, a := range due {
		a.do()
	}
}

func (s *Site) after(d time.Duration, do func()) {
	s.todo = append(s.todo, scheduled{at: s.el + d, do: do})
}

// tick is one second of router r: NTP, the internet probe, the node.
func (s *Site) tick(r *router) {
	if !r.trusted && r.internet && s.el-r.started >= ntpAfter {
		r.skew, r.trusted = 0, true
		for _, f := range r.faces {
			f.node.SetClockTrusted(true)
		}
	}
	switch lost, restored, since := r.prober.Tick(r.now()); {
	case lost:
		s.local(r, events.InternetLost, since)
	case restored:
		s.local(r, events.InternetRestored, since)
	}
	for _, f := range r.faces {
		if f.node != nil {
			f.node.Tick()
		}
	}
}

// local hands an event the router saw itself to its nodes, stamped when
// the condition began, as the daemon does.
func (s *Site) local(r *router, typ events.Type, since time.Time) {
	e := events.Event{Type: typ}
	if now := r.now(); !since.IsZero() && now.Sub(since) > time.Second {
		e.At = clock.Stamp{Wall: since, Mono: max(r.mono()-now.Sub(since), 0), Trusted: r.trusted, Boot: r.boot}
	}
	for _, f := range r.faces {
		f.node.LocalEvent(e)
	}
}

func (s *Site) wall() time.Time { return start.Add(s.el) }

// # Faults

// PowerOff cuts router i's power: its node and everything it held in RAM
// are gone. The equivocator is never power-cycled.
func (s *Site) PowerOff(i int) {
	if r := s.routers[i]; r.powered && r != s.eq {
		s.powerOff(r, "crash")
	}
}

func (s *Site) powerOff(r *router, kind string) {
	r.powered = false
	for _, f := range r.faces {
		f.node = nil
	}
	r.offAt = s.el
	s.cycles = append(s.cycles, Cycle{Member: r.i, Kind: kind, Off: s.el, On: -1})
}

// PowerOn powers router i back on: a new boot from its store, its wall
// clock where sysfixtime leaves it until NTP answers.
func (s *Site) PowerOn(i int) {
	r := s.routers[i]
	if r.powered {
		return
	}
	for j := len(s.cycles) - 1; j >= 0; j-- {
		if s.cycles[j].Member == i {
			s.cycles[j].On = s.el
			break
		}
	}
	r.powered, r.trusted = true, false
	r.skew = -(s.el - r.offAt) - time.Duration(s.rng.Int64N(int64(time.Minute)))
	r.bootAt = s.el - bootUptime
	s.start(r, true)
}

// Reboot reboots router i as planned: it announces going down, shuts
// down, and powers on again down later with the shutdown marker set.
func (s *Site) Reboot(i int, down time.Duration) {
	r := s.routers[i]
	if !r.running() || r == s.eq {
		return
	}
	for _, f := range r.faces {
		f.node.GoingDown()
	}
	r.planned = true
	s.after(shutdownTime, func() {
		if r.powered {
			s.powerOff(r, "planned reboot")
		}
	})
	s.after(down, func() { s.PowerOn(i) })
}

// Upgrade upgrades router i to version: it goes away for UpgradeTime and
// comes back with the new version.
func (s *Site) Upgrade(i int, version string) {
	r := s.routers[i]
	if !r.powered || r == s.eq {
		return
	}
	s.powerOff(r, "upgrade")
	r.version = version
	s.after(UpgradeTime, func() { s.PowerOn(i) })
}

// restart restarts router r's daemon (a configuration reload): it
// announces going down and starts again in the same boot.
func (s *Site) restart(r *router) {
	for _, f := range r.faces {
		f.node.GoingDown()
		f.node = nil
	}
	r.planned = true
	s.start(r, false)
}

// CutLink cuts router i off the network while it stays up: its radio link
// is gone.
func (s *Site) CutLink(i int) {
	s.routers[i].cut = true
	s.splitNow()
}

func (s *Site) splitNow() {
	if !s.split {
		s.splits = append(s.splits, [2]time.Duration{s.el, -1})
	}
	s.partitioned, s.split = true, true
}

// Partition splits the site into groups that cannot reach each other; a
// router in no group is alone.
func (s *Site) Partition(groups ...[]int) {
	for _, r := range s.routers {
		r.group = -1 - r.i
	}
	for g, rs := range groups {
		for _, i := range rs {
			s.routers[i].group = g
		}
	}
	s.splitNow()
}

// Heal ends every partition and cut link.
func (s *Site) Heal() {
	for _, r := range s.routers {
		r.group, r.cut = 0, false
	}
	if s.split {
		s.splits[len(s.splits)-1][1] = s.el
	}
	s.split = false
}

// InternetDown takes the internet away from the routers ids, from every
// router without any.
func (s *Site) InternetDown(ids ...int) { s.setInternet(false, ids) }

// InternetUp gives it back.
func (s *Site) InternetUp(ids ...int) { s.setInternet(true, ids) }

func (s *Site) setInternet(up bool, ids []int) {
	if len(ids) == 0 {
		for _, r := range s.routers {
			r.internet = up
		}
		return
	}
	for _, i := range ids {
		s.routers[i].internet = up
	}
}

// TelegramDown makes Telegram unreachable for everyone.
func (s *Site) TelegramDown() { s.telegram = false }

// TelegramUp ends it.
func (s *Site) TelegramUp() { s.telegram = true }

// SetLoss sets the probability that one packet is lost on any link.
func (s *Site) SetLoss(p float64) { s.loss = p }

// SetDelay sets the longest delay of a datagram, at least one Step.
func (s *Site) SetDelay(d time.Duration) { s.delay = max(d, Step) }

// HealAll ends every fault: links, internet, Telegram, loss, and powers
// every router on; planned steps still pending are dropped.
func (s *Site) HealAll() {
	s.todo = nil
	s.Heal()
	s.InternetUp()
	s.TelegramUp()
	s.SetLoss(0)
	for i := range s.routers {
		s.PowerOn(i)
	}
}

// Equivocate makes the equivocator's two faces record two different
// entries at the same position of its chain: proof, once both reach one
// honest router, that it showed different histories.
func (s *Site) Equivocate() {
	if s.eq == nil {
		return
	}
	a, b := s.eq.stamp(), s.eq.stamp()
	b.Wall, b.Mono = b.Wall.Add(-time.Second), b.Mono-time.Second
	s.eq.faces[0].node.LocalEvent(events.Event{Type: events.UnderFlood, At: a})
	s.eq.faces[1].node.LocalEvent(events.Event{Type: events.UnderFlood, At: b})
}

// # Joining

// Join adds a new router the way an owner does: router 0 opens a join
// window (rollcall invite), the new router joins with the code over the
// network (rollcall join), and starts. On separate LANs both get each
// other as static peers, and router 0's daemon restarts to read its new
// one before the invitation. It returns the new router's index.
func (s *Site) Join(sender bool) (int, error) {
	admin := s.routers[0]
	r := s.add(sender, 0)
	if s.o.Separate {
		// The owner adds the new router's address as a static peer first.
		r.peers = []netip.AddrPort{admin.addr}
		admin.peers = append(admin.peers, r.addr)
		s.restart(admin)
	}
	code, err := admin.faces[0].node.Invite(admin.addr, sender)
	if err != nil {
		return 0, err
	}
	r.powered, r.trusted, r.bootAt = true, true, s.el-10*time.Minute
	st, err := store.OpenNoSync(r.faces[0].dir)
	must(err)
	if err := node.Join(st, r.faces[0], code, r.id, r.name); err != nil {
		return 0, err
	}
	s.start(r, true)
	return r.i, nil
}

// # An unpaired device

// Inject sends b from a device on the LAN that was never paired, to every
// powered router.
func (s *Site) Inject(b []byte) {
	for _, r := range s.routers {
		if r.powered {
			s.air = append(s.air, datagram{due: s.step + 1, src: intruder, to: r, b: slices.Clone(b)})
		}
	}
}

// InjectStream sends b as a TCP request from that device to router i.
func (s *Site) InjectStream(i int, b []byte) ([]byte, error) {
	r := s.routers[i]
	if !r.powered {
		return nil, errUnreachable
	}
	return s.stream(intruder, nil, r, b)
}

// Capture starts or stops recording the datagrams the routers send.
func (s *Site) Capture(on bool) { s.capture = on }

// Captured returns the datagrams router i sent while capturing.
func (s *Site) Captured(i int) [][]byte { return s.captured[s.routers[i]] }

// # Reading the site

// Chat returns the texts of the messages the chat received, in order.
func (s *Site) Chat() []string {
	var out []string
	for _, m := range s.chat {
		out = append(out, m.Text)
	}
	return out
}

// Messages returns the messages the chat received, in order.
func (s *Site) Messages() []Message { return slices.Clone(s.chat) }

// Status returns router i's status (its first face's); a router that is
// off reports State "off".
func (s *Site) Status(i int) node.Status {
	r := s.routers[i]
	if !r.running() {
		return node.Status{State: "off"}
	}
	return r.faces[0].node.Status()
}

// Len returns the number of routers.
func (s *Site) Len() int { return len(s.routers) }

// Name returns router i's name.
func (s *Site) Name(i int) string { return s.routers[i].name }

// Addr returns router i's address.
func (s *Site) Addr(i int) netip.AddrPort { return s.routers[i].addr }

// ID returns router i's member ID.
func (s *Site) ID(i int) ids.MemberID { return s.routers[i].id.ID }

// Powered reports whether router i has power.
func (s *Site) Powered(i int) bool { return s.routers[i].powered }

// Elapsed returns the time since the site started.
func (s *Site) Elapsed() time.Duration { return s.el }

// Wall returns the site's true time.
func (s *Site) Wall() time.Time { return s.wall() }

// Epoch returns the ID of the group's epoch key.
func (s *Site) Epoch() uint32 { return s.key.ID }

// Stats returns what the network carried and the stores wrote so far.
func (s *Site) Stats() Stats { return s.stats }

// Cycles returns every power cycle so far, in order.
func (s *Site) Cycles() []Cycle { return slices.Clone(s.cycles) }

// Stamp returns router i's clocks now, as its node reads them.
func (s *Site) Stamp(i int) clock.Stamp { return s.routers[i].stamp() }

// Partitioned reports whether a partition or a cut link ever happened.
func (s *Site) Partitioned() bool { return s.partitioned }

// Whole reports whether no partition or cut link is in force.
func (s *Site) Whole() bool { return !s.split }

// WholeAt reports whether no partition or cut link was in force at t.
func (s *Site) WholeAt(t time.Duration) bool {
	for _, sp := range s.splits {
		if t >= sp[0] && (sp[1] < 0 || t <= sp[1]) {
			return false
		}
	}
	return true
}
