package member

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"slices"
	"sync"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/clock"
	"github.com/TAIPANBOX/rollcall/internal/events"
	"github.com/TAIPANBOX/rollcall/internal/identity"
	"github.com/TAIPANBOX/rollcall/internal/ids"
	"github.com/TAIPANBOX/rollcall/internal/replay"
	"github.com/TAIPANBOX/rollcall/internal/roster"
	"github.com/TAIPANBOX/rollcall/internal/sig"
	"github.com/TAIPANBOX/rollcall/internal/store"
)

// The defaults of failure detection (design 4.2): a heartbeat every 5 s,
// suspect after 3 missed, silent after 6 (30 s).
const (
	DefaultInterval      = 5 * time.Second
	DefaultSuspectMissed = 3
	DefaultSilentMissed  = 6
)

// MaxHelpers is the most members IndirectProbeRequest names.
const MaxHelpers = 2

// MaxBootSeqRaise is how far RestoreBootSeq may raise this member's boot
// sequence number above the one it started with, in one run.
const MaxBootSeqRaise = 1 << 20

// The store file of the peers' boot sequence numbers.
const (
	peerBootSeqFile    = "peer-bootseq.json"
	peerBootSeqVersion = 1
	maxPeerBootSeqFile = 16 << 10
)

var (
	// ErrConfig reports a Config, or a roster, a Table cannot use.
	ErrConfig = errors.New("member: invalid table configuration")
	// ErrEpoch reports a heartbeat signed for another epoch than the one
	// its packet was sealed under.
	ErrEpoch = errors.New("member: heartbeat signed for another epoch than its packet's")
	// ErrUnknownMember reports a sender that is not in the roster.
	ErrUnknownMember = errors.New("member: sender is not in the roster")
	// ErrReplay reports a packet from an older boot of its sender, from
	// outside the replay window, or seen before.
	ErrReplay = errors.New("member: packet replayed or from an older boot")
	// ErrSignature reports a signature that does not verify under the
	// sender's key in the roster.
	ErrSignature = errors.New("member: signature does not verify")
	// ErrSelf reports a packet that carries this member's own identity.
	ErrSelf = errors.New("member: packet from this member's own identity")
	// ErrDuplicateIdentity reports a validly signed heartbeat that proves
	// two live routers with one identity.
	ErrDuplicateIdentity = errors.New("member: two live routers with one identity")
	// ErrUnsolicited reports a probe answer nobody asked for: its target is
	// not suspect, or its sender was not asked.
	ErrUnsolicited = errors.New("member: probe answer nobody asked for")
	// ErrBadReport reports a probe answer that says the target was heard in
	// the future.
	ErrBadReport = errors.New("member: probe answer with a negative age")
	// ErrBootSeqFile reports a store file of peers' boot sequence numbers
	// that does not decode.
	ErrBootSeqFile = errors.New("member: the peers' boot sequence file is corrupt")
)

// Config is what a Table starts from.
type Config struct {
	Self       ids.MemberID  // the local member
	Boot       ids.BootID    // the local member's boot ID
	BootSeq    uint64        // the boot sequence number this run started with (identity.NextBootSeq)
	Roster     roster.Roster // the accepted roster; it must list Self
	RosterHash ids.Hash      // the Hash of the Signed it came in
	Store      *store.Store  // where the peers' boot sequence numbers are kept

	// Failure detection; zero means the default.
	Interval      time.Duration // between two heartbeats of a member
	SuspectMissed int           // missed heartbeats before a member is suspect
	SilentMissed  int           // missed heartbeats before a member is silent
}

// Table is one member's view of the other members of its group. It is safe
// for concurrent use. Make one with New.
//
// # Time
//
// Every method that needs the time takes now as a clock.Stamp: the local wall
// clock, the local monotonic clock since boot (Mono), and whether the wall
// clock is trusted. Every deadline is measured on Mono alone, so a wall clock
// that steps after NTP answers moves none of them. now.Boot is not read; the
// Table stamps with Config.Boot.
//
// # Failure detection (design 4.2)
//
// A member is last heard at the newer of: the last heartbeat the Table
// accepted from it, and the moment a helper says it last heard it (below).
// Until anything is heard of a member, that is when the Table started, or
// when SetRoster added it, so a new Table needs a full silence of its own
// observation before it reports anyone. A member last heard
// SuspectMissed*Interval ago (15 s) is suspect; SilentMissed*Interval ago
// (30 s), silent, and Tick reports MemberSilent once, stamped at the moment it
// was last heard: the silence started then, not when it was noticed.
//
// Before a suspect becomes silent, other members are asked whether they still
// hear it (an indirect probe, as in SWIM), so that one broken link in a mesh
// does not look like a dead router. Tick returns the suspects due a probe
// round: once when a member becomes suspect and again every Interval while it
// stays suspect (at 15, 20 and 25 s by default). For each, the node calls
// IndirectProbeRequest, which names up to MaxHelpers helpers, the members with
// the lowest IDs that the Table hears directly and that are neither suspect
// nor silent, and sends them the probe. A helper answers with Report; the
// node passes each answer, after Admit, to RecordReport. An answer counts
// only while its target is still suspect, and only from a member asked during
// that suspicion; one that says the helper heard the target more recently
// than the Table did moves the target's last hearing to that moment, so the
// target is silent only once nobody asked has heard it for SilentMissed
// intervals. A helper is trusted with this as a member of the roster: a
// helper that lies can keep a dead member from being reported.
//
// # What a heartbeat shows
//
// When a silent member is heard again, the Table classifies its return with
// events.Classify, from its last heartbeat before the silence (whether it
// announced going down, its boot ID, its OpenWrt version) and the new one;
// Upgraded carries Detail "from" and "to". A member heard in a new boot
// without having gone silent rebooted all the same, and is classified the
// same way. A member whose silence Tick has not reported yet when its next
// heartbeat arrives gets its MemberSilent from Observe, before the return, so
// what is reported does not depend on when Tick ran. Every event is
// witnessed by Config.Self.
//
// Observe also reports, in Observed.RosterMismatch, a heartbeat that
// announces a roster hash other than Config.RosterHash (or the last
// SetRoster's); the node fetches that roster. It does so on every such
// heartbeat, and the node decides how often to fetch.
//
// # The order of checks (security spec 5.2)
//
// The node opens the packet (wire.Open: length, version, epoch, AEAD) and
// hands the plaintext to Observe, which goes on cheapest first: the length
// and format version; the epoch the heartbeat is signed for, against the one
// the packet opened under; the sender, From, against the roster; the replay
// check (below); the Ed25519 signature under the sender's key in the roster;
// every field (decodeBody); and only then is the packet recorded in the
// replay window and handled. Any failure drops the heartbeat, is counted
// (Counters), and changes nothing. A heartbeat from the member's own identity
// is not handled (ErrSelf) except as evidence for RestoreBootSeq.
//
// Admit is the same gate for every other message type from a peer (probe
// answers, for instance), so that every packet of a peer passes one replay
// window, as security spec 5.3 describes it.
//
// # Replay
//
// Per peer, the Table keeps a replay.Window, which it checks before the
// signature and records in only after it, and the highest boot sequence
// number it has accepted from that peer. That number is also kept in the
// store, in one small file written when a number rises (at most once a
// minute, by the store's Flusher), and loaded by New, so that after a restart
// of the local member a packet from an older boot of a peer is still refused.
// A restart still empties the windows, so the packets of a peer's current
// boot are taken again from the first one that arrives, in rising counter
// order.
//
// # Duplicate identity
//
// Two routers with one identity (a backup restored onto a second device)
// show as a validly signed heartbeat that the replay window refuses for a
// reason a replay cannot have: the boot sequence number of the current boot
// with another boot ID, or the previous boot's sequence number and boot ID
// with a counter beyond the last one accepted in that boot (the old boot is
// still running). Such a heartbeat is dropped with ErrDuplicateIdentity and
// raises one DuplicateIdentity event per conflicting boot ID.
//
// # Boot sequence numbers (security spec 5.3)
//
// A member restored from an older backup starts below the boot sequence
// number its peers remember, and they refuse it. The Table collects the
// highest number this identity is known to have used, from two sources only:
// a heartbeat signed with this member's own key in another boot (Observe),
// and a peer's Report about this member (RecordReport, so only from a
// roster member through Admit). A number counts if it is above this run's,
// or equal to it with another boot ID. RestoreBootSeq raises the stored
// number past it with identity.RaiseBootSeq, never by more than
// MaxBootSeqRaise above Config.BootSeq in one run, so a member whose key
// is compromised cannot push another to the end of the number space; a
// restored member that is further behind gets the rest on its next start.
//
// # Clock offsets (design 4.4)
//
// For each peer whose latest heartbeat says its clock is trusted, the Table
// keeps that heartbeat's wall clock minus the local monotonic clock when it
// arrived: what the local monotonic clock must be shifted by to read the
// trusted wall clock. The network delay on a LAN is ignored. Offset returns
// the median of these (the lower one of the middle two for an even count), so
// that one lying clock cannot move it. A local stamp on an untrusted wall
// clock is Mono plus that offset, and counts as trusted; without any trusted
// peer it is the local wall clock, untrusted. A local clock that is trusted
// stamps with its own wall clock.
type Table struct {
	mu sync.Mutex

	self     ids.MemberID
	boot     ids.BootID
	startSeq uint64
	ownSeq   uint64
	selfPub  ed25519.PublicKey

	interval     time.Duration
	suspectAfter time.Duration
	silentAfter  time.Duration

	rosterHash ids.Hash
	peers      map[ids.MemberID]*peer
	offsets    map[ids.MemberID]time.Duration
	evidence   uint64 // the highest boot sequence number this identity is known to have used; 0 for none
	counters   Counters

	st      *store.Store
	flusher *store.Flusher
}

// peer is the Table's state for one other member.
type peer struct {
	id  ids.MemberID
	pub ed25519.PublicKey

	// Replay.
	window  replay.Window
	floor   uint64  // the highest boot sequence number accepted, or loaded from the store
	cur     bootRun // the boot the window is in
	prev    bootRun // the boot before it, as last seen
	dupSeen bool    // a duplicate was reported
	dupBoot ids.BootID

	// What its heartbeats said.
	heardOnce bool          // a heartbeat was accepted since the Table started
	heard     time.Duration // local Mono of the last one; the start until then
	vouched   time.Duration // local Mono at which a helper last heard it
	boot      ids.BootID
	version   string
	goingDown bool

	// Failure detection, as of the last Tick or Observe.
	suspect   bool
	silent    bool
	reachable bool           // heard directly within the suspect deadline
	probed    time.Duration  // local Mono of the last probe round Tick returned
	asked     []ids.MemberID // helpers named in this suspicion; empty whenever suspect is false
}

// bootRun is one boot of a member as the Table saw it.
type bootRun struct {
	set     bool
	seq     uint64
	boot    ids.BootID
	highest uint64 // the highest counter accepted in it
}

// ref returns when p was last heard, by the Table or a helper.
func (p *peer) ref() time.Duration { return max(p.heard, p.vouched) }

// endSuspicion clears p's suspicion and the helpers asked in it. It is the
// only way suspect goes back to false, so asked is empty outside a suspicion.
func (p *peer) endSuspicion() {
	p.suspect = false
	p.asked = nil
}

// verdict is what the replay check makes of a packet's numbers.
type verdict int

const (
	fresh    verdict = iota // not seen: verify the signature, then accept
	stale                   // older boot, outside the window, or seen
	conflict                // only a second live router can send it
)

// check judges a packet's numbers without recording anything.
func (p *peer) check(seq uint64, boot ids.BootID, counter uint64) verdict {
	switch {
	case p.cur.set && seq == p.cur.seq && boot != p.cur.boot:
		return conflict
	case p.prev.set && seq == p.prev.seq && boot == p.prev.boot && counter > p.prev.highest:
		return conflict
	case seq < p.floor || !p.window.Check(seq, boot, counter):
		return stale
	}
	return fresh
}

// Counters counts what a Table did with the packets it was given.
type Counters struct {
	Accepted   uint64 // heartbeats and packets admitted
	Malformed  uint64 // wrong length or format version, or a field out of range
	WrongEpoch uint64 // a heartbeat signed for another epoch than its packet's
	Unknown    uint64 // the sender is not in the roster
	Replay     uint64 // an older boot, outside the replay window, or seen before
	Signature  uint64 // the signature does not verify
	Self       uint64 // the member's own identity
	Duplicate  uint64 // proof of two live routers with one identity
}

// New returns a Table for cfg, started at now: every other member of the
// roster is last heard at now. It loads the peers' boot sequence numbers
// from the store. It returns ErrConfig for a Config it cannot use, an error
// wrapping ErrBootSeqFile for a stored file that does not decode, and the
// store's error for one it cannot read; a missing file is a fresh start.
func New(cfg Config, now clock.Stamp) (*Table, error) {
	interval, suspect, silent := cfg.Interval, cfg.SuspectMissed, cfg.SilentMissed
	if interval == 0 {
		interval = DefaultInterval
	}
	if suspect == 0 {
		suspect = DefaultSuspectMissed
	}
	if silent == 0 {
		silent = DefaultSilentMissed
	}
	switch {
	case cfg.Store == nil:
		return nil, fmt.Errorf("%w: no store", ErrConfig)
	case cfg.Boot == (ids.BootID{}):
		return nil, fmt.Errorf("%w: the boot ID is all zero", ErrConfig)
	case cfg.BootSeq == 0:
		return nil, fmt.Errorf("%w: the boot sequence number is 0", ErrConfig)
	case interval < 0 || suspect < 0 || silent < 0:
		return nil, fmt.Errorf("%w: a negative interval or count", ErrConfig)
	case suspect >= silent:
		return nil, fmt.Errorf("%w: silent after %d missed, not after suspect at %d", ErrConfig, silent, suspect)
	case interval > math.MaxInt64/time.Duration(silent):
		return nil, fmt.Errorf("%w: the silence is longer than a time.Duration holds", ErrConfig)
	}
	selfPub, err := checkRoster(cfg.Roster, cfg.Self)
	if err != nil {
		return nil, err
	}
	floors, err := loadFloors(cfg.Store)
	if err != nil {
		return nil, err
	}
	t := &Table{
		self: cfg.Self, boot: cfg.Boot, startSeq: cfg.BootSeq, ownSeq: cfg.BootSeq, selfPub: selfPub,
		interval:     interval,
		suspectAfter: interval * time.Duration(suspect),
		silentAfter:  interval * time.Duration(silent),
		rosterHash:   cfg.RosterHash,
		peers:        map[ids.MemberID]*peer{},
		offsets:      map[ids.MemberID]time.Duration{},
		st:           cfg.Store,
	}
	for _, m := range cfg.Roster.Members {
		if m.ID != cfg.Self {
			t.peers[m.ID] = &peer{id: m.ID, pub: bytes.Clone(m.SignPub), floor: floors[m.ID], heard: now.Mono}
		}
	}
	t.flusher = cfg.Store.NewFlusher(t.writeFloors)
	return t, nil
}

// checkRoster returns self's signing key in r, or ErrConfig if r does not
// pass roster.Check or does not list self.
func checkRoster(r roster.Roster, self ids.MemberID) (ed25519.PublicKey, error) {
	if err := r.Check(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConfig, err)
	}
	for _, m := range r.Members {
		if m.ID == self {
			return bytes.Clone(m.SignPub), nil
		}
	}
	return nil, fmt.Errorf("%w: the local member is not in the roster", ErrConfig)
}

// Observed is what Observe made of one heartbeat.
type Observed struct {
	Heartbeat      Heartbeat      // the heartbeat, decoded
	Events         []events.Event // what it showed: a silence and a return, or a duplicate identity
	RosterMismatch bool           // its sender holds another roster; the node fetches it
}

// Observe handles b, the plaintext of a heartbeat packet that opened under
// epoch, received at now, in the order of the Table's doc. On success it
// returns the decoded heartbeat, the events it shows and whether its sender
// holds another roster. On failure it returns the zero Observed and
// ErrMalformed, ErrEpoch, ErrUnknownMember, ErrReplay, ErrSignature or
// ErrSelf, with one exception: ErrDuplicateIdentity comes with the
// DuplicateIdentity event, the first time a conflicting boot shows. b is
// neither modified nor kept.
func (t *Table) Observe(epoch uint32, b []byte, now clock.Stamp) (Observed, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	pk, err := split(b)
	if err != nil {
		t.counters.Malformed++
		return Observed{}, err
	}
	if pk.epoch != epoch {
		t.counters.WrongEpoch++
		return Observed{}, ErrEpoch
	}
	if pk.from == t.self {
		return Observed{}, t.observeSelf(pk)
	}
	p := t.peers[pk.from]
	if p == nil {
		t.counters.Unknown++
		return Observed{}, ErrUnknownMember
	}
	switch p.check(pk.bootSeq, pk.boot, pk.counter) {
	case stale:
		t.counters.Replay++
		return Observed{}, ErrReplay
	case conflict:
		return t.duplicate(p, pk, now)
	}
	if !sig.Verify(p.pub, kindHeartbeat, pk.body, pk.sig) {
		t.counters.Signature++
		return Observed{}, ErrSignature
	}
	h, err := decodeBody(pk.body)
	if err != nil {
		t.counters.Malformed++
		return Observed{}, err
	}
	if !t.accept(p, pk.bootSeq, pk.boot, pk.counter) {
		// Cannot happen while t.mu is held from the check to here; kept so
		// that a window that disagrees never lets a packet through.
		t.counters.Replay++
		return Observed{}, ErrReplay
	}
	t.counters.Accepted++
	evs := t.heard(p, h, now)
	return Observed{Heartbeat: h, Events: evs, RosterMismatch: h.RosterHash != t.rosterHash}, nil
}

// observeSelf handles a heartbeat that carries the local member's own ID:
// its own echo, or, signed in another boot, evidence for RestoreBootSeq.
func (t *Table) observeSelf(pk packet) error {
	if pk.boot == t.boot {
		t.counters.Self++
		return ErrSelf
	}
	if !sig.Verify(t.selfPub, kindHeartbeat, pk.body, pk.sig) {
		t.counters.Signature++
		return ErrSignature
	}
	t.counters.Self++
	t.noteOwnBootSeq(pk.bootSeq, pk.boot)
	return ErrSelf
}

// duplicate handles a heartbeat that only a second live router could send:
// with a valid signature it is proof of a duplicate identity.
func (t *Table) duplicate(p *peer, pk packet, now clock.Stamp) (Observed, error) {
	if !sig.Verify(p.pub, kindHeartbeat, pk.body, pk.sig) {
		t.counters.Signature++
		return Observed{}, ErrSignature
	}
	t.counters.Duplicate++
	if p.dupSeen && p.dupBoot == pk.boot {
		return Observed{}, ErrDuplicateIdentity
	}
	p.dupSeen, p.dupBoot = true, pk.boot
	return Observed{Events: []events.Event{t.event(events.DuplicateIdentity, p.id, now.Mono, now)}}, ErrDuplicateIdentity
}

// accept records a packet whose signature verified in p's replay window and
// boot history, and keeps a higher boot sequence number for the store.
func (t *Table) accept(p *peer, seq uint64, boot ids.BootID, counter uint64) bool {
	if !p.window.Accept(seq, boot, counter) {
		return false
	}
	if !p.cur.set || seq > p.cur.seq {
		p.prev, p.cur = p.cur, bootRun{set: true, seq: seq, boot: boot, highest: counter}
	} else {
		p.cur.highest = max(p.cur.highest, counter)
	}
	if seq > p.floor {
		p.floor = seq
		t.flusher.Mark()
	}
	return true
}

// heard updates p after its heartbeat h was accepted at now, and returns the
// events h shows.
func (t *Table) heard(p *peer, h Heartbeat, now clock.Stamp) []events.Event {
	var evs []events.Event
	if !p.silent && now.Mono-p.ref() >= t.silentAfter {
		evs = append(evs, t.event(events.MemberSilent, p.id, p.ref(), now))
		p.silent = true
	}
	if p.silent || (p.heardOnce && h.Boot != p.boot) {
		typ := events.Classify(
			events.Before{AnnouncedGoingDown: p.goingDown, BootID: p.boot, Version: p.version},
			events.Return{BootID: h.Boot, Version: h.Versions[0]},
		)
		e := t.event(typ, p.id, now.Mono, now)
		if typ == events.Upgraded {
			e.Detail = map[string]string{"from": p.version, "to": h.Versions[0]}
		}
		evs = append(evs, e)
	}
	p.heardOnce, p.heard = true, now.Mono
	p.boot, p.version, p.goingDown = h.Boot, h.Versions[0], h.GoingDown
	p.silent, p.reachable = false, true
	p.endSuspicion()
	if h.ClockTrusted {
		t.offsets[p.id] = time.Duration(h.Wall.UnixNano()) - now.Mono
	} else {
		delete(t.offsets, p.id)
	}
	return evs
}

// event returns an event of typ about subject, witnessed by the local member
// and stamped at the local monotonic moment at, as known at now.
func (t *Table) event(typ events.Type, subject ids.MemberID, at time.Duration, now clock.Stamp) events.Event {
	return events.Event{Type: typ, Subject: subject, Witness: t.self, At: t.stamp(at, now)}
}

// stamp returns the local stamp of the monotonic moment at, as the Table's
// doc describes, with the wall clock as known at now.
func (t *Table) stamp(at time.Duration, now clock.Stamp) clock.Stamp {
	s := clock.Stamp{Mono: at, Boot: t.boot}
	if off, ok := t.offset(); ok && !now.Trusted {
		s.Wall, s.Trusted = time.Unix(0, 0).UTC().Add(off).Add(at), true
		return s
	}
	s.Wall, s.Trusted = now.Wall.Add(at-now.Mono), now.Trusted
	return s
}

// Tick moves failure detection to now. It returns the members due an
// indirect probe round, and a MemberSilent event for each member that fell
// silent, stamped when it was last heard; both in ascending order of the
// member ID bytes. It also gives the store's Flusher its turn; a failed
// write is kept by the store (Store.LastError) and retried a minute later.
func (t *Table) Tick(now clock.Stamp) (suspects []ids.MemberID, silent []events.Event) {
	t.mu.Lock()
	for _, p := range t.sortedPeers() {
		if p.silent {
			continue
		}
		since := now.Mono - p.ref()
		switch {
		case since >= t.silentAfter:
			silent = append(silent, t.event(events.MemberSilent, p.id, p.ref(), now))
			p.silent, p.reachable = true, false
			p.endSuspicion()
		case since >= t.suspectAfter:
			if !p.suspect || now.Mono-p.probed >= t.interval {
				suspects = append(suspects, p.id)
				p.probed = now.Mono
			}
			p.suspect, p.reachable = true, false
		default:
			p.endSuspicion()
			p.reachable = p.heardOnce && now.Mono-p.heard < t.suspectAfter
		}
	}
	t.mu.Unlock()
	// Outside t.mu: the write function takes it.
	t.flusher.Tick(now.Wall)
	return suspects, silent
}

// IndirectProbeRequest names the members to ask whether they hear target,
// a suspect: up to MaxHelpers members, lowest member ID first, that the
// Table heard directly within the suspect deadline at the last Tick or
// heartbeat and that are neither suspect nor silent. Their answers count in
// RecordReport until the suspicion ends. It returns nil for a target that is
// not suspect, and for one nobody can be asked about.
func (t *Table) IndirectProbeRequest(target ids.MemberID) []ids.MemberID {
	t.mu.Lock()
	defer t.mu.Unlock()
	p := t.peers[target]
	if p == nil || !p.suspect {
		return nil
	}
	var helpers []ids.MemberID
	for _, q := range t.sortedPeers() {
		// A suspect or silent member is never reachable, the target
		// included.
		if q.reachable && len(helpers) < MaxHelpers {
			helpers = append(helpers, q.id)
		}
	}
	for _, h := range helpers {
		if !slices.Contains(p.asked, h) {
			p.asked = append(p.asked, h)
		}
	}
	return helpers
}

// Admitted is a packet that Admit let through: from a member of the roster,
// fresh, and validly signed. Only Admit makes one; the zero Admitted names
// nobody.
type Admitted struct{ from ids.MemberID }

// From returns the member the packet came from.
func (a Admitted) From() ids.MemberID { return a.from }

// Admit is the Table's gate for a packet of another type than heartbeat
// from the peer from, with that packet's boot sequence number, boot ID and
// counter, in the order of security spec 5.2: the sender against the roster
// (ErrSelf, ErrUnknownMember), the replay check (ErrReplay; a boot that
// would prove a duplicate identity is only dropped here), then
// verify(the sender's signing key in the roster) (ErrSignature, also for a
// nil verify), and only then is the packet recorded in the peer's replay
// window, which its heartbeats share. verify gets a copy of the key, is
// called with the Table locked, and must not call the Table.
func (t *Table) Admit(from ids.MemberID, bootSeq uint64, boot ids.BootID, counter uint64, verify func(ed25519.PublicKey) bool) (Admitted, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if from == t.self {
		t.counters.Self++
		return Admitted{}, ErrSelf
	}
	p := t.peers[from]
	if p == nil {
		t.counters.Unknown++
		return Admitted{}, ErrUnknownMember
	}
	if p.check(bootSeq, boot, counter) != fresh {
		t.counters.Replay++
		return Admitted{}, ErrReplay
	}
	if verify == nil || !verify(bytes.Clone(p.pub)) {
		t.counters.Signature++
		return Admitted{}, ErrSignature
	}
	if !t.accept(p, bootSeq, boot, counter) {
		// Cannot happen while t.mu is held; see Observe.
		t.counters.Replay++
		return Admitted{}, ErrReplay
	}
	t.counters.Accepted++
	return Admitted{from: from}, nil
}

// Report is a member's answer about Target, to an indirect probe or to
// Target's own question at start (security spec 5.3).
type Report struct {
	Target  ids.MemberID
	Heard   bool          // a heartbeat of Target was accepted since the answering Table started
	Ago     time.Duration // how long before the answer that was; 0 when Heard is false
	BootSeq uint64        // the highest boot sequence number known of Target; 0 if none
	Boot    ids.BootID    // the boot ID that came with BootSeq, if it came in this run
}

// Report returns what the local member answers about target at now. For a
// target outside the roster, the local member among them, only Target is
// set.
func (t *Table) Report(target ids.MemberID, now clock.Stamp) Report {
	t.mu.Lock()
	defer t.mu.Unlock()
	r := Report{Target: target}
	p := t.peers[target]
	if p == nil {
		return r
	}
	// Once a packet is accepted, cur.seq is the floor: accept raises the
	// floor to it, and check refuses anything below the floor.
	r.BootSeq = p.floor
	if p.cur.set {
		r.Boot = p.cur.boot
	}
	if p.heardOnce {
		r.Heard, r.Ago = true, max(now.Mono-p.heard, 0)
	}
	return r
}

// RecordReport takes the answer r, received at now in the packet a. An
// answer about the local member is evidence for RestoreBootSeq. Any other is
// an indirect probe answer, as the Table's doc describes: ErrUnsolicited if
// its target is not suspect or a.From() was not asked in this suspicion,
// ErrBadReport for a negative Ago. ErrUnknownMember if a.From() is not, or
// no longer, in the roster.
func (t *Table) RecordReport(a Admitted, r Report, now clock.Stamp) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.peers[a.from] == nil {
		return ErrUnknownMember
	}
	if r.Target == t.self {
		t.noteOwnBootSeq(r.BootSeq, r.Boot)
		return nil
	}
	// Helpers are only ever asked while their target is suspect, and the
	// list is cleared when the suspicion ends (endSuspicion).
	p := t.peers[r.Target]
	if p == nil || !slices.Contains(p.asked, a.from) {
		return ErrUnsolicited
	}
	if r.Ago < 0 {
		return ErrBadReport
	}
	if !r.Heard {
		return nil
	}
	p.vouched = max(p.vouched, now.Mono-r.Ago)
	if now.Mono-p.ref() < t.suspectAfter {
		p.endSuspicion()
	}
	return nil
}

// noteOwnBootSeq keeps seq as evidence for RestoreBootSeq if it is above
// this run's boot sequence number, or equal to it in another boot, and above
// the evidence so far.
func (t *Table) noteOwnBootSeq(seq uint64, boot ids.BootID) {
	if seq < t.ownSeq || (seq == t.ownSeq && boot == t.boot) {
		return
	}
	t.evidence = max(t.evidence, seq)
}

// RestoreBootSeq raises the boot sequence number stored in dir, the local
// member's identity directory, past the highest one this identity is known
// to have used, as the Table's doc describes: with identity.RaiseBootSeq to
// at most Config.BootSeq + MaxBootSeqRaise, then identity.NextBootSeq for the
// number to continue with. It returns that number and true, or the current
// number and false when there is nothing to raise. The node sends its
// heartbeats with the number returned. On an error from identity it returns
// the current number, false and the error.
func (t *Table) RestoreBootSeq(dir string) (uint64, bool, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	limit := t.startSeq + MaxBootSeqRaise
	if limit < t.startSeq {
		limit = math.MaxUint64
	}
	// No evidence is 0, below every boot sequence number. Evidence equal to
	// the current number came from another boot (noteOwnBootSeq), so the
	// current number has to go too.
	v := min(t.evidence, limit)
	if v < t.ownSeq {
		return t.ownSeq, false, nil
	}
	if err := identity.RaiseBootSeq(dir, v); err != nil {
		return t.ownSeq, false, err
	}
	seq, err := identity.NextBootSeq(dir)
	if err != nil {
		return t.ownSeq, false, err
	}
	t.ownSeq = seq
	return seq, true, nil
}

// BootSeq returns the boot sequence number the local member sends with:
// Config.BootSeq, or the last one RestoreBootSeq returned.
func (t *Table) BootSeq() uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.ownSeq
}

// Offset returns the median clock offset of the trusted peers, as the
// Table's doc describes, and false when no peer's latest heartbeat says its
// clock is trusted.
func (t *Table) Offset() (time.Duration, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.offset()
}

func (t *Table) offset() (time.Duration, bool) {
	if len(t.offsets) == 0 {
		return 0, false
	}
	offs := make([]time.Duration, 0, len(t.offsets))
	for _, o := range t.offsets {
		offs = append(offs, o)
	}
	slices.Sort(offs)
	return offs[(len(offs)-1)/2], true
}

// SetRoster makes r, the newly accepted roster whose Signed hashes to hash,
// the Table's roster at now. Members that stay keep their state and get
// their key from r; a member that joins is last heard at now; a member that
// leaves is forgotten, its offset with it, and its packets are refused from
// then on. A roster that does not pass roster.Check, or that does not list
// the local member, is refused with ErrConfig and changes nothing.
func (t *Table) SetRoster(r roster.Roster, hash ids.Hash, now clock.Stamp) error {
	selfPub, err := checkRoster(r, t.self)
	if err != nil {
		return err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	next := make(map[ids.MemberID]*peer, len(r.Members))
	for _, m := range r.Members {
		if m.ID == t.self {
			continue
		}
		p := t.peers[m.ID]
		if p == nil {
			p = &peer{id: m.ID, heard: now.Mono}
		}
		p.pub = bytes.Clone(m.SignPub)
		next[m.ID] = p
	}
	for id := range t.offsets {
		if next[id] == nil {
			delete(t.offsets, id)
		}
	}
	t.peers, t.selfPub, t.rosterHash = next, selfPub, hash
	return nil
}

// Counters returns what the Table counted so far.
func (t *Table) Counters() Counters {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.counters
}

// sortedPeers returns the peers in ascending order of their ID bytes.
func (t *Table) sortedPeers() []*peer {
	ps := make([]*peer, 0, len(t.peers))
	for _, p := range t.peers {
		ps = append(ps, p)
	}
	slices.SortFunc(ps, func(a, b *peer) int { return bytes.Compare(a.id[:], b.id[:]) })
	return ps
}

// peerBootSeqs is the content of the store file:
//
//	{"version":1,"peers":[{"id":"<32 hex digits>","boot_seq":N},...]}
//
// with the peers in ascending order of their ID bytes, each once, N at
// least 1.
type peerBootSeqs struct {
	Version int           `json:"version"`
	Peers   []peerBootSeq `json:"peers"`
}

type peerBootSeq struct {
	ID      ids.MemberID `json:"id"`
	BootSeq uint64       `json:"boot_seq"`
}

// loadFloors reads the peers' boot sequence numbers from st: an empty map if
// the file does not exist, ErrBootSeqFile if it does not decode, and the
// store's error if it cannot be read. Entries for members not in the roster
// are kept and never used.
func loadFloors(st *store.Store) (map[ids.MemberID]uint64, error) {
	floors := map[ids.MemberID]uint64{}
	data, err := st.ReadFile(peerBootSeqFile)
	if errors.Is(err, fs.ErrNotExist) {
		return floors, nil
	}
	if err != nil {
		return nil, fmt.Errorf("member: %w", err)
	}
	if len(data) > maxPeerBootSeqFile {
		return nil, fmt.Errorf("%w: larger than %d bytes", ErrBootSeqFile, maxPeerBootSeqFile)
	}
	var f peerBootSeqs
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBootSeqFile, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("%w: data after the object", ErrBootSeqFile)
	}
	if f.Version != peerBootSeqVersion {
		return nil, fmt.Errorf("%w: version %d, want %d", ErrBootSeqFile, f.Version, peerBootSeqVersion)
	}
	for i, e := range f.Peers {
		if _, dup := floors[e.ID]; dup || e.ID == (ids.MemberID{}) || e.BootSeq == 0 {
			return nil, fmt.Errorf("%w: entry %d is a zero or repeated ID, or boot_seq 0", ErrBootSeqFile, i)
		}
		floors[e.ID] = e.BootSeq
	}
	return floors, nil
}

// writeFloors stores the boot sequence numbers of the current members. The
// store's Flusher calls it.
func (t *Table) writeFloors() error {
	t.mu.Lock()
	f := peerBootSeqs{Version: peerBootSeqVersion, Peers: []peerBootSeq{}}
	for _, p := range t.sortedPeers() {
		if p.floor > 0 {
			f.Peers = append(f.Peers, peerBootSeq{ID: p.id, BootSeq: p.floor})
		}
	}
	t.mu.Unlock()
	data, err := json.Marshal(f)
	if err != nil {
		return err
	}
	return t.st.WriteFileAtomic(peerBootSeqFile, append(data, '\n'))
}
