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

// The limits the timing of a peer's heartbeats is judged with (the sections
// "Failure detection" and "Duplicate identity" of the Table's doc).
const (
	// maxDelay is the longest a heartbeat received directly is taken to have
	// travelled, from the sender's clock reading to the local one: a LAN
	// takes milliseconds; this also covers a receiver that is busy for one
	// heartbeat interval.
	maxDelay = 5 * time.Second
	// driftDiv bounds the rate at which two routers' monotonic clocks drift
	// apart to 1/driftDiv (2000 ppm): crystals within 100 ppm, and NTP
	// slewing each kernel clock by at most 500 ppm, give 1200 ppm.
	driftDiv = 500
)

// MaxBootSeqRaise is how far RestoreBootSeq may raise this member's boot
// sequence number above the one it started with, in one run.
const MaxBootSeqRaise = 1 << 20

// The peer state file in the store, and the suffix of the name a corrupt one
// is set aside under (the store refuses names that start with a dot).
const (
	peerStateFile    = "peer-state.json"
	peerStateVersion = 1
	maxPeerStateFile = 16 << 10
	corruptSuffix    = ".corrupt"
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
	// ErrStateFile reports a peer state file in the store that does not
	// decode.
	ErrStateFile = errors.New("member: the peer state file is corrupt")
	// ErrNotFresher reports a relayed heartbeat that is not newer than the
	// one the Table holds of its sender: an older boot or counter, or a Mono
	// that does not advance in the boot it holds.
	ErrNotFresher = errors.New("member: relayed heartbeat is not newer than the one held")
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
// nor silent, and sends them the probe. A helper answers with Report, which
// carries the target's latest heartbeat as the helper received it, signed by
// the target. The node passes each answer, after Admit, to RecordReport. An
// answer counts only while its target is still suspect, only from a member
// asked during that suspicion, and only through that heartbeat: it must pass
// the same checks as a heartbeat received directly (the target's key in the
// roster, the replay window, every field), and it must be newer than the
// newest the Table holds of the target (a higher boot sequence number, or
// the same with a higher counter and, in a boot the Table holds a heartbeat
// of, a higher Mono). The target is then last heard when the helper says it
// received that heartbeat, but not before the Table's own last direct
// hearing, and, in a boot the Table holds a heartbeat of, not after the
// target's own clock allows: the moment the Table holds for its newest
// heartbeat of that boot, plus how far the target's Mono advanced since,
// plus the drift (driftDiv). The moment the Table holds for a heartbeat is
// when it received it directly or, for a relayed one, the lower of that
// bound and when the answer arrived; never what a helper says. A helper's
// word alone saves nobody, and a helper can replay only heartbeats the
// target really sent, so a helper that keeps them back to relay them later
// cannot keep a dead member alive past its last heartbeat: it is silent 30 s
// after the last heartbeat it sent that anyone asked received. In a boot the
// Table holds no heartbeat of, the first relayed one has only the helper's
// word, so a helper can delay a death by at most one suspicion, once per
// boot.
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
// A heartbeat relayed by a helper shows the same: a new boot is a reboot,
// stamped when the helper received it, and RecordReport returns the event.
// It does not count as heard directly, so it never makes its sender a helper,
// and it teaches no clock offset (its arrival time is the helper's word).
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
// signature and records in only after it, and the boot sequence number, boot
// ID and highest counter of the boot it has accepted packets from. Those
// three are kept in the store, in one small file, peer-state.json, that the
// store's Flusher writes at most once a minute after any packet was
// accepted, and New loads them: after a restart of the local member a packet
// of a peer's older boot is refused, and so is one of the stored boot with a
// counter at or below the stored one, which is how far a recording can still
// be replayed (at most a minute of heartbeats). A packet of the stored boot
// number with another boot ID is a duplicate identity, as below.
//
// A peer state file that cannot be read or decoded does not stop New: the
// Table starts without it, keeps the error for StorageError, and sets a file
// that does not decode aside as peer-state.json.corrupt; the next write
// replaces it.
//
// # Duplicate identity
//
// Two routers with one identity (a backup restored onto a second device)
// show as a validly signed heartbeat that the replay window refuses for a
// reason a replay cannot have: the boot sequence number of the current boot
// with another boot ID, or the previous boot's sequence number and boot ID
// with a counter beyond the last one accepted in that boot, and a Mono that
// shows the previous boot still running after the current one started. A
// router sends one packet per destination, so a member never sees all of a
// neighbour's counters, and a recorded packet it missed comes with such a
// counter: only its timing tells a replay from a second router. The Table
// places the heartbeat's Mono on the local clock from the last heartbeat of
// that boot it received directly (at the earliest maxDelay before it
// arrived, less the drift), and the start of the current boot from its
// heartbeats (at the latest when one arrived, less its Mono and the drift);
// a heartbeat placed after that start is proof, any other is a replay. When
// both boots have one kernel boot ID (the daemon restarted), they read one
// clock: proof is a Mono more than maxDelay past the lowest the current run
// sent. A previous boot the Table heard nothing of directly proves nothing.
// Proof is dropped with ErrDuplicateIdentity and raises one
// DuplicateIdentity event per conflicting boot ID; a replay is dropped with
// ErrReplay.
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

	st         *store.Store
	flusher    *store.Flusher
	storageErr error // what was wrong with the peer state file at start
}

// peer is the Table's state for one other member.
type peer struct {
	id  ids.MemberID
	pub ed25519.PublicKey

	// Replay.
	window   replay.Window
	floor    uint64  // the highest boot sequence number accepted, or loaded from the store
	cur      bootRun // the boot the window is in, or the one loaded from the store
	prev     bootRun // the boot before it, as last seen
	restored bootRun // the boot loaded from the store: counters up to its highest are refused
	dupSeen  bool    // a duplicate was reported
	dupBoot  ids.BootID

	// What its heartbeats said.
	heardOnce bool          // a heartbeat was received directly since the Table started
	heard     time.Duration // local Mono of the last one; the start until then
	vouched   time.Duration // local Mono at which a helper received its last relayed heartbeat
	last      []byte        // its newest heartbeat, direct or relayed, as received
	lastAt    time.Duration // local Mono at which last was received (by a helper, if relayed)
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

	// What the Mono of its heartbeats showed, as local Mono; never stored.
	timed   bool          // a heartbeat of it was accepted, directly or relayed
	minMono time.Duration // the lowest Mono accepted
	maxMono time.Duration // the highest Mono accepted
	upAt    time.Duration // its clock read maxMono at upAt or before
	startBy time.Duration // it started at startBy or before
	direct  bool          // a heartbeat of it was received directly
	hearAt  time.Duration // when the one with the highest Mono of those arrived
	hearMon time.Duration // its Mono
}

// sentBy returns the latest local moment at which r can have sent a
// heartbeat with Mono m: upAt, plus m - maxMono and its drift. It returns
// false when r has no heartbeat accepted, or m is not above maxMono.
func (r *bootRun) sentBy(m time.Duration) (time.Duration, bool) {
	if !r.timed || m <= r.maxMono {
		return 0, false
	}
	return addSat(r.upAt, stretch(m-r.maxMono)), true
}

// note records a heartbeat of r with Mono m, accepted at the local moment
// now, received directly or, if not direct, in an answer that arrived then.
func (r *bootRun) note(m, now time.Duration, direct bool) {
	if !r.timed {
		r.timed, r.minMono, r.maxMono, r.upAt, r.startBy = true, m, m, now, now-shrink(m)
	} else if m > r.maxMono {
		up := now
		if by, _ := r.sentBy(m); !direct && by < up {
			up = by
		}
		r.maxMono, r.upAt = m, up
	}
	r.minMono = min(r.minMono, m)
	r.startBy = min(r.startBy, now-shrink(m))
	if direct && (!r.direct || m >= r.hearMon) {
		r.direct, r.hearAt, r.hearMon = true, now, m
	}
}

// stretch returns the longest a span of d on one router's clock can last on
// another's: d plus its drift. d is not negative.
func stretch(d time.Duration) time.Duration { return addSat(d, d/driftDiv) }

// shrink returns the shortest a span of d on one router's clock can last on
// another's: d less its drift. d is not negative.
func shrink(d time.Duration) time.Duration { return d - d/driftDiv }

// addSat returns a + b, held at the ends of the range instead of wrapping.
func addSat(a, b time.Duration) time.Duration {
	c := a + b
	switch {
	case b > 0 && c < a:
		return math.MaxInt64
	case b < 0 && c > a:
		return math.MinInt64
	}
	return c
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
	overlap                 // the previous boot beyond its highest counter: a conflict if its timing proves one
)

// newer reports whether a packet with these numbers is newer than the newest
// the Table holds of p.
func (p *peer) newer(seq, counter uint64) bool {
	return !p.cur.set || seq > p.cur.seq || (seq == p.cur.seq && counter > p.cur.highest)
}

// check judges a packet's numbers without recording anything.
func (p *peer) check(seq uint64, boot ids.BootID, counter uint64) verdict {
	switch {
	case p.cur.set && seq == p.cur.seq && boot != p.cur.boot:
		return conflict
	case p.prev.set && seq == p.prev.seq && boot == p.prev.boot && counter > p.prev.highest:
		return overlap
	case p.restored.set && seq == p.restored.seq && counter <= p.restored.highest:
		return stale
	case seq < p.floor || !p.window.Check(seq, boot, counter):
		return stale
	}
	return fresh
}

// outlived reports whether a heartbeat of p's previous boot with Mono m was
// sent after p's current boot started, as the Table's doc describes: proof
// that the previous boot was still running beside the current one.
func (p *peer) outlived(m time.Duration) bool {
	old, cur := &p.prev, &p.cur
	if !cur.timed {
		return false
	}
	if old.boot == cur.boot {
		// One kernel boot, one clock; neither reading is negative.
		return m-cur.minMono > maxDelay
	}
	if !old.direct {
		return false
	}
	// The earliest local moment it can have been sent.
	sent := old.hearAt - maxDelay
	if m >= old.hearMon {
		sent = addSat(sent, shrink(m-old.hearMon))
	} else {
		sent = addSat(sent, -stretch(old.hearMon-m))
	}
	return sent > cur.startBy
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
	Relayed    uint64 // heartbeats accepted from a helper's answer
}

// New returns a Table for cfg, started at now: every other member of the
// roster is last heard at now. It loads the peer state file from the store;
// one that cannot be read or decoded is handled as the Table's doc
// describes, and does not make New fail. It returns ErrConfig for a Config
// it cannot use.
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
	states, raw, storageErr := loadState(cfg.Store)
	if raw != nil {
		if err := cfg.Store.WriteFileAtomic(peerStateFile+corruptSuffix, raw); err != nil {
			storageErr = errors.Join(storageErr, fmt.Errorf("member: setting the corrupt file aside: %w", err))
		}
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
		storageErr:   storageErr,
	}
	for _, m := range cfg.Roster.Members {
		if m.ID != cfg.Self {
			run := states[m.ID]
			t.peers[m.ID] = &peer{
				id: m.ID, pub: bytes.Clone(m.SignPub), heard: now.Mono,
				floor: run.seq, cur: run, restored: run,
			}
		}
	}
	t.flusher = cfg.Store.NewFlusher(t.writeState)
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
	h, _, obs, err := t.admitHeartbeat(p, pk, false, now)
	if err != nil {
		return obs, err
	}
	t.counters.Accepted++
	evs := t.heard(p, h, b, now.Mono, true, now)
	return Observed{Heartbeat: h, Events: evs, RosterMismatch: h.RosterHash != t.rosterHash}, nil
}

// admitHeartbeat takes the heartbeat pk from p through the replay check, the
// signature and decodeBody, records it in p's replay window, and notes its
// Mono. A relayed heartbeat must also be newer than the newest held of p. It
// returns the heartbeat and the latest local moment p can have sent it: now
// for one received directly; for a relayed one, now or the bound p's clock
// sets in a boot the Table has a heartbeat of, whichever is earlier. On
// failure it counts the reason; a duplicate identity comes with its event in
// Observed.
func (t *Table) admitHeartbeat(p *peer, pk packet, relayed bool, now clock.Stamp) (Heartbeat, time.Duration, Observed, error) {
	switch v := p.check(pk.bootSeq, pk.boot, pk.counter); v {
	case stale:
		t.counters.Replay++
		return Heartbeat{}, 0, Observed{}, ErrReplay
	case conflict, overlap:
		obs, err := t.duplicate(p, pk, v, now)
		return Heartbeat{}, 0, obs, err
	}
	if relayed && !p.newer(pk.bootSeq, pk.counter) {
		t.counters.Replay++
		return Heartbeat{}, 0, Observed{}, ErrNotFresher
	}
	if !sig.Verify(p.pub, kindHeartbeat, pk.body, pk.sig) {
		t.counters.Signature++
		return Heartbeat{}, 0, Observed{}, ErrSignature
	}
	h, err := decodeBody(pk.body)
	if err != nil {
		t.counters.Malformed++
		return Heartbeat{}, 0, Observed{}, err
	}
	sent := now.Mono
	if relayed && pk.bootSeq == p.cur.seq && p.cur.timed {
		// The boot of a heartbeat the Table holds: its clock bounds it.
		by, ok := p.cur.sentBy(h.Mono)
		if !ok {
			t.counters.Replay++
			return Heartbeat{}, 0, Observed{}, ErrNotFresher
		}
		sent = min(sent, by)
	}
	if !t.accept(p, pk.bootSeq, pk.boot, pk.counter) {
		// Cannot happen while t.mu is held from the check to here; kept so
		// that a window that disagrees never lets a packet through.
		t.counters.Replay++
		return Heartbeat{}, 0, Observed{}, ErrReplay
	}
	p.cur.note(h.Mono, now.Mono, !relayed)
	return h, sent, Observed{}, nil
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

// duplicate handles a heartbeat the replay check judged v: conflict, which
// only a second live router can send, or overlap, which proves one only by
// its timing (outlived). With a valid signature, and for an overlap a Mono
// that outlived accepts, it is proof of a duplicate identity; an overlap
// without that is a replay.
func (t *Table) duplicate(p *peer, pk packet, v verdict, now clock.Stamp) (Observed, error) {
	if !sig.Verify(p.pub, kindHeartbeat, pk.body, pk.sig) {
		t.counters.Signature++
		return Observed{}, ErrSignature
	}
	if v == overlap {
		h, err := decodeBody(pk.body)
		if err != nil {
			t.counters.Malformed++
			return Observed{}, err
		}
		if !p.outlived(h.Mono) {
			t.counters.Replay++
			return Observed{}, ErrReplay
		}
	}
	t.counters.Duplicate++
	if p.dupSeen && p.dupBoot == pk.boot {
		return Observed{}, ErrDuplicateIdentity
	}
	p.dupSeen, p.dupBoot = true, pk.boot
	return Observed{Events: []events.Event{t.event(events.DuplicateIdentity, p.id, now.Mono, now)}}, ErrDuplicateIdentity
}

// accept records a packet whose signature verified in p's replay window and
// boot history, and marks the peer state for the store.
func (t *Table) accept(p *peer, seq uint64, boot ids.BootID, counter uint64) bool {
	if !p.window.Accept(seq, boot, counter) {
		return false
	}
	if !p.cur.set || seq > p.cur.seq {
		p.prev, p.cur = p.cur, bootRun{set: true, seq: seq, boot: boot, highest: counter}
	} else {
		p.cur.highest = max(p.cur.highest, counter)
	}
	p.floor = max(p.floor, seq)
	t.flusher.Mark()
	return true
}

// heard updates p after its heartbeat h, received as raw at the local
// monotonic moment at (directly, or by a helper), was accepted, and returns
// the events h shows.
func (t *Table) heard(p *peer, h Heartbeat, raw []byte, at time.Duration, direct bool, now clock.Stamp) []events.Event {
	var evs []events.Event
	if !p.silent && now.Mono-p.ref() >= t.silentAfter {
		evs = append(evs, t.event(events.MemberSilent, p.id, p.ref(), now))
		p.silent = true
	}
	if p.silent || (p.boot != (ids.BootID{}) && h.Boot != p.boot) {
		typ := events.Classify(
			events.Before{AnnouncedGoingDown: p.goingDown, BootID: p.boot, Version: p.version},
			events.Return{BootID: h.Boot, Version: h.Versions[0]},
		)
		e := t.event(typ, p.id, at, now)
		if typ == events.Upgraded {
			e.Detail = map[string]string{"from": p.version, "to": h.Versions[0]}
		}
		evs = append(evs, e)
	}
	p.boot, p.version, p.goingDown = h.Boot, h.Versions[0], h.GoingDown
	p.last, p.lastAt = bytes.Clone(raw), at
	p.silent = false
	if direct {
		p.heardOnce, p.heard, p.reachable = true, at, true
		if h.ClockTrusted {
			t.offsets[p.id] = time.Duration(h.Wall.UnixNano()) - at
		} else {
			delete(t.offsets, p.id)
		}
	} else {
		p.vouched = max(p.vouched, at)
	}
	if now.Mono-p.ref() < t.suspectAfter {
		p.endSuspicion()
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
	Target    ids.MemberID
	Heartbeat []byte        // Target's newest heartbeat as the answering member received it; nil if none
	Ago       time.Duration // how long before the answer it was received; 0 without one
	BootSeq   uint64        // the highest boot sequence number known of Target; 0 if none
	Boot      ids.BootID    // the boot ID that came with BootSeq; zero if unknown
}

// Report returns what the local member answers about target at now: its
// newest heartbeat of target since the Table started, received directly or
// relayed, and the boot it holds of target, from this run or from the store.
// For a target outside the roster, the local member among them, only Target
// is set.
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
	if p.last != nil {
		r.Heartbeat, r.Ago = bytes.Clone(p.last), max(now.Mono-p.lastAt, 0)
	}
	return r
}

// RecordReport takes the answer r, received at now in the packet a, and
// returns the events its heartbeat shows. An answer about the local member
// is evidence for RestoreBootSeq (BootSeq and Boot). Any other is an indirect
// probe answer, as the Table's doc describes: ErrUnsolicited if its target is
// not suspect or a.From() was not asked in this suspicion; ErrBadReport for a
// negative Ago or a heartbeat of another member; then the errors of Observe
// for its heartbeat, and ErrNotFresher for one not newer than the newest
// held, or whose Mono does not advance past the highest held of its boot.
// An answer without a heartbeat changes nothing. ErrUnknownMember if
// a.From() is not, or no longer, in the roster.
func (t *Table) RecordReport(a Admitted, r Report, now clock.Stamp) ([]events.Event, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.peers[a.from] == nil {
		return nil, ErrUnknownMember
	}
	if r.Target == t.self {
		t.noteOwnBootSeq(r.BootSeq, r.Boot)
		return nil, nil
	}
	// Helpers are only ever asked while their target is suspect, and the
	// list is cleared when the suspicion ends (endSuspicion).
	p := t.peers[r.Target]
	if p == nil || !slices.Contains(p.asked, a.from) {
		return nil, ErrUnsolicited
	}
	if r.Ago < 0 {
		return nil, ErrBadReport
	}
	if r.Heartbeat == nil {
		return nil, nil
	}
	pk, err := split(r.Heartbeat)
	if err != nil {
		t.counters.Malformed++
		return nil, err
	}
	if pk.from != p.id {
		return nil, ErrBadReport
	}
	h, sent, obs, err := t.admitHeartbeat(p, pk, true, now)
	if err != nil {
		return obs.Events, err
	}
	t.counters.Relayed++
	// Never after the target can have sent it: a helper's age only says
	// when, never that the target was alive later than its own clock allows.
	// Never before the Table's own last direct hearing either: a helper's age
	// never says that the target was alive earlier than known.
	at := max(min(now.Mono-r.Ago, sent), p.heard)
	return t.heard(p, h, r.Heartbeat, at, false, now), nil
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

// StorageError returns what was wrong with the peer state file when the
// Table started (it could not be read or decoded, and was not used), or nil.
// It does not change during the Table's life; later write failures are kept
// by the store (Store.LastError).
func (t *Table) StorageError() error { return t.storageErr }

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

// peerStates is the content of the peer state file:
//
//	{"version":1,"peers":[{"id":"<32 hex digits>","boot_seq":N,
//	  "boot":"<32 hex digits>","counter":C},...]}
//
// with the peers in ascending order of their ID bytes, each once, N at least
// 1, the boot ID not all zero.
type peerStates struct {
	Version int         `json:"version"`
	Peers   []peerState `json:"peers"`
}

type peerState struct {
	ID      ids.MemberID `json:"id"`
	BootSeq uint64       `json:"boot_seq"`
	Boot    ids.BootID   `json:"boot"`
	Counter uint64       `json:"counter"`
}

// loadState reads the peer state file from st. A missing file is no state
// and no error. A file the store refuses to read gives the store's error; one
// that does not decode gives an error wrapping ErrStateFile and its content,
// to be set aside. Entries for members not in the roster are kept and never
// used.
func loadState(st *store.Store) (map[ids.MemberID]bootRun, []byte, error) {
	states := map[ids.MemberID]bootRun{}
	data, err := st.ReadFile(peerStateFile)
	if errors.Is(err, fs.ErrNotExist) {
		return states, nil, nil
	}
	if err != nil {
		return states, nil, fmt.Errorf("member: %w", err)
	}
	if err := decodeState(data, states); err != nil {
		return map[ids.MemberID]bootRun{}, data, err
	}
	return states, nil, nil
}

// decodeState fills states from data, or returns an error wrapping
// ErrStateFile.
func decodeState(data []byte, states map[ids.MemberID]bootRun) error {
	if len(data) > maxPeerStateFile {
		return fmt.Errorf("%w: larger than %d bytes", ErrStateFile, maxPeerStateFile)
	}
	var f peerStates
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return fmt.Errorf("%w: %v", ErrStateFile, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return fmt.Errorf("%w: data after the object", ErrStateFile)
	}
	if f.Version != peerStateVersion {
		return fmt.Errorf("%w: version %d, want %d", ErrStateFile, f.Version, peerStateVersion)
	}
	for i, e := range f.Peers {
		if _, dup := states[e.ID]; dup || e.ID == (ids.MemberID{}) || e.BootSeq == 0 || e.Boot == (ids.BootID{}) {
			return fmt.Errorf("%w: entry %d is a zero or repeated ID, boot_seq 0 or a zero boot", ErrStateFile, i)
		}
		states[e.ID] = bootRun{set: true, seq: e.BootSeq, boot: e.Boot, highest: e.Counter}
	}
	return nil
}

// writeState stores the boot each current member's packets were last
// accepted from. The store's Flusher calls it.
func (t *Table) writeState() error {
	t.mu.Lock()
	f := peerStates{Version: peerStateVersion, Peers: []peerState{}}
	for _, p := range t.sortedPeers() {
		if p.cur.set {
			f.Peers = append(f.Peers, peerState{ID: p.id, BootSeq: p.cur.seq, Boot: p.cur.boot, Counter: p.cur.highest})
		}
	}
	t.mu.Unlock()
	data, err := json.Marshal(f)
	if err != nil {
		return err
	}
	return t.st.WriteFileAtomic(peerStateFile, append(data, '\n'))
}
