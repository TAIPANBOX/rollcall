package node

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/clock"
	"github.com/TAIPANBOX/rollcall/internal/deliver"
	"github.com/TAIPANBOX/rollcall/internal/epoch"
	"github.com/TAIPANBOX/rollcall/internal/events"
	"github.com/TAIPANBOX/rollcall/internal/history"
	"github.com/TAIPANBOX/rollcall/internal/identity"
	"github.com/TAIPANBOX/rollcall/internal/ids"
	"github.com/TAIPANBOX/rollcall/internal/member"
	"github.com/TAIPANBOX/rollcall/internal/roster"
	"github.com/TAIPANBOX/rollcall/internal/store"
	"github.com/TAIPANBOX/rollcall/internal/wire"
)

// # The node
//
// A Node is one member of a group. It never opens a socket and never reads
// the system clock: the transport hands it packets (HandlePacket) and TCP
// requests (HandleStream) and carries what it sends (Net), and every time
// comes from its Clock. The daemon calls Tick about once a second.
//
// Every packet is checked in the order of security spec 5.2: length and
// version, epoch known, AEAD (wire.Open with the epoch Ring), replay check,
// sender in the roster, signature, schema, and only then is it recorded
// in the replay window (member.Table.Admit, or Observe for a heartbeat)
// and handled. A packet that fails any check is dropped, counted, and
// never answered; nothing is sent while a packet is handled, so
// unauthenticated input never produces a call on Net. What a packet asks
// for (a roster fetch, a catch-up) is planned and done by the next Tick.
//
// The node fails closed: without a roster or an epoch key in its store New
// returns an error and a stopped Node whose Status says why, and that Node
// sends nothing and answers nothing.

// Net carries the node's packets. The transport implements it.
type Net interface {
	Multicast(b []byte) error
	Unicast(to netip.AddrPort, b []byte) error
	Stream(to netip.AddrPort, b []byte) ([]byte, error)
}

// Clock is the node's only source of time: the wall clock and the
// monotonic clock since boot.
type Clock interface {
	Now() time.Time
	Mono() time.Duration
}

// Config is what the node runs with. Task 21 maps config.Config onto it.
type Config struct {
	Site                   string
	Heartbeat, SilentAfter time.Duration // zero means the defaults, 5 s and 30 s
	Sender                 bool          // this router is configured to send to the chat
	Priority               int
	TZ                     *time.Location

	// Boot is this boot's ID, from /proc/sys/kernel/random/boot_id; zero
	// makes New draw one, and then the node cannot tell a reboot from a
	// restart of the daemon and records no return of its own (boot.go).
	Boot ids.BootID
	// BootSeq is the boot sequence number identity.NextBootSeq gave this
	// boot; 0 counts as 1.
	BootSeq uint64
	// IdentityDir is the identity directory whose boot sequence number
	// the node raises when its peers have seen a higher one (security
	// spec 5.3); empty skips that.
	IdentityDir string
	// Planned is true when the boot before this one ended with an
	// announced shutdown (the shutdown marker of design 4.6): the node's
	// own return is then a planned reboot (boot.go).
	Planned bool
	// Peers are static peers that get every heartbeat by unicast.
	Peers []netip.AddrPort
	// Versions are the OpenWrt release and the rollcall version.
	Versions [2]string
}

// The files the node keeps in its store.
const (
	FileRoster  = "roster.bin"   // the roster chain, newest last
	FileEpoch   = "epoch.json"   // the epoch keys held
	FileSecrets = "secrets.json" // the bot token and chat ID, on a sender only
	fileForks   = "forks.json"
	filePrefix  = "history-" // one file per origin: history-<hex ID>.json
)

// Errors.
var (
	ErrNoRoster   = errors.New("node: no roster in the store; run init or join")
	ErrNoEpochKey = errors.New("node: no epoch key in the store; run init or join")
	ErrState      = errors.New("node: the stored state is unusable")
	ErrRemoved    = errors.New("node: this router was removed from the group")
	ErrNotAdmin   = errors.New("node: this router is not an admin of the group")
	ErrArgument   = errors.New("node: invalid argument")
	ErrStopped    = errors.New("node: stopped")
)

const (
	// keepRosters is how many rosters of the chain the node keeps, to find
	// the common ancestor after a split.
	keepRosters = 16
	// ownCatchUp bounds the wait for the own chain's head after a start.
	ownCatchUp = 60 * time.Second
	// pingEvery is the Telegram reachability check (design 4.5, getMe).
	pingEvery = 30 * time.Second
	// retryEvery spaces the repeats of a fetch, a catch-up or a delivery
	// to one peer.
	retryEvery = 5 * time.Second
	// maxJobs bounds the TCP exchanges of one Tick.
	maxJobs = 64
	// floodBurst failures within floodWindow raise one UnderFlood, and
	// floodQuiet without a burst re-arms it.
	floodBurst  = 50
	floodWindow = 10 * time.Second
	floodQuiet  = 60 * time.Second
	// sendTimeout bounds one call on the channel.
	sendTimeout = 10 * time.Second
)

// Counters counts what the node did with what it was given.
type Counters struct {
	Malformed  uint64 // bad length, version or flags, or a message that does not parse
	Epoch      uint64 // an epoch the node holds no key for
	Auth       uint64 // AEAD failed
	Unknown    uint64 // the sender is not in the roster
	Replay     uint64 // older boot, outside the window, or seen before
	Signature  uint64 // the signature does not verify
	Schema     uint64 // a validly signed payload that does not decode
	Self       uint64 // the node's own identity
	Ignored    uint64 // reserved types, checked and ignored
	Floods     uint64 // bursts of failures that raised UnderFlood
	Accepted   uint64 // messages other than heartbeats that passed every check
	SigChecks  uint64 // signatures verified on messages other than heartbeats
	Heartbeats member.Counters
}

// Node is one member of a group. Make one with New.
type Node struct {
	mu  sync.Mutex
	cfg Config
	st  *store.Store
	id  *identity.Identity
	net Net
	clk Clock
	ch  deliver.Channel

	stopped error // why the node does not run; nil while it runs
	removed bool

	boot       ids.BootID
	trusted    bool
	goingDown  bool
	wanUp      bool
	internetOK bool
	telegramOK time.Time
	telegram   string // the state of the last call on the channel
	started    time.Time

	secrets secretsFile
	ring    *epoch.Ring
	keys    []epoch.Key // the epoch keys held, oldest first; the last is current

	chain   []roster.Signed
	rosters []roster.Roster
	curHash ids.Hash
	keyMap  atomic.Pointer[map[ids.MemberID]ed25519.PublicKey]

	table   *member.Table
	log     *history.Log
	flusher *store.Flusher
	queue   *deliver.Queue
	dirty   map[ids.MemberID]bool // origins whose history file is stale

	// The alive file (boot.go): what the boot before left in it, the
	// moment to write next, and the Flusher that writes it.
	prevAlive *aliveFile
	aliveAt   clock.Stamp
	alive     *store.Flusher

	counter          uint64
	nextBeat         time.Duration
	nextPing         time.Duration
	peers            map[ids.MemberID]*peer
	counters         Counters
	flood            floodState
	lastHeardPrimary time.Time

	caughtUp  bool
	catchUpBy time.Duration
	// restoring holds the first heartbeat until a peer said which boot
	// sequence number it saw last from this router (security spec 5.3),
	// or until restoreBy.
	restoring   bool
	restoreBy   time.Duration
	nextRestore time.Duration
	writes      []ownWrite    // own records waiting for the own chain's head
	ownRetry    time.Duration // when to retry writes that failed to reach flash; 0 for none
	forksSaved  int           // the fork proofs on flash

	jobs       []job
	out        []outPacket
	deliveries map[ids.MemberID]*delivery // epoch key deliveries still to make
	parts      map[ids.MemberID]*partial  // epoch key deliveries being received

	inc  incidents
	rec  recon
	join joinWindow
	turn senderTurn
}

// peer is what the node knows of another member.
type peer struct {
	addr      netip.AddrPort // learned from its authenticated heartbeats, or static
	hb        member.Heartbeat
	heard     bool
	heardWall time.Time
	heardMono time.Duration
	epoch     uint32 // the epoch of its last packet the node admitted
	silent    bool
	suspect   bool
	// restored is true while the node knows the peer only from its state
	// file (state.go), and toldSilent whether the file had it silent.
	restored   bool
	toldSilent bool
	nextRost   time.Duration // earliest next roster fetch from it
	nextSync   time.Duration // earliest next catch-up with it
	nextAsk    time.Duration // earliest next answer to its own boot-seq question
	asked      bool          // asked for this router's own boot sequence number
}

type outPacket struct {
	to        netip.AddrPort
	multicast bool
	b         []byte
}

type floodState struct {
	start  time.Duration
	count  int
	raised bool
	last   time.Duration // last moment a burst was seen
}

// secretsFile is FileSecrets: what only a sender holds.
type secretsFile struct {
	BotToken string `json:"bot_token"`
	ChatID   int64  `json:"chat_id"`
}

type epochFile struct {
	Keys    []epochFileKey `json:"keys"`
	Removed bool           `json:"removed"`
}

type epochFileKey struct {
	ID       uint32    `json:"id"`
	Secret   []byte    `json:"secret"`
	NotAfter time.Time `json:"not_after"`
}

// Bootstrap writes the state a node starts from into st: the roster r and
// the epoch key k, as rollcall init and join leave them. It replaces what
// st held.
func Bootstrap(st *store.Store, r roster.Signed, k epoch.Key) error {
	if st == nil {
		return ErrArgument
	}
	if _, err := rosterOf(r, nil); err != nil {
		return fmt.Errorf("%w: the roster: %w", ErrArgument, err)
	}
	if !validKey(k) {
		return fmt.Errorf("%w: the epoch key", ErrArgument)
	}
	if err := st.WriteFileAtomic(FileRoster, encodeChain([]roster.Signed{r})); err != nil {
		return err
	}
	return writeKeys(st, []epoch.Key{k}, false)
}

// SaveSecrets writes the bot token and chat ID of a sender into st.
func SaveSecrets(st *store.Store, token string, chatID int64) error {
	b, err := json.Marshal(secretsFile{BotToken: token, ChatID: chatID})
	if err != nil {
		return err
	}
	return st.WriteFileAtomic(FileSecrets, b)
}

// New returns the node of identity id, with the state in st. When it
// cannot run (no roster, no epoch key, a store it cannot read) it returns
// the reason and a stopped Node whose Status reports it; that Node does
// nothing else. ch is the chat channel, nil on a router that does not
// send.
func New(cfg Config, st *store.Store, id *identity.Identity, n Net, c Clock, ch deliver.Channel) (*Node, error) {
	nd := &Node{cfg: cfg, st: st, id: id, net: n, clk: c, ch: ch,
		internetOK: true, wanUp: true, ring: &epoch.Ring{},
		peers: map[ids.MemberID]*peer{}, dirty: map[ids.MemberID]bool{},
		deliveries: map[ids.MemberID]*delivery{}, parts: map[ids.MemberID]*partial{}}
	nd.inc.init()
	nd.rec.init()
	if err := nd.start(); err != nil {
		nd.stopped = err
		return nd, err
	}
	return nd, nil
}

func (n *Node) start() error {
	switch {
	case n.st == nil || n.id == nil || n.net == nil || n.clk == nil:
		return fmt.Errorf("%w: nil store, identity, net or clock", ErrArgument)
	case n.id.ID == (ids.MemberID{}) || len(n.id.Sign) != ed25519.PrivateKeySize:
		return fmt.Errorf("%w: the identity", ErrArgument)
	}
	if n.cfg.Heartbeat <= 0 {
		n.cfg.Heartbeat = member.DefaultInterval
	}
	if n.cfg.SilentAfter <= 0 {
		n.cfg.SilentAfter = time.Duration(member.DefaultSilentMissed) * n.cfg.Heartbeat
	}
	if n.cfg.TZ == nil {
		n.cfg.TZ = time.UTC
	}
	if n.cfg.BootSeq == 0 {
		n.cfg.BootSeq = 1
	}
	for i, v := range n.cfg.Versions {
		if !validVersion(v) || len(v) > member.MaxVersionLen {
			n.cfg.Versions[i] = ""
		}
	}
	n.boot = n.cfg.Boot
	if n.boot == (ids.BootID{}) {
		b, err := ids.NewBootID()
		if err != nil {
			return err
		}
		n.boot = b
	}
	n.ring.Now = n.clk.Now
	n.started = n.clk.Now()
	n.lastHeardPrimary = n.started

	if b, err := n.st.ReadFile(FileSecrets); err == nil {
		var s secretsFile
		if decodeJSON(b, &s, 4096) == nil {
			n.secrets = s
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%w: %s: %w", ErrState, FileSecrets, err)
	}

	if err := n.loadRoster(); err != nil {
		return err
	}
	if err := n.loadKeys(); err != nil {
		return err
	}
	cur := n.cur()
	if _, ok := memberOf(cur, n.id.ID); !ok {
		n.removed = true
		return ErrRemoved
	}
	now := n.stamp()
	tab, err := member.New(member.Config{
		Self: n.id.ID, Boot: n.boot, BootSeq: n.cfg.BootSeq,
		Roster: cur, RosterHash: n.curHash, Store: n.st,
		Interval:     n.cfg.Heartbeat,
		SilentMissed: int((n.cfg.SilentAfter + n.cfg.Heartbeat - 1) / n.cfg.Heartbeat),
	}, now)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrState, err)
	}
	n.table = tab
	n.log = history.NewLog(n.keyOf, 0)
	n.flusher = n.st.NewFlusher(n.writeHistory)
	n.alive = n.st.NewFlusher(n.writeAlive)
	n.queue = deliver.NewQueue()
	n.loadAlive()
	n.loadHistory(now)

	n.catchUpBy = now.Mono + ownCatchUp
	n.caughtUp = len(cur.Members) == 1
	n.restoring = n.cfg.IdentityDir != "" && len(cur.Members) > 1
	n.restoreBy = now.Mono + 2*n.cfg.Heartbeat
	n.writes = append(n.writes, ownWrite{kind: history.KindBoot, body: BootBody{
		Boot:    Boot{ID: n.boot, Seq: n.table.BootSeq()},
		Version: n.cfg.Versions[0], Planned: n.cfg.Planned,
	}})
	n.nextBeat = now.Mono
	n.nextPing = now.Mono
	// A fork proof loaded without its alarm (lost with the RAM) raises it
	// now; one whose own record was loaded is raised already.
	for _, p := range n.log.Forks() {
		n.forkLocked(p, now)
	}
	n.flushWritesLocked(now)
	return nil
}

// cur returns the current roster.
func (n *Node) cur() roster.Roster { return n.rosters[len(n.rosters)-1] }

func (n *Node) curSigned() roster.Signed { return n.chain[len(n.chain)-1] }

// stamp returns the local moment now.
func (n *Node) stamp() clock.Stamp {
	return clock.Stamp{Wall: n.clk.Now(), Mono: n.clk.Mono(), Trusted: n.trusted, Boot: n.boot}
}

// localStamp is a stamp for an own event: the wall clock when it is trusted,
// else the offset learned from trusted peers (design 4.4).
func (n *Node) localStamp(now clock.Stamp) clock.Stamp {
	if !now.Trusted && n.table != nil {
		if off, ok := n.table.Offset(); ok {
			now.Wall, now.Trusted = time.Unix(0, 0).UTC().Add(off).Add(now.Mono), true
		}
	}
	return now
}

// keyOf is the history's key resolver: the signing key of a member of the
// current roster. It reads a snapshot, so it never takes the node's lock.
func (n *Node) keyOf(o ids.MemberID) (ed25519.PublicKey, bool) {
	m := n.keyMap.Load()
	if m == nil {
		return nil, false
	}
	k, ok := (*m)[o]
	return k, ok
}

// isMember reports whether o is in the current roster.
func (n *Node) isMember(o ids.MemberID) bool {
	_, ok := n.keyOf(o)
	return ok
}

func (n *Node) setKeyMap(r roster.Roster) {
	m := make(map[ids.MemberID]ed25519.PublicKey, len(r.Members))
	for _, e := range r.Members {
		m[e.ID] = bytes.Clone(e.SignPub)
	}
	n.keyMap.Store(&m)
}

func memberOf(r roster.Roster, id ids.MemberID) (roster.Member, bool) {
	for _, m := range r.Members {
		if m.ID == id {
			return m, true
		}
	}
	return roster.Member{}, false
}

func hasRole(m roster.Member, role roster.Role) bool {
	for _, r := range m.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// rosterOf returns the roster in s: verified against prev when there is
// one, or for a roster at the start of the stored chain, decoded and
// checked (it was verified when it was accepted; the store is the node's
// own).
func rosterOf(s roster.Signed, prev *roster.Signed) (roster.Roster, error) {
	if prev != nil {
		return s.Verify(prev)
	}
	if r, err := s.Verify(nil); err == nil {
		return r, nil
	}
	var r roster.Roster
	if err := decodeJSON(s.Body, &r, roster.MaxBodySize); err != nil {
		return roster.Roster{}, err
	}
	if err := r.Check(); err != nil {
		return roster.Roster{}, err
	}
	return r, nil
}

func (n *Node) loadRoster() error {
	b, err := n.st.ReadFile(FileRoster)
	if errors.Is(err, fs.ErrNotExist) {
		return ErrNoRoster
	}
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrState, FileRoster, err)
	}
	chain, err := decodeChain(b)
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrState, FileRoster, err)
	}
	var rs []roster.Roster
	for i, s := range chain {
		var prev *roster.Signed
		if i > 0 {
			prev = &chain[i-1]
		}
		r, err := rosterOf(s, prev)
		if err != nil {
			return fmt.Errorf("%w: %s: %w", ErrState, FileRoster, err)
		}
		rs = append(rs, r)
	}
	n.chain, n.rosters = chain, rs
	n.curHash = n.curSigned().Hash()
	n.setKeyMap(n.cur())
	return nil
}

func validKey(k epoch.Key) bool {
	return len(k.Secret) == epoch.SecretSize && !bytes.Equal(k.Secret, make([]byte, epoch.SecretSize)) && !k.NotAfter.IsZero()
}

func writeKeys(st *store.Store, keys []epoch.Key, removed bool) error {
	f := epochFile{Removed: removed, Keys: []epochFileKey{}}
	for _, k := range keys {
		f.Keys = append(f.Keys, epochFileKey{ID: k.ID, Secret: k.Secret, NotAfter: k.NotAfter.UTC()})
	}
	b, err := json.Marshal(f)
	if err != nil {
		return err
	}
	return st.WriteFileAtomic(FileEpoch, b)
}

func (n *Node) loadKeys() error {
	b, err := n.st.ReadFile(FileEpoch)
	if errors.Is(err, fs.ErrNotExist) {
		return ErrNoEpochKey
	}
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrState, FileEpoch, err)
	}
	var f epochFile
	if err := decodeJSON(b, &f, 4096); err != nil {
		return fmt.Errorf("%w: %s: %w", ErrState, FileEpoch, err)
	}
	if f.Removed {
		n.removed = true
		return ErrRemoved
	}
	if len(f.Keys) == 0 {
		return ErrNoEpochKey
	}
	for i, fk := range f.Keys {
		k := epoch.Key{ID: fk.ID, Secret: fk.Secret, NotAfter: fk.NotAfter}
		if !validKey(k) || (i > 0 && k.ID <= f.Keys[i-1].ID) {
			return fmt.Errorf("%w: %s: an invalid key", ErrState, FileEpoch)
		}
		n.keys = append(n.keys, k)
	}
	// The stored current key goes in before any delivery is accepted: an
	// empty Ring would take any first key it is given.
	if err := n.ring.Install(n.current(), n.clk.Now()); err != nil {
		return fmt.Errorf("%w: %s: %w", ErrState, FileEpoch, err)
	}
	return nil
}

// current returns the current epoch key.
func (n *Node) current() epoch.Key { return n.keys[len(n.keys)-1] }

// keyByID returns the held epoch key with the given ID.
func (n *Node) keyByID(id uint32) (epoch.Key, bool) {
	for _, k := range n.keys {
		if k.ID == id {
			return k, true
		}
	}
	return epoch.Key{}, false
}

// packetKey returns the packet key of a held epoch.
func (n *Node) packetKey(id uint32) ([]byte, bool) {
	k, ok := n.keyByID(id)
	if !ok {
		return nil, false
	}
	pk, err := wire.PacketKey(k.Secret)
	return pk, err == nil
}

// lookup is the wire.KeyLookup of the node: the Ring's.
func (n *Node) lookup(id uint32) ([]byte, bool) { return n.ring.Lookup(id) }

// running reports whether the node handles anything.
func (n *Node) running() bool { return n.stopped == nil && !n.removed }

// next returns the next packet counter of this boot.
func (n *Node) next() uint64 {
	n.counter++
	return n.counter
}

// Authenticate reports whether frame, the first frame of a TCP connection,
// opens under an epoch the node holds: the transport's gate before it
// reads anything else (security spec 5.4).
func (n *Node) Authenticate(frame []byte) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.running() {
		return false
	}
	_, _, err := wire.Open(n.lookup, frame)
	return err == nil || n.joinFrame(frame)
}

// HandlePacket handles one UDP packet from the address from.
func (n *Node) HandlePacket(from netip.AddrPort, b []byte) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.running() {
		return
	}
	now := n.stamp()
	ep, pt, err := wire.Open(n.lookup, b)
	if err != nil {
		n.wireFailed(err, now)
		return
	}
	if len(pt) == 0 {
		n.counters.Malformed++
		return
	}
	switch t := msgType(pt[0]); {
	case t == msgHeartbeat:
		n.heartbeatIn(from, ep, pt[1:], now)
	case t.reserved():
		env, ok := parseEnvelope(pt)
		if !ok {
			n.counters.Malformed++
			return
		}
		if _, err := n.admit(ep, env, func([]byte) error { return nil }); err == nil {
			n.counters.Ignored++
		}
	default:
		// Every other type travels over TCP only.
		n.counters.Malformed++
	}
}

// wireFailed counts a packet wire.Open refused and watches for a flood.
func (n *Node) wireFailed(err error, now clock.Stamp) {
	switch {
	case errors.Is(err, wire.ErrEpoch), errors.Is(err, wire.ErrKey):
		n.counters.Epoch++
	case errors.Is(err, wire.ErrAuth):
		n.counters.Auth++
	default:
		n.counters.Malformed++
	}
	f := &n.flood
	if now.Mono-f.start > floodWindow || now.Mono < f.start {
		f.start, f.count = now.Mono, 0
	}
	f.count++
	if f.count < floodBurst {
		return
	}
	f.last = now.Mono
	if !f.raised {
		// Local status only (Status.UnderFlood): never a chat message, and
		// nothing in the history.
		f.raised = true
		n.counters.Floods++
	}
}

// admit passes env, which opened under epochID, through the Table's gate:
// the sender against the roster, the replay check, the signature, and
// check on the payload, before the packet is recorded in the replay window.
func (n *Node) admit(epochID uint32, env envelope, check func([]byte) error) (member.Admitted, error) {
	var schema bool
	a, err := n.table.Admit(env.from, env.bootSeq, env.boot, env.counter, func(pub ed25519.PublicKey) bool {
		n.counters.SigChecks++
		if !env.verify(pub, epochID) {
			return false
		}
		if check(env.payload) != nil {
			schema = true
			return false
		}
		return true
	})
	if err != nil {
		switch {
		case schema:
			n.counters.Schema++
		case errors.Is(err, member.ErrSelf):
			n.counters.Self++
		case errors.Is(err, member.ErrUnknownMember):
			n.counters.Unknown++
		case errors.Is(err, member.ErrReplay):
			n.counters.Replay++
		default:
			n.counters.Signature++
		}
		return a, err
	}
	n.counters.Accepted++
	if p := n.peers[env.from]; p != nil {
		p.epoch = epochID
	}
	n.epochSeen(env.from, epochID)
	return a, nil
}

// heartbeatIn handles a heartbeat that opened under epochID.
func (n *Node) heartbeatIn(from netip.AddrPort, epochID uint32, b []byte, now clock.Stamp) {
	obs, err := n.table.Observe(epochID, b, now)
	if err != nil {
		if errors.Is(err, member.ErrDuplicateIdentity) {
			for _, e := range obs.Events {
				n.recordEvent(e, EventBody{Subject: e.Subject, Type: e.Type}, now)
			}
		}
		return
	}
	h := obs.Heartbeat
	p := n.peer(h.From)
	before := p.hb
	p.addr = from
	p.hb, p.heard, p.heardWall, p.heardMono = h, true, now.Wall, now.Mono
	p.epoch, p.silent, p.suspect = epochID, false, false
	n.epochSeen(h.From, epochID)
	if n.restoring && !p.asked {
		p.asked = true
		n.planProbe(h.From, n.id.ID)
	}
	if cur := n.cur(); len(cur.Admins) > 0 && cur.Admins[0] == h.From {
		n.lastHeardPrimary = n.clk.Now()
	}
	for _, e := range obs.Events {
		body := EventBody{Subject: e.Subject, Type: e.Type}
		if absence(e.Type) && e.Subject == h.From && before.From == h.From {
			body.Last = Boot{ID: before.Boot, Seq: before.BootSeq}
			if e.Type != events.MemberSilent {
				body.Back = Boot{ID: h.Boot, Seq: h.BootSeq}
			}
			if hd := n.log.Head(h.From); hd.Seq > 0 {
				body.Ref = EntryRef{Seq: hd.Seq, Hash: hd.Hash}
			}
		}
		n.recordEvent(e, body, now)
	}
	if obs.RosterMismatch && now.Mono >= p.nextRost {
		p.nextRost = now.Mono + retryEvery
		n.planRosterFetch(h.From)
	}
	switch digest := n.log.Digest(); {
	case h.Digest == digest && !n.caughtUp:
		// Same heads, the node's own among them: nothing to catch up.
		n.caughtUpLocked(now)
	case h.Digest != digest && now.Mono >= p.nextSync:
		p.nextSync = now.Mono + retryEvery
		n.planCatchUp(h.From)
	}
}

func (n *Node) peer(id ids.MemberID) *peer {
	p := n.peers[id]
	if p == nil {
		p = &peer{}
		n.peers[id] = p
	}
	return p
}

// HandleStream answers one TCP request frame from the address from, or
// returns nil, and the connection closes without an answer.
func (n *Node) HandleStream(from netip.AddrPort, b []byte) []byte {
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.running() {
		return nil
	}
	now := n.stamp()
	ep, pt, err := wire.Open(n.lookup, b)
	if err != nil {
		if n.joinFrame(b) {
			return n.joinIn(b, now)
		}
		n.wireFailed(err, now)
		return nil
	}
	env, ok := parseEnvelope(pt)
	if !ok {
		n.counters.Malformed++
		return nil
	}
	var reply []byte
	switch env.typ {
	case msgProbeReq:
		reply = n.serveProbe(ep, env, now)
	case msgDigestReq:
		reply = n.serveDigest(ep, env)
	case msgFetch:
		reply = n.serveFetch(ep, env)
	case msgRoster:
		reply = n.serveRoster(ep, env)
	case msgEpoch:
		reply = n.serveEpoch(ep, env, now)
	default:
		if env.typ.reserved() {
			if _, err := n.admit(ep, env, func([]byte) error { return nil }); err == nil {
				n.counters.Ignored++
			}
			return nil
		}
		n.counters.Malformed++
		return nil
	}
	return reply
}

// reply returns the reply frame of type t with payload to the request ref,
// sealed under epochID, or nil if the node cannot make one.
func (n *Node) reply(epochID uint32, t msgType, ref [16]byte, payload []byte) []byte {
	pk, ok := n.packetKey(epochID)
	if !ok || len(payload) > maxReplyPayload {
		return nil
	}
	msg := encodeEnvelope(envelope{typ: t, from: n.id.ID, bootSeq: n.table.BootSeq(), boot: n.boot,
		counter: n.next(), ref: ref, payload: payload}, epochID, n.id.Sign)
	f, err := sealFrame(pk, epochID, msg)
	if err != nil {
		return nil
	}
	return f
}

func (n *Node) serveProbe(ep uint32, env envelope, now clock.Stamp) []byte {
	var req probeReq
	check := func(b []byte) error { return decodeJSON(b, &req, maxJSON) }
	_, err := n.admit(ep, env, check)
	if errors.Is(err, member.ErrReplay) {
		// A router restored from an older backup asks for the highest boot
		// sequence number the others saw from it, from a boot below what
		// they remember: answered on its signature alone (no replay check),
		// at most once per heartbeat interval.
		k, known := n.keyOf(env.from)
		if !known || env.from == n.id.ID || !env.verify(k, ep) || check(env.payload) != nil || req.Target != env.from {
			return nil
		}
		p := n.peer(env.from)
		if now.Mono < p.nextAsk {
			return nil
		}
		p.nextAsk = now.Mono + n.cfg.Heartbeat
		err = nil
	}
	if err != nil {
		return nil
	}
	r := n.table.Report(req.Target, now)
	b, _ := json.Marshal(probeAck{Target: r.Target, Heartbeat: r.Heartbeat, Ago: int64(r.Ago), BootSeq: r.BootSeq, Boot: r.Boot})
	return n.reply(ep, msgProbeAck, env.ref, b)
}

func (n *Node) serveDigest(ep uint32, env envelope) []byte {
	if _, err := n.admit(ep, env, func(b []byte) error { return decodeJSON(b, &digestReq{}, maxJSON) }); err != nil {
		return nil
	}
	var hs headsMsg
	hs.Heads = []headMsg{}
	for _, m := range n.cur().Members {
		h := n.log.Head(m.ID)
		if h.Seq == 0 {
			continue
		}
		hs.Heads = append(hs.Heads, headMsg{Origin: m.ID, Seq: h.Seq, Hash: h.Hash, Pruned: n.log.Pruned(m.ID).Seq})
	}
	b, _ := json.Marshal(hs)
	return n.reply(ep, msgHeads, env.ref, b)
}

func (n *Node) serveFetch(ep uint32, env envelope) []byte {
	var req fetchReq
	if _, err := n.admit(ep, env, func(b []byte) error {
		if err := decodeJSON(b, &req, maxJSON); err != nil {
			return err
		}
		if req.From == 0 || req.To < req.From {
			return errMalformed
		}
		return nil
	}); err != nil {
		return nil
	}
	var out entriesMsg
	out.Entries = []history.Entry{}
	size := 64
	es := n.log.Range(req.Origin, req.From, req.To)
	for _, p := range n.log.Forks() {
		// The other entry of a fork goes along, so the asker finds the
		// fork itself (an alarm is checked before it is repeated).
		if p.A.Origin == req.Origin && p.B.Seq >= req.From && p.B.Seq <= req.To {
			es = append(es, p.B)
		}
	}
	for _, e := range es {
		b, err := json.Marshal(e)
		if err != nil {
			break
		}
		if size+len(b)+1 > maxReplyPayload {
			break
		}
		size += len(b) + 1
		out.Entries = append(out.Entries, e)
	}
	b, _ := json.Marshal(out)
	return n.reply(ep, msgEntries, env.ref, b)
}

func (n *Node) serveRoster(ep uint32, env envelope) []byte {
	var req rosterReq
	check := func(b []byte) error { return decodeJSON(b, &req, maxJSON) }
	_, err := n.admit(ep, env, check)
	if errors.Is(err, member.ErrUnknownMember) && len(n.rosters) > 1 {
		// A member the current roster removed may fetch it, so that it
		// sees its removal and clears its secrets (security spec 5.6). Its
		// key comes from the roster before; the request changes nothing.
		prev := n.rosters[len(n.rosters)-2]
		if m, ok := memberOf(prev, env.from); ok && env.from != n.id.ID && env.verify(m.SignPub, ep) && check(env.payload) == nil {
			if _, still := memberOf(n.cur(), env.from); !still {
				req.Version, err = 0, nil
			}
		}
	}
	if err != nil {
		return nil
	}
	s, ok := n.rosterAt(req.Version)
	if !ok {
		return nil
	}
	return n.reply(ep, msgRoster, env.ref, encodeRosterReply(versionOf(n, s), s))
}

// rosterAt returns the roster of the given version in the chain, the tip
// for 0.
func (n *Node) rosterAt(v uint64) (roster.Signed, bool) {
	if v == 0 {
		return n.curSigned(), true
	}
	for i, r := range n.rosters {
		if r.Version == v {
			return n.chain[i], true
		}
	}
	return roster.Signed{}, false
}

func versionOf(n *Node, s roster.Signed) uint64 {
	h := s.Hash()
	for i, c := range n.chain {
		if c.Hash() == h {
			return n.rosters[i].Version
		}
	}
	return 0
}

// job is one TCP exchange the node makes in a Tick.
type job struct {
	to      ids.MemberID
	typ     msgType // the request
	reply   msgType // the reply it expects
	payload []byte
	sealAs  uint32                                   // the epoch to seal under; 0 for the current one
	check   func([]byte) error                       // the reply payload's schema
	apply   func(a member.Admitted, now clock.Stamp) // what to do with the reply, after check
}

// plan queues j, unless a job of the same type to the same member with the
// same payload is queued already.
func (n *Node) plan(j job) {
	for _, q := range n.jobs {
		if q.to == j.to && q.typ == j.typ && bytes.Equal(q.payload, j.payload) {
			return
		}
	}
	n.jobs = append(n.jobs, j)
}

// request returns j's request packet and its ref.
func (n *Node) request(j job) ([]byte, [16]byte, error) {
	var ref [16]byte
	if _, err := rand.Read(ref[:]); err != nil {
		return nil, ref, err
	}
	ep := j.sealAs
	if ep == 0 {
		ep = n.current().ID
	}
	pk, ok := n.packetKey(ep)
	if !ok {
		return nil, ref, ErrNoEpochKey
	}
	if len(j.payload) > maxRequestPayload {
		return nil, ref, errTooLarge
	}
	msg := encodeEnvelope(envelope{typ: j.typ, from: n.id.ID, bootSeq: n.table.BootSeq(), boot: n.boot,
		counter: n.next(), ref: ref, payload: j.payload}, ep, n.id.Sign)
	p, err := wire.Seal(pk, ep, msg)
	return p, ref, err
}

// answer checks the reply to j, whose ref was ref, and applies it.
func (n *Node) answer(j job, ref [16]byte, frame []byte, now clock.Stamp) {
	ep, msg, err := openFrame(n.lookup, frame)
	if err != nil {
		if errors.Is(err, errMalformed) {
			n.counters.Malformed++
		} else {
			n.wireFailed(err, now)
		}
		return
	}
	env, ok := parseEnvelope(msg)
	if !ok || env.typ != j.reply || env.from != j.to || env.ref != ref {
		n.counters.Malformed++
		return
	}
	a, err := n.admit(ep, env, j.check)
	if err != nil {
		return
	}
	j.apply(a, now)
}

// Tick moves the node to the current time: failure detection, heartbeats,
// catch-up, roster and key distribution, incidents and their delivery.
func (n *Node) Tick() {
	n.mu.Lock()
	if !n.running() {
		n.mu.Unlock()
		return
	}
	now := n.stamp()
	n.tickLocked(now)
	out := n.takeOut()
	n.mu.Unlock()
	n.send(out)

	for i := 0; i < maxJobs; i++ {
		n.mu.Lock()
		if !n.running() || len(n.jobs) == 0 {
			n.mu.Unlock()
			break
		}
		j := n.jobs[0]
		n.jobs = n.jobs[1:]
		p := n.peers[j.to]
		if p == nil || !p.addr.IsValid() {
			n.mu.Unlock()
			continue
		}
		addr := p.addr
		req, ref, err := n.request(j)
		n.mu.Unlock()
		if err != nil {
			continue
		}
		frame, err := n.net.Stream(addr, req)
		if err != nil {
			continue
		}
		n.mu.Lock()
		if n.running() {
			n.answer(j, ref, frame, n.stamp())
		}
		out := n.takeOut()
		n.mu.Unlock()
		n.send(out)
	}

	n.deliver()
}

func (n *Node) takeOut() []outPacket {
	out := n.out
	n.out = nil
	return out
}

func (n *Node) send(out []outPacket) {
	for _, p := range out {
		if p.multicast {
			_ = n.net.Multicast(p.b)
		} else {
			_ = n.net.Unicast(p.to, p.b)
		}
	}
}

func (n *Node) tickLocked(now clock.Stamp) {
	suspects, silent := n.table.Tick(now)
	for _, e := range silent {
		p := n.peer(e.Subject)
		p.silent, p.suspect = true, false
		body := EventBody{Subject: e.Subject, Type: e.Type}
		if p.heard {
			body.Last = Boot{ID: p.hb.Boot, Seq: p.hb.BootSeq}
		}
		if hd := n.log.Head(e.Subject); hd.Seq > 0 {
			body.Ref = EntryRef{Seq: hd.Seq, Hash: hd.Hash}
		}
		n.recordEvent(e, body, now)
	}
	for _, s := range suspects {
		n.peer(s).suspect = true
		for _, h := range n.table.IndirectProbeRequest(s) {
			n.planProbe(h, s)
		}
	}
	if n.flood.raised && now.Mono-n.flood.last > floodQuiet {
		n.flood.raised = false
	}
	if !n.caughtUp && now.Mono >= n.catchUpBy {
		n.caughtUpLocked(now)
	}
	n.keysLocked(now)
	if !n.running() {
		return
	}
	n.restoreLocked(now)
	n.retryWritesLocked(now)
	if now.Mono >= n.nextBeat {
		n.nextBeat = now.Mono + n.cfg.Heartbeat
		n.beatLocked(now)
	}
	n.reconcileLocked(now)
	n.checkPendingLocked(now)
	n.checkWaitingLocked(now)
	n.incidentsLocked(now)
	_ = n.flusher.Tick(now.Wall)
	n.aliveLocked(now)
}

// beatLocked queues this boot's heartbeat to the multicast group and to
// every static peer.
func (n *Node) beatLocked(now clock.Stamp) {
	if n.restoring {
		if now.Mono < n.restoreBy {
			return
		}
		n.restoring = false
		n.flushWritesLocked(now)
	}
	p, err := n.heartbeat(now)
	if err == nil {
		n.out = append(n.out, outPacket{multicast: true, b: p})
		n.announceTurnLocked(now)
	}
	for _, a := range n.cfg.Peers {
		if p, err := n.heartbeat(now); err == nil {
			n.out = append(n.out, outPacket{to: a, b: p})
		}
	}
}

func (n *Node) heartbeat(now clock.Stamp) ([]byte, error) {
	k := n.current()
	self, _ := memberOf(n.cur(), n.id.ID)
	h := member.Heartbeat{
		Epoch: k.ID, From: n.id.ID, BootSeq: n.table.BootSeq(), Boot: n.boot, Counter: n.next(),
		Name: self.Name, Uptime: max(now.Mono, 0), Versions: n.cfg.Versions,
		WanUp: n.wanUp, InternetOK: n.internetOK, TelegramOK: n.telegramOK, Priority: n.cfg.Priority,
		Head: n.log.Head(n.id.ID), Digest: n.log.Digest(), RosterHash: n.curHash,
		Wall: now.Wall, Mono: max(now.Mono, 0), ClockTrusted: n.trusted, GoingDown: n.goingDown,
	}
	b, err := member.EncodeHeartbeat(h, n.id)
	if err != nil {
		return nil, err
	}
	pk, ok := n.packetKey(k.ID)
	if !ok {
		return nil, ErrNoEpochKey
	}
	return wire.Seal(pk, k.ID, append([]byte{byte(msgHeartbeat)}, b...))
}

// SetClockTrusted tells the node whether its wall clock is NTP-synced in
// this boot.
func (n *Node) SetClockTrusted(ok bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.trusted = ok
}

// downCopies is how many times GoingDown sends its announcement.
const downCopies = 3

// GoingDown announces a planned shutdown: every heartbeat from now on says
// so, and it goes out at once, three times, to the multicast group and by
// unicast to every peer whose address the node knows, so one lost packet
// does not turn the planned reboot into an unexpected one (D18). Then
// everything the node keeps on flash is written (flushAllLocked).
func (n *Node) GoingDown() {
	n.mu.Lock()
	if !n.running() {
		n.mu.Unlock()
		return
	}
	n.goingDown = true
	now := n.stamp()
	n.announcedLocked(now)
	for range downCopies {
		n.announceDownLocked(now)
	}
	_ = n.flushAllLocked(now)
	out := n.takeOut()
	n.mu.Unlock()
	n.send(out)
}

// announceDownLocked queues one announcement of the shutdown: a heartbeat
// to the multicast group, and one to every peer address the node knows.
func (n *Node) announceDownLocked(now clock.Stamp) {
	if p, err := n.heartbeat(now); err == nil {
		n.out = append(n.out, outPacket{multicast: true, b: p})
	}
	seen := map[netip.AddrPort]bool{}
	addrs := slices.Clone(n.cfg.Peers)
	for _, m := range n.cur().Members {
		if p := n.peers[m.ID]; p != nil && p.addr.IsValid() && m.ID != n.id.ID {
			addrs = append(addrs, p.addr)
		}
	}
	for _, a := range addrs {
		if seen[a] {
			continue
		}
		seen[a] = true
		if p, err := n.heartbeat(now); err == nil {
			n.out = append(n.out, outPacket{to: a, b: p})
		}
	}
}

// LocalEvent records an event this router saw itself: an interface going
// down or up, the internet lost or back, an uplink switch. A zero subject
// is this router; a zero stamp is now.
func (n *Node) LocalEvent(e events.Event) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.running() {
		return
	}
	now := n.stamp()
	switch e.Type {
	case events.WanDown:
		n.wanUp = false
	case events.WanUp:
		n.wanUp = true
	case events.InternetLost:
		n.internetOK = false
	case events.InternetRestored:
		n.internetOK = true
	}
	if e.Subject == (ids.MemberID{}) {
		e.Subject = n.id.ID
	}
	if e.At == (clock.Stamp{}) {
		e.At = n.localStamp(now)
	}
	e.Witness, e.Ref = n.id.ID, ids.Hash{}
	n.recordEvent(e, EventBody{Subject: e.Subject, Type: e.Type}, now)
}

// deliver runs the election and the delivery queue, and the reachability
// check of the channel, outside the node's lock: the channel calls are
// network calls.
func (n *Node) deliver() {
	n.mu.Lock()
	if !n.running() {
		n.mu.Unlock()
		return
	}
	now := n.stamp()
	sender, _ := n.senderLocked(now)
	sender = n.turnLocked(sender, now)
	own := n.hasChannel()
	ch := n.ch
	ping := own && now.Mono >= n.nextPing
	if ping {
		n.nextPing = now.Mono + pingEvery
	}
	self := n.id.ID
	n.mu.Unlock()

	if ping {
		ctx, cancel := context.WithTimeout(context.Background(), sendTimeout)
		err := ch.Ping(ctx)
		cancel()
		n.mu.Lock()
		n.channelResult(err)
		n.mu.Unlock()
	}
	if own {
		ctx, cancel := context.WithTimeout(context.Background(), sendTimeout)
		id, err := n.queue.Deliver(ctx, ch, self, sender, now.Wall, n.render)
		cancel()
		if id != "" || err != nil {
			n.mu.Lock()
			n.channelResult(err)
			n.mu.Unlock()
		}
	} else {
		n.queue.Due(self, sender, now.Wall)
	}
	n.mu.Lock()
	if n.running() {
		n.recordAcksLocked(n.stamp())
	}
	n.mu.Unlock()
}

// channelResult records the outcome of a call on the channel.
func (n *Node) channelResult(err error) {
	switch {
	case err == nil:
		n.telegramOK = n.clk.Now()
		n.telegram = "ok"
	case errors.Is(err, deliver.ErrBlocked):
		n.telegram = "bot_blocked"
	case errors.Is(err, deliver.ErrRateLimited):
		n.telegram = "rate_limited"
	case errors.Is(err, deliver.ErrTLS):
		n.telegram = "tls_failed"
	default:
		n.telegram = "unreachable"
	}
}

// hasChannel reports whether this router sends: configured to, with a
// channel, and with the sender role in the roster.
func (n *Node) hasChannel() bool {
	if !n.cfg.Sender || n.ch == nil {
		return false
	}
	m, ok := memberOf(n.cur(), n.id.ID)
	return ok && hasRole(m, roster.RoleSender)
}
