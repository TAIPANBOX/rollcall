// Package daemon wires the finished rollcall packages into rollcalld: one
// node, the transport it is handed, the control commands the CLI sends, the
// status report of luci-app-rollcall/STATUS-JSON.md, and what the router
// itself sees (internet probes, the default route).
//
// main in cmd/rollcalld opens the sockets and fills Options with the real
// transport, clock and host readers; tests fill them with fakes. Nothing here
// opens a socket or runs a command.
//
// # The node's life
//
// A router without an identity or a roster runs a daemon with no working
// node: status says it is not set up. rollcall init (run by the CLI, as root,
// on the state directory) and join (run here, over the transport) leave the
// state a node starts from; the daemon looks for it every pollEvery and
// starts the node once it is there.
//
// set-token and a finished bind-telegram hand the running node its new
// secrets and channel (node.SetSecrets); it keeps running. A new node is
// started only after a join, from what the join stored. When the node before
// it had run, it had sent packets under its boot sequence number, so the new
// one takes a new number (identity.NextBootSeq) and the peers accept it as
// the same boot with a higher sequence: no event, no replay rejection.
package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/channel"
	"github.com/TAIPANBOX/rollcall/internal/config"
	"github.com/TAIPANBOX/rollcall/internal/deliver"
	"github.com/TAIPANBOX/rollcall/internal/identity"
	"github.com/TAIPANBOX/rollcall/internal/ids"
	"github.com/TAIPANBOX/rollcall/internal/node"
	"github.com/TAIPANBOX/rollcall/internal/store"
)

const (
	// pollEvery is how often a daemon without a working node looks for the
	// state init or join leaves, and how often it re-reads the secrets file.
	pollEvery = 5 * time.Second
	// fileShutdown is the shutdown marker of design 4.6: the boot ID of the
	// boot that told its peers it was going down. It lives on flash, in the
	// state directory, so that it survives the reboot it announces.
	fileShutdown = "shutdown.json"
	// transientFor bounds how long a daemon without a working node looks
	// again at state it is not allowed to read. rollcall init writes the
	// state as root and gives it to the rollcall user only afterwards
	// (cmd/rollcall handOver), so a poll can land in between; a permission
	// error that lasts longer is not that, and is left in the status.
	transientFor = time.Minute
)

// Options are what the daemon runs with.
type Options struct {
	StateDir string
	Config   config.Config
	Devices  []string // the network devices of the peer zones, from config.Load
	Net      node.Net
	Clock    node.Clock
	Boot     ids.BootID // the kernel's boot ID; zero when it could not be read
	Versions [2]string  // the OpenWrt release and the rollcall version

	// TelegramURL and HTTP reach the Bot API: channel.TelegramBaseURL and
	// channel.GuardedClient([]string{"api.telegram.org"}) outside tests.
	TelegramURL string
	HTTP        *http.Client

	// Discovery reports, per peer-zone device, whether discovery runs there
	// (transport.Discovery). Nil reports nothing.
	Discovery func() map[string]error
	// Sandbox reads the daemon's own sandbox. Nil reports none.
	Sandbox func() node.SandboxStatus
	// Addrs lists the unicast addresses of the peer-zone devices, from which
	// invite picks the address a new router reaches this one at.
	Addrs func() []netip.Addr
	// Logf logs; nil is log.Printf. Logs never carry a secret or a code.
	Logf func(format string, args ...any)
}

// Daemon is one rollcalld.
type Daemon struct {
	o   Options
	st  *store.Store
	loc *time.Location
	ctx context.Context
	end context.CancelFunc

	mu       sync.Mutex
	id       *identity.Identity
	nd       *node.Node // nil until an identity exists
	ndErr    error      // what node.New returned for nd, or why there is none
	ran      bool       // nd started, so it may have sent under seq
	seq      uint64     // the boot sequence number nd runs with
	planned  bool       // the boot before this one announced its shutdown
	rebuild  bool       // start a new node at the next Step
	nextPoll time.Duration
	token    string // the bot token in the store; empty without one
	chatID   int64  // the bound chat; 0 while none is bound
	binding  context.CancelFunc
	switched bool // the default route moved to another interface in this run
	trusted  bool // ntpd reported a synchronised clock in this boot

	// unreadable is set while the last build failed for lack of permission
	// to read the state, since the moment in unreadableSince; gaveUp once
	// that lasted transientFor.
	unreadable      bool
	unreadableSince time.Duration
	gaveUp          bool

	// secMu orders the changes of the secrets: set-token and the end of a
	// binding.
	secMu sync.Mutex
}

// New opens the state directory, takes this run's boot sequence number and
// starts the node if the state for one is there.
func New(o Options) (*Daemon, error) {
	switch {
	case o.StateDir == "":
		return nil, errors.New("daemon: no state directory")
	case o.Net == nil || o.Clock == nil:
		return nil, errors.New("daemon: no transport or clock")
	}
	if o.Logf == nil {
		o.Logf = log.Printf
	}
	if o.TelegramURL == "" {
		o.TelegramURL = channel.TelegramBaseURL
	}
	if o.HTTP == nil {
		o.HTTP = channel.GuardedClient([]string{"api.telegram.org"})
	}
	loc := time.UTC
	if o.Config.TZ != "" {
		l, err := time.LoadLocation(o.Config.TZ)
		if err != nil {
			return nil, fmt.Errorf("daemon: time zone %q: %w", o.Config.TZ, err)
		}
		loc = l
	}
	st, err := store.Open(o.StateDir)
	if err != nil {
		return nil, err
	}
	seq, err := identity.NextBootSeq(o.StateDir)
	if err != nil {
		return nil, err
	}
	ctx, end := context.WithCancel(context.Background())
	d := &Daemon{o: o, st: st, loc: loc, ctx: ctx, end: end, seq: seq}
	d.planned = d.takeShutdownMarker()
	d.mu.Lock()
	d.buildLocked()
	d.mu.Unlock()
	return d, nil
}

// Close stops what the daemon runs in the background: a chat binding.
func (d *Daemon) Close() { d.end() }

// Step is one turn of the main loop, about once a second: start a node
// that is due, and move the current one to the present (node.Tick).
func (d *Daemon) Step() {
	d.mu.Lock()
	now := d.o.Clock.Mono()
	poll := now >= d.nextPoll
	if poll {
		d.nextPoll = now + pollEvery
	}
	switch {
	case d.rebuild:
		d.rebuild = false
		d.buildLocked()
	case poll && d.waitingLocked():
		d.buildLocked()
	case poll:
		d.loadSecretsLocked()
	}
	nd := d.nd
	d.mu.Unlock()
	if nd != nil {
		nd.Tick()
	}
}

// waitingLocked reports whether there is no working node only because
// init or join has not run yet, or has not yet given its files to the
// rollcall user (for at most transientFor).
func (d *Daemon) waitingLocked() bool {
	if d.unreadable && !d.gaveUp {
		return true
	}
	if d.nd == nil {
		return errors.Is(d.ndErr, fs.ErrNotExist)
	}
	return errors.Is(d.ndErr, node.ErrNoRoster) || errors.Is(d.ndErr, node.ErrNoEpochKey)
}

// buildLocked starts a new node from the store, in place of the current
// one.
func (d *Daemon) buildLocked() {
	if d.id == nil {
		id, err := identity.Load(d.o.StateDir)
		if err != nil {
			d.ndErr = err
			d.unreadableLocked(err)
			return
		}
		d.id = id
	}
	if d.ran {
		seq, err := identity.NextBootSeq(d.o.StateDir)
		if err != nil {
			d.o.Logf("rollcalld: no new boot sequence number, keeping the running node: %v", err)
			return
		}
		d.seq = seq
	}
	d.loadSecretsLocked()
	c := d.o.Config
	cfg := node.Config{
		Site: c.Site, Heartbeat: c.Heartbeat, SilentAfter: c.SilentAfter, Sender: c.Sender, TZ: d.loc,
		Boot: d.o.Boot, BootSeq: d.seq, IdentityDir: d.o.StateDir, Planned: d.planned,
		Peers: c.Peers, Versions: d.o.Versions,
	}
	nd, err := node.New(cfg, d.st, d.id, d.o.Net, d.o.Clock, d.channelFor(d.token, d.chatID))
	d.nd, d.ndErr, d.ran = nd, err, err == nil
	d.unreadableLocked(err)
	if err == nil {
		d.planned = false
		nd.SetClockTrusted(d.trusted)
		return
	}
	if !d.waitingLocked() {
		d.o.Logf("rollcalld: the node does not run: %v", err)
	}
}

// unreadableLocked follows how long the state has been unreadable for lack
// of permission; err is what the last build returned. It logs the first
// such error and the moment the daemon stops looking again.
func (d *Daemon) unreadableLocked(err error) {
	if !errors.Is(err, fs.ErrPermission) {
		d.unreadable, d.gaveUp = false, false
		return
	}
	now := d.o.Clock.Mono()
	switch {
	case !d.unreadable:
		d.unreadable, d.unreadableSince, d.gaveUp = true, now, false
		d.o.Logf("rollcalld: the state cannot be read yet, looking again for up to %s (init may still be handing it over): %v", transientFor, err)
	case !d.gaveUp && now-d.unreadableSince >= transientFor:
		d.gaveUp = true
		d.o.Logf("rollcalld: the state could not be read for %s; looking no more until rollcalld restarts: %v", transientFor, err)
	}
}

// channelFor returns the chat channel of a node holding token and chat:
// Telegram when this router is configured to send and both are there.
func (d *Daemon) channelFor(token string, chat int64) deliver.Channel {
	if !d.o.Config.Sender || token == "" || chat == 0 {
		return nil
	}
	return channel.NewTelegram(d.o.TelegramURL, token, chat, d.o.HTTP)
}

// secretsFile is what node.SaveSecrets writes. It is decoded leniently: the
// node owns the file.
type secretsFile struct {
	BotToken string `json:"bot_token"`
	ChatID   int64  `json:"chat_id"`
}

// loadSecretsLocked reads the bot token and chat ID from the store: a join
// as a sender writes them, a removal clears them.
func (d *Daemon) loadSecretsLocked() {
	var s secretsFile
	if b, err := d.st.ReadFile(node.FileSecrets); err == nil {
		_ = json.Unmarshal(b, &s)
	}
	d.token, d.chatID = s.BotToken, s.ChatID
}

// Secrets returns what the control socket redacts from every reply.
func (d *Daemon) Secrets() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []string
	if d.token != "" {
		out = append(out, d.token)
	}
	if c := strconv.FormatInt(d.chatID, 10); d.chatID != 0 && len(c) >= 6 {
		out = append(out, c)
	}
	return out
}

// current returns the node, or nil.
func (d *Daemon) current() *node.Node {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.nd
}

// Authenticate is the transport's gate on the first frame of a TCP
// connection.
func (d *Daemon) Authenticate(frame []byte) bool {
	if n := d.current(); n != nil {
		return n.Authenticate(frame)
	}
	return false
}

// HandlePacket hands a UDP packet to the node.
func (d *Daemon) HandlePacket(from netip.AddrPort, b []byte) {
	if n := d.current(); n != nil {
		n.HandlePacket(from, b)
	}
}

// HandleStream hands a TCP request frame to the node and returns its answer.
func (d *Daemon) HandleStream(from netip.AddrPort, b []byte) []byte {
	if n := d.current(); n != nil {
		return n.HandleStream(from, b)
	}
	return nil
}

// shutdownMarker is the content of fileShutdown.
type shutdownMarker struct {
	Boot string `json:"boot"`
}

// takeShutdownMarker reads the marker and reports whether an earlier boot
// announced its shutdown. A marker of an earlier boot is consumed, so that
// it counts for the next boot only; one of this boot stays, since the
// daemon only restarted.
func (d *Daemon) takeShutdownMarker() bool {
	b, err := d.st.ReadFile(fileShutdown)
	if err != nil {
		return false
	}
	var m shutdownMarker
	if json.Unmarshal(b, &m) != nil || m.Boot == "" || d.o.Boot == (ids.BootID{}) || m.Boot == d.o.Boot.String() {
		return false
	}
	if b, err := json.Marshal(shutdownMarker{}); err == nil {
		_ = d.st.WriteFileAtomic(fileShutdown, b)
	}
	return true
}

// writeShutdownMarker records that this boot announced its shutdown.
func (d *Daemon) writeShutdownMarker() error {
	if d.o.Boot == (ids.BootID{}) {
		return errors.New("the boot ID is unknown, so the next boot cannot tell it was announced")
	}
	b, err := json.Marshal(shutdownMarker{Boot: d.o.Boot.String()})
	if err != nil {
		return err
	}
	return d.st.WriteFileAtomic(fileShutdown, b)
}
