package daemon

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/channel"
	"github.com/TAIPANBOX/rollcall/internal/clock"
	"github.com/TAIPANBOX/rollcall/internal/config"
	"github.com/TAIPANBOX/rollcall/internal/events"
	"github.com/TAIPANBOX/rollcall/internal/identity"
	"github.com/TAIPANBOX/rollcall/internal/ids"
	"github.com/TAIPANBOX/rollcall/internal/node"
	"github.com/TAIPANBOX/rollcall/internal/pairing"
	"github.com/TAIPANBOX/rollcall/internal/roster"
)

// # Control commands
//
// The CLI sends one command per connection (internal/control), and the
// arguments of each are fixed here; the CLI has checked them already and
// they are checked again. Every admin command answers with the reply of
// luci-app-rollcall/STATUS-JSON.md, {"ok": true, "message": ...} with
// join_code or bind_code where they belong; a failure is the handler's error,
// which the control server sends as the refusal text, redacted.
//
//	status
//	notify going-down | clock-synced | iface <action> <iface> | uplink <iface>
//	invite <sender 0|1> <address or "">
//	join <code> <name>
//	remove <name>
//	rotate
//	set-token <token>
//	bind-telegram
//	roles <sender|primary|backup|none> <name>
//	admin-takeover | admin-confirm
//	admin-recover <recovery seed, 64 hex digits>

const (
	// pingTimeout bounds the getMe call bind-telegram makes first; the CLI
	// gives a command 10 s.
	pingTimeout = 8 * time.Second
	// bindWindow is how long the owner has to send the bind code.
	bindWindow = 10 * time.Minute
	// bindDigits is the length of a bind code, digits only so that a phone
	// keyboard types it without case or look-alike letters.
	bindDigits = 10
	// maxTokenLen is pairing.MaxTokenLen: a longer token could not reach a
	// new sender in a join response.
	maxTokenLen = pairing.MaxTokenLen
)

var errArgs = errors.New("wrong arguments for this command")

// reply is the answer of an admin command (STATUS-JSON.md, "Admin
// commands: the reply").
type reply struct {
	OK       bool   `json:"ok"`
	Message  string `json:"message"`
	JoinCode string `json:"join_code,omitempty"`
	BindCode string `json:"bind_code,omitempty"`
}

func ok(msg string) ([]byte, error) { return json.Marshal(reply{OK: true, Message: msg}) }

// Handle runs one control command. The control server has checked that the
// caller is root.
func (d *Daemon) Handle(cmd string, args []string, _ uint32) ([]byte, error) {
	out, err := d.handle(cmd, args)
	if err != nil {
		return nil, errors.New(plain(err))
	}
	return out, nil
}

func (d *Daemon) handle(cmd string, args []string) ([]byte, error) {
	arity := map[string]int{
		"status": 0, "invite": 2, "join": 2, "remove": 1, "rotate": 0, "set-token": 1,
		"bind-telegram": 0, "roles": 2, "admin-takeover": 0, "admin-confirm": 0, "admin-recover": 1,
	}
	if n, fixed := arity[cmd]; fixed && len(args) != n {
		return nil, errArgs
	}
	switch cmd {
	case "status":
		return d.status()
	case "notify":
		return d.notify(args)
	case "invite":
		return d.invite(args[0], args[1])
	case "join":
		return d.join(args[0], args[1])
	case "remove":
		return d.remove(args[0])
	case "rotate":
		return d.rotate()
	case "set-token":
		return d.setToken(args[0])
	case "bind-telegram":
		return d.bindTelegram()
	case "roles":
		return d.roles(args[0], args[1])
	case "admin-takeover":
		return d.publish(takeOver, "Takeover signed. It stays provisional until rollcall admin confirm runs on this router.")
	case "admin-confirm":
		return d.publish(confirmTakeover, "Takeover confirmed. The primary it replaced no longer restores itself.")
	case "admin-recover":
		return d.recover(args[0])
	}
	return nil, errors.New("unknown command")
}

// plain turns an error into the sentence the CLI shows.
func plain(err error) string {
	switch {
	case errors.Is(err, node.ErrNotAdmin):
		return "this router is not an admin of the group"
	case errors.Is(err, node.ErrRemoved):
		return "this router was removed from the group; it can join again with a new join code"
	case errors.Is(err, node.ErrNoRoster), errors.Is(err, node.ErrNoEpochKey), errors.Is(err, fs.ErrNotExist):
		return "this router is not set up; run rollcall init on the first router, or rollcall join on the others"
	}
	msg := err.Error()
	for _, p := range []string{"node: ", "roster: ", "pairing: ", "epoch: ", "identity: ", "store: "} {
		msg = strings.TrimPrefix(msg, p)
	}
	return msg
}

// running returns the node when it runs, and otherwise why it does not.
func (d *Daemon) running() (*node.Node, error) {
	d.mu.Lock()
	nd, err := d.nd, d.ndErr
	d.mu.Unlock()
	switch {
	case nd == nil && err == nil:
		return nil, fs.ErrNotExist
	case nd == nil || err != nil:
		return nil, err
	}
	return nd, nil
}

// self returns this router's ID and its entry of the status.
func (d *Daemon) self(nd *node.Node) (node.Status, error) {
	s := nd.Status()
	if s.State != "running" || s.Self == nil {
		if s.State == "removed" {
			return s, node.ErrRemoved
		}
		return s, errors.New("the node does not run: " + s.Error)
	}
	return s, nil
}

func (d *Daemon) selfID() ids.MemberID {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.id == nil {
		return ids.MemberID{}
	}
	return d.id.ID
}

// notify takes what hotplug and the init script tell the daemon.
func (d *Daemon) notify(args []string) ([]byte, error) {
	switch {
	case len(args) == 1 && args[0] == "going-down":
		nd, err := d.running()
		if err != nil {
			return ok("This router is in no group; there is nobody to tell.")
		}
		nd.GoingDown()
		if err := d.writeShutdownMarker(); err != nil {
			d.o.Logf("rollcalld: shutdown marker not written: %v", err)
		}
		return ok("The other routers were told that this router is going down.")
	case len(args) == 1 && args[0] == "clock-synced":
		// OpenWrt's ntpd reported a usable stratum or stepped the clock
		// (hotplug.d/ntp/50-rollcall): the wall clock holds for this boot.
		d.mu.Lock()
		d.trusted = true
		nd := d.nd
		d.mu.Unlock()
		if nd != nil {
			nd.SetClockTrusted(true)
		}
		return ok("Noted: the clock is synchronised.")
	case len(args) == 3 && args[0] == "iface":
		if !validWord(args[1], 16) || !validIface(args[2]) {
			return nil, errArgs
		}
		typ, ok2 := ifaceEvent(args[1], args[2])
		if !ok2 {
			return ok("Noted; this event is not one rollcall reports.")
		}
		d.localEvent(typ, time.Time{}, nil)
		return ok("Noted.")
	case len(args) == 2 && args[0] == "uplink":
		if !validIface(args[1]) {
			return nil, errArgs
		}
		d.localEvent(events.UplinkSwitched, time.Time{}, map[string]string{"to": args[1]})
		return ok("Noted.")
	}
	return nil, errArgs
}

// ifaceEvent maps a netifd hotplug event to the event rollcall records:
// only the WAN interfaces count, and only going down and coming up.
func ifaceEvent(action, iface string) (events.Type, bool) {
	if !wanIface(iface) {
		return "", false
	}
	switch action {
	case "ifdown":
		return events.WanDown, true
	case "ifup":
		return events.WanUp, true
	}
	return "", false
}

// wanIface reports whether a netifd interface is an uplink by its name:
// wan, wan6, wwan and the others of the wan family. A WAN under another name
// is reported through the default route instead (Host).
func wanIface(iface string) bool {
	return strings.HasPrefix(iface, "wan") || strings.HasPrefix(iface, "wwan")
}

// validWord is a lower-case word of letters and '-', as hotplug actions are.
func validWord(s string, max int) bool {
	if s == "" || len(s) > max {
		return false
	}
	for _, r := range s {
		if (r < 'a' || r > 'z') && r != '-' {
			return false
		}
	}
	return true
}

// validIface is a netifd interface name: letters, digits, '_', '.', '-'.
func validIface(s string) bool {
	if s == "" || len(s) > 32 || s[0] == '-' {
		return false
	}
	for _, r := range s {
		ok := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '.' || r == '-'
		if !ok {
			return false
		}
	}
	return true
}

// localEvent records an event this router saw, stamped with the time its
// condition started (since); a zero since is now.
func (d *Daemon) localEvent(typ events.Type, since time.Time, detail map[string]string) {
	nd, err := d.running()
	if err != nil {
		return
	}
	e := events.Event{Type: typ, Detail: detail}
	if now := d.o.Clock.Now(); !since.IsZero() && now.Sub(since) > time.Second {
		mono := max(d.o.Clock.Mono()-now.Sub(since), 0)
		e.At = clock.Stamp{Wall: since, Mono: mono, Boot: d.o.Boot}
	}
	nd.LocalEvent(e)
}

func (d *Daemon) invite(sender, address string) ([]byte, error) {
	if sender != "0" && sender != "1" {
		return nil, errArgs
	}
	nd, err := d.running()
	if err != nil {
		return nil, err
	}
	var a netip.Addr
	if address != "" {
		if a, err = netip.ParseAddr(address); err != nil {
			return nil, errors.New("the address is not an IP address")
		}
	} else {
		var found bool
		if d.o.Addrs != nil {
			a, found = pickBootstrap(d.o.Addrs())
		}
		if !found {
			return nil, errors.New("no address on the peer-zone interfaces that a new router could reach; give one with --address")
		}
	}
	port := d.o.Config.Port
	if port == 0 {
		port = config.DefaultPort
	}
	code, err := nd.Invite(netip.AddrPortFrom(a.Unmap(), uint16(port)), sender == "1")
	if err != nil {
		return nil, err
	}
	msg := "Join window open for 10 minutes."
	if sender == "1" {
		msg += " The new router gets the sender role."
	}
	return json.Marshal(reply{OK: true, Message: msg, JoinCode: code.String()})
}

// pickBootstrap chooses the address invite puts in the join code: an IPv4
// address of the peer zones if there is one, else a global IPv6 address.
// Link-local addresses carry a zone, which a join code cannot.
func pickBootstrap(addrs []netip.Addr) (netip.Addr, bool) {
	usable := func(a netip.Addr) bool {
		return a.IsValid() && !a.IsLoopback() && !a.IsLinkLocalUnicast() && !a.IsMulticast() && !a.IsUnspecified() && a.Zone() == ""
	}
	for _, a := range addrs {
		if a = a.Unmap(); a.Is4() && usable(a) {
			return a, true
		}
	}
	for _, a := range addrs {
		if a.Is6() && !a.Is4In6() && usable(a) {
			return a, true
		}
	}
	return netip.Addr{}, false
}

func (d *Daemon) join(text, name string) ([]byte, error) {
	if err := roster.ValidName(name); err != nil {
		return nil, fmt.Errorf("the router name is not valid: %w", err)
	}
	if nd, err := d.running(); err == nil && nd.Status().State == "running" {
		return nil, errors.New("this router is in a group already")
	}
	c, err := pairing.ParseCode(text)
	if err != nil {
		return nil, err
	}
	id, err := d.identityForJoin()
	if err != nil {
		return nil, err
	}
	if err := node.Join(d.st, d.o.Net, c, id, name); err != nil {
		return nil, err
	}
	d.mu.Lock()
	d.rebuild = true
	d.mu.Unlock()
	return ok(fmt.Sprintf("Joined the group as %s.", name))
}

// identityForJoin returns this router's identity, made and saved now when
// there is none yet. It never replaces one that is there.
func (d *Daemon) identityForJoin() (*identity.Identity, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.id != nil {
		return d.id, nil
	}
	id, err := identity.Load(d.o.StateDir)
	if errors.Is(err, fs.ErrNotExist) {
		if id, err = identity.Generate(); err == nil {
			err = id.Save(d.o.StateDir)
		}
	}
	if err != nil {
		return nil, err
	}
	d.id = id
	return id, nil
}

func (d *Daemon) remove(name string) ([]byte, error) {
	if err := roster.ValidName(name); err != nil {
		return nil, errArgs
	}
	nd, err := d.running()
	if err != nil {
		return nil, err
	}
	self := d.selfID()
	var sender bool
	if err := nd.Publish(func(r *roster.Roster) error { return removeMember(r, self, name, &sender) }); err != nil {
		return nil, err
	}
	msg := fmt.Sprintf("%s removed. The group key was replaced, so it can no longer read or send anything.", name)
	if sender {
		msg += " It held the bot token: revoke the token in @BotFather and run rollcall set-token with the new one."
	}
	return ok(msg)
}

func (d *Daemon) roles(role, name string) ([]byte, error) {
	if !slices.Contains([]string{"sender", "primary", "backup", "none"}, role) || roster.ValidName(name) != nil {
		return nil, errArgs
	}
	nd, err := d.running()
	if err != nil {
		return nil, err
	}
	err = nd.Publish(func(r *roster.Roster) error { return setRole(r, role, name) })
	switch {
	case errors.Is(err, errUnchanged):
		return ok(fmt.Sprintf("%s has that role already; nothing changed.", name))
	case errors.Is(err, roster.ErrTakeoverFlag):
		return nil, errors.New("only the primary admin appoints a primary; on the backup, use rollcall admin takeover")
	case err != nil:
		return nil, err
	}
	if role == "none" {
		return ok(fmt.Sprintf("%s has no role now.", name))
	}
	return ok(fmt.Sprintf("%s is %s now.", name, role))
}

// publish signs the roster edit makes with this router's key.
func (d *Daemon) publish(edit func(*roster.Roster, ids.MemberID) error, done string) ([]byte, error) {
	nd, err := d.running()
	if err != nil {
		return nil, err
	}
	self := d.selfID()
	err = nd.Publish(func(r *roster.Roster) error { return edit(r, self) })
	if errors.Is(err, errUnchanged) {
		return ok("Nothing to change.")
	}
	if err != nil {
		return nil, err
	}
	return ok(done)
}

func (d *Daemon) rotate() ([]byte, error) {
	nd, err := d.running()
	if err != nil {
		return nil, err
	}
	if err := nd.Rotate(); err != nil {
		return nil, err
	}
	return ok("New group key made. It goes to every member now; the old one stops working in 60 seconds.")
}

// recover signs, with the recovery key, a roster that makes this router the
// only admin, and then replaces the group key (security spec 6.1).
func (d *Daemon) recover(seedHex string) ([]byte, error) {
	seed, err := hex.DecodeString(seedHex)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errArgs
	}
	key := ed25519.NewKeyFromSeed(seed)
	clear(seed)
	defer clear(key)
	nd, err := d.running()
	if err != nil {
		return nil, err
	}
	pub := key.Public().(ed25519.PublicKey)
	self := d.selfID()
	errWrong := errors.New("the recovery code does not belong to this group")
	err = nd.PublishRecovery(func(r *roster.Roster) error {
		if !bytes.Equal(r.RecoveryPub, pub) {
			return errWrong
		}
		return recoverAdmin(r, self)
	}, key)
	if err != nil {
		return nil, err
	}
	if err := nd.Rotate(); err != nil {
		return ok("This router is the primary admin now, but the new group key failed: " + plain(err) + ". Run rollcall rotate.")
	}
	return ok("This router is the primary admin now, signed with the recovery code. The group key was replaced.")
}

// validToken is the rule of a bot token a join response can carry.
func validToken(t string) bool {
	if t == "" || len(t) > maxTokenLen {
		return false
	}
	for _, r := range t {
		ok := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == ':' || r == '_' || r == '-'
		if !ok {
			return false
		}
	}
	return true
}

// senderSelf returns the node when this router holds the sender role: only
// a sender may hold the bot token.
func (d *Daemon) senderSelf() (*node.Node, error) {
	nd, err := d.running()
	if err != nil {
		return nil, err
	}
	s, err := d.self(nd)
	if err != nil {
		return nil, err
	}
	if !slices.Contains(s.Self.Roles, "sender") {
		return nil, fmt.Errorf("%s does not have the sender role; give it with rollcall roles sender -- %s on an admin router", s.Self.Name, s.Self.Name)
	}
	return nd, nil
}

func (d *Daemon) setToken(token string) ([]byte, error) {
	if !validToken(token) {
		return nil, errors.New("that is not a bot token")
	}
	nd, err := d.senderSelf()
	if err != nil {
		return nil, err
	}
	d.secMu.Lock()
	defer d.secMu.Unlock()
	d.mu.Lock()
	// The bound chat stays: a token revoked in @BotFather is replaced by a
	// new token of the same bot, which still reaches that chat.
	chat := d.chatID
	d.mu.Unlock()
	if err := nd.SetSecrets(pairing.Secrets{BotToken: token, ChatID: chat}, d.channelFor(token, chat)); err != nil {
		return nil, fmt.Errorf("the token was not saved: %w", err)
	}
	d.mu.Lock()
	d.token, d.chatID = token, chat
	if d.binding != nil {
		d.binding()
		d.binding = nil
	}
	d.mu.Unlock()
	msg := "Bot token saved."
	if chat == 0 {
		msg += " Run rollcall bind-telegram next to bind the chat."
	}
	if !d.o.Config.Sender {
		msg += " This router sends only with option sender '1' in /etc/config/rollcall."
	}
	return ok(msg)
}

// bindTelegram checks the token with getMe first, so that a wrong one fails
// at once, then waits in the background, for bindWindow, for the owner to
// send the bind code to the bot in a private chat.
func (d *Daemon) bindTelegram() ([]byte, error) {
	if _, err := d.senderSelf(); err != nil {
		return nil, err
	}
	d.mu.Lock()
	token := d.token
	d.mu.Unlock()
	if token == "" {
		return nil, errors.New("no bot token is set; run rollcall set-token first")
	}
	tg := channel.NewTelegram(d.o.TelegramURL, token, 0, d.o.HTTP)
	ctx, cancel := context.WithTimeout(d.ctx, pingTimeout)
	err := tg.Ping(ctx)
	cancel()
	if err != nil {
		return nil, fmt.Errorf("Telegram did not accept the bot token, or could not be reached: %w", err)
	}
	code, err := bindCode()
	if err != nil {
		return nil, err
	}
	bctx, stop := context.WithCancel(d.ctx)
	d.mu.Lock()
	if d.binding != nil {
		d.binding()
	}
	d.binding = stop
	d.mu.Unlock()
	go d.awaitBinding(bctx, stop, tg, token, code)
	return json.Marshal(reply{OK: true, BindCode: code,
		Message: "Send this code to the bot in a private chat within 10 minutes."})
}

func (d *Daemon) awaitBinding(ctx context.Context, stop context.CancelFunc, tg *channel.Telegram, token, code string) {
	defer stop()
	chat, err := tg.BindChat(ctx, code, bindWindow)
	if err != nil {
		if ctx.Err() == nil {
			d.o.Logf("rollcalld: chat binding ended without a chat: %s", plain(err))
		}
		return
	}
	d.secMu.Lock()
	defer d.secMu.Unlock()
	d.mu.Lock()
	same := d.token == token
	d.mu.Unlock()
	nd, err := d.running()
	if !same || err != nil {
		return
	}
	if err := nd.SetSecrets(pairing.Secrets{BotToken: token, ChatID: chat}, d.channelFor(token, chat)); err != nil {
		d.o.Logf("rollcalld: the bound chat was not saved: %s", plain(err))
		return
	}
	d.mu.Lock()
	d.chatID = chat
	d.mu.Unlock()
	d.o.Logf("rollcalld: chat bound")
}

// bindCode returns bindDigits random decimal digits.
func bindCode() (string, error) {
	var b strings.Builder
	for range bindDigits {
		n, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			return "", err
		}
		b.WriteByte(byte('0' + n.Int64()))
	}
	return b.String(), nil
}
