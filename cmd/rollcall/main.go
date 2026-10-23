// Command rollcall is the rollcall command-line tool. It runs as root on the
// router and talks to rollcalld over the control socket; init alone works on
// the state directory itself. LuCI runs it through rpcd with the exact forms
// in luci-app-rollcall/STATUS-JSON.md, whose output it prints with --json.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/control"
	"github.com/TAIPANBOX/rollcall/internal/pairing"
	"github.com/TAIPANBOX/rollcall/internal/roster"
)

// version is set at build time with -ldflags "-X main.version=<tag>".
var version = "dev"

// The control socket (packaging/README.md); cmd/rollcalld names the same.
const (
	ControlDirPath    = "/var/run/rollcall"
	ControlSocketPath = "/var/run/rollcall/control.sock"
)

const (
	defaultStateDir   = "/etc/rollcall"
	defaultConfigPath = "/etc/config/rollcall"
	// tokenEnv carries the bot token to set-token, never the command line.
	tokenEnv = "TELEGRAM_ROLLCALL_TOKEN"
	// Each control command has a time limit; status is what LuCI polls.
	callTimeout   = 10 * time.Second
	statusTimeout = 2 * time.Second
	// maxStdinCode bounds what admin recover reads from standard input.
	maxStdinCode = 1024
)

const usage = `usage: rollcall <command> [arguments]

Setting up:
  rollcall init [--json] [--name <router>] [--site <site>]
      create the group on its first router; prints the recovery code once
  rollcall invite [--json] [--sender] [--address <ip>]
      open a join window for 10 minutes and print the join code; the address
      (the one the new router reaches this router at) may also come last,
      alone after --, as LuCI gives it
  rollcall join [--json] [--name <router>] <join code>
      join the group with the code from rollcall invite

Members and roles, on an admin router (the name always comes last, after --):
  rollcall remove [--json] -- <router>
  rollcall roles [--json] sender|primary|backup|none -- <router>
  rollcall rotate [--json]

Telegram, on a sender:
  rollcall set-token [--json]      the token is read from TELEGRAM_ROLLCALL_TOKEN
  rollcall bind-telegram [--json]  prints a code to send to the bot in a private chat

Admins:
  rollcall admin takeover [--json] on the backup admin, when the primary is gone
  rollcall admin confirm [--json]  confirm the takeover made on this router
  rollcall admin recover [--json]  the recovery code is read from standard input

State:
  rollcall status [--json]
  rollcall notify going-down | clock-synced | iface <action> <interface> | uplink <interface>
      what the init script and hotplug tell rollcalld
  rollcall version

The router name defaults to the hostname. Names are 1 to 32 characters from
a-z, 0-9 and '-', and do not start with '-'.
`

// reply is the answer of an admin command, as STATUS-JSON.md defines it.
type reply struct {
	OK           bool   `json:"ok"`
	Message      string `json:"message,omitempty"`
	Error        string `json:"error,omitempty"`
	JoinCode     string `json:"join_code,omitempty"`
	BindCode     string `json:"bind_code,omitempty"`
	RecoveryCode string `json:"recovery_code,omitempty"` // init only
}

// cli is one run of the command. Its fields are what tests replace.
type cli struct {
	stdin      io.Reader
	stdout     io.Writer
	stderr     io.Writer
	getenv     func(string) string
	call       func(ctx context.Context, cmd string, args ...string) ([]byte, error)
	stateDir   string
	configPath string
	hostname   func() (string, error)
}

func main() {
	c := &cli{
		stdin: os.Stdin, stdout: os.Stdout, stderr: os.Stderr, getenv: os.Getenv,
		call:     control.Client(ControlSocketPath).CallContext,
		stateDir: defaultStateDir, configPath: defaultConfigPath, hostname: os.Hostname,
	}
	os.Exit(c.run(os.Args[1:]))
}

// usageError is a command line the CLI refuses before anything runs.
type usageError struct{ msg string }

func (e usageError) Error() string { return e.msg }

func badUsage(format string, a ...any) error { return usageError{fmt.Sprintf(format, a...)} }

// run runs one command and returns the exit status: 0 done, 1 failed,
// 2 a command line it refuses (1 with --json, as LuCI expects).
func (c *cli) run(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(c.stderr, usage)
		return 2
	}
	asJSON := jsonRequested(args[1:])
	var err error
	switch cmd, rest := args[0], args[1:]; cmd {
	case "help", "-h", "--help":
		fmt.Fprint(c.stdout, usage)
		return 0
	case "version", "--version":
		fmt.Fprintln(c.stdout, "rollcall", version)
		return 0
	case "status":
		return c.status(rest)
	case "init":
		err = c.initGroup(rest)
	case "invite":
		err = c.invite(rest)
	case "join":
		err = c.join(rest)
	case "remove":
		err = c.remove(rest)
	case "rotate", "bind-telegram":
		err = c.simple(cmd, rest)
	case "set-token":
		err = c.setToken(rest)
	case "roles":
		err = c.roles(rest)
	case "admin":
		err = c.adminCmd(rest)
	case "notify":
		err = c.notify(rest)
	default:
		err = badUsage("unknown command; see rollcall help")
	}
	if err == nil {
		return 0
	}
	var ue usageError
	code := 1
	if errors.As(err, &ue) && !asJSON {
		code = 2
	}
	if asJSON {
		c.printJSON(reply{Error: err.Error()})
	} else {
		fmt.Fprintf(c.stderr, "rollcall: %s\n", err)
	}
	return code
}

// jsonRequested reports whether --json comes before any "--".
func jsonRequested(args []string) bool {
	for _, a := range args {
		if a == "--" {
			return false
		}
		if a == "--json" {
			return true
		}
	}
	return false
}

// cmdline is a parsed command line: options and words before "--", and
// the names after it.
type cmdline struct {
	json  bool
	opts  map[string]string
	words []string
	names []string
	sep   bool // "--" was given
}

// parse reads args with the options a command takes: flags (no value) and
// valued options; --json is always allowed. Anything else that starts with
// '-' before "--" is refused, so that no word can pass for an option.
func parse(args []string, flags, valued []string) (cmdline, error) {
	c := cmdline{opts: map[string]string{}}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			c.sep, c.names = true, args[i+1:]
			return c, nil
		case a == "--json":
			c.json = true
		case slices.Contains(flags, a):
			c.opts[a] = "1"
		case slices.Contains(valued, a):
			if _, dup := c.opts[a]; dup {
				return c, badUsage("%s given twice", a)
			}
			if i+1 >= len(args) || args[i+1] == "--" {
				return c, badUsage("%s needs a value", a)
			}
			i++
			c.opts[a] = args[i]
		case strings.HasPrefix(a, "-"):
			return c, badUsage("unknown option; see rollcall help")
		default:
			c.words = append(c.words, a)
		}
	}
	return c, nil
}

// noWords refuses words, and "--", on a command that takes neither.
func (c cmdline) noWords() error {
	if len(c.words) > 0 || c.sep {
		return badUsage("this command takes no arguments; see rollcall help")
	}
	return nil
}

// name returns the one router name after "--", checked with the roster's
// name rule.
func (c cmdline) name() (string, error) {
	switch {
	case !c.sep:
		return "", badUsage("the router name goes last, after --; see rollcall help")
	case len(c.names) != 1:
		return "", badUsage("exactly one router name goes after --")
	}
	if err := roster.ValidName(c.names[0]); err != nil {
		return "", badUsage("not a valid router name: %v", err)
	}
	return c.names[0], nil
}

// timeout is the time limit of a control command.
func timeout(cmd string) time.Duration {
	if cmd == "status" {
		return statusTimeout
	}
	return callTimeout
}

// callErr turns a failed control call into the sentence the CLI shows.
func callErr(err error) error {
	var ce *control.Error
	var op *net.OpError
	switch {
	case errors.As(err, &ce):
		return errors.New(ce.Msg)
	case errors.Is(err, context.DeadlineExceeded):
		return errors.New("rollcalld did not answer in time")
	case errors.Is(err, fs.ErrPermission):
		return errors.New("permission denied: run rollcall as root")
	case errors.As(err, &op) && op.Op == "dial":
		return errNotRunning
	}
	return fmt.Errorf("the control socket failed: %w", err)
}

var errNotRunning = errors.New("rollcalld is not running")

// admin sends one admin command and prints its reply.
func (c *cli) admin(asJSON bool, cmd string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout(cmd))
	defer cancel()
	out, err := c.call(ctx, cmd, args...)
	if err != nil {
		return callErr(err)
	}
	var r reply
	if json.Unmarshal(out, &r) != nil || !r.OK {
		return errors.New("rollcalld gave an answer this rollcall does not read")
	}
	r.Error, r.RecoveryCode = "", ""
	if asJSON {
		c.printJSON(r)
		return nil
	}
	fmt.Fprintln(c.stdout, r.Message)
	for _, code := range []string{r.JoinCode, r.BindCode} {
		if code != "" {
			fmt.Fprintln(c.stdout, code)
		}
	}
	return nil
}

func (c *cli) printJSON(v any) {
	b, _ := json.Marshal(v)
	fmt.Fprintf(c.stdout, "%s\n", b)
}

// simple runs a control command that takes no arguments.
func (c *cli) simple(ctlCmd string, args []string) error {
	p, err := parse(args, nil, nil)
	if err != nil {
		return err
	}
	if err := p.noWords(); err != nil {
		return err
	}
	return c.admin(p.json, ctlCmd)
}

// invite opens a join window. The address the join code names is given
// with --address, or alone after "--", the form of the LuCI ACL, where it
// is the only glob; either way it is checked here before rollcalld is asked.
func (c *cli) invite(args []string) error {
	p, err := parse(args, []string{"--sender"}, []string{"--address"})
	if err != nil {
		return err
	}
	if len(p.words) > 0 {
		return badUsage("rollcall invite [--json] [--sender] [--address <ip> | -- <ip>]")
	}
	addr, given := p.opts["--address"]
	if p.sep {
		if given || len(p.names) != 1 {
			return badUsage("give exactly one address: with --address, or alone after --")
		}
		addr, given = p.names[0], true
	}
	if given {
		a, err := bootstrapAddr(addr)
		if err != nil {
			return err
		}
		addr = a.String()
	}
	sender := "0"
	if p.opts["--sender"] != "" {
		sender = "1"
	}
	return c.admin(p.json, "invite", sender, addr)
}

// bootstrapAddr checks an address for a join code: one IP address, without
// a zone, that another router can reach, so not loopback, link-local,
// multicast, broadcast or unspecified. An IPv4-mapped IPv6 address is taken
// as its IPv4 address.
func bootstrapAddr(s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, badUsage("the address is not an IP address")
	}
	if a.Zone() != "" {
		return netip.Addr{}, badUsage("--address takes an IP address without a zone")
	}
	a = a.Unmap()
	if a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() || a.IsLinkLocalUnicast() || a == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return netip.Addr{}, badUsage("the address must be one another router can reach: not a loopback, link-local, multicast, broadcast or unspecified address")
	}
	return a, nil
}

func (c *cli) join(args []string) error {
	p, err := parse(args, nil, []string{"--name"})
	if err != nil {
		return err
	}
	if p.sep || len(p.words) == 0 {
		return badUsage("rollcall join [--json] [--name <router>] <join code>")
	}
	// A code typed with spaces between its groups arrives as several words.
	code, err := pairing.ParseCode(strings.Join(p.words, ""))
	if err != nil {
		return err
	}
	name, err := c.routerName(p.opts["--name"])
	if err != nil {
		return err
	}
	return c.admin(p.json, "join", code.String(), name)
}

// routerName is the name given, or else the hostname, checked with the
// roster's name rule. It is never folded to lower case or shortened.
func (c *cli) routerName(given string) (string, error) {
	if given != "" {
		if err := roster.ValidName(given); err != nil {
			return "", badUsage("not a valid router name: %v", err)
		}
		return given, nil
	}
	h, err := c.hostname()
	if err != nil || roster.ValidName(h) != nil {
		return "", badUsage("the hostname is not a valid router name (1 to 32 characters from a-z, 0-9 and '-'); give one with --name")
	}
	return h, nil
}

func (c *cli) remove(args []string) error {
	p, err := parse(args, nil, nil)
	if err != nil {
		return err
	}
	if len(p.words) > 0 {
		return badUsage("rollcall remove [--json] -- <router>")
	}
	name, err := p.name()
	if err != nil {
		return err
	}
	return c.admin(p.json, "remove", name)
}

func (c *cli) roles(args []string) error {
	p, err := parse(args, nil, nil)
	if err != nil {
		return err
	}
	if len(p.words) != 1 || !slices.Contains([]string{"sender", "primary", "backup", "none"}, p.words[0]) {
		return badUsage("rollcall roles [--json] sender|primary|backup|none -- <router>")
	}
	name, err := p.name()
	if err != nil {
		return err
	}
	return c.admin(p.json, "roles", p.words[0], name)
}

// setToken sends the bot token from the environment. It never takes the
// token from the command line, where the process list would show it.
func (c *cli) setToken(args []string) error {
	p, err := parse(args, nil, nil)
	if err != nil {
		return err
	}
	if len(p.words) > 0 || p.sep {
		return badUsage("set-token takes no arguments: the token is read from %s", tokenEnv)
	}
	token := strings.TrimSpace(c.getenv(tokenEnv))
	if token == "" {
		return fmt.Errorf("%s is not set", tokenEnv)
	}
	if !validToken(token) {
		return fmt.Errorf("%s does not hold a bot token", tokenEnv)
	}
	return c.admin(p.json, "set-token", token)
}

// validToken is the rule of a bot token: 1 to 128 characters from A-Z,
// a-z, 0-9, ':', '_' and '-'.
func validToken(t string) bool {
	if t == "" || len(t) > pairing.MaxTokenLen {
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

func (c *cli) adminCmd(args []string) error {
	if len(args) == 0 {
		return badUsage("rollcall admin takeover|confirm|recover [--json]")
	}
	switch sub, rest := args[0], args[1:]; sub {
	case "takeover", "confirm":
		return c.simple("admin-"+sub, rest)
	case "recover":
		return c.recover(rest)
	}
	return badUsage("rollcall admin takeover|confirm|recover [--json]")
}

// recover reads the recovery code from standard input, never from the
// command line, and sends its seed to rollcalld.
func (c *cli) recover(args []string) error {
	p, err := parse(args, nil, nil)
	if err != nil {
		return err
	}
	if len(p.words) > 0 || p.sep {
		return badUsage("admin recover reads the recovery code from standard input, not from the command line")
	}
	if f, ok := c.stdin.(*os.File); ok {
		if fi, err := f.Stat(); err == nil && fi.Mode()&os.ModeCharDevice != 0 {
			fmt.Fprint(c.stderr, "Recovery code: ")
		}
	}
	b, err := io.ReadAll(io.LimitReader(c.stdin, maxStdinCode+1))
	if err != nil {
		return fmt.Errorf("reading the recovery code: %w", err)
	}
	if len(b) > maxStdinCode {
		return errors.New("standard input holds more than a recovery code")
	}
	seed, err := parseRecoveryCode(string(b))
	clear(b)
	if err != nil {
		return err
	}
	defer clear(seed)
	return c.admin(p.json, "admin-recover", fmt.Sprintf("%x", seed))
}

func (c *cli) notify(args []string) error {
	p, err := parse(args, nil, nil)
	if err != nil {
		return err
	}
	w := p.words
	switch {
	case p.sep:
	case len(w) == 1 && (w[0] == "going-down" || w[0] == "clock-synced"):
		return c.admin(p.json, "notify", w...)
	case len(w) == 3 && w[0] == "iface":
		return c.admin(p.json, "notify", w...)
	case len(w) == 2 && w[0] == "uplink":
		return c.admin(p.json, "notify", w...)
	}
	return badUsage("rollcall notify going-down | clock-synced | iface <action> <interface> | uplink <interface>")
}
