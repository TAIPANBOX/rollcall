// Package control serves rollcall's local control socket, used by the CLI
// and, through it, by LuCI. Only root may administer rollcall (security
// threat A6): every command needs peer uid 0, read from the kernel
// (SO_PEERCRED), never from the request.
//
// One request per connection. The client sends a 4-byte big-endian length
// and that many bytes of JSON {"cmd": "...", "args": [...]}, at most
// MaxRequest bytes; the server answers the same way with
// {"ok": bool, "out": "...", "error": "..."} and closes. The order of checks
// is fixed: peer credentials (before any byte of the request is read), the
// request frame, the command name, and only then the handler. Every reply
// passes through redaction of the current secrets before it is written.
package control

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/redact"
)

// Limits and the socket's ownership.
const (
	MaxRequest   = 64 << 10 // bytes of request JSON
	MaxReply     = 1 << 20  // bytes of reply JSON
	ReadTimeout  = 5 * time.Second
	WriteTimeout = 5 * time.Second
	SocketMode   = 0o660
	SocketGroup  = "rollcall"
	maxConns     = 8
)

// Fixed reasons the server gives for a refusal.
const (
	MsgPermissionDenied = "permission denied"
	MsgUnknownCommand   = "unknown command"
	MsgBadRequest       = "bad request"
	MsgTooLarge         = "request too large"
	MsgInternal         = "internal error"
	MsgReplyTooLarge    = "reply too large"
	MsgFailed           = "command failed" // a handler error without text
)

var (
	errBadRequest = errors.New(MsgBadRequest)
	errTooLarge   = errors.New(MsgTooLarge)
)

// commands is the closed set of commands; anything else is refused before
// the handler runs.
var commands = []string{
	"status", "notify", "invite", "join", "remove", "rotate", "set-token",
	"bind-telegram", "roles", "admin-takeover", "admin-confirm", "admin-recover",
}

// Commands returns the commands the server accepts, sorted.
func Commands() []string {
	c := slices.Clone(commands)
	slices.Sort(c)
	return c
}

// Handler runs one command for a caller already checked to be uid 0, and
// returns its output. The output and the error text are redacted by the
// server before they are written.
type Handler func(cmd string, args []string, uid uint32) ([]byte, error)

// credFunc returns the peer's uid as the kernel reports it. On error the
// uid is meaningless; the server refuses.
type credFunc func(*net.UnixConn) (uint32, error)

// noUID is what a failed credential lookup returns, so a caller that
// forgets the error still does not see root.
const noUID = ^uint32(0)

// Option configures Serve.
type Option func(*server)

// WithSecrets names the source of the secrets to redact from every reply
// and from a logged panic. It is called for each reply, so a rotated token
// is covered at once. Serve refuses to start without it.
func WithSecrets(f func() []string) Option { return func(s *server) { s.secrets = f } }

// WithLogf sets the logger; the default is log.Printf. Logs carry command
// names and uids, never arguments or output.
func WithLogf(f func(format string, args ...any)) Option { return func(s *server) { s.logf = f } }

// Options for tests: a fake credential lookup, a hook once the socket
// listens, a hook between bind and chmod, a shorter read deadline, fewer
// connection slots.
func withCred(f credFunc) Option             { return func(s *server) { s.cred = f } }
func withReady(f func()) Option              { return func(s *server) { s.ready = f } }
func withAfterBind(f func(string)) Option    { return func(s *server) { s.afterBind = f } }
func withReadTimeout(d time.Duration) Option { return func(s *server) { s.readTimeout = d } }
func withMaxConns(n int) Option              { return func(s *server) { s.maxConns = n } }

// withRoot makes secure act as root with the given group lookup and chown.
func withRoot(lookup func(string) (*user.Group, error), lchown func(string, int, int) error) Option {
	return func(s *server) {
		s.geteuid = func() int { return 0 }
		s.lookupGroup, s.lchown = lookup, lchown
	}
}

type server struct {
	h           Handler
	secrets     func() []string
	logf        func(string, ...any)
	cred        credFunc
	ready       func()
	afterBind   func(path string)
	geteuid     func() int
	lookupGroup func(name string) (*user.Group, error)
	lchown      func(path string, uid, gid int) error
	readTimeout time.Duration
	maxConns    int
}

type request struct {
	Cmd  string   `json:"cmd"`
	Args []string `json:"args"`
}

type reply struct {
	OK    bool   `json:"ok"`
	Out   string `json:"out"`
	Error string `json:"error"`
}

// Serve listens on the unix socket at path and serves requests until ctx
// ends; then it closes the listener, removes the socket file, waits for the
// connections in progress and returns nil.
//
// The socket gets mode 0660; when the daemon runs as root it is also given
// to root:rollcall (a missing rollcall group leaves it root:root, which is
// stricter). Serve refuses a path that exists and is not a socket, a socket
// another server still answers on, and a directory others may write to
// without the sticky bit (they could swap the socket for a link before the
// chmod).
func Serve(ctx context.Context, path string, h Handler, opts ...Option) error {
	s := &server{
		h:           h,
		logf:        log.Printf,
		cred:        peerCred,
		geteuid:     os.Geteuid,
		lookupGroup: user.LookupGroup,
		lchown:      os.Lchown,
		readTimeout: ReadTimeout,
		maxConns:    maxConns,
	}
	for _, o := range opts {
		o(s)
	}
	switch {
	case h == nil:
		return errors.New("control: no handler")
	case s.secrets == nil:
		return errors.New("control: no secrets source (WithSecrets)")
	case path == "":
		return errors.New("control: no socket path")
	}
	ln, err := s.listen(path)
	if err != nil {
		return err
	}
	if s.ready != nil {
		s.ready()
	}
	return s.serve(ctx, ln)
}

func (s *server) listen(path string) (*net.UnixListener, error) {
	dir, err := os.Stat(filepath.Dir(path))
	if err != nil {
		return nil, fmt.Errorf("control: %w", err)
	}
	if !dir.IsDir() {
		return nil, fmt.Errorf("control: %s is not a directory", filepath.Dir(path))
	}
	if dir.Mode().Perm()&0o022 != 0 && dir.Mode()&fs.ModeSticky == 0 {
		return nil, fmt.Errorf("control: directory %s is writable by others and not sticky", filepath.Dir(path))
	}
	if err := clearStale(path); err != nil {
		return nil, err
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("control: %w", err)
	}
	if s.afterBind != nil {
		s.afterBind(path)
	}
	if err := s.secure(path); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

// clearStale removes a socket file left by a server that is gone.
func clearStale(path string) error {
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("control: %w", err)
	}
	if fi.Mode().Type() != fs.ModeSocket {
		return fmt.Errorf("control: %s exists and is not a socket", path)
	}
	if c, err := net.DialTimeout("unix", path, time.Second); err == nil {
		c.Close()
		return fmt.Errorf("control: %s is in use by another server", path)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("control: remove stale socket: %w", err)
	}
	return nil
}

// secure sets the socket file's mode and, as root, its owner.
func (s *server) secure(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("control: %w", err)
	}
	if fi.Mode().Type() != fs.ModeSocket {
		return fmt.Errorf("control: %s was replaced after bind", path)
	}
	if err := os.Chmod(path, SocketMode); err != nil {
		return fmt.Errorf("control: %w", err)
	}
	if euid := s.geteuid(); euid != 0 {
		s.logf("control: not running as root (euid %d); socket %s keeps its owner", euid, path)
		return nil
	}
	g, err := s.lookupGroup(SocketGroup)
	if err != nil {
		s.logf("control: group %s not found; socket %s stays root:root", SocketGroup, path)
		return nil
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return fmt.Errorf("control: group %s has gid %q", SocketGroup, g.Gid)
	}
	if err := s.lchown(path, 0, gid); err != nil {
		return fmt.Errorf("control: %w", err)
	}
	return nil
}

func (s *server) serve(ctx context.Context, ln *net.UnixListener) error {
	var wg sync.WaitGroup
	defer wg.Wait()
	stop := context.AfterFunc(ctx, func() { ln.Close() })
	defer stop()
	defer ln.Close()

	slots := make(chan struct{}, s.maxConns)
	for {
		select {
		case slots <- struct{}{}:
		case <-ctx.Done():
			return nil
		}
		c, err := ln.AcceptUnix()
		if err != nil {
			<-slots
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("control: accept: %w", err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-slots }()
			s.handle(c)
		}()
	}
}

// handle answers one connection. The order of the checks is the security
// property of this package: credentials, frame, command, handler.
func (s *server) handle(c *net.UnixConn) {
	defer c.Close()
	defer func() {
		if r := recover(); r != nil {
			s.logf("control: panic: %s", s.scrub(fmt.Sprint(r)))
			s.refuse(c, MsgInternal)
		}
	}()
	_ = c.SetReadDeadline(time.Now().Add(s.readTimeout))

	uid, err := s.cred(c)
	if err != nil {
		s.logf("control: peer credentials unavailable: %v", err)
		s.refuse(c, MsgPermissionDenied)
		return
	}
	if uid != 0 {
		s.logf("control: uid %d refused", uid)
		s.refuse(c, MsgPermissionDenied)
		return
	}

	req, err := readRequest(c)
	if err != nil {
		s.refuse(c, err.Error())
		return
	}
	if !slices.Contains(commands, req.Cmd) {
		s.logf("control: unknown command refused")
		s.refuse(c, MsgUnknownCommand)
		return
	}
	if req.Cmd != "status" {
		s.logf("control: uid %d runs %s", uid, req.Cmd)
	}
	out, err := s.h(req.Cmd, req.Args, uid)
	if err != nil {
		msg := s.scrub(err.Error())
		if msg == "" {
			msg = MsgFailed
		}
		s.write(c, reply{Error: msg})
		return
	}
	s.write(c, reply{OK: true, Out: s.scrub(string(out))})
}

// scrub removes every current secret from text.
func (s *server) scrub(text string) string { return redact.Redact(text, s.secretForms()...) }

// refuse sends a refusal with a fixed reason.
func (s *server) refuse(c *net.UnixConn, msg string) { s.write(c, reply{Error: msg}) }

// write sends one reply frame. A reply over MaxReply becomes a refusal.
func (s *server) write(c *net.UnixConn, rep reply) {
	b, _ := json.Marshal(rep) // strings and a bool always encode
	if len(b) > MaxReply {
		s.logf("control: reply of %d bytes over the limit", len(b))
		b, _ = json.Marshal(reply{Error: MsgReplyTooLarge})
	}
	_ = c.SetWriteDeadline(time.Now().Add(WriteTimeout))
	if _, err := c.Write(binary.BigEndian.AppendUint32(make([]byte, 0, 4+len(b)), uint32(len(b)))); err != nil {
		return
	}
	_, _ = c.Write(b)
}

// secretForms is every secret as it may appear in a reply: raw, and as JSON
// writes it inside a string, with and without HTML escaping, so a handler
// that prints JSON is redacted too.
func (s *server) secretForms() []string {
	var out []string
	for _, x := range s.secrets() {
		if x == "" {
			continue
		}
		out = append(out, x)
		for _, html := range []bool{true, false} {
			var b bytes.Buffer
			enc := json.NewEncoder(&b)
			enc.SetEscapeHTML(html)
			_ = enc.Encode(x) // a string always encodes
			e := strings.TrimSuffix(b.String(), "\n")
			if e = e[1 : len(e)-1]; e != x {
				out = append(out, e)
			}
		}
	}
	return out
}

// readRequest reads one request frame. It refuses with errTooLarge or
// errBadRequest only.
func readRequest(r io.Reader) (request, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return request{}, errBadRequest
	}
	n := binary.BigEndian.Uint32(hdr[:])
	switch {
	case n == 0:
		return request{}, errBadRequest
	case n > MaxRequest:
		return request{}, errTooLarge
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return request{}, errBadRequest
	}
	var req request
	if err := decodeOne(body, &req); err != nil {
		return request{}, errBadRequest
	}
	return req, nil
}

// decodeOne decodes exactly one JSON value without unknown fields.
func decodeOne(body []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("data after the JSON value")
	}
	return nil
}
