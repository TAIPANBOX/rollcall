package control

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/redact"
)

const canary = "CANARY-123:abc"

// briefCommands is the command list of the plan, written out here so a
// change to Commands is a visible change to this test.
var briefCommands = []string{
	"status", "notify", "invite", "join", "remove", "rotate", "set-token",
	"bind-telegram", "roles", "admin-takeover", "admin-confirm", "admin-recover",
}

func fixedCred(uid uint32, err error) credFunc {
	return func(*net.UnixConn) (uint32, error) { return uid, err }
}

type call struct {
	cmd  string
	args []string
	uid  uint32
}

// recorder is a handler that records every call and answers with out.
type recorder struct {
	mu    sync.Mutex
	calls []call
}

func (r *recorder) handler(out string, err error) Handler {
	return func(cmd string, args []string, uid uint32) ([]byte, error) {
		r.mu.Lock()
		r.calls = append(r.calls, call{cmd, slices.Clone(args), uid})
		r.mu.Unlock()
		if err != nil {
			return nil, err
		}
		return []byte(out), nil
	}
}

func (r *recorder) all() []call {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.calls)
}

type logBuf struct {
	mu    sync.Mutex
	lines []string
}

func (l *logBuf) logf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

func (l *logBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

// socketDir is a fresh private directory with a short path: a unix socket
// path is limited to about 104 bytes on darwin.
func socketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "rc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// start runs Serve on path until the returned stop is called; stop returns
// what Serve returned.
func start(t *testing.T, path string, h Handler, opts ...Option) (stop func() error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan struct{})
	done := make(chan error, 1)
	all := append([]Option{WithSecrets(func() []string { return nil }), WithLogf(t.Logf), withReady(func() { close(ready) })}, opts...)
	go func() { done <- Serve(ctx, path, h, all...) }()
	select {
	case <-ready:
	case err := <-done:
		cancel()
		t.Fatalf("Serve: %v", err)
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("Serve did not start")
	}
	var once sync.Once
	var result error
	return func() error {
		once.Do(func() {
			cancel()
			select {
			case result = <-done:
			case <-time.After(10 * time.Second):
				result = errors.New("Serve did not stop")
			}
		})
		return result
	}
}

// serve starts Serve on a fresh socket and stops it when the test ends.
func serve(t *testing.T, h Handler, opts ...Option) string {
	t.Helper()
	path := filepath.Join(socketDir(t), "rollcall.sock")
	stop := start(t, path, h, opts...)
	t.Cleanup(func() {
		if err := stop(); err != nil {
			t.Errorf("Serve returned %v", err)
		}
	})
	return path
}

func frame(body string) []byte {
	b := binary.BigEndian.AppendUint32(nil, uint32(len(body)))
	return append(b, body...)
}

// exchange sends raw bytes (closing the write side after them when
// closeWrite is set) and returns everything the server sent before it
// closed the connection.
func exchange(t *testing.T, path string, send []byte, closeWrite bool) []byte {
	t.Helper()
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if len(send) > 0 {
		_, _ = conn.Write(send) // a server that refuses early may close first
	}
	if closeWrite {
		_ = conn.(*net.UnixConn).CloseWrite()
	}
	data, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	return data
}

// decode reads one reply frame from raw server output.
func decode(t *testing.T, raw []byte) reply {
	t.Helper()
	rep, err := readReply(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("reply %q: %v", raw, err)
	}
	return rep
}

func wantRefusal(t *testing.T, err error, msg string) {
	t.Helper()
	var se *Error
	if !errors.As(err, &se) || se.Msg != msg {
		t.Fatalf("error %v; want the server's %q", err, msg)
	}
}

func TestCommands(t *testing.T) {
	got := Commands()
	want := slices.Clone(briefCommands)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("Commands() = %v; want %v", got, want)
	}
	got[0] = "changed"
	if Commands()[0] == "changed" {
		t.Fatal("Commands returns its own slice")
	}
	if MaxRequest != 64<<10 || ReadTimeout != 5*time.Second || SocketMode != 0o660 || SocketGroup != "rollcall" {
		t.Fatalf("limits changed: %d %s %o %q", MaxRequest, ReadTimeout, SocketMode, SocketGroup)
	}
}

func TestControlRejectsNonRoot(t *testing.T) {
	for _, uid := range []uint32{1, 1000, 65534, math.MaxUint32} {
		t.Run(fmt.Sprint(uid), func(t *testing.T) {
			rec := &recorder{}
			logs := &logBuf{}
			path := serve(t, rec.handler("ran", nil), withCred(fixedCred(uid, nil)), WithLogf(logs.logf))
			for _, cmd := range append(slices.Clone(briefCommands), "no-such-command", "") {
				out, err := Client(path).Call(cmd, "x")
				wantRefusal(t, err, MsgPermissionDenied)
				if out != nil {
					t.Errorf("uid %d %q: output %q with the refusal", uid, cmd, out)
				}
			}
			// The refusal does not wait for a request: a peer that sends
			// nothing is refused at once, not after the read deadline.
			began := time.Now()
			rep := decode(t, exchange(t, path, nil, false))
			if rep.OK || rep.Error != MsgPermissionDenied || rep.Out != "" {
				t.Errorf("silent uid %d peer: %+v; want %q", uid, rep, MsgPermissionDenied)
			}
			if took := time.Since(began); took > ReadTimeout/2 {
				t.Errorf("the refusal took %s; it should not wait for a request", took)
			}
			if calls := rec.all(); len(calls) != 0 {
				t.Fatalf("handler ran %d times for uid %d: %+v", len(calls), uid, calls)
			}
			if !strings.Contains(logs.String(), fmt.Sprintf("uid %d", uid)) {
				t.Errorf("refusal of uid %d not logged: %q", uid, logs)
			}
		})
	}
}

func TestControlRootRunsEveryCommand(t *testing.T) {
	rec := &recorder{}
	path := serve(t, rec.handler("ran", nil), withCred(fixedCred(0, nil)))
	for _, cmd := range briefCommands {
		out, err := Client(path).Call(cmd, "a", "")
		if err != nil || string(out) != "ran" {
			t.Fatalf("%s: %q, %v; want ran", cmd, out, err)
		}
	}
	calls := rec.all()
	if len(calls) != len(briefCommands) {
		t.Fatalf("handler ran %d times; want %d", len(calls), len(briefCommands))
	}
	for i, c := range calls {
		if c.cmd != briefCommands[i] || !slices.Equal(c.args, []string{"a", ""}) || c.uid != 0 {
			t.Errorf("call %d = %+v; want %s [a ''] uid 0", i, c, briefCommands[i])
		}
	}
}

// TestControlCredentialFailure: a lookup that fails is a refusal, even if
// it also says uid 0.
func TestControlCredentialFailure(t *testing.T) {
	rec := &recorder{}
	logs := &logBuf{}
	path := serve(t, rec.handler("ran", nil), withCred(fixedCred(0, errors.New("getsockopt failed"))), WithLogf(logs.logf))
	for _, cmd := range briefCommands {
		_, err := Client(path).Call(cmd)
		wantRefusal(t, err, MsgPermissionDenied)
	}
	if n := len(rec.all()); n != 0 {
		t.Fatalf("handler ran %d times without peer credentials", n)
	}
	if !strings.Contains(logs.String(), "getsockopt failed") {
		t.Errorf("credential failure not logged: %q", logs)
	}
}

func TestControlRefusesUnknownCommand(t *testing.T) {
	rec := &recorder{}
	path := serve(t, rec.handler("ran", nil), withCred(fixedCred(0, nil)))
	for _, cmd := range []string{"reboot", "", "STATUS", "status ", " status", "admin", "admin takeover", "set_token", "status\x00"} {
		out, err := Client(path).Call(cmd)
		wantRefusal(t, err, MsgUnknownCommand)
		if out != nil {
			t.Errorf("%q: output %q with the refusal", cmd, out)
		}
	}
	if n := len(rec.all()); n != 0 {
		t.Fatalf("handler ran %d times for unknown commands", n)
	}
}

func TestStatusRedacted(t *testing.T) {
	// quoted is a secret that JSON writes differently from its raw form.
	quoted := `CANARY-"q"\x<y>`
	h := func(cmd string, args []string, uid uint32) ([]byte, error) {
		switch cmd {
		case "status":
			js, err := json.Marshal(map[string]string{"token": canary, "other": quoted})
			if err != nil {
				return nil, err
			}
			var plain bytes.Buffer
			enc := json.NewEncoder(&plain)
			enc.SetEscapeHTML(false)
			if err := enc.Encode(map[string]string{"other": quoted}); err != nil {
				return nil, err
			}
			return []byte("token " + canary + " " + quoted + "\n" + string(js) + "\n" + plain.String()), nil
		case "set-token":
			return nil, fmt.Errorf("token %s refused", canary)
		case "rotate":
			panic("rotate failed with " + canary)
		}
		return []byte("ok"), nil
	}
	logs := &logBuf{}
	path := serve(t, h, withCred(fixedCred(0, nil)), WithLogf(logs.logf),
		WithSecrets(func() []string { return []string{"", canary, quoted} }))

	raw := exchange(t, path, frame(`{"cmd":"status","args":[]}`), false)
	if bytes.Contains(raw, []byte(canary)) || bytes.Contains(raw, []byte("CANARY")) {
		t.Fatalf("the canary reached the wire: %q", raw)
	}
	rep := decode(t, raw)
	if !rep.OK || strings.Count(rep.Out, redact.Marker) != 5 {
		t.Fatalf("status reply %+v; want ok and five %s markers", rep, redact.Marker)
	}

	out, err := Client(path).Call("status")
	if err != nil || bytes.Contains(out, []byte("CANARY")) {
		t.Fatalf("Call(status) = %q, %v; want output without the canary", out, err)
	}

	_, err = Client(path).Call("set-token", "x")
	var se *Error
	if !errors.As(err, &se) || strings.Contains(se.Msg, "CANARY") || !strings.Contains(se.Msg, redact.Marker) {
		t.Fatalf("set-token error %v; want the canary redacted", err)
	}

	_, err = Client(path).Call("rotate")
	wantRefusal(t, err, MsgInternal)
	if out, err := Client(path).Call("notify"); err != nil || string(out) != "ok" {
		t.Fatalf("after a handler panic: %q, %v; want the server still serving", out, err)
	}
	if l := logs.String(); strings.Contains(l, "CANARY") || !strings.Contains(l, "panic") {
		t.Fatalf("log after the panic: %q; want the panic logged without the canary", l)
	}
}

func TestControlRequestLimits(t *testing.T) {
	rec := &recorder{}
	path := serve(t, rec.handler("ran", nil), withCred(fixedCred(0, nil)))

	exact := `{"cmd":"status","args":[]}`
	exact += strings.Repeat(" ", MaxRequest-len(exact))
	cases := []struct {
		name       string
		send       []byte
		closeWrite bool
		ok         bool
		msg        string
	}{
		{"exactly the limit", frame(exact), false, true, ""},
		{"one byte over the limit", binary.BigEndian.AppendUint32(nil, MaxRequest+1), false, false, MsgTooLarge},
		{"largest length", binary.BigEndian.AppendUint32(nil, math.MaxUint32), false, false, MsgTooLarge},
		{"empty body", frame(""), false, false, MsgBadRequest},
		{"not JSON", frame("status"), false, false, MsgBadRequest},
		{"unknown field", frame(`{"cmd":"status","args":[],"uid":0}`), false, false, MsgBadRequest},
		{"two objects", frame(`{"cmd":"status"}{"cmd":"remove"}`), false, false, MsgBadRequest},
		{"args not a list", frame(`{"cmd":"status","args":"x"}`), false, false, MsgBadRequest},
		{"cmd not a string", frame(`{"cmd":1}`), false, false, MsgBadRequest},
		{"truncated body", append(binary.BigEndian.AppendUint32(nil, 100), `{"cmd":"st`...), true, false, MsgBadRequest},
		{"truncated header", []byte{0, 0}, true, false, MsgBadRequest},
		{"nothing at all", nil, true, false, MsgBadRequest},
		{"null", frame("null"), false, false, MsgUnknownCommand},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep := decode(t, exchange(t, path, tc.send, tc.closeWrite))
			if rep.OK != tc.ok || rep.Error != tc.msg {
				t.Fatalf("reply %+v; want ok=%v error %q", rep, tc.ok, tc.msg)
			}
		})
	}
	if n := len(rec.all()); n != 1 {
		t.Fatalf("handler ran %d times; want once, for the request at the limit", n)
	}
}

func TestControlReadDeadline(t *testing.T) {
	rec := &recorder{}
	path := serve(t, rec.handler("ran", nil), withCred(fixedCred(0, nil)), withReadTimeout(150*time.Millisecond))
	for name, send := range map[string][]byte{
		"nothing":     nil,
		"header only": binary.BigEndian.AppendUint32(nil, 20),
		"half a body": append(binary.BigEndian.AppendUint32(nil, 20), `{"cmd"`...),
	} {
		began := time.Now()
		rep := decode(t, exchange(t, path, send, false))
		if took := time.Since(began); took > 3*time.Second {
			t.Errorf("%s: the server held the connection for %s", name, took)
		}
		if rep.OK || rep.Error != MsgBadRequest {
			t.Errorf("%s: reply %+v; want %q", name, rep, MsgBadRequest)
		}
	}
	if n := len(rec.all()); n != 0 {
		t.Fatalf("handler ran %d times for requests that never arrived", n)
	}
}

func TestControlConnectionLimit(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	h := func(cmd string, args []string, uid uint32) ([]byte, error) {
		if cmd == "join" {
			close(entered)
			<-release
		}
		return []byte(cmd), nil
	}
	path := serve(t, h, withCred(fixedCred(0, nil)), withMaxConns(1))

	first := make(chan error, 1)
	go func() {
		_, err := Client(path).Call("join")
		first <- err
	}()
	<-entered

	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write(frame(`{"cmd":"status","args":[]}`)); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if n, err := conn.Read(make([]byte, 1)); n != 0 || err == nil {
		t.Fatalf("a second connection was served while the only slot was taken (%d bytes, %v)", n, err)
	}

	close(release)
	if err := <-first; err != nil {
		t.Fatalf("first call: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	data, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("second connection after the slot freed: %v", err)
	}
	if rep := decode(t, data); !rep.OK || rep.Out != "status" {
		t.Fatalf("second connection reply %+v", rep)
	}
}

func TestServeSocketFile(t *testing.T) {
	path := filepath.Join(socketDir(t), "rollcall.sock")
	logs := &logBuf{}
	stop := start(t, path, (&recorder{}).handler("", nil), WithLogf(logs.logf), WithInfof(logs.logf))
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("socket file: %v", err)
	}
	if fi.Mode().Type() != os.ModeSocket || fi.Mode().Perm() != SocketMode {
		t.Fatalf("socket file mode %v; want a socket with %o", fi.Mode(), SocketMode)
	}
	if os.Geteuid() != 0 && !strings.Contains(logs.String(), "not running as root") {
		t.Errorf("skipped chown not logged: %q", logs)
	}
	if err := stop(); err != nil {
		t.Fatalf("Serve returned %v after the context ended", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket file left behind after Serve returned: %v", err)
	}
}

func TestServeExistingPath(t *testing.T) {
	h := (&recorder{}).handler("ran", nil)

	t.Run("regular file", func(t *testing.T) {
		path := filepath.Join(socketDir(t), "rollcall.sock")
		if err := os.WriteFile(path, []byte("keep me"), 0o600); err != nil {
			t.Fatal(err)
		}
		err := Serve(context.Background(), path, h, WithSecrets(func() []string { return nil }))
		if err == nil || !strings.Contains(err.Error(), "not a socket") {
			t.Fatalf("Serve over a regular file: %v", err)
		}
		if b, _ := os.ReadFile(path); string(b) != "keep me" {
			t.Fatalf("the regular file changed: %q", b)
		}
	})

	t.Run("symlink", func(t *testing.T) {
		dir := socketDir(t)
		target := filepath.Join(dir, "target")
		if err := os.WriteFile(target, []byte("keep me"), 0o600); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "rollcall.sock")
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		err := Serve(context.Background(), path, h, WithSecrets(func() []string { return nil }))
		if err == nil || !strings.Contains(err.Error(), "not a socket") {
			t.Fatalf("Serve over a symlink: %v", err)
		}
		if fi, err := os.Lstat(path); err != nil || fi.Mode().Type() != os.ModeSymlink {
			t.Fatalf("the symlink changed: %v %v", fi, err)
		}
		if fi, _ := os.Stat(target); fi.Mode().Perm() != 0o600 {
			t.Fatalf("the symlink's target changed mode: %v", fi.Mode())
		}
	})

	t.Run("live socket", func(t *testing.T) {
		path := serve(t, h, withCred(fixedCred(0, nil)))
		err := Serve(context.Background(), path, h, WithSecrets(func() []string { return nil }))
		if err == nil || !strings.Contains(err.Error(), "in use") {
			t.Fatalf("second Serve on a live socket: %v", err)
		}
		if out, err := Client(path).Call("status"); err != nil || string(out) != "ran" {
			t.Fatalf("the first server after the second tried: %q, %v", out, err)
		}
	})

	t.Run("stale socket", func(t *testing.T) {
		path := filepath.Join(socketDir(t), "rollcall.sock")
		ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
		if err != nil {
			t.Fatal(err)
		}
		ln.SetUnlinkOnClose(false)
		ln.Close()
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("stale socket not left: %v", err)
		}
		stop := start(t, path, h, withCred(fixedCred(0, nil)))
		defer stop()
		if out, err := Client(path).Call("status"); err != nil || string(out) != "ran" {
			t.Fatalf("Serve over a stale socket: %q, %v", out, err)
		}
	})
}

func TestServeRefusesOpenDirectory(t *testing.T) {
	h := (&recorder{}).handler("ran", nil)
	for _, mode := range []os.FileMode{0o777, 0o770, 0o722} {
		dir := socketDir(t)
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "rollcall.sock")
		err := Serve(context.Background(), path, h, WithSecrets(func() []string { return nil }))
		if err == nil || !strings.Contains(err.Error(), "writable") {
			t.Fatalf("directory %o: Serve %v; want a refusal", mode, err)
		}
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("directory %o: a socket file was created", mode)
		}
	}
	// A sticky directory (like /tmp) keeps others from replacing the socket.
	dir := socketDir(t)
	if err := os.Chmod(dir, 0o777|os.ModeSticky); err != nil {
		t.Fatal(err)
	}
	stop := start(t, filepath.Join(dir, "rollcall.sock"), h)
	if err := stop(); err != nil {
		t.Fatalf("sticky directory: %v", err)
	}
}

func TestServeArguments(t *testing.T) {
	dir := socketDir(t)
	path := filepath.Join(dir, "rollcall.sock")
	h := (&recorder{}).handler("", nil)
	for name, err := range map[string]error{
		"nil handler": Serve(context.Background(), path, nil, WithSecrets(func() []string { return nil })),
		"no secrets":  Serve(context.Background(), path, h),
		"nil secrets": Serve(context.Background(), path, h, WithSecrets(nil)),
		"empty path":  Serve(context.Background(), "", h, WithSecrets(func() []string { return nil })),
	} {
		if err == nil {
			t.Errorf("%s: Serve accepted", name)
		}
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a refused Serve created the socket file")
	}
}

func TestPeerCredentialsOnThisPlatform(t *testing.T) {
	path := filepath.Join(socketDir(t), "s")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		if c, err := net.Dial("unix", path); err == nil {
			defer c.Close()
			_, _ = io.Copy(io.Discard, c)
		}
	}()
	conn, err := ln.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	uid, err := peerCred(conn)
	if runtime.GOOS == "linux" {
		if err != nil || uid != uint32(os.Getuid()) {
			t.Fatalf("peerCred = %d, %v; want this process's uid %d", uid, err, os.Getuid())
		}
		return
	}
	if err == nil || uid != noUID {
		t.Fatalf("peerCred on %s = %d, %v; want an error and noUID", runtime.GOOS, uid, err)
	}
}

// TestServeDefaultCredentials runs the real credential lookup: only root on
// Linux may run a command; everyone else, and every other platform, is
// refused.
func TestServeDefaultCredentials(t *testing.T) {
	rec := &recorder{}
	path := serve(t, rec.handler("ran", nil))
	out, err := Client(path).Call("status")
	if runtime.GOOS == "linux" && os.Getuid() == 0 {
		if err != nil || string(out) != "ran" {
			t.Fatalf("root on linux: %q, %v", out, err)
		}
		return
	}
	wantRefusal(t, err, MsgPermissionDenied)
	if n := len(rec.all()); n != 0 {
		t.Fatalf("handler ran %d times for uid %d on %s", n, os.Getuid(), runtime.GOOS)
	}
}

func TestServeReplyLimit(t *testing.T) {
	// {"ok":true,"out":"","error":""} is 31 bytes of JSON around the output.
	const overhead = 31
	sizes := map[string]int{"cmd": 0}
	h := func(cmd string, args []string, uid uint32) ([]byte, error) {
		return bytes.Repeat([]byte("a"), sizes[args[0]]), nil
	}
	sizes["fits"] = MaxReply - overhead
	sizes["over"] = MaxReply - overhead + 1
	path := serve(t, h, withCred(fixedCred(0, nil)))
	out, err := Client(path).Call("status", "fits")
	if err != nil || len(out) != MaxReply-overhead {
		t.Fatalf("reply of exactly MaxReply bytes: %d bytes, %v", len(out), err)
	}
	_, err = Client(path).Call("status", "over")
	wantRefusal(t, err, MsgReplyTooLarge)
}

func TestServeSocketPathProblems(t *testing.T) {
	h := (&recorder{}).handler("", nil)
	secrets := WithSecrets(func() []string { return nil })
	dir := socketDir(t)
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct{ path, msg string }{
		"missing directory":   {filepath.Join(dir, "none", "s"), "no such file"},
		"not a directory":     {filepath.Join(file, "s"), "not a directory"},
		"path over the limit": {filepath.Join(dir, strings.Repeat("a", 120)), "invalid argument"},
	} {
		err := Serve(context.Background(), tc.path, h, secrets)
		if err == nil || !strings.Contains(err.Error(), tc.msg) {
			t.Errorf("%s: Serve %v; want an error mentioning %q", name, err, tc.msg)
		}
	}

	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	closed := socketDir(t)
	if err := os.Chmod(closed, 0o600); err != nil { // no search permission
		t.Fatal(err)
	}
	defer os.Chmod(closed, 0o700)
	if err := Serve(context.Background(), filepath.Join(closed, "s"), h, secrets); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("directory without search permission: Serve %v", err)
	}

	readOnly := socketDir(t)
	stale := filepath.Join(readOnly, "s")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: stale, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	ln.SetUnlinkOnClose(false)
	ln.Close()
	if err := os.Chmod(readOnly, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(readOnly, 0o700)
	if err := Serve(context.Background(), stale, h, secrets); err == nil || !strings.Contains(err.Error(), "stale socket") {
		t.Errorf("stale socket in a read-only directory: Serve %v", err)
	}
}

// TestServeChecksTheFileAfterBind: if the socket file is swapped between
// bind and chmod, Serve stops and the chmod never reaches what replaced it.
func TestServeChecksTheFileAfterBind(t *testing.T) {
	h := (&recorder{}).handler("", nil)
	secrets := WithSecrets(func() []string { return nil })

	dir := socketDir(t)
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	swap := withAfterBind(func(path string) {
		if err := os.Remove(path); err != nil {
			t.Error(err)
		}
		if err := os.Symlink(target, path); err != nil {
			t.Error(err)
		}
	})
	err := Serve(context.Background(), filepath.Join(dir, "s"), h, secrets, swap)
	if err == nil || !strings.Contains(err.Error(), "replaced after bind") {
		t.Fatalf("socket swapped for a link: Serve %v", err)
	}
	if fi, err := os.Stat(target); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("the link's target changed: %v %v", fi.Mode(), err)
	}

	gone := withAfterBind(func(path string) { _ = os.Remove(path) })
	if err := Serve(context.Background(), filepath.Join(socketDir(t), "s"), h, secrets, gone); err == nil {
		t.Fatal("socket file removed after bind: Serve went on")
	}
}

// TestServeStopsWhileFull: the context ends while every slot is taken; Serve
// returns once the connection in progress finishes.
func TestServeStopsWhileFull(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	h := func(cmd string, args []string, uid uint32) ([]byte, error) {
		close(entered)
		<-release
		return nil, nil
	}
	path := filepath.Join(socketDir(t), "s")
	stop := start(t, path, h, withCred(fixedCred(0, nil)), withMaxConns(1))
	done := make(chan error, 1)
	go func() {
		_, err := Client(path).Call("join")
		done <- err
	}()
	<-entered
	stopped := make(chan error, 1)
	go func() { stopped <- stop() }()
	select {
	case err := <-stopped:
		t.Fatalf("Serve returned %v while a handler still ran", err)
	case <-time.After(200 * time.Millisecond):
	}
	close(release)
	if err := <-stopped; err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("the call in progress: %v", err)
	}
}

// TestServeOwnershipAsRoot runs the root branch with a fake group database
// and chown: root gives the socket to root:rollcall; without the group it
// stays root:root; a broken group entry or a failed chown stops Serve.
func TestServeOwnershipAsRoot(t *testing.T) {
	h := (&recorder{}).handler("", nil)
	type chown struct {
		path     string
		uid, gid int
	}
	var got []chown
	record := func(path string, uid, gid int) error {
		got = append(got, chown{path, uid, gid})
		return nil
	}
	group := func(gid string) func(string) (*user.Group, error) {
		return func(name string) (*user.Group, error) {
			if name != SocketGroup {
				return nil, user.UnknownGroupError(name)
			}
			return &user.Group{Gid: gid, Name: name}, nil
		}
	}

	path := filepath.Join(socketDir(t), "s")
	stop := start(t, path, h, withRoot(group("1234"), record))
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != (chown{path, 0, 1234}) {
		t.Fatalf("chown calls %+v; want one to root:1234 on %s", got, path)
	}

	got = nil
	logs := &logBuf{}
	noGroup := func(name string) (*user.Group, error) { return nil, user.UnknownGroupError(name) }
	stop = start(t, filepath.Join(socketDir(t), "s"), h, withRoot(noGroup, record), WithLogf(logs.logf))
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 || !strings.Contains(logs.String(), "stays root:root") {
		t.Fatalf("without the group: chown %+v, log %q; want no chown and a log line", got, logs)
	}

	secrets := WithSecrets(func() []string { return nil })
	err := Serve(context.Background(), filepath.Join(socketDir(t), "s"), h, secrets, withRoot(group("x1"), record))
	if err == nil || !strings.Contains(err.Error(), "gid") {
		t.Fatalf("group with a bad gid: Serve %v", err)
	}
	fail := func(string, int, int) error { return errors.New("chown refused") }
	err = Serve(context.Background(), filepath.Join(socketDir(t), "s"), h, secrets, withRoot(group("1234"), fail))
	if err == nil || !strings.Contains(err.Error(), "chown refused") {
		t.Fatalf("failed chown: Serve %v", err)
	}
}
