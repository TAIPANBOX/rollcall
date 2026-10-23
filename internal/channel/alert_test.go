package channel

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/deliver"
)

// quietTLS starts an httptest server over TLS with cfg, its handshake errors
// not logged.
func quietTLS(t *testing.T, cfg *tls.Config) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, okAnswer)
	}))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.TLS = cfg
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// alertServer is a real crypto/tls server that ends every handshake with a
// fatal alert before it shows a certificate, as an interceptor that refuses
// the connection does: it offers only a cipher suite that Go clients no
// longer offer, so it answers the ClientHello with handshake_failure.
func alertServer(t *testing.T) *httptest.Server {
	t.Helper()
	return quietTLS(t, &tls.Config{
		MaxVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA},
	})
}

// rawServer accepts TCP connections, reads the ClientHello and answers
// with reply, raw bytes, and returns its https URL.
func rawServer(t *testing.T, reply []byte) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				buf := make([]byte, 4096)
				_, _ = conn.Read(buf)
				_, _ = conn.Write(reply)
				_, _ = conn.Read(buf) // the client's alert, if any
			}()
		}
	}()
	return "https://" + ln.Addr().String()
}

// wantErrTLS fails the test unless err is deliver.ErrTLS with nothing of
// the transport in it.
func wantErrTLS(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, deliver.ErrTLS) {
		t.Fatalf("err = %v, want deliver.ErrTLS (\"cannot reach Telegram securely\")", err)
	}
	if strings.Contains(err.Error(), "request failed") || strings.Contains(err.Error(), "127.0.0.1") {
		t.Fatalf("err = %q, want nothing of the transport in it", err.Error())
	}
	noCanary(t, err)
}

// TestTelegramTLSAlertIsErrTLS: a TLS alert, the peer's or the one Go sends
// when the peer breaks the protocol, is a TLS failure like an untrusted
// certificate: nothing was sent in clear, and the status says the channel
// cannot be reached securely. crypto/tls reports an alert as a *net.OpError
// whose Err is its unexported alert type, not as tls.AlertError.
func TestTelegramTLSAlertIsErrTLS(t *testing.T) {
	t.Run("an alert in the handshake", func(t *testing.T) {
		srv := alertServer(t)
		wantErrTLS(t, NewTelegram(srv.URL, canary, 42, nil).Send(context.Background(), "x"))
	})
	t.Run("an alert after the handshake", func(t *testing.T) {
		// TLS 1.3: the client finishes its side of the handshake before
		// the server checks for a client certificate; the server's
		// certificate_required alert arrives on the first read.
		srv := quietTLS(t, &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAnyClientCert})
		wantErrTLS(t, NewTelegram(srv.URL, canary, 42, srv.Client()).Send(context.Background(), "x"))
	})
	t.Run("an alert the peer sends raw", func(t *testing.T) {
		// A fatal handshake_failure alert record, TLS 1.2 record version.
		url := rawServer(t, []byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28})
		wantErrTLS(t, NewTelegram(url, canary, 42, nil).Send(context.Background(), "x"))
	})
	t.Run("our alert on a malformed handshake", func(t *testing.T) {
		// A handshake record holding a message of an unknown type: Go
		// answers with unexpected_message and reports a "local error".
		url := rawServer(t, []byte{0x16, 0x03, 0x03, 0x00, 0x04, 0xfe, 0x00, 0x00, 0x00})
		wantErrTLS(t, NewTelegram(url, canary, 42, nil).Send(context.Background(), "x"))
	})
}

func TestNtfyTLSAlertIsErrTLS(t *testing.T) {
	srv := alertServer(t)
	n, err := NewNtfy(srv.URL+"/alerts", canary, false, nil)
	if err != nil {
		t.Fatalf("NewNtfy: %v", err)
	}
	wantErrTLS(t, n.Send(context.Background(), "x"))
	wantErrTLS(t, n.Ping(context.Background()))
}

// TestBindChatStopsOnTLSAlert: binding ends at once on a TLS alert, as on
// any TLS failure, instead of polling an interceptor to the end of the
// window.
func TestBindChatStopsOnTLSAlert(t *testing.T) {
	srv := alertServer(t)
	start := time.Now()
	_, err := fastBind(srv.URL, nil).BindChat(context.Background(), "741852", 3*time.Second)
	wantErrTLS(t, err)
	if took := time.Since(start); took > time.Second {
		t.Fatalf("binding kept polling for %v after a TLS alert; it must stop at once", took)
	}
}

// TestTLSAlertOnlyFromCryptoTLS: an error counts as a TLS alert only when
// it is crypto/tls's own: a *net.OpError with Op "remote error" or "local
// error" around an alert of crypto/tls, anywhere in the error's tree. The
// same Op around another error, or the alert under another Op, is not one.
func TestTLSAlertOnlyFromCryptoTLS(t *testing.T) {
	srv := alertServer(t)
	_, err := (&http.Client{Transport: &http.Transport{}}).Get(srv.URL)
	var op *net.OpError
	if !errors.As(err, &op) || op.Op != "remote error" {
		t.Fatalf("a handshake with the alert server: err = %v, want a *net.OpError \"remote error\"", err)
	}
	alert := op.Err
	other := errors.New("io failure")
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"the alert as crypto/tls returns it", err, true},
		{"a local alert", &net.OpError{Op: "local error", Err: alert}, true},
		{"wrapped", fmt.Errorf("telegram sendMessage: %w", &net.OpError{Op: "remote error", Err: alert}), true},
		{"in a join, after another error", errors.Join(&net.OpError{Op: "read", Err: other}, &net.OpError{Op: "remote error", Err: alert}), true},
		{"under an outer OpError", &net.OpError{Op: "read", Err: &net.OpError{Op: "remote error", Err: alert}}, true},
		{"a lookalike error", &net.OpError{Op: "remote error", Err: errors.New("tls: handshake failure")}, false},
		{"the alert under another Op", &net.OpError{Op: "read", Err: alert}, false},
		{"no Err", &net.OpError{Op: "remote error"}, false},
		{"another error", other, false},
		{"nil", nil, false},
	}
	for _, c := range cases {
		if got := isTLS(c.err); got != c.want {
			t.Errorf("%s: isTLS = %v, want %v", c.name, got, c.want)
		}
	}
}
