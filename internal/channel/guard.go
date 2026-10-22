// Package channel holds the clients that send messages to Telegram and ntfy.
//
// Every request goes through a client from GuardedClient, and every error a
// client returns is free of its token: net/http puts the request URL into its
// errors, and the Telegram URL carries the token.
package channel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/deliver"
	"github.com/TAIPANBOX/rollcall/internal/redact"
)

const (
	// clientTimeout bounds one request from start to end.
	clientTimeout = 15 * time.Second
	// dialTimeout bounds one connection attempt and one TLS handshake.
	dialTimeout = 10 * time.Second
	// maxRedirects is how many redirects one request may follow.
	maxRedirects = 10
	// maxResponse bounds how much of an answer is read.
	maxResponse = 1 << 20
	// maxRetryAfterSeconds bounds a Retry-After value in seconds. The queue
	// caps the wait at deliver.MaxRetryAfter anyway.
	maxRetryAfterSeconds = int64(deliver.MaxRetryAfter / time.Second)
)

var (
	errHostNotAllowed  = errors.New("channel: host not allowed")
	errRedirectRefused = errors.New("channel: redirect refused")
	errTooLarge        = errors.New("channel: the answer is too large")
)

// GuardedClient returns the HTTP client the channels use. It dials only the
// hosts in allowedHosts, compared as the request names them, before DNS. It
// refuses a redirect to another host and a redirect from https to http. It
// verifies certificates as usual. It uses no proxy from the environment: a
// proxy would hide the host the dial guard is meant to see.
func GuardedClient(allowedHosts []string) *http.Client {
	allowed := make(map[string]bool, len(allowedHosts))
	for _, h := range allowedHosts {
		if h != "" {
			allowed[strings.ToLower(h)] = true
		}
	}
	permitted := func(host string) bool { return host != "" && allowed[strings.ToLower(host)] }
	dialer := &net.Dialer{Timeout: dialTimeout}
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				host = addr
			}
			if !permitted(host) {
				return nil, fmt.Errorf("%w: %s", errHostNotAllowed, host)
			}
			return dialer.DialContext(ctx, network, addr)
		},
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: dialTimeout,
		ForceAttemptHTTP2:   true,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   clientTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return errors.New("channel: stopped after too many redirects")
			}
			if !permitted(req.URL.Hostname()) {
				return fmt.Errorf("%w: %s", errRedirectRefused, req.URL.Hostname())
			}
			if req.URL.Scheme != "https" && via[0].URL.Scheme == "https" {
				return fmt.Errorf("%w: https to %s", errRedirectRefused, req.URL.Scheme)
			}
			return nil
		},
	}
}

// hostOf returns the host name of raw, without port, or "" if it does not parse.
func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// readBody reads an answer of at most maxResponse bytes.
func readBody(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxResponse+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxResponse {
		return nil, errTooLarge
	}
	return b, nil
}

// isTLS reports whether err is a certificate or TLS failure. Nothing was sent
// in clear when one happens, and the queue keeps the incident.
func isTLS(err error) bool {
	var cve *tls.CertificateVerificationError
	var ua x509.UnknownAuthorityError
	var he x509.HostnameError
	var cie x509.CertificateInvalidError
	var sre x509.SystemRootsError
	var rhe tls.RecordHeaderError
	var ae tls.AlertError
	return errors.As(err, &cve) || errors.As(err, &ua) || errors.As(err, &he) ||
		errors.As(err, &cie) || errors.As(err, &sre) || errors.As(err, &rhe) ||
		errors.As(err, &ae)
}

// keptSentinels are the errors a scrubbed error still matches with errors.Is:
// the ends of a context and the guard's refusals. Nothing else from the
// transport is kept, because its texts are not ours to vouch for.
var keptSentinels = []error{context.Canceled, context.DeadlineExceeded, errHostNotAllowed, errRedirectRefused}

// scrubbed is a transport failure with its text redacted.
type scrubbed struct {
	msg  string
	keep error
}

// Error returns the redacted text.
func (e *scrubbed) Error() string { return e.msg }

// Unwrap returns the kept sentinel, or nil.
func (e *scrubbed) Unwrap() error { return e.keep }

// transportError turns a failed request or read into the error a channel
// returns. A certificate or TLS failure becomes deliver.ErrTLS, with nothing
// of the transport kept. Any other failure keeps its cause's text with the
// request URL dropped and every secret redacted. op names the call.
func transportError(op string, err error, secrets ...string) error {
	if isTLS(err) {
		return fmt.Errorf("%s: %w", op, deliver.ErrTLS)
	}
	cause := err
	var ue *url.Error
	if errors.As(err, &ue) {
		cause = ue.Err
	}
	var keep error
	for _, s := range keptSentinels {
		if errors.Is(cause, s) {
			keep = s
			break
		}
	}
	return &scrubbed{
		msg:  op + ": request failed: " + redact.Redact(cause.Error(), secrets...),
		keep: keep,
	}
}

// statusError maps an answer's status to the package's errors: 403 is
// deliver.ErrBlocked, 429 a *deliver.RateLimitError with retryAfter, and any
// other status outside 2xx a plain error naming the code only. It returns nil
// for 2xx.
func statusError(op string, code int, retryAfter time.Duration) error {
	switch {
	case code >= 200 && code < 300:
		return nil
	case code == http.StatusForbidden:
		return fmt.Errorf("%s: %w", op, deliver.ErrBlocked)
	case code == http.StatusTooManyRequests:
		return fmt.Errorf("%s: %w", op, &deliver.RateLimitError{RetryAfter: retryAfter})
	default:
		return fmt.Errorf("%s: HTTP %d", op, code)
	}
}
