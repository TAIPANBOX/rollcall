package channel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/deliver"
	"github.com/TAIPANBOX/rollcall/internal/redact"
)

// rfc1918 are the IPv4 private ranges.
var rfc1918 = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
}

var _ deliver.Channel = (*Ntfy)(nil)

// errNtfyRefused reports an ntfy answer of 401 (the server does not accept
// the token) or 403 (the token may not publish to the topic). It is not
// deliver.ErrBlocked, which is a Telegram chat that blocked the bot; the
// queue shows it as a failed send with the code, and retries at its usual
// pace.
var errNtfyRefused = errors.New("the ntfy server refused the token, or its right to publish to the topic")

// Ntfy is a deliver.Channel that publishes plain text to one ntfy topic. Its
// token is sent as a bearer header and is never printed.
type Ntfy struct {
	topic  string // the topic URL that messages are posted to
	origin string // scheme and host, for the health check
	host   string // host and port, for String
	token  string
	hc     *http.Client
}

// NewNtfy returns a client that posts to the topic at rawURL, with token as a
// bearer token. https is always accepted. Plain http is accepted only when
// allowInsecureLAN is true and the host is an IP literal in RFC 1918,
// link-local or loopback space. A host name is never accepted over http. A
// nil hc uses GuardedClient for the URL's host.
func NewNtfy(rawURL, token string, allowInsecureLAN bool, hc *http.Client) (*Ntfy, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return nil, errors.New("ntfy: the URL needs a scheme and a host")
	}
	if u.User != nil {
		return nil, errors.New("ntfy: the URL must not carry user information")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !allowInsecureLAN || !isLANAddress(u.Hostname()) {
			return nil, errors.New("ntfy: plain http is allowed only to an RFC 1918, link-local or loopback IP address, and only with allow_insecure_lan")
		}
	default:
		return nil, errors.New("ntfy: the URL scheme must be https, or http to a LAN address")
	}
	if hc == nil {
		hc = GuardedClient([]string{u.Hostname()})
	}
	return &Ntfy{
		topic:  rawURL,
		origin: u.Scheme + "://" + u.Host,
		host:   u.Host,
		token:  token,
		hc:     hc,
	}, nil
}

// isLANAddress reports whether host is an IP literal in RFC 1918, link-local or
// loopback space. A host name is never one.
func isLANAddress(host string) bool {
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	if addr.IsLoopback() || addr.IsLinkLocalUnicast() {
		return true
	}
	for _, p := range rfc1918 {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// Send publishes text as the body of one message to the topic.
func (n *Ntfy) Send(ctx context.Context, text string) error {
	const op = "ntfy publish"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.topic, strings.NewReader(text))
	if err != nil {
		return transportError(op, err, n.secrets()...)
	}
	req.Header.Set("Content-Type", "text/plain; charset=utf-8")
	if n.token != "" {
		req.Header.Set("Authorization", "Bearer "+n.token)
	}
	return n.do(op, req)
}

// Ping reads the server's health endpoint. It sends neither a message nor the
// token.
//
// Limit: Ping proves that the server answers over a verified connection,
// not that it accepts the token. The health endpoint needs no token, and
// nothing in this repository describes an ntfy endpoint that checks a
// token's right to publish to a topic without publishing, so a wrong token
// or a topic it may not write to passes Ping and shows on the first Send
// as errNtfyRefused (TestNtfyPingDoesNotProveTheToken). A caller that takes
// a passing Ping as a working channel must also look at what Send returns.
func (n *Ntfy) Ping(ctx context.Context) error {
	const op = "ntfy health"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, n.origin+"/v1/health", nil)
	if err != nil {
		return transportError(op, err, n.secrets()...)
	}
	return n.do(op, req)
}

// do sends req and maps its answer: 401 and 403 to errNtfyRefused, any
// other status as statusError does. A 2xx body is drained, so the connection
// can be reused.
func (n *Ntfy) do(op string, req *http.Request) error {
	resp, err := n.hc.Do(req)
	if err != nil {
		return transportError(op, err, n.secrets()...)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponse))
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("%s: HTTP %d: %w", op, resp.StatusCode, errNtfyRefused)
	}
	return statusError(op, resp.StatusCode, retryAfterHeader(resp.Header.Get("Retry-After")))
}

// secrets are the token and the topic URL, for redaction.
func (n *Ntfy) secrets() []string {
	return []string{n.token, n.topic}
}

// retryAfterHeader reads a Retry-After value, in seconds or as an HTTP date. It
// returns 0 when the value is neither, or is in the past.
func retryAfterHeader(v string) time.Duration {
	v = strings.TrimSpace(v)
	if secs, err := strconv.ParseInt(v, 10, 64); err == nil {
		if secs <= 0 {
			return 0
		}
		return time.Duration(min(secs, maxRetryAfterSeconds)) * time.Second
	}
	if at, err := http.ParseTime(v); err == nil {
		if d := time.Until(at); d > 0 {
			return min(d, deliver.MaxRetryAfter)
		}
	}
	return 0
}

// String names the host and marks where the token goes. It never prints the
// token or the topic.
func (n Ntfy) String() string {
	return fmt.Sprintf("channel.Ntfy{host: %s, token: %s}", n.host, redact.Marker)
}

// Format prints String for every verb, %#v included.
func (n Ntfy) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, n.String())
}
