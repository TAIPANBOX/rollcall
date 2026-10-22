package channel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/deliver"
)

func TestNtfyRefusesHTTPToPublicHosts(t *testing.T) {
	cases := []string{
		"http://ntfy.example.com/alerts",
		"http://203.0.113.7/alerts",
		"http://8.8.8.8/alerts",
		"http://[2001:db8::1]/alerts",
	}
	for _, u := range cases {
		if _, err := NewNtfy(u, canary, true, nil); err == nil {
			t.Errorf("NewNtfy(%q, allowInsecureLAN=true) accepted plain HTTP to a public host", u)
		}
	}
}

func TestNtfyHTTPToLANOnlyWithFlag(t *testing.T) {
	lan := []string{
		"http://192.168.1.10/alerts",
		"http://10.0.0.5/alerts",
		"http://172.16.4.4/alerts",
		"http://169.254.7.7/alerts",
		"http://127.0.0.1:8080/alerts",
		"http://[::1]/alerts",
		"http://[fe80::1]/alerts",
	}
	for _, u := range lan {
		if _, err := NewNtfy(u, canary, false, nil); err == nil {
			t.Errorf("NewNtfy(%q) without allow_insecure_lan accepted plain HTTP", u)
		}
		if _, err := NewNtfy(u, canary, true, nil); err != nil {
			t.Errorf("NewNtfy(%q, allow_insecure_lan) refused a LAN address: %v", u, err)
		}
	}
}

func TestNtfyHTTPRefusesHostnamesAndNonPrivateRanges(t *testing.T) {
	cases := []string{
		"http://ntfy.lan/alerts",
		"http://localhost/alerts",
		"http://172.32.0.1/alerts",
		"http://192.169.0.1/alerts",
	}
	for _, u := range cases {
		if _, err := NewNtfy(u, canary, true, nil); err == nil {
			t.Errorf("NewNtfy(%q, allow_insecure_lan) accepted plain HTTP where only an RFC 1918, link-local or loopback IP literal is allowed", u)
		}
	}
}

func TestNtfySchemeMustBeHTTPOrHTTPS(t *testing.T) {
	for _, u := range []string{"ftp://ntfy.example.com/alerts", "ws://192.168.1.2/alerts", "ntfy.example.com/alerts"} {
		if _, err := NewNtfy(u, canary, true, nil); err == nil {
			t.Errorf("NewNtfy(%q) accepted a scheme that is not http or https", u)
		}
	}
}

func TestNtfyRefusesUserInfoAndNoHost(t *testing.T) {
	for _, u := range []string{"https://user:secret@ntfy.example.com/alerts", "https:///alerts"} {
		if _, err := NewNtfy(u, canary, false, nil); err == nil {
			t.Errorf("NewNtfy(%q) accepted a URL it must refuse", u)
		}
	}
}

func TestNtfyAcceptsHTTPS(t *testing.T) {
	if _, err := NewNtfy("https://ntfy.example.com/alerts", canary, false, nil); err != nil {
		t.Fatalf("NewNtfy over https: %v", err)
	}
}

func TestNtfySendPostsTextWithBearerToken(t *testing.T) {
	srv, reqs := serve(t, okFn)
	n, err := NewNtfy(srv.URL+"/alerts", canary, true, srv.Client())
	if err != nil {
		t.Fatalf("NewNtfy: %v", err)
	}
	if err := n.Send(context.Background(), "Home: router silent"); err != nil {
		t.Fatalf("Send: %v", err)
	}
	got := reqs.all()
	if len(got) != 1 {
		t.Fatalf("requests = %d, want 1", len(got))
	}
	r := got[0]
	if r.method != http.MethodPost || r.path != "/alerts" || r.query != "" {
		t.Errorf("request = %s %s?%s, want POST /alerts", r.method, r.path, r.query)
	}
	if r.body != "Home: router silent" {
		t.Errorf("body = %q, want the text as the body", r.body)
	}
	if h := r.header.Get("Authorization"); h != "Bearer "+canary {
		t.Errorf("Authorization = %q, want the bearer token in the header", h)
	}
	if !strings.HasPrefix(r.header.Get("Content-Type"), "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain", r.header.Get("Content-Type"))
	}
}

func TestNtfyPingReadsHealth(t *testing.T) {
	srv, reqs := serve(t, okFn)
	n, err := NewNtfy(srv.URL+"/alerts", canary, true, srv.Client())
	if err != nil {
		t.Fatalf("NewNtfy: %v", err)
	}
	if err := n.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	got := reqs.all()
	if len(got) != 1 || got[0].method != http.MethodGet || got[0].path != "/v1/health" {
		t.Fatalf("requests = %+v, want one GET /v1/health and nothing published", got)
	}
}

func TestNtfyBlockedIsErrBlocked(t *testing.T) {
	srv, _ := serve(t, status(403, "forbidden"))
	n, _ := NewNtfy(srv.URL+"/alerts", canary, true, srv.Client())
	err := n.Send(context.Background(), "x")
	if !errors.Is(err, deliver.ErrBlocked) {
		t.Fatalf("err = %v, want deliver.ErrBlocked", err)
	}
	noCanary(t, err)
}

func TestNtfyRateLimitHonoursRetryAfterHeader(t *testing.T) {
	srv, _ := serve(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "9")
		w.WriteHeader(429)
	})
	n, _ := NewNtfy(srv.URL+"/alerts", canary, true, srv.Client())
	err := n.Send(context.Background(), "x")
	var rl *deliver.RateLimitError
	if !errors.As(err, &rl) || rl.RetryAfter != 9*time.Second {
		t.Fatalf("err = %v, want a rate limit error with RetryAfter 9s", err)
	}
	if !errors.Is(err, deliver.ErrRateLimited) {
		t.Fatalf("err = %v, want it to match deliver.ErrRateLimited", err)
	}
	noCanary(t, err)
}

func TestNtfyTLSFailureIsErrTLS(t *testing.T) {
	srv, _ := serveTLS(t, okFn)
	n, err := NewNtfy(srv.URL+"/alerts", canary, false, nil)
	if err != nil {
		t.Fatalf("NewNtfy: %v", err)
	}
	err = n.Send(context.Background(), "x")
	if !errors.Is(err, deliver.ErrTLS) {
		t.Fatalf("err = %v, want deliver.ErrTLS", err)
	}
	noCanary(t, err)
}

func TestNtfyOtherStatusIsPlain(t *testing.T) {
	srv, _ := serve(t, status(500, "internal"))
	n, _ := NewNtfy(srv.URL+"/alerts", canary, true, srv.Client())
	err := n.Send(context.Background(), "x")
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("err = %v, want a plain error with the status code 500", err)
	}
	if errors.Is(err, deliver.ErrBlocked) || errors.Is(err, deliver.ErrRateLimited) || errors.Is(err, deliver.ErrTLS) {
		t.Fatalf("err = %v, want no deliver sentinel", err)
	}
	noCanary(t, err)
}

func TestNtfyDefaultClientRefusesRedirectToOtherHost(t *testing.T) {
	srv, _ := serve(t, func(_ int, w http.ResponseWriter, r *http.Request) {
		_, port, _ := net.SplitHostPort(r.Host)
		http.Redirect(w, r, "http://localhost:"+port+"/alerts", http.StatusFound)
	})
	n, err := NewNtfy(srv.URL+"/alerts", canary, true, nil)
	if err != nil {
		t.Fatalf("NewNtfy: %v", err)
	}
	if err := n.Send(context.Background(), "x"); !errors.Is(err, errRedirectRefused) {
		t.Fatalf("err = %v, want the guarded client to refuse the redirect", err)
	}
}

func TestCanaryNeverInNtfyErrors(t *testing.T) {
	closed := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	refusedURL := closed.URL
	closed.Close()

	tlsSrv, _ := serveTLS(t, okFn)
	s500, _ := serve(t, status(500, "internal"))
	s403, _ := serve(t, status(403, "forbidden"))
	s429, _ := serve(t, status(429, ""))

	cases := []struct {
		name string
		base string
		srv  *httptest.Server
	}{
		{"connection refused", refusedURL, nil},
		{"untrusted certificate", tlsSrv.URL, nil},
		{"HTTP 500", s500.URL, s500},
		{"HTTP 403", s403.URL, s403},
		{"HTTP 429", s429.URL, s429},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var hc *http.Client
			if c.srv != nil {
				hc = c.srv.Client()
			}
			n, err := NewNtfy(c.base+"/alerts", canary, true, hc)
			if err != nil {
				t.Fatalf("NewNtfy: %v", err)
			}
			sendErr := n.Send(context.Background(), "x")
			if sendErr == nil {
				t.Fatal("Send err = nil, want an error")
			}
			noCanary(t, sendErr)
			pingErr := n.Ping(context.Background())
			noCanary(t, pingErr)
		})
	}
}

func TestNtfyNeverPrintsToken(t *testing.T) {
	n, _ := NewNtfy("https://ntfy.example.com/alerts", canary, false, nil)
	forms := []string{
		fmt.Sprintf("%v", n),
		fmt.Sprintf("%+v", n),
		fmt.Sprintf("%#v", n),
		fmt.Sprintf("%v", *n),
		n.String(),
	}
	for _, s := range forms {
		if strings.Contains(s, canary) {
			t.Errorf("printed form shows the token: %q", s)
		}
	}
	if !strings.Contains(n.String(), "[redacted]") {
		t.Errorf("String() = %q, want the token slot marked [redacted]", n.String())
	}
}

func TestRetryAfterHeaderForms(t *testing.T) {
	cases := map[string]time.Duration{
		"9":      9 * time.Second,
		"99999":  deliver.MaxRetryAfter,
		"0":      0,
		"-3":     0,
		"soon":   0,
		"":       0,
		"  12  ": 12 * time.Second,
	}
	for v, want := range cases {
		if got := retryAfterHeader(v); got != want {
			t.Errorf("retryAfterHeader(%q) = %v, want %v", v, got, want)
		}
	}
	date := time.Now().Add(30 * time.Second).UTC().Format(http.TimeFormat)
	if got := retryAfterHeader(date); got < 20*time.Second || got > 30*time.Second {
		t.Errorf("retryAfterHeader(HTTP date 30s ahead) = %v, want about 30s", got)
	}
	past := time.Now().Add(-time.Minute).UTC().Format(http.TimeFormat)
	if got := retryAfterHeader(past); got != 0 {
		t.Errorf("retryAfterHeader(past date) = %v, want 0", got)
	}
}
