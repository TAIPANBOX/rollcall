package channel

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
)

// canary is the fake token that no error and no printed form may show.
const canary = "CANARY-123:abc"

// recorded is one request a fake server received.
type recorded struct {
	method string
	path   string
	query  string
	header http.Header
	body   string
}

// reqLog keeps the requests a fake server received, in order.
type reqLog struct {
	mu   sync.Mutex
	reqs []recorded
}

// add records r and returns how many requests have arrived, this one included.
func (l *reqLog) add(r *http.Request) int {
	body, _ := io.ReadAll(r.Body)
	l.mu.Lock()
	defer l.mu.Unlock()
	l.reqs = append(l.reqs, recorded{
		method: r.Method,
		path:   r.URL.Path,
		query:  r.URL.RawQuery,
		header: r.Header.Clone(),
		body:   string(body),
	})
	return len(l.reqs)
}

// all returns a copy of the requests so far.
func (l *reqLog) all() []recorded {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.reqs)
}

// answerFunc answers request number n, counted from 1.
type answerFunc func(n int, w http.ResponseWriter, r *http.Request)

// serve starts a plain HTTP fake server that answers with answer.
func serve(t *testing.T, answer answerFunc) (*httptest.Server, *reqLog) {
	t.Helper()
	return start(t, false, answer)
}

// serveTLS starts a fake server over TLS. Its certificate is not trusted by
// the default roots, so a client that verifies certificates must refuse it.
func serveTLS(t *testing.T, answer answerFunc) (*httptest.Server, *reqLog) {
	t.Helper()
	return start(t, true, answer)
}

func start(t *testing.T, useTLS bool, answer answerFunc) (*httptest.Server, *reqLog) {
	t.Helper()
	l := &reqLog{}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		answer(l.add(r), w, r)
	})
	var srv *httptest.Server
	if useTLS {
		srv = httptest.NewTLSServer(h)
	} else {
		srv = httptest.NewServer(h)
	}
	t.Cleanup(srv.Close)
	return srv, l
}

// status answers every request with code and body.
func status(code int, body string) answerFunc {
	return func(_ int, w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(code)
		fmt.Fprint(w, body)
	}
}

// noCanary fails the test when err's text shows the canary.
func noCanary(t *testing.T, err error) {
	t.Helper()
	if err != nil && strings.Contains(err.Error(), canary) {
		t.Fatalf("error shows the token: %q", err.Error())
	}
}
