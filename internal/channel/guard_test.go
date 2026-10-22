package channel

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestGuardedClientRefusesUnlistedHost(t *testing.T) {
	srv, reqs := serve(t, okFn)
	resp, err := GuardedClient([]string{"api.telegram.org"}).Get(srv.URL + "/anything")
	if resp != nil {
		resp.Body.Close()
	}
	if !errors.Is(err, errHostNotAllowed) {
		t.Fatalf("err = %v, want the dial refused for a host that is not listed", err)
	}
	if n := len(reqs.all()); n != 0 {
		t.Fatalf("the server saw %d requests, want none", n)
	}
}

func TestGuardedClientAllowsListedHost(t *testing.T) {
	srv, reqs := serve(t, okFn)
	resp, err := GuardedClient([]string{"127.0.0.1"}).Get(srv.URL + "/ok")
	if err != nil {
		t.Fatalf("Get to a listed host: %v", err)
	}
	resp.Body.Close()
	if n := len(reqs.all()); n != 1 {
		t.Fatalf("requests = %d, want 1", n)
	}
}

func TestGuardedClientRefusesRedirectToOtherHost(t *testing.T) {
	srv, reqs := serve(t, func(_ int, w http.ResponseWriter, r *http.Request) {
		_, port, _ := net.SplitHostPort(r.Host)
		http.Redirect(w, r, "http://localhost:"+port+"/elsewhere", http.StatusFound)
	})
	resp, err := GuardedClient([]string{"127.0.0.1"}).Get(srv.URL + "/start")
	if resp != nil {
		resp.Body.Close()
	}
	if !errors.Is(err, errRedirectRefused) {
		t.Fatalf("err = %v, want the redirect to another host refused", err)
	}
	if n := len(reqs.all()); n != 1 {
		t.Fatalf("requests = %d, want only the first; the redirect must not be followed", n)
	}
}

func TestGuardedClientRefusesDowngradeToHTTP(t *testing.T) {
	plain, _ := serve(t, okFn)
	tlsSrv, _ := serveTLS(t, func(_ int, w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+"/x", http.StatusFound)
	})
	client := GuardedClient([]string{"127.0.0.1"})
	tr, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport is %T, want *http.Transport", client.Transport)
	}
	pool := x509.NewCertPool()
	pool.AddCert(tlsSrv.Certificate())
	tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	resp, err := client.Get(tlsSrv.URL + "/start")
	if resp != nil {
		resp.Body.Close()
	}
	if !errors.Is(err, errRedirectRefused) {
		t.Fatalf("err = %v, want an https to http redirect refused", err)
	}
}

func TestGuardedClientVerifiesCertificates(t *testing.T) {
	tlsSrv, _ := serveTLS(t, okFn)
	resp, err := GuardedClient([]string{"127.0.0.1"}).Get(tlsSrv.URL)
	if resp != nil {
		resp.Body.Close()
	}
	var cve *tls.CertificateVerificationError
	var ua x509.UnknownAuthorityError
	if !errors.As(err, &cve) && !errors.As(err, &ua) {
		t.Fatalf("err = %v, want the untrusted certificate refused", err)
	}
}

func TestGuardedClientLimits(t *testing.T) {
	client := GuardedClient([]string{"api.telegram.org"})
	if client.Timeout != 15*time.Second {
		t.Fatalf("Timeout = %v, want 15s", client.Timeout)
	}
	tr, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport is %T, want *http.Transport", client.Transport)
	}
	if tr.Proxy != nil {
		t.Fatal("transport uses a proxy; the dial guard would see the proxy, not the host")
	}
	if tr.TLSClientConfig != nil && tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("certificate verification is disabled")
	}
}

func TestGuardedClientStopsRedirectLoop(t *testing.T) {
	var self string
	srv, reqs := serve(t, func(_ int, w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, self, http.StatusFound)
	})
	self = srv.URL + "/loop"
	resp, err := GuardedClient([]string{"127.0.0.1"}).Get(self)
	if resp != nil {
		resp.Body.Close()
	}
	if err == nil {
		t.Fatal("a redirect loop was followed without end")
	}
	if n := len(reqs.all()); n > maxRedirects {
		t.Fatalf("requests = %d, want the client to stop at %d", n, maxRedirects)
	}
}
