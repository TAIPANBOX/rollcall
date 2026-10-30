package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/probe"
)

// rounds is a probe whose rounds answer as up says, round by round from 0;
// it counts the rounds it ran.
type rounds struct {
	mu sync.Mutex
	n  int
	up func(round int) bool
}

func (r *rounds) probe(context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := r.n
	r.n++
	if r.up(n) {
		return nil
	}
	return errors.New("no answer")
}

// hostRun drives a daemon and its Host for secs seconds, one tick a second,
// the internet probe answering as internet says and every DNS server as dns
// says, round by round. It returns the texts of the incidents the node keeps,
// their times, and the first moment.
func hostRun(t *testing.T, secs int, internet, dns func(round int) bool) (texts, times []string, first time.Time) {
	t.Helper()
	h := start(t, newFixture(t, false, false).dir, nil)
	in := &rounds{up: internet}
	host := &Host{D: h.d, Probe: &probe.Prober{Probe: in.probe}}
	// The DNS servers answer as dns says for the round the internet probe
	// just ran: a skipped round asks them nothing, yet time goes on.
	host.DNS = &probe.Prober{Probe: DNSProbe(func() []string { return []string{"192.168.70.1"} }, "openwrt.org",
		host.Internet, func(context.Context, string, string) error {
			in.mu.Lock()
			defer in.mu.Unlock()
			if dns(in.n - 1) {
				return nil
			}
			return errors.New("no answer")
		}, t.Logf)}
	for el := 0; el < secs; el++ {
		h.clk.advance(time.Second)
		h.d.Step()
		now := h.clk.Now()
		if first.IsZero() {
			first = now
		}
		host.Tick(now)
	}
	incs, _ := h.status()["incidents"].([]any)
	for _, x := range incs {
		inc := x.(map[string]any)
		texts = append(texts, fmt.Sprint(inc["text"]))
		times = append(times, fmt.Sprint(inc["time"]))
	}
	t.Logf("incidents: %q at %q", texts, times)
	return texts, times, first
}

// TestHostTellsDNSCut: the internet probe gets through every round; the DNS
// servers fail rounds 3 to 32 (5 minutes) and answer again from round 33.
// The router records the DNS loss after the third failed round, dated at the
// first, and the return at the first answer: the start of the cut and then
// the cut with its length (lab cell D2, 2026-10-30, where rc92 recorded
// nothing).
func TestHostTellsDNSCut(t *testing.T) {
	cut := func(r int) bool { return r < 3 || r > 32 }
	texts, times, first := hostRun(t, 420, func(int) bool { return true }, cut)
	if len(texts) != 2 {
		t.Fatalf("%d incidents %q, want the start of the DNS cut and the cut", len(texts), texts)
	}
	at := first.Add(30 * time.Second).Format(time.RFC3339) // round 3: the first failure
	if !strings.Contains(texts[1], "DNS stopped answering") || times[1] != at {
		t.Fatalf("start %q at %s, want DNS stopped answering at %s, the first failed round", texts[1], times[1], at)
	}
	if !strings.Contains(texts[0], "DNS was down from") || !strings.Contains(texts[0], "(5 min)") {
		t.Fatalf("end %q, want the cut with its 5 min", texts[0])
	}
	for _, x := range texts {
		if strings.Contains(x, "internet") {
			t.Fatalf("incident %q names the internet; it answered every round", x)
		}
	}
}

// TestHostNoDNSLossWithoutInternet: the internet goes in rounds 3 to 11,
// and with it every DNS answer; once DNS failed a round earlier, while the
// internet still answered. The router records the internet loss and its
// return, and nothing about DNS: a round whose internet probe did not get
// through judges nothing, so the DNS failures never make three in a row, and
// once both answer again there is no DNS return to tell either.
func TestHostNoDNSLossWithoutInternet(t *testing.T) {
	for _, dnsFrom := range []int{3, 2} {
		t.Run(fmt.Sprintf("DNS fails from round %d", dnsFrom), func(t *testing.T) {
			texts, _, _ := hostRun(t, 200, func(r int) bool { return r < 3 || r > 11 }, func(r int) bool { return r < dnsFrom || r > 11 })
			if len(texts) != 2 || !strings.Contains(texts[0], "internet was down from") || !strings.Contains(texts[1], "internet lost") {
				t.Fatalf("incidents %q, want the internet loss and the outage", texts)
			}
			for _, x := range texts {
				if strings.Contains(x, "DNS") {
					t.Fatalf("incident %q tells DNS; only the internet was lost", x)
				}
			}
		})
	}
}

// TestDNSProbeOffWithoutServers: without a server, a round judges nothing
// and the log says so once; when the uplink names servers again it says
// which, once; a round whose internet probe failed judges nothing either; an
// answer of any server passes, and all of them failing fails.
func TestDNSProbeOffWithoutServers(t *testing.T) {
	var list []string
	internet := true
	var notes []string
	var asked []string
	var mu sync.Mutex
	answers := map[string]bool{}
	p := DNSProbe(func() []string { return list }, "openwrt.org", func() bool { return internet },
		func(_ context.Context, server, name string) error {
			mu.Lock()
			defer mu.Unlock()
			asked = append(asked, server+" "+name)
			if answers[server] {
				return nil
			}
			return errors.New("no answer")
		}, func(format string, args ...any) { notes = append(notes, fmt.Sprintf(format, args...)) })
	ctx := context.Background()
	for range 3 {
		if err := p(ctx); !errors.Is(err, probe.ErrSkip) {
			t.Fatalf("no server: %v, want a round that judges nothing", err)
		}
	}
	if len(notes) != 1 || !strings.Contains(notes[0], "the DNS probe is off") || len(asked) != 0 {
		t.Fatalf("notes %q, asked %q; want one line that the probe is off, and nobody asked", notes, asked)
	}
	list = []string{"192.168.70.1", "fe80::1%wan"}
	internet = false
	if err := p(ctx); !errors.Is(err, probe.ErrSkip) || len(asked) != 0 {
		t.Fatalf("the internet probe failed this round: %v, asked %q; want nothing judged, nobody asked", err, asked)
	}
	internet = true
	if err := p(ctx); err == nil || errors.Is(err, probe.ErrSkip) {
		t.Fatalf("every server failed: %v, want a failure", err)
	}
	// A failed round waited for every server: both were asked.
	mu.Lock()
	both := slices.Sorted(slices.Values(asked))
	answers["fe80::1%wan"] = true
	mu.Unlock()
	if !slices.Equal(both, []string{"192.168.70.1 openwrt.org", "fe80::1%wan openwrt.org"}) {
		t.Fatalf("asked %q, want every server once", both)
	}
	if err := p(ctx); err != nil {
		t.Fatalf("one server answered: %v", err)
	}
	if len(notes) != 2 || !strings.Contains(notes[1], "asks 192.168.70.1, fe80::1%wan for openwrt.org") {
		t.Fatalf("notes %q", notes)
	}
}

// TestUplinkDNSServers: the servers the configuration names, or else those
// the uplink's file names, read again every round.
func TestUplinkDNSServers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolv.conf.auto")
	servers := UplinkDNSServers(nil, path)
	if got := servers(); len(got) != 0 {
		t.Fatalf("no file: %q", got)
	}
	if err := os.WriteFile(path, []byte("# Interface wan\nnameserver 192.168.70.1\nnameserver 127.0.0.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := servers(); !slices.Equal(got, []string{"192.168.70.1"}) {
		t.Fatalf("from the file: %q", got)
	}
	if err := os.WriteFile(path, []byte("search lan\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := servers(); len(got) != 0 {
		t.Fatalf("the WAN went down and its servers with it: %q", got)
	}
	if got := UplinkDNSServers([]string{"192.0.2.53"}, path)(); !slices.Equal(got, []string{"192.0.2.53"}) {
		t.Fatalf("configured: %q", got)
	}
}
