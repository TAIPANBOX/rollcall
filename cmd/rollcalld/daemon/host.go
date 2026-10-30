package daemon

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/events"
	"github.com/TAIPANBOX/rollcall/internal/node"
	"github.com/TAIPANBOX/rollcall/internal/probe"
)

// # What the router itself sees
//
// Host runs beside the main loop, once a second: the internet probe
// (probe.Prober, lost after 3 failures 10 s apart), the DNS probe and the
// default route (host.RouteWatch). Each change becomes a LocalEvent of the
// node, stamped with the time the condition started, not the time it was
// detected.
//
// The DNS probe asks the DNS servers the uplink names (DNSProbe) in the same
// rounds as the internet probe, right after it. It judges a round only when
// the internet probe of that round got through: DNS lost is a loss of its own
// only while the internet answers; when the internet is gone, the internet
// loss tells it, and DNS records nothing (@decided 2026-10-30).

// RouteWatcher is host.RouteWatch.
type RouteWatcher interface {
	Tick() (switched bool, from, to string)
}

// Host feeds the router's own observations to the daemon's node.
type Host struct {
	D      *Daemon
	Probe  *probe.Prober // nil: no internet probe
	DNS    *probe.Prober // nil: no DNS probe; its probe asks Internet (DNSProbe)
	Routes RouteWatcher  // nil: the default route is not watched
}

// Internet reports whether the internet probe's last round got an answer:
// the gate of the DNS probe.
func (h *Host) Internet() bool { return h.Probe != nil && h.Probe.Answered() }

// Tick runs the probes when they are due, the internet probe first, and
// reads the default route.
func (h *Host) Tick(now time.Time) {
	if h.Probe != nil {
		switch lost, restored, since := h.Probe.Tick(now); {
		case lost:
			h.D.localEvent(events.InternetLost, since, nil)
		case restored:
			h.D.localEvent(events.InternetRestored, since, nil)
		}
	}
	if h.DNS != nil {
		switch lost, restored, since := h.DNS.Tick(now); {
		case lost:
			h.D.localEvent(events.DNSLost, since, nil)
		case restored:
			h.D.localEvent(events.DNSRestored, since, nil)
		}
	}
	if h.Routes != nil {
		if switched, from, to := h.Routes.Tick(); switched {
			h.D.mu.Lock()
			h.D.switched = true
			h.D.mu.Unlock()
			h.D.localEvent(events.UplinkSwitched, now, map[string]string{"from": from, "to": to})
		}
	}
}

// DefaultProbeTargets are probed when the configuration names none: TCP 443
// on two public resolvers, as IP literals, so the probe needs no DNS.
var DefaultProbeTargets = []string{"1.1.1.1", "8.8.8.8"}

// InternetProbe returns the probe of probe.Prober over targets: the internet
// answers when any target does. The targets run at once, so one that hangs
// does not use up the deadline of the others. An IPv4 literal is probed with
// ICMP when icmp is set (the daemon then holds CAP_NET_RAW) and with TCP 443
// otherwise; any other target with TCP, host:port or host on port 443.
func InternetProbe(targets []string, icmp bool, tcpProbe, icmpProbe func(ctx context.Context, addr string) error) func(context.Context) error {
	if len(targets) == 0 {
		targets = DefaultProbeTargets
	}
	return func(ctx context.Context) error {
		res := make(chan error, len(targets))
		for _, t := range targets {
			go func() {
				if a, err := netip.ParseAddr(t); err == nil && a.Is4() && icmp {
					res <- icmpProbe(ctx, t)
					return
				}
				res <- tcpProbe(ctx, t)
			}()
		}
		var last error
		for range targets {
			if last = <-res; last == nil {
				return nil
			}
		}
		return last
	}
}

// ResolvConfAuto is where netifd lists the DNS servers of the uplinks on
// OpenWrt, and dnsmasq reads its upstream servers from: the DNS probe asks
// those, past dnsmasq's cache. The jail mounts its directory read-only.
const ResolvConfAuto = "/tmp/resolv.conf.d/resolv.conf.auto"

// maxDNSServers bounds the servers one round of the DNS probe asks.
const maxDNSServers = 8

// UplinkDNSServers returns the servers of the DNS probe: fixed, when the
// configuration names them, or else those path (ResolvConfAuto) lists now,
// read again every round, since the uplink's DHCP may change them.
func UplinkDNSServers(fixed []string, path string) func() []string {
	return func() []string {
		if len(fixed) > 0 {
			return fixed
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		return probe.ResolvConfServers(b, maxDNSServers)
	}
}

// DNSProbe returns the probe of the DNS prober: name asked of every server
// that servers lists, at once; an answer from any of them passes (probe.DNS
// counts any answer, NXDOMAIN too), and the round fails when none answers. A
// round judges nothing (probe.ErrSkip) when internet says the internet probe
// of the round did not get through, or when servers lists none: then the
// probe is off, and note logs that once, and once again when servers are
// listed again or the list changes.
func DNSProbe(servers func() []string, name string, internet func() bool,
	dns func(ctx context.Context, server, name string) error, note func(format string, args ...any)) func(context.Context) error {
	var last []string
	said := false
	return func(ctx context.Context) error {
		list := servers()
		if !said || !slices.Equal(list, last) {
			if len(list) == 0 {
				note("rollcalld: the DNS probe is off: the uplink names no DNS server and the configuration none")
			} else {
				note("rollcalld: the DNS probe asks %s for %s", strings.Join(list, ", "), name)
			}
			last, said = slices.Clone(list), true
		}
		if len(list) == 0 || !internet() {
			return probe.ErrSkip
		}
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		res := make(chan error, len(list))
		for _, s := range list {
			go func() { res <- dns(ctx, s, name) }()
		}
		var err error
		for range list {
			if err = <-res; err == nil {
				return nil
			}
		}
		return err
	}
}

// SystemClock is the node's clock on a router: the wall clock, and the
// monotonic clock since boot, read once from /proc/uptime and carried on
// by Go's own monotonic clock, so that it keeps counting from the boot across
// daemon restarts. Without /proc/uptime it counts from the daemon's start.
func SystemClock(root string) node.Clock {
	c := sysClock{start: time.Now()}
	if b, err := os.ReadFile(filepath.Join(root, "proc", "uptime")); err == nil {
		if f := strings.Fields(string(b)); len(f) > 0 {
			if s, err := strconv.ParseFloat(f[0], 64); err == nil && s >= 0 && s < 1e9 {
				c.base = time.Duration(s * float64(time.Second))
			}
		}
	}
	return c
}

type sysClock struct {
	base  time.Duration
	start time.Time
}

func (c sysClock) Now() time.Time      { return time.Now() }
func (c sysClock) Mono() time.Duration { return c.base + time.Since(c.start) }
