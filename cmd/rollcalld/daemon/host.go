package daemon

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
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
// (probe.Prober, lost after 3 failures 10 s apart) and the default route
// (host.RouteWatch). Each change becomes a LocalEvent of the node, stamped
// with the time the condition started, not the time it was detected.

// RouteWatcher is host.RouteWatch.
type RouteWatcher interface {
	Tick() (switched bool, from, to string)
}

// Host feeds the router's own observations to the daemon's node.
type Host struct {
	D      *Daemon
	Probe  *probe.Prober // nil: no internet probe
	Routes RouteWatcher  // nil: the default route is not watched
}

// Tick runs the probe when it is due and reads the default route.
func (h *Host) Tick(now time.Time) {
	if h.Probe != nil {
		switch lost, restored, since := h.Probe.Tick(now); {
		case lost:
			h.D.localEvent(events.InternetLost, since, nil)
		case restored:
			h.D.localEvent(events.InternetRestored, since, nil)
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
