// Command rollcalld is the rollcall daemon.
//
//	rollcalld -config /etc/config/rollcall -state /etc/rollcall -run /tmp/rollcall \
//	          -control /var/run/rollcall/control.sock
//
// It reads /etc/config/rollcall and, beside it, the firewall, system and
// network files; listens on the devices of the peer zones only; serves the
// control socket for the CLI; and runs the node once a second. SIGTERM and
// SIGINT stop it cleanly. It never runs a command and never talks to ubus.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"maps"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	_ "time/tzdata" // the router has no zoneinfo package; the zone comes from /etc/config/system

	"github.com/TAIPANBOX/rollcall/cmd/rollcalld/daemon"
	"github.com/TAIPANBOX/rollcall/internal/channel"
	"github.com/TAIPANBOX/rollcall/internal/config"
	"github.com/TAIPANBOX/rollcall/internal/control"
	"github.com/TAIPANBOX/rollcall/internal/host"
	"github.com/TAIPANBOX/rollcall/internal/ids"
	"github.com/TAIPANBOX/rollcall/internal/node"
	"github.com/TAIPANBOX/rollcall/internal/probe"
	"github.com/TAIPANBOX/rollcall/internal/transport"
)

// version is set at build time with -ldflags "-X main.version=<tag>".
var version = "dev"

// The control socket (packaging/README.md); cmd/rollcall names the same.
const (
	ControlDirPath    = "/var/run/rollcall"
	ControlSocketPath = "/var/run/rollcall/control.sock"
)

const tickEvery = time.Second

func main() {
	var f flags
	flag.StringVar(&f.config, "config", "/etc/config/rollcall", "rollcall configuration; firewall, system and network are read from the same directory")
	flag.StringVar(&f.state, "state", "/etc/rollcall", "state directory (identity, roster, keys, history)")
	flag.StringVar(&f.run, "run", "/tmp/rollcall", "run-time directory")
	flag.StringVar(&f.control, "control", ControlSocketPath, "control socket")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println("rollcalld", version)
		return
	}
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "rollcalld: unexpected arguments")
		os.Exit(2)
	}
	log.SetFlags(0)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if err := run(ctx, f); err != nil {
		log.Printf("rollcalld: %v", err)
		os.Exit(1)
	}
}

type flags struct {
	config, state, run, control string
}

func run(ctx context.Context, f flags) error {
	dir := filepath.Dir(f.config)
	cfg, zones, err := config.Load(f.config, filepath.Join(dir, "firewall"), filepath.Join(dir, "system"), filepath.Join(dir, "network"))
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}
	devices := peerDevices(zones)

	// rollcalld ships for Linux only; elsewhere there is no seccomp or
	// no_new_privs to check, and the binary is a developer build. Nothing in
	// UCI or on the command line turns the check off.
	if runtime.GOOS == "linux" {
		if err := sandboxGate("/"); err != nil {
			return fmt.Errorf("%w; start rollcalld through /etc/init.d/rollcall", err)
		}
	}
	if err := os.MkdirAll(f.run, 0o700); err != nil {
		return err
	}

	boot, err := host.BootID()
	if err != nil {
		log.Printf("rollcalld: no boot ID from the kernel, so a restart looks like a reboot to the peers: %v", err)
		boot = ids.BootID{}
	}
	release, _ := host.OpenWrtVersion()

	// The transport's TCP gate needs the daemon, and the daemon the
	// transport: the gate refuses until the daemon exists.
	var d atomic.Pointer[daemon.Daemon]
	auth := func(frame []byte) bool {
		if dd := d.Load(); dd != nil {
			return dd.Authenticate(frame)
		}
		return false
	}
	tr, err := openPeers(cfg.Port, devices, auth)
	if err != nil {
		return err
	}
	log.Printf("rollcalld %s: listening on port %d on %s; SO_BINDTODEVICE applied: %v",
		version, cfg.Port, strings.Join(devices, ", "), tr.BoundToDevice())
	devs := tr.Devices()
	for _, line := range deviceNotes(nil, devs) {
		log.Print(line)
	}

	dd, err := daemon.New(daemon.Options{
		StateDir: f.state, Config: cfg, Devices: devices, Net: tr, Clock: daemon.SystemClock("/"),
		Boot: boot, Versions: [2]string{release, version},
		TelegramURL: channel.TelegramBaseURL, HTTP: channel.GuardedClient([]string{"api.telegram.org"}),
		Discovery: func() map[string]error { return discoveryWith(transport.Discovery(devices), tr.Devices()) },
		Sandbox:   func() node.SandboxStatus { s, _ := daemon.ReadSandbox("/"); return s },
		Addrs:     func() []netip.Addr { return deviceAddrs(devices) },
	})
	if err != nil {
		tr.Close()
		return err
	}
	defer dd.Close()
	d.Store(dd)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	wg.Go(func() {
		if err := tr.Serve(ctx, dd.HandlePacket, dd.HandleStream); err != nil {
			errs <- fmt.Errorf("transport: %w", err)
		}
	})
	wg.Go(func() {
		if err := control.Serve(ctx, f.control, refreshOnIface(dd.Handle, tr.Refresh), control.WithSecrets(dd.Secrets)); err != nil {
			errs <- err
		}
	})
	wg.Go(func() { watchHost(ctx, dd, cfg) })

	t := time.NewTicker(tickEvery)
	defer t.Stop()
	var failed error
	flooded := false
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case failed = <-errs:
			break loop
		case <-t.C:
			dd.Step()
			now := tr.Devices()
			for _, line := range deviceNotes(devs, now) {
				log.Print(line)
			}
			devs = now
			if f := tr.UnderFlood(); f != flooded {
				log.Print(floodNote(flooded, f, tr.Counters()))
				flooded = f
			}
		}
	}
	cancel()
	wg.Wait()
	if failed != nil {
		return failed
	}
	log.Printf("rollcalld: stopped")
	return nil
}

// sandboxGate decides whether the daemon may listen (security spec 1.5,
// 4.10, 14.2): the kernel must report, in root's proc/self/status ("/" on a
// router), no_new_privs set (NoNewPrivs: 1) and seccomp in filter mode
// (Seccomp: 2). Anything else refuses, an unreadable status included: a
// daemon that cannot show its sandbox does not run in a weaker mode. The jail
// is reported in status but not decided here: it has no kernel flag to read.
func sandboxGate(root string) error {
	b, err := os.ReadFile(filepath.Join(root, "proc", "self", "status"))
	if err != nil {
		return fmt.Errorf("refusing to listen: the sandbox cannot be checked: %w", err)
	}
	var noNewPrivs, seccomp string
	for line := range strings.Lines(string(b)) {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch k {
		case "NoNewPrivs":
			noNewPrivs = strings.TrimSpace(v)
		case "Seccomp":
			seccomp = strings.TrimSpace(v)
		}
	}
	switch {
	case noNewPrivs != "1":
		return fmt.Errorf("refusing to listen: no_new_privs is not set (NoNewPrivs: %q)", noNewPrivs)
	case seccomp != "2":
		return fmt.Errorf("refusing to listen: seccomp is not in filter mode (Seccomp: %q)", seccomp)
	}
	return nil
}

// openPeers opens the transport on the devices of the peer zones. It binds
// what they carry now and follows them from then on: a device that does not
// exist yet (wg0 not up), an address still in duplicate address detection, or
// one that failed it, is reported in status and the log and tried again on
// every pass, and stops none of the others.
func openPeers(port int, devices []string, auth func([]byte) bool) (*transport.Transport, error) {
	if len(devices) == 0 {
		return nil, errors.New("the peer zones have no network devices")
	}
	tr, err := transport.Open(port, devices, auth)
	if err != nil {
		return nil, fmt.Errorf("listening on the peer zones: %w", err)
	}
	return tr, nil
}

// refreshOnIface passes each control command to h; after an interface event
// from hotplug (rollcall notify iface ...) it also asks the transport for a
// pass over the peer-zone devices, so an address that came or went, or a
// device netifd recreated, is bound again at once.
func refreshOnIface(h control.Handler, refresh func()) control.Handler {
	return func(cmd string, args []string, uid uint32) ([]byte, error) {
		out, err := h(cmd, args, uid)
		if cmd == "notify" && len(args) > 0 && args[0] == "iface" {
			refresh()
		}
		return out, err
	}
}

// discoveryWith adds to disc, the discovery state of each device, what the
// transport could not bind there, so status shows a peer-zone device that is
// not listened on. A device whose lookup already failed keeps that one error.
func discoveryWith(disc map[string]error, devs map[string]transport.DeviceStatus) map[string]error {
	for name, st := range devs {
		switch cur := disc[name]; {
		case st.Err == nil:
		case cur == nil:
			disc[name] = st.Err
		case errors.Is(cur, transport.ErrNoLinkLocal):
			disc[name] = errors.Join(cur, st.Err)
		}
	}
	return disc
}

// deviceNotes are the log lines for what changed on the peer-zone devices
// since prev: one when a device cannot be listened on (or fully), and one
// when it is listened on again.
func deviceNotes(prev, cur map[string]transport.DeviceStatus) []string {
	var out []string
	for _, name := range slices.Sorted(maps.Keys(cur)) {
		was, now := errText(prev[name].Err), errText(cur[name].Err)
		if was == now && prev != nil {
			continue
		}
		if now != "" {
			out = append(out, fmt.Sprintf("rollcalld: %s: %s; tried again every %s and on each interface event", name, now, transport.ReconcileEvery))
			continue
		}
		var addrs []string
		for _, a := range cur[name].Addrs {
			addrs = append(addrs, a.String())
		}
		out = append(out, fmt.Sprintf("rollcalld: %s: listening on %s", name, strings.Join(addrs, ", ")))
	}
	return out
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return strings.ReplaceAll(err.Error(), "\n", "; ")
}

// watchHost runs the internet probe and the default-route watch.
func watchHost(ctx context.Context, d *daemon.Daemon, cfg config.Config) {
	h := &daemon.Host{D: d, Routes: &host.RouteWatch{},
		Probe: &probe.Prober{Probe: daemon.InternetProbe(cfg.ProbeTargets, cfg.ICMP, probe.TCP, probe.ICMP)}}
	t := time.NewTicker(tickEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			h.Tick(now)
		}
	}
}

// peerDevices is every device of every peer zone, once, sorted.
func peerDevices(zones map[string][]string) []string {
	var out []string
	for _, devs := range zones {
		out = append(out, devs...)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// deviceAddrs lists the addresses of the devices, for invite.
func deviceAddrs(devices []string) []netip.Addr {
	var out []netip.Addr
	for _, dev := range devices {
		ifi, err := net.InterfaceByName(dev)
		if err != nil {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				if ip, ok := netip.AddrFromSlice(n.IP); ok {
					out = append(out, ip.Unmap())
				}
			}
		}
	}
	return out
}

// floodNote is the log line when the transport's flood signal changes, and
// "" while it holds. The flood is local: it reaches the log and status, never
// the chat (security spec 5.2).
func floodNote(was, now bool, c transport.Counters) string {
	switch {
	case now && !was:
		return fmt.Sprintf("rollcalld: under flood: the peer zones carry more than the transport admits; "+
			"UDP dropped so far: %d over one source's rate, %d over the total rate, %d from too many sources, %d oversize; "+
			"TCP refused so far: %d over one address's slots, %d with every slot taken, %d without a first frame in time, %d failing authentication",
			c.SourceLimited, c.RateLimited, c.SourcesFull, c.Oversize, c.ConnsSource, c.ConnsFull, c.PreAuth, c.AuthFailed)
	case was && !now:
		return "rollcalld: the flood on the peer zones has stopped"
	}
	return ""
}
