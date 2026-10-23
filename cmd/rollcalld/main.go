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

const (
	// listenRetry and listenFor bound the wait for the peer-zone addresses at
	// boot: an IPv6 address is not bindable until duplicate address detection
	// ends, and ListenPeers binds all or nothing.
	listenRetry = 5 * time.Second
	listenFor   = 2 * time.Minute
	tickEvery   = time.Second
)

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

	sb, known := daemon.ReadSandbox("/")
	if runtime.GOOS == "linux" && known && sb.State == "off" {
		return errors.New("no sandbox: no_new_privs, seccomp and the jail are all missing; start rollcalld through /etc/init.d/rollcall")
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
	tr, err := listen(ctx, cfg.Port, devices, auth)
	if err != nil {
		return err
	}
	log.Printf("rollcalld %s: listening on port %d on %s; SO_BINDTODEVICE applied: %v",
		version, cfg.Port, strings.Join(devices, ", "), tr.BoundToDevice())

	dd, err := daemon.New(daemon.Options{
		StateDir: f.state, Config: cfg, Devices: devices, Net: tr, Clock: daemon.SystemClock("/"),
		Boot: boot, Versions: [2]string{release, version},
		TelegramURL: channel.TelegramBaseURL, HTTP: channel.GuardedClient([]string{"api.telegram.org"}),
		Discovery: func() map[string]error { return transport.Discovery(devices) },
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
		if err := control.Serve(ctx, f.control, dd.Handle, control.WithSecrets(dd.Secrets)); err != nil {
			errs <- err
		}
	})
	wg.Go(func() { watchHost(ctx, dd, cfg) })

	t := time.NewTicker(tickEvery)
	defer t.Stop()
	var failed error
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case failed = <-errs:
			break loop
		case <-t.C:
			dd.Step()
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

// listen binds the peer-zone sockets, retrying while the addresses are not
// bindable yet.
func listen(ctx context.Context, port int, devices []string, auth func([]byte) bool) (*transport.Transport, error) {
	if len(devices) == 0 {
		return nil, errors.New("the peer zones have no network devices")
	}
	deadline := time.Now().Add(listenFor)
	for {
		tr, err := transport.ListenPeers(port, devices, auth)
		if err == nil {
			return tr, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("listening on the peer zones: %w", err)
		}
		log.Printf("rollcalld: listening on the peer zones failed, retrying in %s: %v", listenRetry, err)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(listenRetry):
		}
	}
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
