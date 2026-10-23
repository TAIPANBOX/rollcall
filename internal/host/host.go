// Package host reads the state of the router from the kernel and from the
// OpenWrt release file: the default route, interface state, the OpenWrt
// version and the boot ID. It reads files only, never ubus. Every path is
// relative to Root, so tests point Root at a fixture directory.
package host

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/TAIPANBOX/rollcall/internal/ids"
)

// Root is the directory the host files are read from. It is "/" on a router;
// tests point it at a fixture directory.
var Root = "/"

// ErrNoDefaultRoute is returned when neither routing table has a usable default route.
var ErrNoDefaultRoute = errors.New("host: no default route")

// Route flags from linux/route.h.
const (
	rtfUp     = 0x0001
	rtfReject = 0x0200
)

// defaultRoute is one usable default route.
type defaultRoute struct {
	iface  string
	metric int
}

// parseProcRoute reads the IPv4 table in the format of /proc/net/route and
// returns its usable default routes in file order. A row that is not a
// default route, or is not up, is skipped. A malformed row is an error.
func parseProcRoute(data []byte) ([]defaultRoute, error) {
	var out []defaultRoute
	for i, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || f[0] == "Iface" {
			continue
		}
		if len(f) < 8 {
			return nil, fmt.Errorf("host: /proc/net/route line %d: %d fields, want at least 8", i+1, len(f))
		}
		flags, err := strconv.ParseUint(f[3], 16, 32)
		if err != nil {
			return nil, fmt.Errorf("host: /proc/net/route line %d: flags: %w", i+1, err)
		}
		metric, err := strconv.Atoi(f[6])
		if err != nil {
			return nil, fmt.Errorf("host: /proc/net/route line %d: metric: %w", i+1, err)
		}
		if f[1] != "00000000" || f[7] != "00000000" {
			continue
		}
		if flags&rtfUp == 0 || flags&rtfReject != 0 {
			continue
		}
		out = append(out, defaultRoute{iface: f[0], metric: metric})
	}
	return out, nil
}

// parseIPv6Route reads the IPv6 table in the format of /proc/net/ipv6_route and
// returns its usable default routes in file order. Each row has ten fields:
// destination and prefix length, source and source prefix length, next hop,
// metric, refcount, use, flags and device. A row whose source prefix is not
// empty is source-specific and is skipped, like a row that is not up.
func parseIPv6Route(data []byte) ([]defaultRoute, error) {
	allZero := strings.Repeat("0", 32)
	var out []defaultRoute
	for i, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if len(f) != 10 {
			return nil, fmt.Errorf("host: /proc/net/ipv6_route line %d: %d fields, want 10", i+1, len(f))
		}
		metric, err := strconv.ParseUint(f[5], 16, 32)
		if err != nil {
			return nil, fmt.Errorf("host: /proc/net/ipv6_route line %d: metric: %w", i+1, err)
		}
		flags, err := strconv.ParseUint(f[8], 16, 32)
		if err != nil {
			return nil, fmt.Errorf("host: /proc/net/ipv6_route line %d: flags: %w", i+1, err)
		}
		if f[0] != allZero || f[1] != "00" || f[3] != "00" {
			continue
		}
		if flags&rtfUp == 0 || flags&rtfReject != 0 {
			continue
		}
		out = append(out, defaultRoute{iface: f[9], metric: int(metric)})
	}
	return out, nil
}

// parseOpenWrtRelease reads KEY=VALUE lines. A value may be single-quoted,
// double-quoted or bare. Blank lines, comments and lines without '=' are skipped.
func parseOpenWrtRelease(data []byte) map[string]string {
	out := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		key, val, ok := strings.Cut(line, "=")
		if !ok || strings.HasPrefix(line, "#") {
			continue
		}
		if len(val) >= 2 && (val[0] == '\'' || val[0] == '"') && val[len(val)-1] == val[0] {
			val = val[1 : len(val)-1]
		}
		out[strings.TrimSpace(key)] = val
	}
	return out
}

// validIface reports whether name can be a Linux interface name (at most 15
// bytes) and is safe to place in a path.
func validIface(name string) bool {
	if name == "" || len(name) > 15 || name == "." || name == ".." {
		return false
	}
	return !strings.ContainsAny(name, "/\x00")
}

// lowestMetric returns the interface of the route with the lowest metric. On a
// tie the first route in file order wins.
func lowestMetric(routes []defaultRoute) (string, bool) {
	if len(routes) == 0 {
		return "", false
	}
	best := routes[0]
	for _, r := range routes[1:] {
		if r.metric < best.metric {
			best = r
		}
	}
	return best.iface, true
}

// readRoutes parses one routing table under Root. A missing file is an empty
// table: a kernel built without IPv6 has no ipv6_route.
func readRoutes(rel string, parse func([]byte) ([]defaultRoute, error)) ([]defaultRoute, error) {
	data, err := os.ReadFile(filepath.Join(Root, rel))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return parse(data)
}

// DefaultRouteIface returns the interface that carries the default route. The
// IPv4 table decides when it has a usable default route; the IPv6 table is
// read only when it does not. Within a table the lowest metric wins.
// ErrNoDefaultRoute means neither table has one.
func DefaultRouteIface() (string, error) {
	v4, err := readRoutes("proc/net/route", parseProcRoute)
	if err != nil {
		return "", err
	}
	if iface, ok := lowestMetric(v4); ok {
		return iface, nil
	}
	v6, err := readRoutes("proc/net/ipv6_route", parseIPv6Route)
	if err != nil {
		return "", err
	}
	if iface, ok := lowestMetric(v6); ok {
		return iface, nil
	}
	return "", ErrNoDefaultRoute
}

// OperState returns the operational state of dev as the kernel reports it in
// sys/class/net/<dev>/operstate, for example "up", "down" or "unknown".
func OperState(dev string) (string, error) {
	if !validIface(dev) {
		return "", fmt.Errorf("host: invalid interface name %q", dev)
	}
	b, err := os.ReadFile(filepath.Join(Root, "sys", "class", "net", dev, "operstate"))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// OpenWrtVersion returns DISTRIB_RELEASE from etc/openwrt_release.
func OpenWrtVersion() (string, error) {
	data, err := os.ReadFile(filepath.Join(Root, "etc", "openwrt_release"))
	if err != nil {
		return "", err
	}
	v := parseOpenWrtRelease(data)["DISTRIB_RELEASE"]
	if v == "" {
		return "", errors.New("host: DISTRIB_RELEASE missing from etc/openwrt_release")
	}
	return v, nil
}

// BootID returns the kernel's boot ID from proc/sys/kernel/random/boot_id. The
// kernel writes it as a UUID; the hyphens are removed before decoding.
func BootID() (ids.BootID, error) {
	data, err := os.ReadFile(filepath.Join(Root, "proc", "sys", "kernel", "random", "boot_id"))
	if err != nil {
		return ids.BootID{}, err
	}
	var id ids.BootID
	if err := id.UnmarshalText([]byte(strings.ReplaceAll(strings.TrimSpace(string(data)), "-", ""))); err != nil {
		return ids.BootID{}, fmt.Errorf("host: boot_id: %w", err)
	}
	return id, nil
}

// RouteWatch remembers the interface that carries the default route and
// reports when it moves to another one. The first Tick only sets the
// baseline. A moment with no default route is not a switch, and the last
// interface seen stays the reference, so a flap through "no route" from wan
// to wwan reports one switch. It is not safe for concurrent use.
type RouteWatch struct {
	last string
	seen bool
}

// Tick reads the default route. switched is true when it now uses an
// interface other than the last one seen; from and to name the two.
func (w *RouteWatch) Tick() (switched bool, from, to string) {
	cur, err := DefaultRouteIface()
	if err != nil {
		return false, "", ""
	}
	if !w.seen {
		w.seen, w.last = true, cur
		return false, "", ""
	}
	if cur == w.last {
		return false, "", ""
	}
	from, w.last = w.last, cur
	return true, from, cur
}
