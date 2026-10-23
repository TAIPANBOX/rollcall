// Package config reads rollcall's UCI configuration, and the parts of the
// firewall, network and system configuration it depends on.
//
// /etc/config/rollcall holds exactly one section of type rollcall:
//
//	config rollcall 'main'
//		option site 'Home'                  # free text, at most 64 printable characters
//		list peer_zone 'lan'                # firewall zones peers are reached in (default lan);
//		                                    # a zone facing the internet needs static peers
//		list peer '192.0.2.10'              # static peer: IP or IP:port ([v6]:port); default port = port
//		option port '7432'                  # UDP and TCP, 1024..65535
//		option heartbeat '5'                # seconds
//		option silent_after '30'            # seconds, at least 3 x heartbeat
//		list probe_target 'dns.google:443'  # IP, or host:port
//		option icmp '0'
//		option sender '0'
//		option ntfy_url 'https://ntfy.sh/topic'
//		option allow_insecure_lan '0'       # plain http to a private IP literal
//
// peer_zone, peer and probe_target are lists and only lists, so each entry
// is one zone, one peer or one target and never several words that the
// package's firewall rule builder (the firewall command of
// /etc/init.d/rollcall) and the daemon could read differently. Any other
// option or section is refused, so a typing mistake never passes unnoticed,
// and secrets never belong in this file.
//
// A peer zone faces the internet when the firewall masquerades it, or when
// it is or holds wan, wan6 or wwan; such a zone is accepted only together
// with static peers, and its firewall rule admits only their addresses.
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Defaults and limits.
const (
	DefaultPort        = 7432
	DefaultHeartbeat   = 5 * time.Second
	DefaultSilentAfter = 30 * time.Second
	DefaultPeerZone    = "lan"

	MinPort         = 1024
	MaxPeerZones    = 8
	MaxPeers        = 32 // the roster's limit
	MaxProbeTargets = 8
	MaxSiteLen      = 64     // characters
	maxSeconds      = 86_400 // heartbeat and silent_after: one day at most
)

// Where Config.TZ came from.
const (
	TZSystem  = "zonename" // the zonename option of /etc/config/system
	TZDefault = "default"  // UTC, because the system names no zone
)

// Config is rollcall's configuration.
type Config struct {
	Site             string
	PeerZones        []string
	Peers            []netip.AddrPort
	Port             int
	Heartbeat        time.Duration
	SilentAfter      time.Duration
	ProbeTargets     []string
	ICMP             bool
	Sender           bool
	NtfyURL          string
	AllowInsecureLAN bool
	TZ               string // IANA zone name, for example Europe/Kyiv
	TZSource         string // TZSystem or TZDefault

	// zones maps every firewall zone to its network devices. Load fills
	// it; a Config built by hand has none, so Validate finds every peer
	// zone unknown.
	zones map[string][]string
	// external marks the firewall zones that face the internet (externalZones). Load fills it;
	// the names wan, wan6 and wwan count as external without it.
	external map[string]bool
}

// Load reads the four files and returns the validated configuration and the
// network devices of each peer zone. The map holds exactly the peer zones,
// so a caller cannot listen in any other zone by mistake.
//
// A firewall zone names netifd interfaces (option network, list network),
// and devices directly (list device); /etc/config/network maps each
// interface to its device (option device, or option ifname on older
// configurations; a bridge of the old form is br-<name>; @name refers to
// another interface; a WireGuard interface is its own device). Wildcard
// devices (tun+) are skipped. A missing system file, or one without a
// zonename, gives UTC.
func Load(rollcallPath, firewallPath, systemPath, networkPath string) (Config, map[string][]string, error) {
	rc, err := parseFile(rollcallPath)
	if err != nil {
		return Config{}, nil, err
	}
	fw, err := parseFile(firewallPath)
	if err != nil {
		return Config{}, nil, err
	}
	nw, err := parseFile(networkPath)
	if err != nil {
		return Config{}, nil, err
	}
	cfg, err := fromSections(rc)
	if err != nil {
		return Config{}, nil, fmt.Errorf("%s: %w", rollcallPath, err)
	}
	cfg.TZ, cfg.TZSource, err = timeZone(systemPath)
	if err != nil {
		return Config{}, nil, err
	}
	cfg.zones = zoneDevices(fw, nw)
	cfg.external = externalZones(fw)
	if err := cfg.Validate(); err != nil {
		return Config{}, nil, fmt.Errorf("%s: %w", rollcallPath, err)
	}
	peer := make(map[string][]string, len(cfg.PeerZones))
	for _, z := range cfg.PeerZones {
		peer[z] = slices.Clone(cfg.zones[z])
	}
	return cfg, peer, nil
}

func parseFile(path string) ([]Section, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	secs, err := ParseUCI(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return secs, nil
}

var (
	scalarKeys = map[string]bool{
		"site": true, "port": true, "heartbeat": true, "silent_after": true, "icmp": true,
		"sender": true, "ntfy_url": true, "allow_insecure_lan": true,
	}
	listKeys = map[string]bool{"peer_zone": true, "peer": true, "probe_target": true}
)

// fromSections builds a Config from the sections of /etc/config/rollcall.
// It does not validate across fields; Validate does.
func fromSections(secs []Section) (Config, error) {
	var main *Section
	for i := range secs {
		s := &secs[i]
		if s.Type != "rollcall" {
			return Config{}, fmt.Errorf("line %d: unknown section type %q", s.Line, s.Type)
		}
		if main != nil {
			return Config{}, fmt.Errorf("line %d: a second 'config rollcall' section (the first is at line %d)", s.Line, main.Line)
		}
		main = s
	}
	if main == nil {
		return Config{}, errors.New("no 'config rollcall' section")
	}
	at := func(format string, args ...any) error {
		return fmt.Errorf("line %d: %s", main.Line, fmt.Sprintf(format, args...))
	}
	for k := range main.Options {
		if listKeys[k] {
			return Config{}, at("%q must be a list (list %s '...'), not an option", k, k)
		}
		if !scalarKeys[k] {
			return Config{}, at("unknown option %q", k)
		}
	}
	for k := range main.Lists {
		if scalarKeys[k] {
			return Config{}, at("%q must be an option, not a list", k)
		}
		if !listKeys[k] {
			return Config{}, at("unknown option %q", k)
		}
	}
	words := func(k string) []string { return slices.Clone(main.Lists[k]) }

	cfg := Config{
		Site:         main.Options["site"],
		PeerZones:    words("peer_zone"),
		Port:         DefaultPort,
		Heartbeat:    DefaultHeartbeat,
		SilentAfter:  DefaultSilentAfter,
		ProbeTargets: words("probe_target"),
		NtfyURL:      main.Options["ntfy_url"],
	}
	if cfg.PeerZones == nil {
		cfg.PeerZones = []string{DefaultPeerZone}
	}
	if v, ok := main.Options["port"]; ok {
		p, err := strconv.Atoi(v)
		if err != nil {
			return Config{}, at("port %q is not a number", v)
		}
		cfg.Port = p
	}
	for _, d := range []struct {
		key string
		dst *time.Duration
	}{{"heartbeat", &cfg.Heartbeat}, {"silent_after", &cfg.SilentAfter}} {
		v, ok := main.Options[d.key]
		if !ok {
			continue
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > maxSeconds {
			return Config{}, at("%s %q must be a whole number of seconds from 1 to %d", d.key, v, maxSeconds)
		}
		*d.dst = time.Duration(n) * time.Second
	}
	for _, b := range []struct {
		key string
		dst *bool
	}{{"icmp", &cfg.ICMP}, {"sender", &cfg.Sender}, {"allow_insecure_lan", &cfg.AllowInsecureLAN}} {
		v, ok := main.Options[b.key]
		if !ok {
			continue
		}
		x, err := parseBool(v)
		if err != nil {
			return Config{}, at("%s: %v", b.key, err)
		}
		*b.dst = x
	}
	for _, p := range words("peer") {
		ap, err := parsePeer(p, cfg.Port)
		if err != nil {
			return Config{}, at("%v", err)
		}
		cfg.Peers = append(cfg.Peers, ap)
	}
	return cfg, nil
}

// parsePeer reads a static peer: an IP address, or IP:port with brackets
// around an IPv6 address. Without a port the peer uses port.
func parsePeer(s string, port int) (netip.AddrPort, error) {
	if a, err := netip.ParseAddr(s); err == nil {
		return netip.AddrPortFrom(a, uint16(port)), nil
	}
	host, ps, err := net.SplitHostPort(s)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("peer %q is not an IP address or IP:port (host names are not supported)", s)
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("peer %q is not an IP address or IP:port (host names are not supported)", s)
	}
	n, err := strconv.Atoi(ps)
	if err != nil || n < 1 || n > 65535 {
		return netip.AddrPort{}, fmt.Errorf("peer %q: port must be from 1 to 65535", s)
	}
	return netip.AddrPortFrom(a, uint16(n)), nil
}

// parseBool reads a uci boolean.
func parseBool(v string) (bool, error) {
	switch v {
	case "1", "yes", "on", "true", "enabled":
		return true, nil
	case "0", "no", "off", "false", "disabled":
		return false, nil
	}
	return false, fmt.Errorf("%q is not a boolean (use 1 or 0)", v)
}

// timeZone reads the zonename of the first system section. uci writes
// spaces where the zone database has underscores.
func timeZone(path string) (tz, source string, err error) {
	secs, err := parseFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return "UTC", TZDefault, nil
	}
	if err != nil {
		return "", "", err
	}
	for _, s := range secs {
		if s.Type != "system" {
			continue
		}
		name := strings.ReplaceAll(s.Options["zonename"], " ", "_")
		if name == "" {
			break
		}
		if !validTZ(name) {
			return "", "", fmt.Errorf("%s: line %d: zonename %q is not a time zone name", path, s.Line, name)
		}
		return name, TZSystem, nil
	}
	return "UTC", TZDefault, nil
}

// validTZ accepts an IANA zone name: segments of [A-Za-z0-9_+-] joined by
// slashes, none of them empty, "." or "..".
func validTZ(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, seg := range strings.Split(s, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
		for i := 0; i < len(seg); i++ {
			c := seg[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '+' || c == '-') {
				return false
			}
		}
	}
	return true
}

// zoneDevices maps each named firewall zone to its sorted network devices.
func zoneDevices(fw, nw []Section) map[string][]string {
	ifaces := map[string]Section{}
	for _, s := range nw {
		if s.Type == "interface" && s.Name != "" {
			ifaces[s.Name] = s
		}
	}
	zones := map[string][]string{}
	for _, s := range fw {
		name := s.Options["name"]
		if s.Type != "zone" || name == "" {
			continue
		}
		devs := zones[name]
		nets := append(slices.Clone(s.Lists["network"]), strings.Fields(s.Options["network"])...)
		for _, n := range nets {
			devs = append(devs, ifaceDevices(n, ifaces, 0)...)
		}
		direct := append(slices.Clone(s.Lists["device"]), strings.Fields(s.Options["device"])...)
		for _, d := range direct {
			if !strings.ContainsAny(d, "+*") {
				devs = append(devs, d)
			}
		}
		devs = slices.DeleteFunc(devs, func(d string) bool { return !validDevice(d) })
		slices.Sort(devs)
		zones[name] = slices.Compact(devs)
	}
	return zones
}

// uplinkNames are the names OpenWrt gives its upstream zone and interfaces: the wan zone, the
// wan and wan6 interfaces, and wwan for a wireless uplink. A zone with one of these names, or
// holding an interface with one of them, faces the internet.
var uplinkNames = map[string]bool{"wan": true, "wan6": true, "wwan": true}

// externalZones marks the firewall zones that face the internet: a zone that masquerades
// (masq or masq6 set to anything uci does not read as off: a value nobody can read is taken as
// on, so a doubtful zone needs static peers), or one holding a network named wan, wan6 or
// wwan. A name given to several zone sections is external when any of them is. The names wan,
// wan6 and wwan themselves are external in Validate even without this map. The package's
// firewall rule builder (packaging/files/etc/init.d/rollcall, firewall) applies the same rule.
func externalZones(fw []Section) map[string]bool {
	ext := map[string]bool{}
	for _, s := range fw {
		name := s.Options["name"]
		if s.Type != "zone" || name == "" {
			continue
		}
		for _, k := range []string{"masq", "masq6"} {
			if v, ok := s.Options[k]; ok {
				if on, err := parseBool(v); on || err != nil {
					ext[name] = true
				}
			}
		}
		nets := append(slices.Clone(s.Lists["network"]), strings.Fields(s.Options["network"])...)
		for _, n := range nets {
			if uplinkNames[n] {
				ext[name] = true
			}
		}
	}
	return ext
}

// isExternal reports whether peer zone z faces the internet.
func (c Config) isExternal(z string) bool {
	return uplinkNames[z] || c.external[z]
}

// maxAliasDepth bounds @name references, so a cycle ends.
const maxAliasDepth = 4

// ifaceDevices returns the devices of one netifd interface.
func ifaceDevices(name string, ifaces map[string]Section, depth int) []string {
	s, ok := ifaces[name]
	if !ok || depth > maxAliasDepth {
		return nil
	}
	alias := func(word string) ([]string, bool) {
		if ref, ok := strings.CutPrefix(word, "@"); ok {
			return ifaceDevices(ref, ifaces, depth+1), true
		}
		return nil, false
	}
	if d := s.Options["device"]; d != "" {
		if devs, ok := alias(d); ok {
			return devs
		}
		return []string{d}
	}
	if s.Options["type"] == "bridge" {
		return []string{"br-" + name}
	}
	if f := strings.Fields(s.Options["ifname"]); len(f) > 0 {
		var out []string
		for _, w := range f {
			if devs, ok := alias(w); ok {
				out = append(out, devs...)
			} else {
				out = append(out, w)
			}
		}
		return out
	}
	if s.Options["proto"] == "wireguard" {
		return []string{name}
	}
	return nil
}

// validDevice is the kernel's rule for an interface name: 1 to 15 bytes,
// no slash, no white space, not "." or "..".
func validDevice(d string) bool {
	if d == "" || len(d) > 15 || d == "." || d == ".." {
		return false
	}
	for i := 0; i < len(d); i++ {
		if d[i] == '/' || d[i] <= ' ' || d[i] == 0x7f {
			return false
		}
	}
	return true
}

// Validate checks the configuration as a whole and reports every problem it
// finds, joined.
func (c Config) Validate() error {
	var errs []error
	bad := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	if c.Port < MinPort || c.Port > 65535 {
		bad("port %d must be from %d to 65535", c.Port, MinPort)
	}
	if c.Heartbeat <= 0 {
		bad("heartbeat %s must be positive", c.Heartbeat)
	}
	if c.SilentAfter <= 0 {
		bad("silent_after %s must be positive", c.SilentAfter)
	} else if c.Heartbeat > 0 && c.SilentAfter < 3*c.Heartbeat {
		bad("silent_after %s must be at least 3 x heartbeat (%s)", c.SilentAfter, 3*c.Heartbeat)
	}

	switch {
	case len(c.PeerZones) == 0:
		bad("no peer zone")
	case len(c.PeerZones) > MaxPeerZones:
		bad("%d peer zones; at most %d", len(c.PeerZones), MaxPeerZones)
	}
	seen := map[string]bool{}
	for _, z := range c.PeerZones {
		if seen[z] {
			bad("peer zone %q is listed twice", z)
			continue
		}
		seen[z] = true
		if c.isExternal(z) && len(c.Peers) == 0 {
			bad("peer zone %q faces the internet (it masquerades, or it is or holds wan, wan6 or wwan) and is allowed only together with static peers, which its firewall rule then admits alone", z)
		}
		devs, ok := c.zones[z]
		switch {
		case !ok:
			bad("unknown peer zone %q (no such zone in the firewall configuration)", z)
		case len(devs) == 0:
			bad("peer zone %q has no network device", z)
		}
	}

	if len(c.Peers) > MaxPeers {
		bad("%d static peers; at most %d", len(c.Peers), MaxPeers)
	}
	peers := map[netip.AddrPort]bool{}
	for _, p := range c.Peers {
		if err := checkPeer(p); err != nil {
			errs = append(errs, err)
		}
		if peers[p] {
			bad("static peer %s is listed twice", p)
		}
		peers[p] = true
	}

	if len(c.ProbeTargets) > MaxProbeTargets {
		bad("%d probe targets; at most %d", len(c.ProbeTargets), MaxProbeTargets)
	}
	for _, p := range c.ProbeTargets {
		if err := checkProbeTarget(p); err != nil {
			errs = append(errs, err)
		}
	}

	if err := checkNtfy(c.NtfyURL, c.AllowInsecureLAN); err != nil {
		errs = append(errs, err)
	}
	if err := checkSite(c.Site); err != nil {
		errs = append(errs, err)
	}
	if !validTZ(c.TZ) {
		bad("time zone %q is not a zone name", c.TZ)
	}
	return errors.Join(errs...)
}

func checkPeer(p netip.AddrPort) error {
	a := p.Addr()
	var why string
	switch {
	case !a.IsValid():
		why = "is not an address"
	case a.Is4In6():
		why = "is an IPv4-mapped IPv6 address; write the IPv4 address"
	case a.IsUnspecified():
		why = "is the unspecified address"
	case a.IsMulticast():
		why = "is a multicast address"
	case a == netip.AddrFrom4([4]byte{255, 255, 255, 255}):
		why = "is the broadcast address"
	case a.Is6() && a.IsLinkLocalUnicast() && a.Zone() == "":
		why = "is link-local and needs a zone (fe80::1%br-lan)"
	case p.Port() == 0:
		why = "has port 0"
	default:
		return nil
	}
	return fmt.Errorf("static peer %s %s", p, why)
}

// checkProbeTarget accepts an IP address, or host:port where host is an IP
// address or a DNS name.
func checkProbeTarget(s string) error {
	bad := func(why string) error { return fmt.Errorf("probe target %q %s", s, why) }
	if a, err := netip.ParseAddr(s); err == nil {
		return checkProbeAddr(a, bad)
	}
	host, ps, err := net.SplitHostPort(s)
	if err != nil {
		return bad("is not an IP address or host:port")
	}
	n, err := strconv.Atoi(ps)
	if err != nil || n < 1 || n > 65535 {
		return bad("needs a port from 1 to 65535")
	}
	if a, err := netip.ParseAddr(host); err == nil {
		return checkProbeAddr(a, bad)
	}
	if !validHostname(host) {
		return bad("does not name a valid host")
	}
	return nil
}

func checkProbeAddr(a netip.Addr, bad func(string) error) error {
	switch {
	case a.Zone() != "":
		return bad("carries a zone; internet probes need a global address")
	case a.IsUnspecified(), a.IsMulticast():
		return bad("is not a unicast address")
	}
	return nil
}

// validHostname is the RFC 1123 rule: labels of letters, digits and inner
// hyphens, 1 to 63 bytes each, 253 bytes in all, an optional final dot.
func validHostname(h string) bool {
	h = strings.TrimSuffix(h, ".")
	if h == "" || len(h) > 253 {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// checkNtfy accepts no URL, an https URL, or plain http to a private,
// link-local or loopback IP literal when allowInsecureLAN is set. The URL
// carries no user, query or fragment, so no credential ends up in UCI.
func checkNtfy(raw string, allowInsecureLAN bool) error {
	if raw == "" {
		return nil
	}
	bad := func(why string) error { return fmt.Errorf("ntfy_url %s", why) }
	for i := 0; i < len(raw); i++ {
		if raw[i] <= ' ' || raw[i] >= 0x7f {
			return bad("may contain only printable ASCII without spaces")
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		return bad("is not a valid URL")
	}
	switch {
	case u.Scheme != "https" && u.Scheme != "http":
		return bad("must use https")
	case u.User != nil:
		return bad("may not carry a user or password; the access token is stored apart")
	case u.RawQuery != "" || u.ForceQuery:
		return bad("may not carry a query; the access token is stored apart")
	case u.Fragment != "" || strings.Contains(raw, "#"):
		return bad("may not carry a fragment")
	case u.Hostname() == "":
		return bad("needs a host")
	case strings.Trim(u.Path, "/") == "":
		return bad("needs a topic in its path")
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return bad("needs a port from 1 to 65535")
		}
	}
	if u.Scheme == "https" {
		return nil
	}
	if !allowInsecureLAN {
		return bad("uses plain http; that needs allow_insecure_lan and a private IP address")
	}
	a, err := netip.ParseAddr(u.Hostname())
	if err != nil {
		return bad("uses plain http, which needs an IP address, not a host name")
	}
	switch {
	case a.Is4In6():
		return bad("uses an IPv4-mapped IPv6 address; write the IPv4 address")
	case a.IsPrivate(), a.IsLinkLocalUnicast(), a.IsLoopback():
		return nil
	}
	return bad("uses plain http, which is allowed only to private, link-local or loopback addresses")
}

func checkSite(s string) error {
	if !utf8.ValidString(s) {
		return errors.New("site is not valid UTF-8")
	}
	if n := utf8.RuneCountInString(s); n > MaxSiteLen {
		return fmt.Errorf("site has %d characters; at most %d", n, MaxSiteLen)
	}
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return fmt.Errorf("site contains the non-printable character %U", r)
		}
	}
	return nil
}
