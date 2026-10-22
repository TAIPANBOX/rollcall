package config

import (
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func testZones() map[string][]string {
	return map[string][]string{
		"lan":   {"br-lan"},
		"wan":   {"eth1"},
		"guest": {"br-guest"},
		"empty": {},
	}
}

// validConfig is the default configuration with the zones a firewall
// configuration would have given it.
func validConfig() Config {
	return Config{
		PeerZones:   []string{"lan"},
		Port:        DefaultPort,
		Heartbeat:   DefaultHeartbeat,
		SilentAfter: DefaultSilentAfter,
		TZ:          "UTC",
		TZSource:    TZDefault,
		zones:       testZones(),
	}
}

func wantInvalid(t *testing.T, c Config, fragment string) {
	t.Helper()
	err := c.Validate()
	if err == nil {
		t.Fatalf("Validate accepted %+v; want an error about %q", c, fragment)
	}
	if !strings.Contains(err.Error(), fragment) {
		t.Fatalf("Validate error %q does not mention %q", err, fragment)
	}
}

func wantValid(t *testing.T, c Config) {
	t.Helper()
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate(%+v): %v", c, err)
	}
}

func TestValidateAcceptsDefaults(t *testing.T) {
	wantValid(t, validConfig())
	if DefaultPort != 7432 || DefaultHeartbeat != 5*time.Second || DefaultSilentAfter != 30*time.Second {
		t.Fatalf("defaults changed: port %d, heartbeat %s, silent after %s", DefaultPort, DefaultHeartbeat, DefaultSilentAfter)
	}
}

func TestValidateRejectsWANZone(t *testing.T) {
	c := validConfig()
	c.PeerZones = []string{"lan", "wan"}
	wantInvalid(t, c, `peer zone "wan"`)

	c.PeerZones = []string{"wan"}
	wantInvalid(t, c, `peer zone "wan"`)

	c.Peers = []netip.AddrPort{netip.MustParseAddrPort("192.0.2.10:7432")}
	wantValid(t, c)
	c.PeerZones = []string{"lan", "wan"}
	wantValid(t, c)
}

func TestValidatePort(t *testing.T) {
	for _, p := range []int{-1, 0, 80, 1023, 65536, 100000} {
		c := validConfig()
		c.Port = p
		wantInvalid(t, c, "port")
	}
	for _, p := range []int{1024, 7432, 65535} {
		c := validConfig()
		c.Port = p
		wantValid(t, c)
	}
}

func TestValidateRejectsUnknownZone(t *testing.T) {
	c := validConfig()
	c.PeerZones = []string{"lan", "dmz"}
	wantInvalid(t, c, `unknown peer zone "dmz"`)

	// A configuration built by hand has no firewall zones at all: every
	// peer zone is unknown.
	c = validConfig()
	c.zones = nil
	wantInvalid(t, c, `unknown peer zone "lan"`)

	c = validConfig()
	c.PeerZones = []string{"empty"}
	wantInvalid(t, c, `peer zone "empty" has no network device`)
}

func TestValidatePeerZoneList(t *testing.T) {
	c := validConfig()
	c.PeerZones = nil
	wantInvalid(t, c, "no peer zone")

	c.PeerZones = []string{"lan", "lan"}
	wantInvalid(t, c, `peer zone "lan" is listed twice`)

	c = validConfig()
	for i := 0; i <= MaxPeerZones; i++ {
		c.PeerZones = append(c.PeerZones, "guest")
	}
	wantInvalid(t, c, "peer zones")
}

func TestValidateTiming(t *testing.T) {
	cases := []struct {
		name              string
		heartbeat, silent time.Duration
		ok                bool
		fragment          string
	}{
		{"defaults", 5 * time.Second, 30 * time.Second, true, ""},
		{"exactly three heartbeats", 5 * time.Second, 15 * time.Second, true, ""},
		{"one second", time.Second, 3 * time.Second, true, ""},
		{"under three heartbeats", 5 * time.Second, 15*time.Second - 1, false, "silent_after"},
		{"zero heartbeat", 0, 30 * time.Second, false, "heartbeat"},
		{"negative heartbeat", -time.Second, 30 * time.Second, false, "heartbeat"},
		{"zero silent_after", 5 * time.Second, 0, false, "silent_after"},
		{"negative silent_after", 5 * time.Second, -30 * time.Second, false, "silent_after"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := validConfig()
			c.Heartbeat, c.SilentAfter = tc.heartbeat, tc.silent
			if tc.ok {
				wantValid(t, c)
			} else {
				wantInvalid(t, c, tc.fragment)
			}
		})
	}
}

func TestValidatePeers(t *testing.T) {
	good := []string{"192.0.2.10:7432", "[2001:db8::1]:7432", "[fe80::1%br-lan]:7432", "10.0.0.1:1"}
	for _, p := range good {
		c := validConfig()
		c.Peers = []netip.AddrPort{netip.MustParseAddrPort(p)}
		wantValid(t, c)
	}
	bad := map[string]string{
		"0.0.0.0:7432":            "unspecified",
		"[::]:7432":               "unspecified",
		"224.0.0.1:7432":          "multicast",
		"[ff02::114]:7432":        "multicast",
		"[::ffff:192.0.2.1]:7432": "IPv4-mapped",
		"192.0.2.10:0":            "port",
		"[fe80::1]:7432":          "zone",
		"255.255.255.255:7432":    "broadcast",
	}
	for p, fragment := range bad {
		c := validConfig()
		c.Peers = []netip.AddrPort{netip.MustParseAddrPort(p)}
		wantInvalid(t, c, fragment)
	}

	c := validConfig()
	c.Peers = []netip.AddrPort{{}}
	wantInvalid(t, c, "not an address")

	c = validConfig()
	c.Peers = []netip.AddrPort{netip.MustParseAddrPort("192.0.2.10:7432"), netip.MustParseAddrPort("192.0.2.10:7432")}
	wantInvalid(t, c, "twice")

	c = validConfig()
	for i := 0; i <= MaxPeers; i++ {
		c.Peers = append(c.Peers, netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, 2, byte(i + 1)}), 7432))
	}
	wantInvalid(t, c, "static peers")
}

func TestValidateProbeTargets(t *testing.T) {
	good := []string{
		"1.1.1.1", "2606:4700:4700::1111", "1.1.1.1:53", "dns.google:443",
		"[2606:4700:4700::1111]:443", "example.com.:443", "a-b.example:853",
	}
	for _, p := range good {
		c := validConfig()
		c.ProbeTargets = []string{p}
		wantValid(t, c)
	}
	bad := []string{
		"", "dns.google", "dns.google:0", "dns.google:65536", "dns.google:abc", "dns.google:",
		":443", "-bad.example:443", "bad-.example:443", "a..b:443", "a_b.example:443",
		"fe80::1%eth0", "[fe80::1%eth0]:443", "0.0.0.0", "224.0.0.1", "[::]:443",
		"1.1.1.1:53:53", "http://1.1.1.1", strings.Repeat("a", 64) + ".example:443",
		"has space:443",
	}
	for _, p := range bad {
		c := validConfig()
		c.ProbeTargets = []string{p}
		wantInvalid(t, c, "probe target")
	}

	c := validConfig()
	for i := 0; i <= MaxProbeTargets; i++ {
		c.ProbeTargets = append(c.ProbeTargets, "1.1.1.1")
	}
	wantInvalid(t, c, "probe targets")
}

func TestValidateNtfyURL(t *testing.T) {
	cases := []struct {
		url   string
		lan   bool
		ok    bool
		about string
	}{
		{"", false, true, ""},
		{"https://ntfy.sh/rollcall", false, true, ""},
		{"https://ntfy.example.com:8443/home/alerts", false, true, ""},
		{"HTTPS://ntfy.sh/rollcall", false, true, ""},
		{"http://192.168.1.5/rollcall", true, true, ""},
		{"http://10.0.0.2:8080/rollcall", true, true, ""},
		{"http://172.16.0.9/rollcall", true, true, ""},
		{"http://127.0.0.1/rollcall", true, true, ""},
		{"http://169.254.1.1/rollcall", true, true, ""},
		{"http://[fd00::5]/rollcall", true, true, ""},
		{"http://[fe80::1%25br-lan]/rollcall", true, true, ""},
		{"http://[::1]/rollcall", true, true, ""},

		{"http://192.168.1.5/rollcall", false, false, "allow_insecure_lan"},
		{"http://ntfy.lan/rollcall", true, false, "IP address"},
		{"http://8.8.8.8/rollcall", true, false, "private"},
		{"http://172.32.0.1/rollcall", true, false, "private"},
		{"http://0.0.0.0/rollcall", true, false, "private"},
		{"http://[::ffff:192.168.1.5]/rollcall", true, false, "IPv4-mapped"},
		{"ftp://ntfy.sh/rollcall", false, false, "https"},
		{"ntfy.sh/rollcall", false, false, "https"},
		{"https://user:secret@ntfy.sh/rollcall", false, false, "user"},
		{"https://ntfy.sh/rollcall?auth=x", false, false, "query"},
		{"https://ntfy.sh/rollcall#x", false, false, "fragment"},
		{"https://ntfy.sh", false, false, "topic"},
		{"https://ntfy.sh/", false, false, "topic"},
		{"https:///rollcall", false, false, "host"},
		{"https://ntfy.sh/a b", false, false, "ntfy_url"},
		{"https://ntfy.sh:0/rollcall", false, false, "port"},
		{"https://ntfy.sh:99999/rollcall", false, false, "port"},
		{"https://ntfy.sh:abc/rollcall", false, false, "ntfy_url"},
	}
	for _, tc := range cases {
		c := validConfig()
		c.NtfyURL, c.AllowInsecureLAN = tc.url, tc.lan
		if tc.ok {
			wantValid(t, c)
		} else {
			wantInvalid(t, c, tc.about)
		}
	}
}

func TestValidateSite(t *testing.T) {
	for _, s := range []string{"", "Home", "Cottage by the lake", "\u0414\u0456\u043c", strings.Repeat("a", MaxSiteLen)} {
		c := validConfig()
		c.Site = s
		wantValid(t, c)
	}
	for _, s := range []string{"a\nb", "tab\there", "\x00", "bad \xff utf8", strings.Repeat("a", MaxSiteLen+1), "zero\u200bwidth"} {
		c := validConfig()
		c.Site = s
		wantInvalid(t, c, "site")
	}
}

func TestValidateTZ(t *testing.T) {
	for _, z := range []string{"UTC", "Europe/Kyiv", "America/Argentina/Buenos_Aires", "Etc/GMT+3", "America/Port-au-Prince"} {
		c := validConfig()
		c.TZ = z
		wantValid(t, c)
	}
	for _, z := range []string{"", "../etc/passwd", "/etc/localtime", "Europe/../x", "Europe//Kyiv", "Europe/Kyiv/", "a b", "Europe/Kyiv\n"} {
		c := validConfig()
		c.TZ = z
		wantInvalid(t, c, "time zone")
	}
}

func TestValidateReportsEveryProblem(t *testing.T) {
	c := validConfig()
	c.Port = 80
	c.Heartbeat = 0
	c.PeerZones = []string{"dmz"}
	err := c.Validate()
	if err == nil {
		t.Fatal("Validate accepted three problems")
	}
	for _, f := range []string{"port", "heartbeat", `"dmz"`} {
		if !strings.Contains(err.Error(), f) {
			t.Errorf("error %q does not mention %q", err, f)
		}
	}
}

// files writes the four configuration files into a temporary directory and
// returns their paths in Load's order. An empty text leaves that file out.
func files(t *testing.T, rollcall, firewall, system, network string) (string, string, string, string) {
	t.Helper()
	dir := t.TempDir()
	write := func(name, text string) string {
		p := filepath.Join(dir, name)
		if text != "" {
			if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return p
	}
	return write("rollcall", rollcall), write("firewall", firewall), write("system", system), write("network", network)
}

const fixtureFirewall = `config defaults
	option input 'REJECT'
	option output 'ACCEPT'

config zone
	option name 'lan'
	list network 'lan'
	list network 'iot'
	option input 'ACCEPT'

config zone
	option name 'wan'
	option network 'wan wan6'
	option masq '1'

config zone
	option name 'vpn'
	list network 'wg0'
	list device 'tailscale0'
	list device 'tun+'

config zone
	option name 'legacy'
	option network 'oldlan old2 oldalias nodev'
	list device 'averyveryverylongname0'
	list device 'a/b'

config zone
	option name 'loop'
	list network 'a'

config zone
	option name 'ghost'
	list network 'nowhere'

config zone
	option input 'DROP'

config forwarding
	option src 'lan'
	option dest 'wan'

config rule
	option name 'Allow-DHCP-Renew'
	option src 'wan'
	option proto 'udp'
	option dest_port '68'
	option target 'ACCEPT'
`

const fixtureNetwork = `config interface 'loopback'
	option device 'lo'
	option proto 'static'

config globals 'globals'
	option ula_prefix 'fd12:3456:789a::/48'

config device
	option name 'br-lan'
	option type 'bridge'
	list ports 'lan1'
	list ports 'lan2'

config interface 'lan'
	option device 'br-lan'
	option proto 'static'

config interface 'iot'
	option device 'lan3.20'

config interface 'wan'
	option device 'eth1'
	option proto 'dhcp'

config interface 'wan6'
	option device '@wan'
	option proto 'dhcpv6'

config interface 'wg0'
	option proto 'wireguard'

config interface 'oldlan'
	option type 'bridge'
	option ifname 'eth0.1 eth0.3'

config interface 'old2'
	option ifname 'eth0.2'

config interface 'oldalias'
	option ifname '@old2'

config interface 'nodev'
	option proto 'none'

config interface 'a'
	option device '@b'

config interface 'b'
	option device '@a'
`

const fixtureSystem = `config system
	option hostname 'flint2'
	option zonename 'Europe/Kyiv'
	option timezone 'EET-2EEST,M3.5.0/3,M10.5.0/4'
`

const fixtureRollcall = `config rollcall 'main'
	option site 'Home'
	list peer_zone 'lan'
	list peer_zone 'vpn'
	list peer_zone 'legacy'
	list peer_zone 'wan'
	list peer '192.0.2.10'
	list peer '[2001:db8::7]:7500'
	option port '7440'
	option heartbeat '4'
	option silent_after '20'
	list probe_target '1.1.1.1'
	list probe_target 'dns.google:443'
	option icmp '1'
	option sender 'yes'
	option ntfy_url 'http://192.168.1.5/rollcall'
	option allow_insecure_lan 'on'
`

func TestLoad(t *testing.T) {
	cfg, zones, err := Load(files(t, fixtureRollcall, fixtureFirewall, fixtureSystem, fixtureNetwork))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := Config{
		Site:      "Home",
		PeerZones: []string{"lan", "vpn", "legacy", "wan"},
		Peers: []netip.AddrPort{
			netip.MustParseAddrPort("192.0.2.10:7440"),
			netip.MustParseAddrPort("[2001:db8::7]:7500"),
		},
		Port:             7440,
		Heartbeat:        4 * time.Second,
		SilentAfter:      20 * time.Second,
		ProbeTargets:     []string{"1.1.1.1", "dns.google:443"},
		ICMP:             true,
		Sender:           true,
		NtfyURL:          "http://192.168.1.5/rollcall",
		AllowInsecureLAN: true,
		TZ:               "Europe/Kyiv",
		TZSource:         TZSystem,
	}
	got := cfg
	got.zones = nil
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Load config:\n got %+v\nwant %+v", got, want)
	}
	wantZones := map[string][]string{
		"lan":    {"br-lan", "lan3.20"},
		"vpn":    {"tailscale0", "wg0"},
		"legacy": {"br-oldlan", "eth0.2"},
		"wan":    {"eth1"},
	}
	if !reflect.DeepEqual(zones, wantZones) {
		t.Fatalf("Load zones:\n got %v\nwant %v", zones, wantZones)
	}

	// The map is the caller's: changing it does not change the config.
	zones["lan"][0] = "changed"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate after the caller changed the map: %v", err)
	}
	if cfg.zones["lan"][0] != "br-lan" {
		t.Fatalf("the returned map aliases the config's zones")
	}
}

func TestLoadDefaults(t *testing.T) {
	cfg, zones, err := Load(files(t, "config rollcall\n", fixtureFirewall, fixtureSystem, fixtureNetwork))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !reflect.DeepEqual(cfg.PeerZones, []string{"lan"}) || cfg.Port != 7432 ||
		cfg.Heartbeat != 5*time.Second || cfg.SilentAfter != 30*time.Second ||
		cfg.Peers != nil || cfg.ProbeTargets != nil || cfg.ICMP || cfg.Sender ||
		cfg.NtfyURL != "" || cfg.AllowInsecureLAN || cfg.Site != "" {
		t.Fatalf("defaults: %+v", cfg)
	}
	if !reflect.DeepEqual(zones, map[string][]string{"lan": {"br-lan", "lan3.20"}}) {
		t.Fatalf("zones: %v; want only the peer zone lan", zones)
	}
}

func TestLoadTimeZone(t *testing.T) {
	cases := []struct {
		name, system string
		tz, source   string
	}{
		{"zonename", fixtureSystem, "Europe/Kyiv", TZSystem},
		{"spaces become underscores", "config system\n\toption zonename 'America/Argentina/Buenos Aires'\n", "America/Argentina/Buenos_Aires", TZSystem},
		{"no zonename", "config system\n\toption hostname 'x'\n\toption timezone 'GMT0'\n", "UTC", TZDefault},
		{"empty zonename", "config system\n\toption zonename ''\n", "UTC", TZDefault},
		{"no system section", "config timeserver 'ntp'\n\tlist server '0.openwrt.pool.ntp.org'\n", "UTC", TZDefault},
		{"missing file", "", "UTC", TZDefault},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, _, err := Load(files(t, "config rollcall\n", fixtureFirewall, tc.system, fixtureNetwork))
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if cfg.TZ != tc.tz || cfg.TZSource != tc.source {
				t.Fatalf("TZ = %q from %q; want %q from %q", cfg.TZ, cfg.TZSource, tc.tz, tc.source)
			}
		})
	}

	_, _, err := Load(files(t, "config rollcall\n", fixtureFirewall, "config system\n\toption zonename '../../etc/passwd'\n", fixtureNetwork))
	if err == nil || !strings.Contains(err.Error(), "time zone") {
		t.Fatalf("Load with a path in zonename: %v; want a time zone error", err)
	}
}

func TestLoadPeers(t *testing.T) {
	rc := "config rollcall\n\tlist peer_zone 'wan'\n\tlist peer '192.0.2.10'\n\tlist peer '2001:db8::1'\n\tlist peer '192.0.2.11:7500'\n"
	cfg, _, err := Load(files(t, rc, fixtureFirewall, fixtureSystem, fixtureNetwork))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := []netip.AddrPort{
		netip.MustParseAddrPort("192.0.2.10:7432"),
		netip.MustParseAddrPort("[2001:db8::1]:7432"),
		netip.MustParseAddrPort("192.0.2.11:7500"),
	}
	if !reflect.DeepEqual(cfg.Peers, want) {
		t.Fatalf("Peers = %v; want %v", cfg.Peers, want)
	}
}

func TestLoadRefuses(t *testing.T) {
	cases := []struct {
		name, rollcall string
		fragment       string
	}{
		{"no rollcall section", "# nothing\n", "no 'config rollcall' section"},
		{"two rollcall sections", "config rollcall 'a'\nconfig rollcall 'b'\n", "line 2"},
		{"unknown section type", "config rollcall\nconfig telegram\n", `section type "telegram"`},
		{"unknown option", "config rollcall\n\toption token 'CANARY-123:abc'\n", `unknown option "token"`},
		{"unknown list", "config rollcall\n\tlist peers '192.0.2.1'\n", `unknown option "peers"`},
		{"scalar as a list", "config rollcall\n\tlist port '7432'\n", `"port" must be an option`},
		{"zones as an option", "config rollcall\n\toption peer_zone 'lan'\n", `"peer_zone" must be a list`},
		{"peers as an option", "config rollcall\n\tlist peer_zone 'wan'\n\toption peer '192.0.2.1'\n", `"peer" must be a list`},
		{"probes as an option", "config rollcall\n\toption probe_target '1.1.1.1 9.9.9.9'\n", `"probe_target" must be a list`},
		{"port not a number", "config rollcall\n\toption port 'abc'\n", "port"},
		{"port too low", "config rollcall\n\toption port '80'\n", "port"},
		{"heartbeat as a duration", "config rollcall\n\toption heartbeat '5s'\n", "heartbeat"},
		{"heartbeat too long", "config rollcall\n\toption heartbeat '86401'\n", "heartbeat"},
		{"silent_after negative", "config rollcall\n\toption silent_after '-30'\n", "silent_after"},
		{"silent_after too short", "config rollcall\n\toption silent_after '14'\n", "silent_after"},
		{"bad boolean", "config rollcall\n\toption icmp 'maybe'\n", "icmp"},
		{"host name peer", "config rollcall\n\tlist peer_zone 'wan'\n\tlist peer 'router.lan'\n", "peer"},
		{"peer port zero", "config rollcall\n\tlist peer_zone 'wan'\n\tlist peer '192.0.2.1:0'\n", "peer"},
		{"host name with a port", "config rollcall\n\tlist peer_zone 'wan'\n\tlist peer 'router.lan:7432'\n", "host names are not supported"},
		{"peer port out of range", "config rollcall\n\tlist peer_zone 'wan'\n\tlist peer '192.0.2.1:70000'\n", "peer"},
		{"wan without peers", "config rollcall\n\tlist peer_zone 'wan'\n", `peer zone "wan"`},
		{"unknown zone", "config rollcall\n\tlist peer_zone 'dmz'\n", `unknown peer zone "dmz"`},
		{"zone without devices", "config rollcall\n\tlist peer_zone 'ghost'\n", "no network device"},
		{"zone with a cycle", "config rollcall\n\tlist peer_zone 'loop'\n", "no network device"},
		{"insecure ntfy", "config rollcall\n\toption ntfy_url 'http://192.168.1.5/t'\n", "allow_insecure_lan"},
		{"syntax error", "config rollcall\n\toption port '7432\n", "line 2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rp, fp, sp, np := files(t, tc.rollcall, fixtureFirewall, fixtureSystem, fixtureNetwork)
			cfg, zones, err := Load(rp, fp, sp, np)
			if err == nil {
				t.Fatalf("Load accepted %q: %+v", tc.rollcall, cfg)
			}
			if !strings.Contains(err.Error(), tc.fragment) {
				t.Fatalf("Load error %q does not mention %q", err, tc.fragment)
			}
			if !strings.Contains(err.Error(), rp) {
				t.Errorf("Load error %q does not name the file %s", err, rp)
			}
			if !reflect.DeepEqual(cfg, Config{}) || zones != nil {
				t.Errorf("Load returned a config with the error: %+v %v", cfg, zones)
			}
			if strings.Contains(err.Error(), "CANARY-123:abc") {
				t.Errorf("Load error repeats an option value: %q", err)
			}
		})
	}
}

func TestLoadRefusesBadOtherFiles(t *testing.T) {
	rp, fp, sp, np := files(t, "config rollcall\n", fixtureFirewall, fixtureSystem, fixtureNetwork)
	for name, paths := range map[string][4]string{
		"missing rollcall": {rp + ".none", fp, sp, np},
		"missing firewall": {rp, fp + ".none", sp, np},
		"missing network":  {rp, fp, sp, np + ".none"},
	} {
		if _, _, err := Load(paths[0], paths[1], paths[2], paths[3]); err == nil || !strings.Contains(err.Error(), ".none") {
			t.Errorf("%s: Load error %v; want one naming the missing file", name, err)
		}
	}
	for name, which := range map[string]int{"firewall": 1, "system": 2, "network": 3} {
		paths := [4]string{rp, fp, sp, np}
		bad := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(bad, []byte("config zone\n\toption name 'lan\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		paths[which] = bad
		_, _, err := Load(paths[0], paths[1], paths[2], paths[3])
		if err == nil || !strings.Contains(err.Error(), bad) || !strings.Contains(err.Error(), "line 2") {
			t.Errorf("%s with a syntax error: Load error %v; want one naming %s line 2", name, err, bad)
		}
	}
}

func TestParseBool(t *testing.T) {
	for _, v := range []string{"1", "yes", "on", "true", "enabled"} {
		if b, err := parseBool(v); err != nil || !b {
			t.Errorf("parseBool(%q) = %v, %v; want true", v, b, err)
		}
	}
	for _, v := range []string{"0", "no", "off", "false", "disabled"} {
		if b, err := parseBool(v); err != nil || b {
			t.Errorf("parseBool(%q) = %v, %v; want false", v, b, err)
		}
	}
	for _, v := range []string{"", "2", "Yes", "y", "maybe"} {
		if _, err := parseBool(v); err == nil {
			t.Errorf("parseBool(%q) accepted", v)
		}
	}
}
