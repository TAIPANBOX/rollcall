package gates

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// fakeUCI answers `uci get` from UCI_DB (lines key=value, value as uci prints it, lists joined by
// spaces) and appends every other command to UCI_LOG. A missing key fails, as uci does.
const fakeUCI = `#!/bin/sh
[ "$1" = -q ] && shift
cmd=$1
shift
case $cmd in
get)
	exec awk -v k="$1" 'index($0, k "=") == 1 { print substr($0, length(k) + 2); found = 1; exit } END { exit !found }' "$UCI_DB"
	;;
*)
	printf '%s %s\n' "$cmd" "$*" >>"$UCI_LOG"
	;;
esac
`

// fakeLogger records the warnings the builder sends to syslog.
const fakeLogger = `#!/bin/sh
printf 'logger %s\n' "$*" >>"$UCI_LOG"
`

// firewallZones is the firewall configuration of every case: lan; wan (masq); wan2, which
// masquerades under another name; uplink, which holds the network wwan; v6up (masq6); a zone
// named wwan; guest, whose masq is off; and odd, whose masq value nobody can read.
var firewallZones = []string{
	"firewall.@zone[0]=zone", "firewall.@zone[0].name=lan", "firewall.@zone[0].network=lan",
	"firewall.@zone[1]=zone", "firewall.@zone[1].name=wan", "firewall.@zone[1].network=wan wan6", "firewall.@zone[1].masq=1",
	"firewall.@zone[2]=zone", "firewall.@zone[2].name=wan2", "firewall.@zone[2].network=lte", "firewall.@zone[2].masq=1",
	"firewall.@zone[3]=zone", "firewall.@zone[3].name=uplink", "firewall.@zone[3].network=wwan",
	"firewall.@zone[4]=zone", "firewall.@zone[4].name=v6up", "firewall.@zone[4].masq6=on",
	"firewall.@zone[5]=zone", "firewall.@zone[5].name=wwan",
	"firewall.@zone[6]=zone", "firewall.@zone[6].name=guest", "firewall.@zone[6].masq=0",
	"firewall.@zone[7]=zone", "firewall.@zone[7].name=odd", "firewall.@zone[7].masq=sometimes",
}

// firewallCase is one run of the builder: the rollcall options (nil: no rollcall section), the
// rules it must leave, and text one of its warnings must hold.
type firewallCase struct {
	name     string
	rollcall []string
	old      []string // firewall sections left by earlier runs
	want     []string // one line per rule, in order (firewallRule)
	warn     string
}

var firewallCases = []firewallCase{
	{name: "default zone is lan, default port", rollcall: []string{},
		want: []string{"src=lan port=7432"}},
	{name: "option port", rollcall: []string{"port=7500"},
		want: []string{"src=lan port=7500"}},
	{name: "port with leading zeros", rollcall: []string{"port=07500"},
		want: []string{"src=lan port=7500"}},
	{name: "port below 1024", rollcall: []string{"port=80"}, warn: "option port"},
	{name: "port not a number", rollcall: []string{"port=7o00"}, warn: "option port"},
	{name: "port too large", rollcall: []string{"port=99999"}, warn: "option port"},
	{name: "wan only to the static peers, per family",
		rollcall: []string{"peer_zone=lan wan", "peer=192.0.2.10 [2001:db8::7]:7500 198.51.100.4:7432 fe80::1%br-lan"},
		want: []string{
			"src=lan port=7432",
			"src=wan port=7432 family=ipv4 src_ip=192.0.2.10,198.51.100.4",
			"src=wan port=7432 family=ipv6 src_ip=2001:db8::7,fe80::1",
		}},
	{name: "a masquerading zone not named wan", rollcall: []string{"peer_zone=wan2", "peer=192.0.2.10"},
		want: []string{"src=wan2 port=7432 family=ipv4 src_ip=192.0.2.10"}},
	{name: "a zone holding wwan, no static peer", rollcall: []string{"peer_zone=uplink"}, warn: "faces the internet"},
	{name: "masq6 zone, no static peer", rollcall: []string{"peer_zone=v6up"}, warn: "faces the internet"},
	{name: "zone named wwan, no static peer", rollcall: []string{"peer_zone=wwan"}, warn: "faces the internet"},
	{name: "unreadable masq counts as on", rollcall: []string{"peer_zone=odd"}, warn: "faces the internet"},
	{name: "wan without a static peer, lan still opened", rollcall: []string{"peer_zone=lan wan"},
		want: []string{"src=lan port=7432"}, warn: "'wan' faces the internet"},
	{name: "masq off is internal", rollcall: []string{"peer_zone=guest"},
		want: []string{"src=guest port=7432"}},
	{name: "unknown zone", rollcall: []string{"peer_zone=dmz"}, warn: "not a zone of /etc/config/firewall"},
	{name: "a glob is not a zone", rollcall: []string{"peer_zone=*"}, warn: "not a zone name"},
	{name: "a host name peer is left out", rollcall: []string{"peer_zone=wan", "peer=router.example 192.0.2.9"},
		want: []string{"src=wan port=7432 family=ipv4 src_ip=192.0.2.9"}, warn: "not an address"},
	{name: "no rollcall section", rollcall: nil, warn: "no rollcall section"},
	{name: "earlier rules are removed", rollcall: []string{},
		old:  []string{"firewall.rollcall=rule", "firewall.rollcall_1=rule", "firewall.rollcall_2=rule"},
		want: []string{"src=lan port=7432"}},
}

// TestFirewallRuleBuilder runs the firewall command of the init script, the package's only
// firewall rule builder, against a stub uci and checks the rules it writes: one per peer zone
// (lan by default) on option port, and a zone that faces the internet opened only to the static
// peers or not at all. This holds design 4.2 and security 4.1: nothing is opened to the internet.
func TestFirewallRuleBuilder(t *testing.T) {
	root := requireRoot(t)
	script := filepath.Join(root, filepath.FromSlash(initScriptRel))
	if _, err := os.Stat(script); err != nil {
		t.Fatalf("measured nothing: %v", err)
	}
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Fatalf("measured nothing: no sh: %v", err)
	}
	bin := t.TempDir()
	writeExec(t, filepath.Join(bin, "uci"), fakeUCI)
	writeExec(t, filepath.Join(bin, "logger"), fakeLogger)

	for _, c := range firewallCases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			db := slices.Clone(firewallZones)
			db = append(db, c.old...)
			if c.rollcall != nil {
				db = append(db, "rollcall.@rollcall[0]=rollcall")
				for _, kv := range c.rollcall {
					db = append(db, "rollcall.@rollcall[0]."+kv)
				}
			}
			dbPath, logPath := filepath.Join(dir, "db"), filepath.Join(dir, "log")
			writeFile(t, dbPath, strings.Join(db, "\n")+"\n")
			writeFile(t, logPath, "")

			cmd := exec.Command(sh, "-c", `. "$1" && firewall`, "sh", script)
			cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
				"UCI_DB="+dbPath, "UCI_LOG="+logPath)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("measured nothing: the firewall command failed: %v\n%s", err, out)
			}
			data, err := os.ReadFile(logPath)
			if err != nil {
				t.Fatal(err)
			}
			got, deleted, warnings, problems := firewallRules(string(data))
			for _, p := range problems {
				t.Error(p)
			}
			if !slices.Equal(got, c.want) {
				t.Errorf("rules:\n got %q\nwant %q", got, c.want)
			}
			for _, old := range c.old {
				sec, _, _ := strings.Cut(old, "=")
				if !deleted[sec] {
					t.Errorf("earlier rule %s was not removed", sec)
				}
			}
			if c.warn != "" && !strings.Contains(warnings, c.warn) {
				t.Errorf("no warning holding %q; warnings:\n%s", c.warn, warnings)
			}
		})
	}
}

// firewallRules reads the stub's log: every rule written, as "src=Z port=P[ family=F
// src_ip=A,B]", the sections deleted, the warnings, and what is wrong in any rule (each must
// be an ACCEPT rule for UDP and TCP, and the log must end in a commit of the firewall).
func firewallRules(log string) (rules []string, deleted map[string]bool, warnings string, problems []string) {
	deleted = map[string]bool{}
	type rule struct{ opts map[string][]string }
	var order []string
	byName := map[string]*rule{}
	lines := strings.Split(strings.TrimRight(log, "\n"), "\n")
	last := ""
	for _, line := range lines {
		if line == "" {
			continue
		}
		last = line
		cmd, arg, _ := strings.Cut(line, " ")
		switch cmd {
		case "logger":
			warnings += arg + "\n"
			continue
		case "delete":
			deleted[arg] = true
			continue
		case "commit":
			continue
		}
		key, val, _ := strings.Cut(arg, "=")
		sec, opt, hasOpt := strings.Cut(strings.TrimPrefix(key, "firewall."), ".")
		if !strings.HasPrefix(key, "firewall.") {
			problems = append(problems, "the builder wrote outside the firewall configuration: "+line)
			continue
		}
		if !hasOpt {
			if val != "rule" {
				problems = append(problems, "section "+sec+" is not a rule: "+line)
			}
			if _, ok := byName[sec]; !ok {
				byName[sec] = &rule{opts: map[string][]string{}}
				order = append(order, sec)
			}
			continue
		}
		r, ok := byName[sec]
		if !ok {
			problems = append(problems, "option of a section never created: "+line)
			continue
		}
		if cmd == "set" {
			r.opts[opt] = []string{val}
		} else {
			r.opts[opt] = append(r.opts[opt], val)
		}
	}
	if last != "commit firewall" {
		problems = append(problems, "the log does not end in 'commit firewall': "+last)
	}
	for _, sec := range order {
		o := byName[sec].opts
		if !slices.Equal(o["proto"], []string{"udp", "tcp"}) || !slices.Equal(o["target"], []string{"ACCEPT"}) {
			problems = append(problems, "rule "+sec+" is not an ACCEPT rule for udp and tcp")
		}
		s := "src=" + strings.Join(o["src"], ",") + " port=" + strings.Join(o["dest_port"], ",")
		if f := o["family"]; f != nil {
			s += " family=" + strings.Join(f, ",")
		}
		if ips := o["src_ip"]; ips != nil {
			s += " src_ip=" + strings.Join(ips, ",")
		}
		rules = append(rules, s)
	}
	return rules, deleted, warnings, problems
}

func writeExec(t *testing.T, path, text string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(text), 0o755); err != nil {
		t.Fatal(err)
	}
}

// init registers the teeth cases for TestFirewallRuleBuilder: each plants a fault the old
// builder had or a real edit could make.
func init() {
	toothCases = append(toothCases,
		toothCase{name: "firewall_clean", gate: "TestFirewallRuleBuilder", outcome: wantPass},
		toothCase{
			// The defect the gate was added for: the internet side opened to every source.
			name: "firewall_external_zone_open_to_all", gate: "TestFirewallRuleBuilder",
			plant: func(t *testing.T, dst string) {
				editCopy(t, dst, initScriptRel, func(s string) string {
					return strings.Replace(s, "\t\t\tinternal) rollcall_rule \"$zone\" ;;\n",
						"\t\t\tinternal | external) rollcall_rule \"$zone\" ;;\n", 1)
				})
			},
			outcome: wantFail, expect: `got ["src=wan2 port=7432"]`,
		},
		toothCase{
			name: "firewall_no_src_ip", gate: "TestFirewallRuleBuilder",
			plant: func(t *testing.T, dst string) {
				editCopy(t, dst, initScriptRel, func(s string) string {
					return strings.Replace(s, "\t\tuci add_list \"$s.src_ip=$a\"\n", "\t\t:\n", 1)
				})
			},
			outcome: wantFail, expect: `got ["src=wan2 port=7432 family=ipv4"]`,
		},
		toothCase{
			name: "firewall_literal_port", gate: "TestFirewallRuleBuilder",
			plant: func(t *testing.T, dst string) {
				editCopy(t, dst, initScriptRel, func(s string) string {
					return strings.Replace(s, "uci set \"$s.dest_port=$port\"", "uci set \"$s.dest_port=7432\"", 1)
				})
			},
			outcome: wantFail, expect: `got ["src=lan port=7432"]`,
		},
		toothCase{
			name: "firewall_masq_ignored", gate: "TestFirewallRuleBuilder",
			plant: func(t *testing.T, dst string) {
				editCopy(t, dst, initScriptRel, func(s string) string {
					return strings.Replace(s, "for v in masq masq6; do", "for v in; do", 1)
				})
			},
			outcome: wantFail, expect: "a_masquerading_zone_not_named_wan",
		},
		toothCase{
			name: "firewall_no_builder", gate: "TestFirewallRuleBuilder",
			plant: func(t *testing.T, dst string) {
				editCopy(t, dst, initScriptRel, func(s string) string {
					return strings.Replace(s, "firewall() {", "firewall_gone() {", 1)
				})
			},
			outcome: wantFail, expect: "measured nothing",
		},
		toothCase{
			name: "firewall_no_init_script", gate: "TestFirewallRuleBuilder",
			plant: func(t *testing.T, dst string) {
				removeFile(t, filepath.Join(dst, filepath.FromSlash(initScriptRel)))
			},
			outcome: wantFail, expect: "measured nothing",
		},
	)
}
