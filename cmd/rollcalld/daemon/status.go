package daemon

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/TAIPANBOX/rollcall/internal/node"
)

// # Status
//
// The report is the one of luci-app-rollcall/STATUS-JSON.md, schema 1. The
// node fills what it knows; the daemon adds running, discovery, topology and
// sandbox, and the Telegram states only it can tell (not_configured,
// not_bound). The types below fix the field set: every field of a set-up
// router is always written, and a router that is not set up writes the short
// form.

// report is the status of a set-up router.
type report struct {
	Schema        int                   `json:"schema"`
	Running       bool                  `json:"running"`
	Initialised   bool                  `json:"initialised"`
	Generated     string                `json:"generated"`
	Site          string                `json:"site"`
	Self          *node.SelfStatus      `json:"self"`
	Members       []node.MemberStatus   `json:"members"`
	Sender        *string               `json:"sender"`
	Incidents     []node.IncidentStatus `json:"incidents"`
	Discovery     []node.DiscoveryEntry `json:"discovery"`
	Topology      string                `json:"topology"`
	Sandbox       node.SandboxStatus    `json:"sandbox"`
	Storage       node.StorageStatus    `json:"storage"`
	Telegram      node.TelegramStatus   `json:"telegram"`
	GroupKey      *node.GroupKeyStatus  `json:"group_key"`
	BackupWarning bool                  `json:"backup_warning"`
}

// notSetUp is the status of a router without a group. Error says why when
// the reason is not simply that init or join has not run.
type notSetUp struct {
	Schema      int    `json:"schema"`
	Running     bool   `json:"running"`
	Initialised bool   `json:"initialised"`
	Error       string `json:"error,omitempty"`
}

// The topology hints of STATUS-JSON.md.
const (
	topoNoSecondUplink = "no_second_uplink"
	topoSecondUplink   = "second_uplink"
	topoOverlaySites   = "overlay_sites"
)

func (d *Daemon) status() ([]byte, error) {
	d.mu.Lock()
	nd, ndErr := d.nd, d.ndErr
	token, chat, switched := d.token, d.chatID, d.switched
	d.mu.Unlock()

	if nd == nil {
		return json.Marshal(notSetUp{Schema: 1, Running: true, Error: whyNot(ndErr)})
	}
	s := nd.Status()
	if !s.Initialised || s.Self == nil {
		why := ""
		if s.State == "removed" {
			why = plain(node.ErrRemoved)
		} else if s.State == "stopped" {
			why = whyNot(ndErr)
		}
		return json.Marshal(notSetUp{Schema: 1, Running: true, Error: why})
	}
	r := report{
		Schema: 1, Running: true, Initialised: true, Generated: s.Generated, Site: s.Site,
		Self: s.Self, Members: nonNil(s.Members), Sender: s.Sender, Incidents: nonNil(s.Incidents),
		Discovery: d.discovery(), Topology: topology(d.o.Devices, switched),
		Storage: s.Storage, Telegram: s.Telegram, GroupKey: s.GroupKey, BackupWarning: s.BackupWarning,
	}
	if d.o.Sandbox != nil {
		r.Sandbox = d.o.Sandbox()
	} else {
		r.Sandbox = sandboxOf(false, false, false)
	}
	r.Telegram.State = telegramState(s, d.o.Config.Sender, token, chat)
	return json.Marshal(r)
}

// whyNot is the error a not-set-up report carries: none when init or join
// has simply not run yet.
func whyNot(err error) string {
	if err == nil || errors.Is(err, fs.ErrNotExist) || errors.Is(err, node.ErrNoRoster) || errors.Is(err, node.ErrNoEpochKey) {
		return ""
	}
	return plain(err)
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// telegramState adds to the node's Telegram state what only the daemon
// knows: whether this router holds a token and a bound chat. The node calls
// a router that holds no channel not_configured or not_sender.
func telegramState(s node.Status, configured bool, token string, chat int64) string {
	sender := s.Self != nil && slices.Contains(s.Self.Roles, "sender")
	switch {
	case !sender || !configured:
		return "not_sender"
	case token == "":
		return "not_configured"
	case chat == 0:
		return "not_bound"
	}
	return s.Telegram.State
}

// discovery lists the peer-zone interfaces where discovery cannot run.
func (d *Daemon) discovery() []node.DiscoveryEntry {
	out := []node.DiscoveryEntry{}
	if d.o.Discovery == nil {
		return out
	}
	for iface, err := range d.o.Discovery() {
		if err != nil {
			out = append(out, node.DiscoveryEntry{Interface: iface, Error: err.Error()})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Interface < out[j].Interface })
	return out
}

// topology is the hint of which row of the design's topology table applies,
// from what this router can see itself: a peer zone on a WireGuard or
// Tailscale device joins sites over an overlay; a default route that moved
// to another interface in this run shows a second uplink. Without either it
// is the case where an outage of the main line is reported after recovery.
func topology(devices []string, switched bool) string {
	for _, dev := range devices {
		if strings.HasPrefix(dev, "wg") || strings.HasPrefix(dev, "tailscale") {
			return topoOverlaySites
		}
	}
	if switched {
		return topoSecondUplink
	}
	return topoNoSecondUplink
}

// sandboxOf is the sandbox object of the status report.
func sandboxOf(noNewPrivs, seccomp, jail bool) node.SandboxStatus {
	s := node.SandboxStatus{NoNewPrivs: noNewPrivs, Seccomp: seccomp, Jail: jail}
	switch {
	case noNewPrivs && seccomp && jail:
		s.State = "enforced"
	case noNewPrivs || seccomp || jail:
		s.State = "partial"
	default:
		s.State = "off"
	}
	return s
}

// ReadSandbox reads the daemon's own sandbox under root ("/" on a router):
// NoNewPrivs and Seccomp from proc/self/status, and the jail from the files
// the jail leaves out. known is false when proc/self/status could not be
// read (a jail without /proc), so that the flags are unknown rather than off.
//
// The jail is judged by its view of /etc: the init script mounts
// /etc/openwrt_release into it and never /etc/shadow, which every OpenWrt
// root has. It is a heuristic, and errs towards "no jail" off OpenWrt.
func ReadSandbox(root string) (s node.SandboxStatus, known bool) {
	var noNewPrivs, seccomp bool
	if b, err := os.ReadFile(filepath.Join(root, "proc", "self", "status")); err == nil {
		known = true
		sc := bufio.NewScanner(bytes.NewReader(b))
		for sc.Scan() {
			k, v, found := strings.Cut(sc.Text(), ":")
			if !found {
				continue
			}
			v = strings.TrimSpace(v)
			switch k {
			case "NoNewPrivs":
				noNewPrivs = v == "1"
			case "Seccomp":
				seccomp = v != "" && v != "0"
			}
		}
	}
	_, errRelease := os.Stat(filepath.Join(root, "etc", "openwrt_release"))
	_, errShadow := os.Stat(filepath.Join(root, "etc", "shadow"))
	jail := errRelease == nil && errors.Is(errShadow, fs.ErrNotExist)
	return sandboxOf(noNewPrivs, seccomp, jail), known
}
