package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// The snapshot is what rollcalld needs from /etc/config/firewall, network and system, written
// by root. On OpenWrt 25.12 network and system are mode 0600 root (network may hold PPPoE
// passwords and WireGuard private keys), and the daemon, which runs as the user rollcall inside
// its jail, may not read them. So root (rollcall snapshot, run by the init script before every
// start, by reload_service and by the interface hotplug) parses them with this package and
// writes only the facts: every firewall zone with its devices and whether it faces the
// internet, and the time zone. The daemon reads the snapshot and never those files.
const (
	// SnapshotPath is where root writes the snapshot: the control directory, which the init
	// script makes rollcall:rollcall 0700 and mounts into the jail. /var/run is root's on
	// OpenWrt, so nobody else can put anything at that path before the init script does.
	SnapshotPath = "/var/run/rollcall/snapshot.json"
	// SnapshotMode: written by root, readable by the daemon through the group rollcall, nothing
	// for anyone else.
	SnapshotMode fs.FileMode = 0o640
	// SnapshotVersion is the format this package writes and reads.
	SnapshotVersion = 1

	MaxSnapshotSize  = 64 << 10
	MaxSnapshotZones = 32
	MaxZoneDevices   = 64
	maxZoneName      = 64
)

// ErrSnapshotStale is a snapshot made from configuration files other than the ones there now.
var ErrSnapshotStale = errors.New("stale")

// Snapshot is the secret-free part of the firewall, network and system configuration.
type Snapshot struct {
	Version  int              `json:"version"`
	Sources  []SnapshotSource `json:"sources"`
	Zones    []SnapshotZone   `json:"zones"`
	TZ       string           `json:"tz"`
	TZSource string           `json:"tz_source"`
}

// SnapshotSource names one file the snapshot was made from, as it was then. The daemon can stat
// network and system without reading them, so they carry their size and modification time; the
// firewall file is readable, so it carries the SHA-256 of its content, which the init script's
// firewall command rewrites unchanged at every reload. The system file may be missing.
type SnapshotSource struct {
	Name    string `json:"name"` // firewall, network or system, in that order
	Missing bool   `json:"missing,omitempty"`
	Size    int64  `json:"size"`
	MtimeNS int64  `json:"mtime_ns,omitempty"`
	SHA256  string `json:"sha256,omitempty"`
}

// SnapshotZone is one firewall zone: its sorted network devices, and whether it faces the
// internet (externalZones).
type SnapshotZone struct {
	Name     string   `json:"name"`
	Devices  []string `json:"devices"`
	External bool     `json:"external"`
}

// snapshotSources are the files a snapshot is made from, in the order it lists them.
var snapshotSources = []string{"firewall", "network", "system"}

// Facts reads the firewall, system and network files, as root, and returns the snapshot of
// them. A missing system file gives UTC. A zone whose name is outside [A-Za-z0-9_-] (at most 64
// bytes) is left out: the firewall rule builder gives it no rule either. A line of network or
// system the parser refuses is reported by its number alone, since those files may hold secrets.
func Facts(firewallPath, systemPath, networkPath string) (Snapshot, error) {
	fw, fwSrc, err := parseSource(firewallPath, "firewall", false)
	if err != nil {
		return Snapshot{}, err
	}
	nw, nwSrc, err := parseSource(networkPath, "network", true)
	if err != nil {
		return Snapshot{}, err
	}
	sys, sysSrc, err := parseSource(systemPath, "system", true)
	if errors.Is(err, fs.ErrNotExist) {
		sysSrc, err = SnapshotSource{Name: "system", Missing: true}, nil
	}
	if err != nil {
		return Snapshot{}, err
	}
	s := Snapshot{Version: SnapshotVersion, Sources: []SnapshotSource{fwSrc, nwSrc, sysSrc}}
	if s.TZ, s.TZSource, err = tzOf(sys, systemPath); err != nil {
		return Snapshot{}, err
	}
	zones, external := zoneDevices(fw, nw), externalZones(fw)
	for _, name := range slices.Sorted(maps.Keys(zones)) {
		if !validZoneName(name) {
			continue
		}
		devs := zones[name]
		if devs == nil {
			devs = []string{}
		}
		s.Zones = append(s.Zones, SnapshotZone{Name: name, Devices: devs, External: external[name]})
	}
	if err := s.check(); err != nil {
		return Snapshot{}, fmt.Errorf("%s: %w", firewallPath, err)
	}
	return s, nil
}

// parseSource parses one file and records it as it was read: the stamp comes from the open
// file, so it describes the bytes parsed even if the path is replaced meanwhile. With quiet, a
// syntax error names the line but none of its text.
func parseSource(path, name string, quiet bool) ([]Section, SnapshotSource, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, SnapshotSource{}, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, SnapshotSource{}, err
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxUCISize+1))
	if err != nil {
		return nil, SnapshotSource{}, fmt.Errorf("%s: %w", path, err)
	}
	secs, err := ParseUCI(bytes.NewReader(data))
	if err != nil {
		var se *SyntaxError
		if quiet && errors.As(err, &se) {
			err = fmt.Errorf("line %d: outside the UCI syntax rollcall reads", se.Line)
		}
		return nil, SnapshotSource{}, fmt.Errorf("%s: %w", path, err)
	}
	src := SnapshotSource{Name: name, Size: int64(len(data))}
	if name == "firewall" {
		sum := sha256.Sum256(data)
		src.SHA256 = hex.EncodeToString(sum[:])
	} else {
		src.Size, src.MtimeNS = fi.Size(), fi.ModTime().UnixNano()
	}
	return secs, src, nil
}

// LoadWithSnapshot reads /etc/config/rollcall and takes the zones and the time zone from the
// snapshot: what the daemon does instead of Load.
func LoadWithSnapshot(rollcallPath string, s Snapshot) (Config, map[string][]string, error) {
	if err := s.check(); err != nil {
		return Config{}, nil, fmt.Errorf("snapshot: %w", err)
	}
	rc, err := parseFile(rollcallPath)
	if err != nil {
		return Config{}, nil, err
	}
	cfg, err := fromSections(rc)
	if err != nil {
		return Config{}, nil, fmt.Errorf("%s: %w", rollcallPath, err)
	}
	cfg.TZ, cfg.TZSource = s.TZ, s.TZSource
	cfg.zones, cfg.external = map[string][]string{}, map[string]bool{}
	for _, z := range s.Zones {
		cfg.zones[z.Name] = slices.Clone(z.Devices)
		if z.External {
			cfg.external[z.Name] = true
		}
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, nil, fmt.Errorf("%s: %w", rollcallPath, err)
	}
	peer := make(map[string][]string, len(cfg.PeerZones))
	for _, z := range cfg.PeerZones {
		peer[z] = slices.Clone(cfg.zones[z])
	}
	return cfg, peer, nil
}

// WriteSnapshot replaces the snapshot at path whole: a new file in the same directory, made
// with O_EXCL (so a link planted there is never followed), mode SnapshotMode, owned by root and
// the directory's group when root writes it, synced, then renamed over path. The directory must
// exist and be a directory, not a link to one: root never writes through a link the daemon,
// which owns that directory, could have put there.
func WriteSnapshot(path string, s Snapshot) error {
	if err := s.check(); err != nil {
		return fmt.Errorf("snapshot: %w", err)
	}
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if len(data) > MaxSnapshotSize {
		return fmt.Errorf("snapshot: %d bytes, larger than %d", len(data), MaxSnapshotSize)
	}
	dir := filepath.Dir(path)
	di, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("the run directory: %w (/etc/init.d/rollcall makes it)", err)
	}
	if !di.IsDir() {
		return fmt.Errorf("the run directory %s is not a directory", dir)
	}
	f, err := os.CreateTemp(dir, ".snapshot-*")
	if err != nil {
		return err
	}
	tmp, done := f.Name(), false
	defer func() {
		if !done {
			f.Close()
			os.Remove(tmp)
		}
	}()
	if err := f.Chmod(SnapshotMode); err != nil {
		return err
	}
	if os.Geteuid() == 0 {
		if gid, ok := groupOf(di); ok {
			if err := f.Chown(0, gid); err != nil {
				return err
			}
		}
	}
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	done = true
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}

// RemoveSnapshot removes the snapshot, so a daemon started after a failed rewrite refuses to
// start rather than run on facts that may be out of date.
func RemoveSnapshot(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// ReadSnapshot reads the snapshot the daemon starts from. The file is in a directory the daemon
// owns, so it is read as untrusted input: a regular file (not a link), writable by its owner
// alone, at most MaxSnapshotSize bytes, one JSON object with no unknown field, and every name
// and bound checked (check). It is refused as stale (ErrSnapshotStale) when a file it was made
// from, in configDir, is no longer that file (fresh). A missing file gives an error that
// errors.Is reports as fs.ErrNotExist. There is no fallback to the configuration files.
func ReadSnapshot(path, configDir string) (Snapshot, error) {
	s, err := readSnapshot(path)
	if err != nil {
		return Snapshot{}, fmt.Errorf("%s: %w", path, err)
	}
	if err := s.fresh(configDir); err != nil {
		return Snapshot{}, fmt.Errorf("%s: %w", path, err)
	}
	return s, nil
}

func readSnapshot(path string) (Snapshot, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return Snapshot{}, err
	}
	switch {
	case !fi.Mode().IsRegular():
		return Snapshot{}, fmt.Errorf("not a regular file (%v)", fi.Mode().Type())
	case fi.Mode().Perm()&0o022 != 0:
		return Snapshot{}, fmt.Errorf("mode %04o: writable by group or others", fi.Mode().Perm())
	case fi.Size() > MaxSnapshotSize:
		return Snapshot{}, fmt.Errorf("larger than %d bytes", MaxSnapshotSize)
	}
	f, err := os.Open(path)
	if err != nil {
		return Snapshot{}, err
	}
	defer f.Close()
	if ofi, err := f.Stat(); err != nil || !os.SameFile(fi, ofi) {
		return Snapshot{}, errors.New("replaced while it was opened")
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxSnapshotSize+1))
	if err != nil {
		return Snapshot{}, err
	}
	if len(data) > MaxSnapshotSize {
		return Snapshot{}, fmt.Errorf("larger than %d bytes", MaxSnapshotSize)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var s Snapshot
	if err := dec.Decode(&s); err != nil {
		return Snapshot{}, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Snapshot{}, errors.New("trailing data after the snapshot")
	}
	if err := s.check(); err != nil {
		return Snapshot{}, err
	}
	return s, nil
}

// check validates a snapshot as a whole.
func (s Snapshot) check() error {
	if s.Version != SnapshotVersion {
		return fmt.Errorf("version %d; this rollcall reads version %d", s.Version, SnapshotVersion)
	}
	if len(s.Sources) != len(snapshotSources) {
		return fmt.Errorf("%d sources; want firewall, network and system", len(s.Sources))
	}
	for i, src := range s.Sources {
		if src.Name != snapshotSources[i] {
			return fmt.Errorf("sources must be firewall, network and system, in that order")
		}
		if err := src.check(); err != nil {
			return fmt.Errorf("source %s: %w", src.Name, err)
		}
	}
	if len(s.Zones) > MaxSnapshotZones {
		return fmt.Errorf("%d zones; at most %d", len(s.Zones), MaxSnapshotZones)
	}
	for i, z := range s.Zones {
		if !validZoneName(z.Name) {
			return fmt.Errorf("zone %d: invalid zone name", i)
		}
		if i > 0 && s.Zones[i-1].Name >= z.Name {
			return fmt.Errorf("zone %s: zones must be in strictly increasing order of name", z.Name)
		}
		if len(z.Devices) > MaxZoneDevices {
			return fmt.Errorf("zone %s: %d devices; at most %d", z.Name, len(z.Devices), MaxZoneDevices)
		}
		for j, d := range z.Devices {
			if !validDevice(d) {
				return fmt.Errorf("zone %s: device %d is not a valid device name", z.Name, j)
			}
			if j > 0 && z.Devices[j-1] >= d {
				return fmt.Errorf("zone %s: devices must be in strictly increasing order", z.Name)
			}
		}
	}
	switch {
	case !validTZ(s.TZ):
		return errors.New("tz is not a time zone name")
	case s.TZSource != TZSystem && s.TZSource != TZDefault:
		return errors.New("tz_source must be zonename or default")
	case s.TZSource == TZDefault && s.TZ != "UTC":
		return errors.New("the default time zone is UTC")
	}
	return nil
}

func (src SnapshotSource) check() error {
	switch {
	case src.Missing && src.Name != "system":
		return errors.New("only the system file may be missing")
	case src.Missing && (src.Size != 0 || src.MtimeNS != 0 || src.SHA256 != ""):
		return errors.New("a missing file has no size, time or sha256")
	case src.Missing:
		return nil
	case src.Size < 0 || src.Size > MaxUCISize:
		return fmt.Errorf("size %d outside 0 to %d", src.Size, MaxUCISize)
	case src.Name == "firewall":
		if len(src.SHA256) != 2*sha256.Size || strings.ToLower(src.SHA256) != src.SHA256 {
			return errors.New("needs a lower-case hex sha256")
		}
		if _, err := hex.DecodeString(src.SHA256); err != nil {
			return errors.New("needs a lower-case hex sha256")
		}
		if src.MtimeNS != 0 {
			return errors.New("is identified by its sha256, not a time")
		}
	case src.SHA256 != "":
		return errors.New("is identified by its size and time, not a sha256")
	}
	return nil
}

// fresh refuses the snapshot when a file it was made from, in dir, is not that file any more:
// network or system with another size or modification time, the firewall file with other
// content, or a system file that was missing and exists now. A file the daemon cannot see is
// not compared: inside the jail none of the three is mounted, and there the root side keeps the
// snapshot current (the init script before each start and at reload, the interface hotplug).
func (s Snapshot) fresh(dir string) error {
	for _, src := range s.Sources {
		path := filepath.Join(dir, src.Name)
		fi, err := os.Stat(path)
		if err != nil {
			continue
		}
		changed := false
		switch {
		case src.Missing:
			changed = true
		case src.Name == "firewall":
			data, err := readBounded(path)
			if err != nil {
				continue
			}
			sum := sha256.Sum256(data)
			changed = hex.EncodeToString(sum[:]) != src.SHA256
		default:
			changed = fi.Size() != src.Size || fi.ModTime().UnixNano() != src.MtimeNS
		}
		if changed {
			return fmt.Errorf("%w: %s changed after the snapshot was written; run rollcall snapshot as root, or /etc/init.d/rollcall restart", ErrSnapshotStale, src.Name)
		}
	}
	return nil
}

func readBounded(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, MaxUCISize+1))
}

// validZoneName is the rule the firewall rule builder applies to a zone name ([A-Za-z0-9_-]),
// at most maxZoneName bytes.
func validZoneName(s string) bool {
	if s == "" || len(s) > maxZoneName {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}
