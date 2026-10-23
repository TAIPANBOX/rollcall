package sim

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	mrand "math/rand/v2"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/history"
	"github.com/TAIPANBOX/rollcall/internal/identity"
	"github.com/TAIPANBOX/rollcall/internal/member"
	"github.com/TAIPANBOX/rollcall/internal/node"
	"github.com/TAIPANBOX/rollcall/internal/wire"
)

// The scenarios of features/group.feature, one test each. Every site starts
// at 09:00:00 UTC on 2026-10-23; times in the messages are UTC.

const (
	heartbeat   = 5 * time.Second
	silentAfter = 30 * time.Second
	// probeCycle is one round of the indirect probe a member runs before
	// it declares a suspect silent (at 15, 20 and 25 s).
	probeCycle = 5 * time.Second
	// settle is how long a node holds an event so that the events of the
	// same cause join it: the coalescing window (10 s) and two catch-up
	// retries (5 s each).
	settle = 20 * time.Second
	// probePeriod is the internet probe period; lost after 3 failures.
	probePeriod = 10 * time.Second
	// chatAfter is how long after detection the chat may tell a silence:
	// the coalescing settle, at most 10 s, and delivery.
	chatAfter = 15 * time.Second
)

// matching returns the messages whose text matches the regular expression.
func matching(ms []Message, pattern string) []Message {
	re := regexp.MustCompile(pattern)
	var out []Message
	for _, m := range ms {
		if re.MatchString(m.Text) {
			out = append(out, m)
		}
	}
	return out
}

func logChat(t *testing.T, s *Site) []Message {
	t.Helper()
	ms := s.Messages()
	var b strings.Builder
	for _, m := range ms {
		b.WriteString("\n  ")
		b.WriteString(m.String())
	}
	t.Logf("chat (%d):%s", len(ms), b.String())
	return ms
}

// stateOf returns the state st reports for the member called name.
func stateOf(st node.Status, name string) string {
	for _, m := range st.Members {
		if m.Name == name {
			return m.State
		}
	}
	return ""
}

func senderOf(st node.Status) string {
	if st.Sender == nil {
		return ""
	}
	return *st.Sender
}

// allName reports whether every running member names want as the sender.
func allName(s *Site, want string) bool {
	for i := 0; i < s.Len(); i++ {
		if senderOf(s.Status(i)) != want {
			return false
		}
	}
	return true
}

// TestPowerLossReported: a router loses power; within 30 s and one probe
// round another router marks it silent, and the chat tells it within 30 s
// and 15 s; when it comes back, the chat tells an unexpected reboot with
// the downtime.
func TestPowerLossReported(t *testing.T) {
	v := newVerdict(t)
	defer v.done()
	s := NewSite(3, 1)
	defer s.Close()
	s.Run(90 * time.Second)
	cut := s.Elapsed()
	s.PowerOff(2)
	silentAt, ok := s.RunUntil(func() bool { return stateOf(s.Status(0), "r03") == "silent" }, 2*time.Minute)
	if !ok {
		t.Fatal("r01 never marked r03 silent")
	}
	if d := silentAt - cut; d > silentAfter+probeCycle {
		v.fail("", "r03 marked silent %s after the power cut, want within %s", d, silentAfter+probeCycle)
	}
	s.Run(cut + 2*time.Minute - s.Elapsed())
	back := s.Elapsed()
	s.PowerOn(2)
	s.Run(2 * time.Minute)
	ms := logChat(t, s)

	silence := matching(ms, `^Home: r03 stopped answering at 09:01\b`)
	if len(silence) != 1 {
		t.Fatalf("%d messages tell r03's silence, want 1", len(silence))
	}
	t.Logf("marked silent %s after the cut; told in the chat %s after the cut", silentAt-cut, silence[0].At-cut)
	if d := silence[0].At - cut; d > silentAfter+chatAfter {
		v.fail("D8", "the chat told the silence %s after the power cut, want within %s", d, silentAfter+chatAfter)
	}
	reboot := matching(ms, `^Home: r03 rebooted unexpectedly at 09:01, back after 2 min( [0-9]+ s)?[,.]`)
	if len(reboot) != 1 || reboot[0].At < back {
		v.fail("", "messages telling r03's reboot with its downtime: %v; want 1, after its return", reboot)
	}
	if len(ms) != 2 {
		v.fail("", "%d messages, want 2: the silence and the reboot", len(ms))
	}
}

// TestSenderLosesInternetOtherTakesOver: the router that sends loses its
// internet connection while another router has its own; the other router
// takes over sending and reports the lost connection, and the outage with
// its length once the connection is back.
func TestSenderLosesInternetOtherTakesOver(t *testing.T) {
	v := newVerdict(t)
	defer v.done()
	s := NewSite(3, 2)
	defer s.Close()
	s.Run(90 * time.Second)
	if !allName(s, "r01") {
		t.Fatalf("before the loss the sender is %q, want r01 on every router", senderOf(s.Status(2)))
	}
	lost := s.Elapsed()
	s.InternetDown(0)
	took, ok := s.RunUntil(func() bool { return allName(s, "r02") }, 3*time.Minute)
	if !ok {
		t.Fatal("r02 never took over sending")
	}
	t.Logf("every router names r02 the sender %s after r01 lost its internet", took-lost)
	s.Run(lost + 4*time.Minute - s.Elapsed())
	ms := logChat(t, s)
	loss := matching(ms, `^Home: internet lost at 09:01\b.*Seen by r01\.`)
	if len(loss) != 1 || loss[0].By != "r02" {
		t.Fatalf("messages telling r01's lost connection: %v; want 1, sent by r02", loss)
	}
	bound := 3*probePeriod + heartbeat + settle + 5*time.Second
	if d := loss[0].At - lost; d > bound {
		v.fail("", "the loss reached the chat %s after it began, want within %s", d, bound)
	}

	restored := s.Elapsed()
	s.InternetUp(0)
	if _, ok := s.RunUntil(func() bool { return allName(s, "r01") }, 2*time.Minute); !ok {
		t.Fatal("r01 did not take sending back once its internet returned")
	}
	s.Run(2 * time.Minute)
	ms = logChat(t, s)
	if o := matching(ms, `^Home: internet was down from 09:01 to 09:05 \(4 min( [0-9]+ s)?\)`); len(o) != 1 {
		v.fail("", "%d messages tell the outage with its length, want 1", len(o))
	}
	for _, m := range ms {
		if m.By == "r01" && m.At < restored {
			v.fail("", "r01 sent while it had no internet: %s", m)
		}
	}
	if len(ms) != 2 {
		v.fail("", "%d messages, want 2: the loss and the outage", len(ms))
	}
}

// TestNobodyReachesTelegram20Min: nobody reaches Telegram for twenty
// minutes; once it is back, one message tells the outage with its start,
// end and length, and the reboot that happened during it is not lost.
func TestNobodyReachesTelegram20Min(t *testing.T) {
	v := newVerdict(t)
	defer v.done()
	s := NewSite(3, 3)
	defer s.Close()
	s.Run(90 * time.Second)
	down := s.Elapsed()
	s.InternetDown()
	s.Run(5 * time.Minute)
	s.PowerOff(2)
	s.Run(2 * time.Minute)
	s.PowerOn(2)
	s.Run(down + 20*time.Minute - s.Elapsed())
	up := s.Elapsed()
	s.InternetUp()
	s.Run(5 * time.Minute)
	ms := logChat(t, s)
	for _, m := range ms {
		if m.At < up {
			v.fail("", "a message went out while nobody reached Telegram: %s", m)
		}
	}
	if d := duplicates(ms); len(d) > 0 {
		v.fail("D2", "sent more than once: %v", d)
	}
	internet := distinct(matching(ms, `internet`))
	if len(internet) != 1 {
		v.fail("D5", "%d messages about the internet, want 1: %q", len(internet), internet)
	}
	outage := matching(ms, `^Home: internet was down from 09:01 to 09:21 \(20 min( [0-9]+ s)?\).* Seen by (r0[123](, |\.)){3}`)
	if len(outage) == 0 || !strings.Contains(outage[0].Text, "r01") || !strings.Contains(outage[0].Text, "r02") || !strings.Contains(outage[0].Text, "r03") {
		v.fail("", "no message tells the outage from 09:01 to 09:21, 20 min, seen by every router")
	}
	if r := distinct(matching(ms, `^Home: r03 rebooted unexpectedly at 09:06, back after 2 min( [0-9]+ s)?[,.]`)); len(r) != 1 {
		v.fail("", "%d messages tell the reboot during the outage, want 1", len(r))
	}
}

// TestPlannedVsCrash: one router reboots on purpose and another crashes;
// the chat tells the first as planned and the second as unexpected, once
// each.
func TestPlannedVsCrash(t *testing.T) {
	v := newVerdict(t)
	defer v.done()
	s := NewSite(4, 4)
	defer s.Close()
	s.Run(90 * time.Second)
	s.Reboot(1, 70*time.Second)
	s.Run(3 * time.Minute)
	s.PowerOff(2)
	s.Run(70 * time.Second)
	s.PowerOn(2)
	s.Run(3 * time.Minute)
	ms := logChat(t, s)
	if p := matching(ms, `^Home: r02 rebooted as planned at 09:01, back after 1 min( [0-9]+ s)?[,.]`); len(p) != 1 {
		v.fail("", "%d messages tell r02's planned reboot with its length, want 1", len(p))
	}
	if c := matching(ms, `^Home: r03 rebooted unexpectedly at 09:04, back after 1 min( [0-9]+ s)?[,.]`); len(c) != 1 {
		v.fail("", "%d messages tell r03's crash with its length, want 1", len(c))
	}
	if w := matching(ms, `r02 rebooted unexpectedly|r03 rebooted as planned`); len(w) != 0 {
		v.fail("", "a reboot told as the other kind: %v", w)
	}
	if r := matching(ms, `rebooted`); len(r) != 2 {
		v.fail("", "%d messages tell a reboot, want 2: one for each", len(r))
	}
}

// TestUpgradeReported: a router upgraded to a new version is reported with
// the old and the new version when it comes back.
func TestUpgradeReported(t *testing.T) {
	v := newVerdict(t)
	defer v.done()
	s := NewSite(3, 5)
	defer s.Close()
	s.Run(90 * time.Second)
	s.Upgrade(1, "24.10.5")
	s.Run(6 * time.Minute)
	ms := logChat(t, s)
	if u := matching(ms, `^Home: r02 upgraded 24\.10\.4 -> 24\.10\.5 at 09:01, back after 3 min( [0-9]+ s)?[,.]`); len(u) != 1 {
		v.fail("", "%d messages tell the upgrade with both versions, want 1", len(u))
	}
	if r := matching(ms, `rebooted|upgraded`); len(r) != 1 {
		v.fail("", "%d messages about r02's return, want 1", len(r))
	}
}

// TestQuietDayEmptyChat: a day without incidents leaves the chat empty,
// while the routers keep hearing each other all day.
func TestQuietDayEmptyChat(t *testing.T) {
	s := NewSite(3, 6)
	defer s.Close()
	s.Run(24 * time.Hour)
	if ms := logChat(t, s); len(ms) != 0 {
		t.Errorf("%d messages on a quiet day, want none", len(ms))
	}
	for i := 0; i < s.Len(); i++ {
		st := s.Status(i)
		for _, m := range st.Members {
			if m.State != "up" {
				t.Errorf("after the day %s sees %s %s, want up", s.Name(i), m.Name, m.State)
			}
		}
	}
	st := s.Stats()
	if want := int(24 * time.Hour / heartbeat); st.UDP < want {
		t.Errorf("%d datagrams delivered in a day, want at least %d (the routers did not talk)", st.UDP, want)
	}
	t.Logf("a quiet day: %d datagrams delivered, %d TCP exchanges, %d store writes per router", st.UDP, st.Streams, st.Writes/s.Len())
}

// TestMeshNodeLinkLoss: a mesh node that stays up loses its radio link;
// the chat tells a link problem about it, no reboot, and nothing about the
// routers that stayed in touch.
func TestMeshNodeLinkLoss(t *testing.T) {
	v := newVerdict(t)
	defer v.done()
	s := NewSite(3, 7)
	defer s.Close()
	s.Run(90 * time.Second)
	s.CutLink(2)
	s.Run(2 * time.Minute)
	s.Heal()
	s.Run(3 * time.Minute)
	ms := logChat(t, s)
	if l := matching(ms, `^Home: r03 lost contact 09:01 to 09:03 but stayed up: a link problem, not a reboot[,.]`); len(l) != 1 {
		v.fail("", "%d messages tell r03's link problem, want 1", len(l))
	}
	if r := matching(ms, `rebooted|upgraded`); len(r) != 0 {
		v.fail("", "a reboot told for a router that stayed up: %v", r)
	}
	if o := matching(ms, `r01|r02`); len(o) != 0 {
		v.fail("D9", "messages about the routers that kept their link: %v", o)
	}
	if len(ms) > 2 {
		v.fail("D1,D9", "%d messages, want at most 2: r03's silence and its link problem", len(ms))
	}
}

// TestSeparateRoutersFormGroup: two routers, each on its own LAN with its
// own DHCP (no shared segment, so no multicast between them), are joined
// into one group with a join code, and each sees the other as a member.
func TestSeparateRoutersFormGroup(t *testing.T) {
	s := New(Options{N: 1, Seed: 8, Separate: true})
	defer s.Close()
	s.Run(30 * time.Second)
	j, err := s.Join(false)
	if err != nil {
		t.Fatalf("join: %v", err)
	}
	s.Run(time.Minute)
	for _, i := range []int{0, j} {
		st := s.Status(i)
		if len(st.Members) != 2 || stateOf(st, "r01") != "up" || stateOf(st, "r02") != "up" {
			t.Errorf("%s sees %+v; want r01 and r02 up", s.Name(i), st.Members)
		}
	}
	st := s.Stats()
	if st.Multicast != 0 || st.UDP == 0 {
		t.Errorf("%d multicast and %d datagrams delivered; want no multicast across the two LANs and unicast between them", st.Multicast, st.UDP)
	}
	ms := logChat(t, s)
	if a := matching(ms, `^Home: the group changed: r02 added \(by r01\)`); len(a) != 1 || len(ms) != 1 {
		t.Errorf("chat %v; want only the announcement of r02", ms)
	}
}

// TestSingleRouterGroup: a group of one router still reports its
// incident: the internet outage it saw, once the internet is back.
func TestSingleRouterGroup(t *testing.T) {
	v := newVerdict(t)
	defer v.done()
	s := NewSite(1, 9)
	defer s.Close()
	s.Run(90 * time.Second)
	s.InternetDown(0)
	s.Run(5 * time.Minute)
	s.InternetUp(0)
	s.Run(2 * time.Minute)
	ms := logChat(t, s)
	if o := matching(ms, `^Home: internet was down from 09:01 to 09:06 \(5 min( [0-9]+ s)?\)\. Seen by r01\.`); len(o) != 1 {
		v.fail("", "%d messages tell the outage from 09:01 to 09:06, 5 min, seen by r01; want 1", len(o))
	}
	if len(ms) != 1 {
		v.fail("D5", "%d messages, want only the outage", len(ms))
	}
}

// TestUnpairedDeviceCannotInject: a device on the LAN that was never
// paired sends heartbeats and events of its own, heartbeats in the name of
// a member, noise, and replays of what it recorded; the group drops all of
// it, and nothing reaches the chat.
func TestUnpairedDeviceCannotInject(t *testing.T) {
	s := NewSite(3, 10)
	defer s.Close()
	s.Capture(true)
	s.Run(time.Minute)
	before := make([]node.Status, s.Len())
	for i := range before {
		before[i] = s.Status(i)
	}

	rng := mrand.New(mrand.NewPCG(10, 10))
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(rng.Uint32())
	}
	self := &identity.Identity{Sign: ed25519.NewKeyFromSeed(seed)}
	self.ID[0] = 0xee
	foreign := make([]byte, 32)
	for i := range foreign {
		foreign[i] = byte(rng.Uint32())
	}
	pk, err := wire.PacketKey(foreign)
	if err != nil {
		t.Fatal(err)
	}
	seal := func(pt []byte) []byte {
		p, err := wire.Seal(pk, s.Epoch(), pt)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	heartbeatOf := func(id *identity.Identity, name string, goingDown bool) []byte {
		b, err := member.EncodeHeartbeat(member.Heartbeat{Epoch: s.Epoch(), From: id.ID, BootSeq: 99, Boot: [16]byte{1}, Counter: 1,
			Name: name, Wall: s.Wall(), Mono: time.Hour, ClockTrusted: true, GoingDown: goingDown}, id)
		if err != nil {
			t.Fatal(err)
		}
		return append([]byte{1}, b...)
	}
	// An event of its own: a history entry saying r02 rebooted.
	ev, err := node.NewEvent(self, history.Head{}, node.EventBody{Subject: s.ID(1), Type: "reboot_unplanned",
		At: node.AtOf(s.Stamp(0))})
	if err != nil {
		t.Fatal(err)
	}
	evJSON, _ := json.Marshal(ev)
	// A heartbeat in r02's name, signed with the device's key.
	pose := &identity.Identity{ID: s.ID(1), Sign: self.Sign}
	recorded := s.Captured(2)
	if len(recorded) == 0 {
		t.Fatal("nothing of r03 was recorded on the LAN")
	}
	var sealed, replayed int
	for round := 0; round < 20; round++ {
		for _, b := range [][]byte{seal(heartbeatOf(self, "intruder", false)), seal(heartbeatOf(pose, "r02", true)), seal(evJSON)} {
			s.Inject(b)
			sealed++
		}
		noise := make([]byte, 1+rng.IntN(1200))
		for i := range noise {
			noise[i] = byte(rng.Uint32())
		}
		s.Inject(noise)
		s.Inject(recorded[rng.IntN(len(recorded))])
		replayed++
		for i := 0; i < s.Len(); i++ {
			for _, b := range [][]byte{seal(evJSON), evJSON, noise} {
				if r, err := s.InjectStream(i, b); err == nil || r != nil {
					t.Fatalf("%s answered an unpaired device's stream request", s.Name(i))
				}
			}
		}
		s.Run(time.Second)
	}
	s.Run(2 * time.Minute)
	if ms := logChat(t, s); len(ms) != 0 {
		t.Errorf("%d messages after the injection, want none", len(ms))
	}
	for i := 0; i < s.Len(); i++ {
		st := s.Status(i)
		for _, m := range st.Members {
			if m.State != "up" {
				t.Errorf("%s sees %s %s after the injection, want up", s.Name(i), m.Name, m.State)
			}
		}
		if len(st.Members) != 3 || st.Version != before[i].Version {
			t.Errorf("%s: %d members, roster version %d; want 3 and %d", s.Name(i), len(st.Members), st.Version, before[i].Version)
		}
		if got := st.Counters.Auth - before[i].Counters.Auth; got < uint64(sealed) {
			t.Errorf("%s refused %d packets on authentication, want at least the %d sealed under a foreign key", s.Name(i), got, sealed)
		}
		if i != 2 {
			if got := st.Counters.Heartbeats.Replay - before[i].Counters.Heartbeats.Replay; got < uint64(replayed) {
				t.Errorf("%s refused %d replays, want %d", s.Name(i), got, replayed)
			}
		}
	}
}

// TestSiteWidePowerCutReported: the power fails in the whole house, so
// every router goes off at once and comes back two minutes later; the chat
// tells each router's unexpected reboot. A group of one router does the
// same. (Not one of the ten bound scenarios: it covers the most common home
// incident, which none of them puts every router through at once.)
func TestSiteWidePowerCutReported(t *testing.T) {
	for _, n := range []int{3, 1} {
		t.Run(fmt.Sprintf("routers=%d", n), func(t *testing.T) {
			v := newVerdict(t)
			defer v.done()
			s := NewSite(n, 11)
			defer s.Close()
			s.Run(90 * time.Second)
			for i := 0; i < n; i++ {
				s.PowerOff(i)
			}
			s.Run(2 * time.Minute)
			back := s.Elapsed()
			for i := 0; i < n; i++ {
				s.PowerOn(i)
				s.Run(5 * time.Second)
			}
			s.Run(3 * time.Minute)
			ms := logChat(t, s)
			for i := 0; i < n; i++ {
				name := s.Name(i)
				if !slices.ContainsFunc(ms, func(m Message) bool {
					who, verb := told(m)
					return m.At >= back && verb == "rebooted unexpectedly" && slices.Contains(who, name)
				}) {
					v.fail("", "no message tells that %s rebooted unexpectedly after the power cut", name)
				}
			}
		})
	}
}

// duplicates returns the texts of the incidents sent more than once.
func duplicates(ms []Message) []string {
	seen := map[string]int{}
	var out []string
	for _, m := range ms {
		if x := tagOf.FindStringSubmatch(m.Text); x != nil {
			if seen[x[1]]++; seen[x[1]] == 2 {
				out = append(out, m.Text)
			}
		}
	}
	return out
}

// distinct returns the texts of ms without their incident tags, each once.
func distinct(ms []Message) []string {
	var out []string
	for _, m := range ms {
		t := m.Text
		if x := tagOf.FindStringSubmatch(t); x != nil {
			t = strings.TrimSuffix(t, x[0])
		}
		if !slices.Contains(out, t) {
			out = append(out, t)
		}
	}
	return out
}
