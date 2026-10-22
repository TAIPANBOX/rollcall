package member

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/clock"
	"github.com/TAIPANBOX/rollcall/internal/events"
	"github.com/TAIPANBOX/rollcall/internal/identity"
	"github.com/TAIPANBOX/rollcall/internal/ids"
	"github.com/TAIPANBOX/rollcall/internal/sig"
	"github.com/TAIPANBOX/rollcall/internal/store"
)

// start is the local monotonic clock when a fixture's table starts. It is
// far from 0, so that a table that counted from the boot instead of from its
// own start is caught.
const start = 1000 * time.Second

const s = time.Second

// sim is what a fixture remembers of one simulated router.
type sim struct {
	seq       uint64
	boot      byte
	counter   uint64
	version   string
	goingDown bool
}

// fixture is a table of ms[0] in a group of ms, on a trusted clock.
type fixture struct {
	t    testing.TB
	ms   []tm
	self tm
	dir  string // the store's directory
	st   *store.Store
	cfg  Config
	tab  *Table
	sims map[ids.MemberID]*sim
}

func newFixture(t testing.TB, n int, startAt time.Duration) *fixture {
	return newFixtureOf(t, members(n), startAt)
}

func newFixtureOf(t testing.TB, ms []tm, startAt time.Duration) *fixture {
	return newFixtureWith(t, ms, startAt, nil)
}

func newFixtureWith(t testing.TB, ms []tm, startAt time.Duration, edit func(*Config)) *fixture {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "state")
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{t: t, ms: ms, self: ms[0], dir: dir, st: st, sims: map[ids.MemberID]*sim{}}
	f.cfg = Config{
		Self: ms[0].id.ID, Boot: localBoot, BootSeq: 6,
		Roster: testRoster(ms), RosterHash: testRosterHash, Store: st,
	}
	if edit != nil {
		edit(&f.cfg)
	}
	f.tab, err = New(f.cfg, at(startAt))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return f
}

// restart makes a new table on the same store, as after a restart of the
// local member.
func (f *fixture) restart(startAt time.Duration) {
	f.t.Helper()
	tab, err := New(f.cfg, at(startAt))
	if err != nil {
		f.t.Fatalf("New after restart: %v", err)
	}
	f.tab = tab
}

func (f *fixture) sim(m tm) *sim {
	p := f.sims[m.id.ID]
	if p == nil {
		p = &sim{seq: 1, boot: 1, version: "24.10.4"}
		f.sims[m.id.ID] = p
	}
	return p
}

// beat returns m's next heartbeat in its current boot.
func (f *fixture) beat(m tm) Heartbeat {
	p := f.sim(m)
	p.counter++
	h := fullBeat(m)
	h.BootSeq, h.Boot, h.Counter = p.seq, bootID(p.boot), p.counter
	h.Versions[0], h.GoingDown = p.version, p.goingDown
	return h
}

// reboot starts m's next boot.
func (f *fixture) reboot(m tm) {
	p := f.sim(m)
	p.seq++
	p.boot++
	p.goingDown = false
}

func (f *fixture) send(m tm, now clock.Stamp) (Observed, error) {
	return f.tab.Observe(testEpoch, enc(f.t, f.beat(m), m), now)
}

func (f *fixture) mustSend(m tm, now clock.Stamp) Observed {
	f.t.Helper()
	obs, err := f.send(m, now)
	if err != nil {
		f.t.Fatalf("heartbeat of %s at %v: %v", m.name, now.Mono, err)
	}
	return obs
}

// admit passes a packet from m through Admit with m's next counter and a
// good signature, as the node does for a probe answer.
func (f *fixture) admit(m tm) Admitted {
	f.t.Helper()
	p := f.sim(m)
	p.counter++
	msg := []byte("probe answer")
	sg := ed25519.Sign(m.id.Sign, msg)
	a, err := f.tab.Admit(m.id.ID, p.seq, bootID(p.boot), p.counter, func(pub ed25519.PublicKey) bool {
		return ed25519.Verify(pub, msg, sg)
	})
	if err != nil {
		f.t.Fatalf("Admit of %s: %v", m.name, err)
	}
	return a
}

// tick runs Tick at now and fails on any silent event.
func (f *fixture) tick(now clock.Stamp) []ids.MemberID {
	f.t.Helper()
	sus, sil := f.tab.Tick(now)
	if len(sil) != 0 {
		f.t.Fatalf("Tick at %v reported %s", now.Mono, describe(sil))
	}
	return sus
}

func idsOf(ms ...tm) []ids.MemberID {
	var out []ids.MemberID
	for _, m := range ms {
		out = append(out, m.id.ID)
	}
	return out
}

func describe(evs []events.Event) string {
	var b bytes.Buffer
	for _, e := range evs {
		fmt.Fprintf(&b, "[%s subject %x.. witness %x.. at %v] ", e.Type, e.Subject[:1], e.Witness[:1], e.At.Mono)
	}
	return b.String()
}

// wantEvent checks one event's type, subject, witness and stamp.
func wantEvent(t testing.TB, e events.Event, typ events.Type, subject tm, self tm, stamp clock.Stamp) {
	t.Helper()
	if e.Type != typ || e.Subject != subject.id.ID || e.Witness != self.id.ID {
		t.Errorf("event %s about %x.. by %x..; want %s about %s by %s", e.Type, e.Subject[:1], e.Witness[:1], typ, subject.name, self.name)
	}
	if !reflect.DeepEqual(e.At, stamp) {
		t.Errorf("%s stamped %+v, want %+v", e.Type, e.At, stamp)
	}
}

func TestSuspectAfterThreeMissed(t *testing.T) {
	f := newFixture(t, 3, start)
	r02, r03 := f.ms[1], f.ms[2]
	h := start + 2*s
	f.mustSend(r02, at(h))
	f.mustSend(r03, at(h))
	// r03 keeps beating every 5 s; r02 is never heard again.
	f.mustSend(r03, at(h+5*s))
	f.mustSend(r03, at(h+10*s))
	if sus := f.tick(at(h + 15*s - 1)); len(sus) != 0 {
		t.Errorf("suspects after 2 missed heartbeats and a bit: %x", sus)
	}
	if got := f.tab.IndirectProbeRequest(r02.id.ID); got != nil {
		t.Errorf("helpers for a member that is not suspect: %x", got)
	}
	f.mustSend(r03, at(h+15*s))
	if sus := f.tick(at(h + 15*s)); !slices.Equal(sus, idsOf(r02)) {
		t.Errorf("suspects after 3 missed = %x, want r02", sus)
	}
	if got := f.tab.IndirectProbeRequest(r02.id.ID); !slices.Equal(got, idsOf(r03)) {
		t.Errorf("helpers = %x, want r03", got)
	}
	if sus := f.tick(at(h + 17*s)); len(sus) != 0 {
		t.Errorf("a second probe round 2 s after the first: %x", sus)
	}
	f.mustSend(r03, at(h+20*s))
	if sus := f.tick(at(h + 20*s - 1)); len(sus) != 0 {
		t.Errorf("a probe round less than 5 s after the last: %x", sus)
	}
	if sus := f.tick(at(h + 20*s)); !slices.Equal(sus, idsOf(r02)) {
		t.Errorf("suspects 5 s after the first round = %x, want r02 again", sus)
	}

	// The counts are configurable: every 2 s, suspect after 4 missed.
	g := newFixtureWith(t, members(3), start, func(c *Config) {
		c.Interval, c.SuspectMissed, c.SilentMissed = 2*s, 4, 7
	})
	g.mustSend(r02, at(h))
	g.mustSend(r03, at(h))
	for d := 2 * s; d <= 8*s; d += 2 * s {
		g.mustSend(r03, at(h+d))
	}
	if sus := g.tick(at(h + 8*s - 1)); len(sus) != 0 {
		t.Errorf("custom: suspects before 4 missed: %x", sus)
	}
	if sus := g.tick(at(h + 8*s)); !slices.Equal(sus, idsOf(r02)) {
		t.Errorf("custom: suspects after 4 missed = %x, want r02", sus)
	}
	if sus := g.tick(at(h + 10*s - 1)); len(sus) != 0 {
		t.Errorf("custom: a round before the 2 s interval: %x", sus)
	}
	if sus := g.tick(at(h + 10*s)); !slices.Equal(sus, idsOf(r02)) {
		t.Errorf("custom: no round after the 2 s interval: %x", sus)
	}
}

func TestSilentAfterSixMissed(t *testing.T) {
	f := newFixture(t, 3, start)
	r02, r03 := f.ms[1], f.ms[2]
	h := start + 2*s
	f.mustSend(r02, at(h))
	for d := time.Duration(0); d <= 25*s; d += 5 * s {
		f.mustSend(r03, at(h+d))
	}
	f.tick(at(h + 30*s - 1))
	f.mustSend(r03, at(h+30*s))
	_, sil := f.tab.Tick(at(h + 30*s))
	if len(sil) != 1 {
		t.Fatalf("Tick after 6 missed reported %d events, want 1: %s", len(sil), describe(sil))
	}
	wantEvent(t, sil[0], events.MemberSilent, r02, f.self, at(h))
	if _, sil := f.tab.Tick(at(h + 31*s)); len(sil) != 0 {
		t.Errorf("silence reported again: %s", describe(sil))
	}
	if sus, _ := f.tab.Tick(at(h + 35*s)); len(sus) != 0 {
		t.Errorf("a silent member is still probed: %x", sus)
	}
	_, sil = f.tab.Tick(at(h + 60*s))
	if len(sil) != 1 || sil[0].Subject != r03.id.ID {
		t.Errorf("at +60 s want r03 silent alone, got %s", describe(sil))
	}

	// Configurable: every 2 s, silent after 7 missed.
	g := newFixtureWith(t, members(3), start, func(c *Config) {
		c.Interval, c.SuspectMissed, c.SilentMissed = 2*s, 4, 7
	})
	g.mustSend(r02, at(h))
	g.mustSend(r03, at(h))
	if _, sil := g.tab.Tick(at(h + 14*s - 1)); len(sil) != 0 {
		t.Errorf("custom: silent before 7 missed: %s", describe(sil))
	}
	if _, sil := g.tab.Tick(at(h + 14*s)); len(sil) != 2 {
		t.Errorf("custom: after 7 missed want r02 and r03 silent, got %s", describe(sil))
	}
}

func TestSilentStampedAtLastHeard(t *testing.T) {
	f := newFixture(t, 2, start)
	r02 := f.ms[1]
	h := start + 7*s + 300*time.Millisecond
	f.mustSend(r02, at(h-5*s))
	f.mustSend(r02, at(h))
	_, sil := f.tab.Tick(at(h + 47*s))
	if len(sil) != 1 {
		t.Fatalf("want one silent event, got %s", describe(sil))
	}
	// The silence started when r02 was last heard, not when it was noticed.
	wantEvent(t, sil[0], events.MemberSilent, r02, f.self, at(h))
}

func TestFreshTableWaitsFullSilence(t *testing.T) {
	f := newFixture(t, 4, start)
	if sus := f.tick(at(start + 15*s - 1)); len(sus) != 0 {
		t.Errorf("suspects before 15 s of own observation: %x", sus)
	}
	if sus := f.tick(at(start + 15*s)); !slices.Equal(sus, idsOf(f.ms[1:]...)) {
		t.Errorf("suspects after 15 s unheard = %x, want every peer", sus)
	}
	f.tick(at(start + 30*s - 1))
	_, sil := f.tab.Tick(at(start + 30*s))
	if len(sil) != 3 {
		t.Fatalf("want every peer silent after 30 s, got %s", describe(sil))
	}
	for i, e := range sil {
		wantEvent(t, e, events.MemberSilent, f.ms[i+1], f.self, at(start))
	}
}

// probeLoop runs a group of 4 for d seconds after h. r03 and r04 beat every
// 5 s; r02 beats every 5 s until died, but none of its heartbeats after h
// reach the local member. When relay is set, every helper asked about r02
// answers with r02's newest heartbeat, which the helpers received as r02
// sent it. It returns the silent events, the number of probe rounds and the
// number of answers that counted.
func probeLoop(t *testing.T, f *fixture, h, d, died time.Duration, relay bool) ([]events.Event, int, int) {
	t.Helper()
	r02, r03, r04 := f.ms[1], f.ms[2], f.ms[3]
	var silent []events.Event
	var latest []byte
	var sentAt time.Duration
	rounds, counted := 0, 0
	for step := s; step <= d; step += s {
		now := h + step
		if step%(5*s) == 0 {
			f.mustSend(r03, at(now))
			f.mustSend(r04, at(now))
			if now <= died {
				latest, sentAt = enc(t, f.beat(r02), r02), now
			}
		}
		sus, sil := f.tab.Tick(at(now))
		silent = append(silent, sil...)
		for _, target := range sus {
			if target != r02.id.ID {
				t.Fatalf("at +%v suspect %x, want only r02", step, target)
			}
			rounds++
			helpers := f.tab.IndirectProbeRequest(target)
			if !slices.Equal(helpers, idsOf(r03, r04)) {
				t.Fatalf("at +%v helpers %x, want r03 and r04", step, helpers)
			}
			if !relay {
				continue
			}
			for _, hm := range []tm{r03, r04} {
				_, err := f.relay(hm, r02, latest, now-sentAt, at(now))
				switch {
				case err == nil && latest != nil:
					counted++
				case err == nil, errors.Is(err, ErrUnsolicited), errors.Is(err, ErrReplay), errors.Is(err, ErrNotFresher):
					// No heartbeat to carry; the first answer ended the
					// suspicion; or the heartbeat was relayed before.
				default:
					t.Fatalf("at +%v RecordReport from %s: %v", step, hm.name, err)
				}
			}
		}
	}
	return silent, rounds, counted
}

func TestIndirectProbeAvoidsFalseSilent(t *testing.T) {
	h := start + s
	died := h + 200*s
	setup := func() *fixture {
		f := newFixture(t, 4, start)
		for _, m := range f.ms[1:] {
			f.mustSend(m, at(h))
		}
		return f
	}

	// The helpers hear r02 until it dies; the local member never does.
	f := setup()
	silent, rounds, counted := probeLoop(t, f, h, 260*s, died, true)
	if rounds < 10 || counted < 10 {
		t.Errorf("only %d probe rounds and %d answers that counted in 260 s", rounds, counted)
	}
	if len(silent) != 1 {
		t.Fatalf("want exactly one silent event, after r02 died; got %s", describe(silent))
	}
	// Silent 30 s after its last heartbeat, stamped when a helper got it.
	wantEvent(t, silent[0], events.MemberSilent, f.ms[1], f.self, at(died))

	// The control: nobody answers, and r02 is silent after 30 s.
	g := setup()
	silent, _, _ = probeLoop(t, g, h, 40*s, died, false)
	if len(silent) != 1 {
		t.Fatalf("control: want r02 silent once, got %s", describe(silent))
	}
	wantEvent(t, silent[0], events.MemberSilent, g.ms[1], g.self, at(h))

	// Helpers that have no newer heartbeat of r02 change nothing.
	k := setup()
	silent, _, counted = probeLoop(t, k, h, 40*s, h, true)
	if len(silent) != 1 || counted != 0 {
		t.Fatalf("nothing to relay: want r02 silent once and no answer counted, got %s, %d", describe(silent), counted)
	}
	wantEvent(t, silent[0], events.MemberSilent, k.ms[1], k.self, at(h))
}

func TestIndirectProbeHelpers(t *testing.T) {
	ms := members(7)
	r02, r03, r04, r05, r06, r07 := ms[1], ms[2], ms[3], ms[4], ms[5], ms[6]
	h := start + s

	t.Run("lowest two", func(t *testing.T) {
		f := newFixtureOf(t, ms, start)
		for _, m := range ms[1:] {
			f.mustSend(m, at(h))
		}
		for _, m := range ms[2:] {
			f.mustSend(m, at(h+10*s))
		}
		if sus := f.tick(at(h + 15*s)); !slices.Equal(sus, idsOf(r02)) {
			t.Fatalf("suspects %x, want r02", sus)
		}
		if got := f.tab.IndirectProbeRequest(r02.id.ID); !slices.Equal(got, idsOf(r03, r04)) {
			t.Errorf("helpers %x, want r03 and r04", got)
		}
		// Deterministic: asking again gives the same two.
		if got := f.tab.IndirectProbeRequest(r02.id.ID); !slices.Equal(got, idsOf(r03, r04)) {
			t.Errorf("second request %x, want r03 and r04", got)
		}
		if got := f.tab.IndirectProbeRequest(stranger().id.ID); got != nil {
			t.Errorf("helpers for a stranger: %x", got)
		}
		if got := f.tab.IndirectProbeRequest(f.self.id.ID); got != nil {
			t.Errorf("helpers for the local member: %x", got)
		}
	})

	t.Run("skip suspect and silent", func(t *testing.T) {
		f := newFixtureOf(t, ms, start)
		for _, m := range ms[1:] {
			f.mustSend(m, at(h))
		}
		// r02 and r03 are last heard at +20 s; r04 at h, so it is silent by
		// +30 s; r05 to r07 go on.
		for d := 5 * s; d <= 40*s; d += 5 * s {
			for _, m := range []tm{r05, r06, r07} {
				f.mustSend(m, at(h+d))
			}
			if d == 20*s {
				f.mustSend(r02, at(h+d))
				f.mustSend(r03, at(h+d))
			}
			f.tab.Tick(at(h + d))
		}
		// At +40 s: r04 silent, r02 and r03 suspect.
		if got := f.tab.IndirectProbeRequest(r02.id.ID); !slices.Equal(got, idsOf(r05, r06)) {
			t.Errorf("helpers %x, want r05 and r06 (r03 suspect, r04 silent)", got)
		}
		if got := f.tab.IndirectProbeRequest(r04.id.ID); got != nil {
			t.Errorf("helpers for a silent member: %x", got)
		}
	})

	t.Run("unheard and vouched-only are no helpers", func(t *testing.T) {
		f := newFixtureOf(t, ms[:5], start)
		for _, m := range ms[1:5] {
			f.mustSend(m, at(h))
		}
		// r06 joins at +10 s: not suspect yet, but never heard.
		if err := f.tab.SetRoster(testRoster(ms[:6]), testRosterHash, at(h+10*s)); err != nil {
			t.Fatal(err)
		}
		// r02, r03 and r05 stop; r04 goes on.
		f.mustSend(r04, at(h+10*s))
		sus := f.tick(at(h + 15*s))
		if !slices.Equal(sus, idsOf(r02, r03, r05)) {
			t.Fatalf("suspects %x, want r02, r03 and r05", sus)
		}
		// r04 is the only member heard directly.
		if got := f.tab.IndirectProbeRequest(r03.id.ID); !slices.Equal(got, idsOf(r04)) {
			t.Fatalf("helpers for r03 %x, want r04 alone (r06 never heard)", got)
		}
		// r03 is vouched for by r04: no longer suspect, but the local member
		// still cannot hear it.
		if _, err := f.relay(r04, r03, enc(t, f.beat(r03), r03), s, at(h+15*s)); err != nil {
			t.Fatal(err)
		}
		f.tick(at(h + 16*s))
		if got := f.tab.IndirectProbeRequest(r02.id.ID); !slices.Equal(got, idsOf(r04)) {
			t.Errorf("helpers for r02 %x, want r04 alone (r03 heard only through r04, r05 suspect, r06 never heard)", got)
		}
	})

	t.Run("nobody to ask", func(t *testing.T) {
		f := newFixture(t, 2, start)
		f.mustSend(r02, at(h))
		if sus := f.tick(at(h + 15*s)); !slices.Equal(sus, idsOf(r02)) {
			t.Fatalf("suspects %x", sus)
		}
		if got := f.tab.IndirectProbeRequest(r02.id.ID); len(got) != 0 {
			t.Errorf("helpers in a group of two: %x", got)
		}
	})
}

func TestProbeAnswerRules(t *testing.T) {
	ms := members(5)
	r02, r03, r04, r05 := ms[1], ms[2], ms[3], ms[4]
	h := start + s
	// heard is an answer that r02 was heard a second ago, with r02's next
	// heartbeat, which never reached the local member.
	heard := func(f *fixture) Report {
		return Report{Target: r02.id.ID, Ago: s, Heartbeat: enc(t, f.beat(r02), r02)}
	}

	// setup: r02 suspect at +15 s, helpers r03 and r04 asked; r05 not.
	setup := func(t *testing.T) *fixture {
		f := newFixtureOf(t, ms, start)
		for _, m := range ms[1:] {
			f.mustSend(m, at(h))
		}
		for _, m := range ms[2:] {
			f.mustSend(m, at(h+10*s))
		}
		if sus := f.tick(at(h + 15*s)); !slices.Equal(sus, idsOf(r02)) {
			t.Fatalf("suspects %x", sus)
		}
		if got := f.tab.IndirectProbeRequest(r02.id.ID); !slices.Equal(got, idsOf(r03, r04)) {
			t.Fatalf("helpers %x", got)
		}
		return f
	}
	stillSilentAt := func(t *testing.T, f *fixture, when time.Duration) {
		t.Helper()
		_, sil := f.tab.Tick(at(when))
		if len(sil) != 1 || sil[0].Subject != r02.id.ID {
			t.Errorf("want r02 silent at %v, got %s", when, describe(sil))
		}
	}

	t.Run("a member not asked", func(t *testing.T) {
		f := setup(t)
		if _, err := f.tab.RecordReport(f.admit(r05), heard(f), at(h+16*s)); !errors.Is(err, ErrUnsolicited) {
			t.Errorf("RecordReport from r05 = %v, want ErrUnsolicited", err)
		}
		stillSilentAt(t, f, h+30*s)
	})
	t.Run("target not suspect", func(t *testing.T) {
		f := setup(t)
		rep := Report{Target: r03.id.ID, Ago: s, Heartbeat: enc(t, f.beat(r03), r03)}
		if _, err := f.tab.RecordReport(f.admit(r04), rep, at(h+16*s)); !errors.Is(err, ErrUnsolicited) {
			t.Errorf("RecordReport about r03 = %v, want ErrUnsolicited", err)
		}
	})
	t.Run("target heard again", func(t *testing.T) {
		f := setup(t)
		f.mustSend(r02, at(h+16*s))
		// Heard directly: no longer suspect, before any Tick.
		if got := f.tab.IndirectProbeRequest(r02.id.ID); got != nil {
			t.Errorf("helpers for a member just heard: %x", got)
		}
		if _, err := f.tab.RecordReport(f.admit(r03), heard(f), at(h+16*s)); !errors.Is(err, ErrUnsolicited) {
			t.Errorf("an answer about a member just heard = %v, want ErrUnsolicited", err)
		}
	})
	t.Run("target unknown", func(t *testing.T) {
		f := setup(t)
		rep := Report{Target: stranger().id.ID, Heartbeat: enc(t, fullBeat(stranger()), stranger())}
		if _, err := f.tab.RecordReport(f.admit(r04), rep, at(h+16*s)); !errors.Is(err, ErrUnsolicited) {
			t.Errorf("RecordReport about a stranger = %v, want ErrUnsolicited", err)
		}
	})
	t.Run("after silence", func(t *testing.T) {
		f := setup(t)
		stillSilentAt(t, f, h+30*s)
		if _, err := f.tab.RecordReport(f.admit(r03), heard(f), at(h+31*s)); !errors.Is(err, ErrUnsolicited) {
			t.Errorf("RecordReport after silence = %v, want ErrUnsolicited", err)
		}
	})
	t.Run("asked in an earlier suspicion", func(t *testing.T) {
		f := setup(t)
		if _, err := f.tab.RecordReport(f.admit(r03), heard(f), at(h+16*s)); err != nil {
			t.Fatal(err)
		}
		// The recent vouch ends the suspicion at once, before any Tick: the
		// other helper's answer is late, and there is nobody to ask.
		if _, err := f.tab.RecordReport(f.admit(r04), heard(f), at(h+16*s)); !errors.Is(err, ErrUnsolicited) {
			t.Errorf("an answer after a recent vouch = %v, want ErrUnsolicited", err)
		}
		if got := f.tab.IndirectProbeRequest(r02.id.ID); got != nil {
			t.Errorf("helpers after a recent vouch: %x", got)
		}
		f.tick(at(h + 17*s))
		if _, err := f.tab.RecordReport(f.admit(r04), heard(f), at(h+18*s)); !errors.Is(err, ErrUnsolicited) {
			t.Errorf("an answer after the suspicion ended = %v, want ErrUnsolicited", err)
		}
	})
	t.Run("negative ago", func(t *testing.T) {
		f := setup(t)
		rep := heard(f)
		rep.Ago = -s
		if _, err := f.tab.RecordReport(f.admit(r03), rep, at(h+16*s)); !errors.Is(err, ErrBadReport) {
			t.Errorf("RecordReport with a negative ago = %v, want ErrBadReport", err)
		}
		stillSilentAt(t, f, h+30*s)
	})
	t.Run("not admitted", func(t *testing.T) {
		f := setup(t)
		if _, err := f.tab.RecordReport(Admitted{}, heard(f), at(h+16*s)); !errors.Is(err, ErrUnknownMember) {
			t.Errorf("RecordReport without Admit = %v, want ErrUnknownMember", err)
		}
		stillSilentAt(t, f, h+30*s)
	})
	t.Run("helper removed since", func(t *testing.T) {
		f := setup(t)
		a := f.admit(r03)
		if err := f.tab.SetRoster(testRoster([]tm{ms[0], r02, r04, r05}), testRosterHash, at(h+16*s)); err != nil {
			t.Fatal(err)
		}
		if _, err := f.tab.RecordReport(a, heard(f), at(h+16*s)); !errors.Is(err, ErrUnknownMember) {
			t.Errorf("RecordReport from a removed helper = %v, want ErrUnknownMember", err)
		}
	})
	t.Run("a vouch that is not recent keeps the suspicion", func(t *testing.T) {
		f := setup(t)
		rep := heard(f)
		rep.Ago = 15 * s // heard at h+1 s: newer than h, but 15 s ago
		if _, err := f.tab.RecordReport(f.admit(r03), rep, at(h+16*s)); err != nil {
			t.Fatal(err)
		}
		// Still suspect, so r04's later answer, with a newer heartbeat,
		// counts: heard at h+2 s.
		rep = heard(f)
		rep.Ago = 15 * s
		if _, err := f.tab.RecordReport(f.admit(r04), rep, at(h+17*s)); err != nil {
			t.Errorf("second answer in the same suspicion = %v", err)
		}
		f.tick(at(h + 32*s - 1))
		_, sil := f.tab.Tick(at(h + 32*s)) // 30 s after h+2 s, the newest hearing
		if len(sil) != 1 {
			t.Fatalf("want r02 silent at +32 s, got %s", describe(sil))
		}
		wantEvent(t, sil[0], events.MemberSilent, r02, f.self, at(h+2*s))
	})
}

func TestBackAfterSilenceClassifies(t *testing.T) {
	cases := []struct {
		name     string
		announce bool   // the last heartbeat before silence said "going down"
		reboot   bool   // it comes back in a new boot
		version  string // its OpenWrt version on return
		unheard  bool   // never heard before the silence
		want     events.Type
	}{
		{name: "crash", reboot: true, version: "24.10.4", want: events.RebootUnplanned},
		{name: "planned", announce: true, reboot: true, version: "24.10.4", want: events.RebootPlanned},
		{name: "upgrade", reboot: true, version: "24.10.5", want: events.Upgraded},
		{name: "planned upgrade", announce: true, reboot: true, version: "24.10.5", want: events.Upgraded},
		{name: "link lost", version: "24.10.4", want: events.LinkLost},
		{name: "announced, stayed up", announce: true, version: "24.10.4", want: events.LinkLost},
		{name: "never heard before", unheard: true, version: "24.10.4", want: events.MemberBack},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t, 2, start)
			r02 := f.ms[1]
			h := start + s
			before := events.Before{}
			if !c.unheard {
				f.sim(r02).goingDown = c.announce
				f.mustSend(r02, at(h))
				before = events.Before{AnnouncedGoingDown: c.announce, BootID: bootID(1), Version: "24.10.4"}
			}
			_, sil := f.tab.Tick(at(h + 40*s))
			if len(sil) != 1 {
				t.Fatalf("silence: %s", describe(sil))
			}
			if c.reboot {
				f.reboot(r02)
			}
			f.sim(r02).version = c.version
			obs := f.mustSend(r02, at(h+90*s))
			if len(obs.Events) != 1 {
				t.Fatalf("return: %s", describe(obs.Events))
			}
			e := obs.Events[0]
			ret := events.Return{BootID: bootID(f.sim(r02).boot), Version: c.version}
			if want := events.Classify(before, ret); want != c.want {
				t.Fatalf("the case is wrong: Classify says %s", want)
			}
			wantEvent(t, e, c.want, r02, f.self, at(h+90*s))
			var wantDetail map[string]string
			if c.want == events.Upgraded {
				wantDetail = map[string]string{"from": "24.10.4", "to": c.version}
			}
			if !reflect.DeepEqual(e.Detail, wantDetail) {
				t.Errorf("Detail %v, want %v", e.Detail, wantDetail)
			}
			// Back means back: no second event, and silent again only after
			// another 30 s.
			if obs := f.mustSend(r02, at(h+95*s)); len(obs.Events) != 0 {
				t.Errorf("second heartbeat after return: %s", describe(obs.Events))
			}
			f.tick(at(h + 125*s - 1))
		})
	}
}

func TestRebootWithoutSilence(t *testing.T) {
	f := newFixture(t, 2, start)
	r02 := f.ms[1]
	h := start + s
	if obs := f.mustSend(r02, at(h)); len(obs.Events) != 0 {
		t.Errorf("first heartbeat: %s", describe(obs.Events))
	}
	// Back within 20 s, suspect but not silent, in a new boot.
	f.tick(at(h + 20*s))
	f.reboot(r02)
	obs := f.mustSend(r02, at(h+20*s))
	if len(obs.Events) != 1 {
		t.Fatalf("fast reboot: %s", describe(obs.Events))
	}
	wantEvent(t, obs.Events[0], events.RebootUnplanned, r02, f.self, at(h+20*s))
	// A pause in the same boot is no event.
	if obs := f.mustSend(r02, at(h+45*s)); len(obs.Events) != 0 {
		t.Errorf("a 25 s pause in one boot: %s", describe(obs.Events))
	}
	// A fast upgrade.
	f.reboot(r02)
	f.sim(r02).version = "25.12.0"
	obs = f.mustSend(r02, at(h+50*s))
	if len(obs.Events) != 1 || obs.Events[0].Type != events.Upgraded {
		t.Fatalf("fast upgrade: %s", describe(obs.Events))
	}
	if want := map[string]string{"from": "24.10.4", "to": "25.12.0"}; !reflect.DeepEqual(obs.Events[0].Detail, want) {
		t.Errorf("Detail %v, want %v", obs.Events[0].Detail, want)
	}
}

func TestSilentCaughtUpInObserve(t *testing.T) {
	f := newFixture(t, 2, start)
	r02 := f.ms[1]
	h := start + s
	f.mustSend(r02, at(h))
	if obs := f.mustSend(r02, at(h+30*s-1)); len(obs.Events) != 0 {
		t.Errorf("heard just before 30 s: %s", describe(obs.Events))
	}
	// No Tick for 31 s: the heartbeat itself shows the silence and the
	// return, so the result does not depend on when Tick ran.
	obs := f.mustSend(r02, at(h+61*s))
	if len(obs.Events) != 2 {
		t.Fatalf("heard after 31 s without a Tick: %s", describe(obs.Events))
	}
	wantEvent(t, obs.Events[0], events.MemberSilent, r02, f.self, at(h+30*s-1))
	wantEvent(t, obs.Events[1], events.LinkLost, r02, f.self, at(h+61*s))
	if _, sil := f.tab.Tick(at(h + 62*s)); len(sil) != 0 {
		t.Errorf("Tick repeats the silence: %s", describe(sil))
	}
}

// bootSeqDir returns an identity directory whose stored boot sequence number
// is stored, and the number NextBootSeq hands out for this boot.
func bootSeqDir(t *testing.T, stored uint64) (string, uint64) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "id")
	if err := identity.RaiseBootSeq(dir, stored); err != nil {
		t.Fatal(err)
	}
	seq, err := identity.NextBootSeq(dir)
	if err != nil {
		t.Fatal(err)
	}
	return dir, seq
}

func TestBootSeqRestoreFromPeers(t *testing.T) {
	ms := members(3)
	r01, r02 := ms[0], ms[1]

	// r01 ran up to boot 9 before it was restored from an older backup.
	hf := newFixtureOf(t, []tm{r02, r01, ms[2]}, start)
	past := Heartbeat{}
	{
		hf.sims[r01.id.ID] = &sim{seq: 9, boot: 0x09, version: "24.10.4"}
		past = hf.beat(r01)
		if _, err := hf.tab.Observe(testEpoch, enc(t, past, r01), at(start+s)); err != nil {
			t.Fatal(err)
		}
	}
	rep := hf.tab.Report(r01.id.ID, at(start+3*s))
	if rep.BootSeq != 9 || rep.Boot != bootID(0x09) || !bytes.Equal(rep.Heartbeat, enc(t, past, r01)) || rep.Ago != 2*s {
		t.Fatalf("r02 reports %+v about r01, want boot 9", rep)
	}

	// The restored r01 starts at 6 from its stale file.
	dir, seq := bootSeqDir(t, 5)
	if seq != 6 {
		t.Fatalf("NextBootSeq = %d", seq)
	}
	rf := newFixtureWith(t, ms, start, func(c *Config) { c.BootSeq = seq })
	if got, raised, err := rf.tab.RestoreBootSeq(dir); got != 6 || raised || err != nil {
		t.Fatalf("RestoreBootSeq with no evidence = %d, %v, %v", got, raised, err)
	}
	if _, err := rf.tab.RecordReport(rf.admit(r02), rep, at(start+4*s)); err != nil {
		t.Fatalf("RecordReport: %v", err)
	}
	got, raised, err := rf.tab.RestoreBootSeq(dir)
	if got != 10 || !raised || err != nil {
		t.Fatalf("RestoreBootSeq = %d, %v, %v; want 10, true", got, raised, err)
	}
	if rf.tab.BootSeq() != 10 {
		t.Errorf("BootSeq() = %d, want 10", rf.tab.BootSeq())
	}
	if next, _ := identity.NextBootSeq(dir); next != 11 {
		t.Errorf("the stored boot sequence number is %d, want 10", next-1)
	}
	if got, raised, err := rf.tab.RestoreBootSeq(dir); got != 10 || raised || err != nil {
		t.Errorf("second RestoreBootSeq = %d, %v, %v; want 10, false", got, raised, err)
	}

	// The peer refuses r01's stale boot and takes the new one.
	stale := hf.beat(r01)
	stale.BootSeq, stale.Boot = 6, localBoot
	if _, err := hf.tab.Observe(testEpoch, enc(t, stale, r01), at(start+5*s)); !errors.Is(err, ErrReplay) {
		t.Errorf("boot 6 after boot 9: %v, want ErrReplay", err)
	}
	fresh := stale
	fresh.BootSeq, fresh.Counter = 10, 1
	if _, err := hf.tab.Observe(testEpoch, enc(t, fresh, r01), at(start+5*s)); err != nil {
		t.Errorf("boot 10: %v", err)
	}
}

func TestBootSeqEvidenceRules(t *testing.T) {
	ms := members(3)
	r01, r02, r03 := ms[0], ms[1], ms[2]
	cases := []struct {
		name    string
		report  Report
		from    tm
		want    uint64
		raised  bool
		wantErr error
	}{
		{name: "lower", report: Report{Target: r01.id.ID, BootSeq: 5, Boot: bootID(5)}, from: r02, want: 6},
		{name: "this boot", report: Report{Target: r01.id.ID, BootSeq: 6, Boot: localBoot}, from: r02, want: 6},
		{name: "same number, other boot", report: Report{Target: r01.id.ID, BootSeq: 6, Boot: bootID(6)}, from: r02, want: 7, raised: true},
		{name: "same number, boot unknown", report: Report{Target: r01.id.ID, BootSeq: 6}, from: r02, want: 7, raised: true},
		{name: "about another member", report: Report{Target: r03.id.ID, BootSeq: 99, Boot: bootID(9)}, from: r02, want: 6, wantErr: ErrUnsolicited},
		{name: "higher", report: Report{Target: r01.id.ID, BootSeq: 7}, from: r03, want: 8, raised: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir, seq := bootSeqDir(t, 5)
			f := newFixtureWith(t, ms, start, func(cf *Config) { cf.BootSeq = seq })
			if _, err := f.tab.RecordReport(f.admit(c.from), c.report, at(start+s)); !errors.Is(err, c.wantErr) {
				t.Fatalf("RecordReport = %v, want %v", err, c.wantErr)
			}
			got, raised, err := f.tab.RestoreBootSeq(dir)
			if got != c.want || raised != c.raised || err != nil {
				t.Errorf("RestoreBootSeq = %d, %v, %v; want %d, %v", got, raised, err, c.want, c.raised)
			}
		})
	}

	// The highest evidence wins, whatever the order.
	dir, seq := bootSeqDir(t, 5)
	f := newFixtureWith(t, ms, start, func(cf *Config) { cf.BootSeq = seq })
	for _, n := range []uint64{8, 12, 9} {
		rep := Report{Target: r01.id.ID, BootSeq: n}
		if _, err := f.tab.RecordReport(f.admit(r02), rep, at(start+s)); err != nil {
			t.Fatal(err)
		}
	}
	if got, _, _ := f.tab.RestoreBootSeq(dir); got != 13 {
		t.Errorf("RestoreBootSeq after 8, 12, 9 = %d, want 13", got)
	}
}

func TestBootSeqRaiseBounded(t *testing.T) {
	ms := members(2)
	r01, r02 := ms[0], ms[1]
	dir, seq := bootSeqDir(t, 5)
	f := newFixtureWith(t, ms, start, func(c *Config) { c.BootSeq = seq })
	huge := Report{Target: r01.id.ID, BootSeq: seq + MaxBootSeqRaise + 7}
	if _, err := f.tab.RecordReport(f.admit(r02), huge, at(start+s)); err != nil {
		t.Fatal(err)
	}
	got, raised, err := f.tab.RestoreBootSeq(dir)
	if want := seq + MaxBootSeqRaise + 1; got != want || !raised || err != nil {
		t.Fatalf("RestoreBootSeq = %d, %v, %v; want %d (raised to the start's %d + 2^20)", got, raised, err, want, seq)
	}
	// Once at the bound, nothing more in this run, however often asked.
	for i := 0; i < 3; i++ {
		if again, raised, err := f.tab.RestoreBootSeq(dir); again != got || raised || err != nil {
			t.Errorf("RestoreBootSeq again = %d, %v, %v; want %d, false", again, raised, err, got)
		}
	}
	if next, _ := identity.NextBootSeq(dir); next != got+1 {
		t.Errorf("stored %d, want %d", next-1, got)
	}
	if MaxBootSeqRaise != 1<<20 {
		t.Errorf("MaxBootSeqRaise = %d, want 2^20", MaxBootSeqRaise)
	}

	// The bound does not wrap around at the top of the number space.
	dir, seq = bootSeqDir(t, math.MaxUint64-4)
	f = newFixtureWith(t, ms, start, func(c *Config) { c.BootSeq = seq })
	top := Report{Target: r01.id.ID, BootSeq: math.MaxUint64}
	if _, err := f.tab.RecordReport(f.admit(r02), top, at(start+s)); err != nil {
		t.Fatal(err)
	}
	got, raised, err = f.tab.RestoreBootSeq(dir)
	if !errors.Is(err, identity.ErrBootSeqExhausted) || raised || got != seq {
		t.Errorf("RestoreBootSeq at the top = %d, %v, %v; want %d, false, ErrBootSeqExhausted", got, raised, err, seq)
	}
}

func TestBootSeqEvidenceFromOwnHeartbeat(t *testing.T) {
	ms := members(2)
	r01 := ms[0]
	dir, seq := bootSeqDir(t, 5)
	f := newFixtureWith(t, ms, start, func(c *Config) { c.BootSeq = seq })
	own := func(seq uint64, boot ids.BootID, key ed25519.PrivateKey) error {
		h := fullBeat(r01)
		h.BootSeq, h.Boot, h.Counter = seq, boot, 1
		body := handBody(h)
		_, err := f.tab.Observe(testEpoch, handSign(body, key), at(start+s))
		return err
	}
	// Its own echo, this boot: nothing to learn, and no signature is
	// checked for it, valid or not.
	if err := own(seq, localBoot, r01.id.Sign); !errors.Is(err, ErrSelf) {
		t.Errorf("own echo: %v, want ErrSelf", err)
	}
	if err := own(seq+3, localBoot, strangerKey); !errors.Is(err, ErrSelf) {
		t.Errorf("own echo with another signature: %v, want ErrSelf", err)
	}
	// A heartbeat of its own key from a boot it no longer remembers, forged:
	// refused.
	if err := own(40, bootID(40), strangerKey); !errors.Is(err, ErrSignature) {
		t.Errorf("forged own heartbeat: %v, want ErrSignature", err)
	}
	if got, raised, _ := f.tab.RestoreBootSeq(dir); raised {
		t.Fatalf("raised to %d on an echo or a forgery", got)
	}
	// Genuine: boot 9 from before the restore.
	if err := own(9, bootID(9), r01.id.Sign); !errors.Is(err, ErrSelf) {
		t.Errorf("own heartbeat from boot 9: %v, want ErrSelf", err)
	}
	if got, raised, err := f.tab.RestoreBootSeq(dir); got != 10 || !raised || err != nil {
		t.Errorf("RestoreBootSeq = %d, %v, %v; want 10, true", got, raised, err)
	}
	c := f.tab.Counters()
	if c.Self != 3 || c.Signature != 1 || c.Accepted != 0 {
		t.Errorf("counters %+v; want 3 own, 1 bad signature, none accepted", c)
	}
}

func TestOffsetFromTrustedPeer(t *testing.T) {
	ms := members(5)
	r02, r03, r04, r05 := ms[1], ms[2], ms[3], ms[4]
	h := start + s
	// The peers' wall clock runs a year and more ahead of the local one,
	// which started at 1970 when the router booted without NTP.
	peerWall := t0.Add(400 * 24 * time.Hour)
	// beatAt sends m's heartbeat at local mono, its wall clock reading
	// wall + (mono - h).
	beatAt := func(f *fixture, m tm, wall time.Time, trusted bool, now clock.Stamp) {
		t.Helper()
		b := f.beat(m)
		b.Wall, b.ClockTrusted = wall.Add(now.Mono-h), trusted
		if _, err := f.tab.Observe(testEpoch, enc(t, b, m), now); err != nil {
			t.Fatal(err)
		}
	}
	want := time.Duration(peerWall.UnixNano()) - h

	t.Run("untrusted local clock", func(t *testing.T) {
		f := newFixtureOf(t, ms[:3], start)
		if _, ok := f.tab.Offset(); ok {
			t.Error("an offset before any heartbeat")
		}
		beatAt(f, r03, peerWall.Add(-time.Hour), false, untrustedAt(h))
		if _, ok := f.tab.Offset(); ok {
			t.Error("an offset from an untrusted peer")
		}
		beatAt(f, r02, peerWall, true, untrustedAt(h))
		if off, ok := f.tab.Offset(); !ok || off != want {
			t.Fatalf("Offset = %v, %v; want %v (r02's wall clock minus the local monotonic clock)", off, ok, want)
		}
		beatAt(f, r02, peerWall, true, untrustedAt(h+25*s))
		if off, _ := f.tab.Offset(); off != want {
			t.Errorf("Offset after a second heartbeat = %v, want %v", off, want)
		}
		// r03 goes silent. The untrusted local member stamps the silence
		// with its monotonic clock plus the offset, and the stamp counts as
		// trusted (design 4.4).
		_, sil := f.tab.Tick(untrustedAt(h + 30*s))
		if len(sil) != 1 {
			t.Fatalf("silence: %s", describe(sil))
		}
		e := sil[0]
		wantEvent(t, e, events.MemberSilent, r03, f.self, clock.Stamp{Wall: peerWall, Mono: h, Trusted: true, Boot: localBoot})
		// r02 says its clock is no longer trusted: its offset is gone.
		beatAt(f, r02, peerWall, false, untrustedAt(h+31*s))
		if _, ok := f.tab.Offset(); ok {
			t.Error("an offset after the trusted peer lost its clock")
		}
	})

	t.Run("trusted local clock", func(t *testing.T) {
		f := newFixtureOf(t, ms[:3], start)
		beatAt(f, r02, peerWall, true, at(h))
		beatAt(f, r03, peerWall, true, at(h))
		beatAt(f, r02, peerWall, true, at(h+25*s))
		_, sil := f.tab.Tick(at(h + 30*s))
		if len(sil) != 1 {
			t.Fatalf("silence: %s", describe(sil))
		}
		wantEvent(t, sil[0], events.MemberSilent, r03, f.self, at(h))
	})

	t.Run("no trusted peer", func(t *testing.T) {
		f := newFixtureOf(t, ms[:2], start)
		beatAt(f, r02, peerWall, false, untrustedAt(h))
		_, sil := f.tab.Tick(untrustedAt(h + 30*s))
		if len(sil) != 1 {
			t.Fatalf("silence: %s", describe(sil))
		}
		wantEvent(t, sil[0], events.MemberSilent, r02, f.self, untrustedAt(h))
	})

	t.Run("median", func(t *testing.T) {
		f := newFixtureOf(t, ms, start)
		year := 365 * 24 * time.Hour
		beatAt(f, r02, peerWall, true, untrustedAt(h))
		beatAt(f, r03, peerWall.Add(s), true, untrustedAt(h))
		if off, _ := f.tab.Offset(); off != want {
			t.Errorf("two peers: Offset %v, want the lower %v", off, want)
		}
		beatAt(f, r04, peerWall.Add(year), true, untrustedAt(h))
		if off, _ := f.tab.Offset(); off != want+s {
			t.Errorf("three peers, one lying: Offset %v, want the median %v", off, want+s)
		}
		// r05's first heartbeat lies one way, its latest the other; only
		// the latest counts.
		beatAt(f, r05, peerWall.Add(year), true, untrustedAt(h))
		beatAt(f, r05, peerWall.Add(-year), true, untrustedAt(h+s))
		if off, _ := f.tab.Offset(); off != want {
			t.Errorf("four peers, a liar each way: Offset %v, want the lower median %v", off, want)
		}
	})
}

func TestDuplicateIdentityDetected(t *testing.T) {
	ms := members(2)
	r02 := ms[1]
	h := start + s
	beat := func(seq uint64, boot byte, counter uint64) Heartbeat {
		b := fullBeat(r02)
		b.BootSeq, b.Boot, b.Counter, b.GoingDown = seq, bootID(boot), counter, false
		return b
	}
	obs := func(f *fixture, b Heartbeat, key ed25519.PrivateKey, now time.Duration) (Observed, error) {
		return f.tab.Observe(testEpoch, handSign(handBody(b), key), at(now))
	}

	t.Run("interleaved boot sequences", func(t *testing.T) {
		f := newFixture(t, 2, start)
		// Device A runs boot 10; device B, the same identity restored from a
		// backup, starts boot 11 beside it.
		for c := uint64(1); c <= 2; c++ {
			if _, err := obs(f, beat(10, 0xa, c), r02.id.Sign, h); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := obs(f, beat(11, 0xb, 1), r02.id.Sign, h+s); err != nil {
			t.Fatal(err)
		}
		// A replay of A's old heartbeat is only a replay.
		if o, err := obs(f, beat(10, 0xa, 2), r02.id.Sign, h+2*s); !errors.Is(err, ErrReplay) || len(o.Events) != 0 {
			t.Errorf("replay of A: %v %s, want ErrReplay and no event", err, describe(o.Events))
		}
		// A forged heartbeat in A's boot proves nothing.
		if o, err := obs(f, beat(10, 0xa, 3), strangerKey, h+2*s); !errors.Is(err, ErrSignature) || len(o.Events) != 0 {
			t.Errorf("forged A: %v %s, want ErrSignature and no event", err, describe(o.Events))
		}
		// A is still alive: it goes on counting in boot 10.
		o, err := obs(f, beat(10, 0xa, 3), r02.id.Sign, h+5*s)
		if !errors.Is(err, ErrDuplicateIdentity) || len(o.Events) != 1 {
			t.Fatalf("A alive after B started: %v %s, want ErrDuplicateIdentity and one event", err, describe(o.Events))
		}
		wantEvent(t, o.Events[0], events.DuplicateIdentity, r02, f.self, at(h+5*s))
		// Reported once per conflicting boot.
		if o, err := obs(f, beat(10, 0xa, 4), r02.id.Sign, h+10*s); !errors.Is(err, ErrDuplicateIdentity) || len(o.Events) != 0 {
			t.Errorf("A again: %v %s, want ErrDuplicateIdentity and no new event", err, describe(o.Events))
		}
		// B carries on.
		if _, err := obs(f, beat(11, 0xb, 2), r02.id.Sign, h+10*s); err != nil {
			t.Errorf("B: %v", err)
		}
		if c := f.tab.Counters(); c.Duplicate != 2 {
			t.Errorf("counters %+v, want 2 duplicates", c)
		}
	})

	t.Run("one boot number, two boot IDs", func(t *testing.T) {
		f := newFixture(t, 2, start)
		if _, err := obs(f, beat(10, 0xa, 1), r02.id.Sign, h); err != nil {
			t.Fatal(err)
		}
		if o, err := obs(f, beat(10, 0xb, 1), strangerKey, h+s); !errors.Is(err, ErrSignature) || len(o.Events) != 0 {
			t.Errorf("forged second boot ID: %v %s", err, describe(o.Events))
		}
		o, err := obs(f, beat(10, 0xb, 1), r02.id.Sign, h+s)
		if !errors.Is(err, ErrDuplicateIdentity) || len(o.Events) != 1 {
			t.Fatalf("second boot ID: %v %s, want ErrDuplicateIdentity and one event", err, describe(o.Events))
		}
		wantEvent(t, o.Events[0], events.DuplicateIdentity, r02, f.self, at(h+s))
		// The first device keeps its place.
		if _, err := obs(f, beat(10, 0xa, 2), r02.id.Sign, h+5*s); err != nil {
			t.Errorf("first device after the conflict: %v", err)
		}
	})

	t.Run("an honest reboot is no duplicate", func(t *testing.T) {
		f := newFixture(t, 2, start)
		for c := uint64(1); c <= 3; c++ {
			if _, err := obs(f, beat(10, 0xa, c), r02.id.Sign, h); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := obs(f, beat(11, 0xb, 1), r02.id.Sign, h+s); err != nil {
			t.Fatal(err)
		}
		for c := uint64(1); c <= 3; c++ {
			if o, err := obs(f, beat(10, 0xa, c), r02.id.Sign, h+2*s); !errors.Is(err, ErrReplay) || len(o.Events) != 0 {
				t.Errorf("old boot, counter %d: %v %s, want ErrReplay", c, err, describe(o.Events))
			}
		}
		if c := f.tab.Counters(); c.Duplicate != 0 {
			t.Errorf("counters %+v, want no duplicate", c)
		}
	})
}

func TestRosterHashMismatchFlagged(t *testing.T) {
	f := newFixture(t, 3, start)
	r02, r03 := f.ms[1], f.ms[2]
	h := start + s
	if obs := f.mustSend(r02, at(h)); obs.RosterMismatch {
		t.Error("the same roster hash is flagged")
	}
	other := ids.Hash{0x99}
	b := f.beat(r03)
	b.RosterHash = other
	obs, err := f.tab.Observe(testEpoch, enc(t, b, r03), at(h))
	if err != nil {
		t.Fatalf("a heartbeat with another roster hash is refused: %v", err)
	}
	if !obs.RosterMismatch {
		t.Error("another roster hash is not flagged")
	}
	if obs.Heartbeat.RosterHash != other || obs.Heartbeat.From != r03.id.ID {
		t.Errorf("Observed.Heartbeat %+v", obs.Heartbeat)
	}
	// The member still counts as heard.
	f.tick(at(h + 29*s))

	// Once the local member holds that roster, the old hash is the odd one.
	if err := f.tab.SetRoster(testRoster(f.ms), other, at(h+29*s)); err != nil {
		t.Fatal(err)
	}
	b = f.beat(r03)
	b.RosterHash = other
	if obs, _ := f.tab.Observe(testEpoch, enc(t, b, r03), at(h+29*s)); obs.RosterMismatch {
		t.Error("the new hash is flagged after SetRoster")
	}
	if obs := f.mustSend(r02, at(h+29*s)); !obs.RosterMismatch {
		t.Error("the old hash is not flagged after SetRoster")
	}
}

func TestObserveCheckOrder(t *testing.T) {
	f := newFixture(t, 3, start)
	r02 := f.ms[1]
	h := start + s
	counters := func() Counters { return f.tab.Counters() }

	// A sender outside the roster, validly signed: dropped and counted.
	x := stranger()
	if obs, err := f.tab.Observe(testEpoch, enc(t, fullBeat(x), x), at(h)); !errors.Is(err, ErrUnknownMember) || !reflect.DeepEqual(obs, Observed{}) {
		t.Errorf("unknown member: %+v, %v", obs, err)
	}
	// Unknown is decided before the signature.
	bad := handSign(handBody(fullBeat(x)), strangerKey)
	bad[len(bad)-1] ^= 1
	if _, err := f.tab.Observe(testEpoch, bad, at(h)); !errors.Is(err, ErrUnknownMember) {
		t.Errorf("unknown member, bad signature: %v, want ErrUnknownMember", err)
	}
	if c := counters(); c.Unknown != 2 || c.Signature != 0 {
		t.Errorf("counters %+v", c)
	}

	// Signed for another epoch than the packet's.
	b := f.beat(r02)
	if _, err := f.tab.Observe(testEpoch+1, enc(t, b, r02), at(h)); !errors.Is(err, ErrEpoch) {
		t.Errorf("another epoch: %v, want ErrEpoch", err)
	}
	// Garbage and truncation.
	good := enc(t, b, r02)
	for _, g := range [][]byte{nil, good[:100], make([]byte, 300), make([]byte, MaxEncodedLen+1)} {
		if _, err := f.tab.Observe(testEpoch, g, at(h)); !errors.Is(err, ErrMalformed) {
			t.Errorf("%d bytes of garbage: %v, want ErrMalformed", len(g), err)
		}
	}
	// A bad signature.
	forged := handSign(handBody(b), strangerKey)
	if _, err := f.tab.Observe(testEpoch, forged, at(h)); !errors.Is(err, ErrSignature) {
		t.Errorf("forged: %v, want ErrSignature", err)
	}
	// Validly signed but malformed fields: dropped, and the counter stays
	// free for the real heartbeat.
	mb := b
	mb.Name = "BAD"
	if _, err := f.tab.Observe(testEpoch, handSign(handBody(mb), r02.id.Sign), at(h)); !errors.Is(err, ErrMalformed) {
		t.Errorf("signed but malformed: %v, want ErrMalformed", err)
	}
	orig := bytes.Clone(good)
	if _, err := f.tab.Observe(testEpoch, good, at(h)); err != nil {
		t.Fatalf("the genuine heartbeat: %v", err)
	}
	if !bytes.Equal(good, orig) {
		t.Error("Observe modified its input")
	}
	// The replay check comes before the signature: a replayed counter with
	// a broken signature is a replay, and no signature is checked.
	before := counters().Signature
	broken := bytes.Clone(good)
	broken[len(broken)-1] ^= 1
	if _, err := f.tab.Observe(testEpoch, broken, at(h)); !errors.Is(err, ErrReplay) {
		t.Errorf("replayed counter, broken signature: %v, want ErrReplay", err)
	}
	if _, err := f.tab.Observe(testEpoch, good, at(h)); !errors.Is(err, ErrReplay) {
		t.Errorf("replay: %v, want ErrReplay", err)
	}
	if c := counters(); c.Signature != before {
		t.Errorf("a signature was checked for a replay: %+v", c)
	}
	want := Counters{Accepted: 1, Malformed: 5, WrongEpoch: 1, Unknown: 2, Replay: 2, Signature: 1}
	if c := counters(); c != want {
		t.Errorf("counters %+v, want %+v", c, want)
	}
}

func TestForgeryDoesNotMoveWindow(t *testing.T) {
	f := newFixture(t, 2, start)
	r02 := f.ms[1]
	h := start + s
	beat := func(seq uint64, counter uint64) Heartbeat {
		b := fullBeat(r02)
		b.BootSeq, b.Boot, b.Counter, b.GoingDown = seq, bootID(byte(seq)), counter, false
		return b
	}
	send := func(b Heartbeat, key ed25519.PrivateKey) error {
		_, err := f.tab.Observe(testEpoch, handSign(handBody(b), key), at(h))
		return err
	}
	if err := send(beat(5, 10), r02.id.Sign); err != nil {
		t.Fatal(err)
	}
	steps := []struct {
		name string
		b    Heartbeat
		key  ed25519.PrivateKey
		want error
	}{
		{"forged far ahead", beat(5, 1000), strangerKey, ErrSignature},
		{"genuine next", beat(5, 11), r02.id.Sign, nil},
		{"forged newer boot", beat(6, 1), strangerKey, ErrSignature},
		{"genuine same boot", beat(5, 12), r02.id.Sign, nil},
		{"forged next counter", beat(5, 13), strangerKey, ErrSignature},
		{"genuine with that counter", beat(5, 13), r02.id.Sign, nil},
	}
	for _, st := range steps {
		if err := send(st.b, st.key); !errors.Is(err, st.want) {
			t.Errorf("%s: %v, want %v", st.name, err, st.want)
		}
	}
	// The forged boot 6 did not reach the stored boot numbers either.
	f.tick(at(h + s))
	data, err := f.st.ReadFile(peerStateFile)
	if err != nil {
		t.Fatal(err)
	}
	if want := fmt.Sprintf(`{"version":1,"peers":[{"id":"%s","boot_seq":5,"boot":"%s","counter":13}]}`+"\n", r02.id.ID, bootID(5)); string(data) != want {
		t.Errorf("stored %s, want %s", data, want)
	}
}

func TestPeerStatePersisted(t *testing.T) {
	ms := members(3)
	r02, r03 := ms[1], ms[2]
	f := newFixtureOf(t, ms, start)
	h := start + s
	f.sims[r02.id.ID] = &sim{seq: 7, boot: 7, version: "24.10.4"}
	f.mustSend(r02, at(h))
	f.mustSend(r03, at(h))
	f.tick(at(h))
	data, err := f.st.ReadFile(peerStateFile)
	if err != nil {
		t.Fatalf("nothing stored: %v", err)
	}
	stored := func(c2, c3 uint64) string {
		return fmt.Sprintf(`{"version":1,"peers":[{"id":"%s","boot_seq":%d,"boot":"%s","counter":%d},{"id":"%s","boot_seq":1,"boot":"%s","counter":%d}]}`+"\n",
			r02.id.ID, f.sim(r02).seq, bootID(f.sim(r02).boot), c2, r03.id.ID, bootID(1), c3)
	}
	if want := stored(1, 1); string(data) != want {
		t.Fatalf("stored\n%s\nwant\n%s", data, want)
	}
	if fi, err := os.Stat(filepath.Join(f.dir, peerStateFile)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("file mode %v, %v; want 0600", fi.Mode().Perm(), err)
	}

	// After a restart, r02's older boot is refused although the replay
	// window starts empty, and the stored boot is known.
	f.restart(start + 100*s)
	old := f.beat(r02)
	old.BootSeq, old.Boot = 6, bootID(6)
	if _, err := f.tab.Observe(testEpoch, enc(t, old, r02), at(start+101*s)); !errors.Is(err, ErrReplay) {
		t.Errorf("boot 6 after a restart that stored 7: %v, want ErrReplay", err)
	}
	if rep := f.tab.Report(r02.id.ID, at(start+101*s)); rep.BootSeq != 7 || rep.Heartbeat != nil || rep.Boot != bootID(7) {
		t.Errorf("Report after restart %+v, want boot 7 and its ID from the file, no heartbeat", rep)
	}

	// Every accepted heartbeat marks the state; it is written at most once
	// a minute.
	if err := f.st.WriteFileAtomic(peerStateFile, []byte("marker")); err != nil {
		t.Fatal(err)
	}
	for d := 105 * s; d <= 160*s; d += 5 * s {
		f.mustSend(r02, at(start+d))
		f.mustSend(r03, at(start+d))
		f.tick(at(start + d))
		if d == 105*s {
			if data, _ := f.st.ReadFile(peerStateFile); string(data) != stored(f.sim(r02).counter, f.sim(r03).counter) {
				t.Fatalf("first Tick after a restart wrote %s", data)
			}
			if err := f.st.WriteFileAtomic(peerStateFile, []byte("marker")); err != nil {
				t.Fatal(err)
			}
		}
	}
	if data, _ := f.st.ReadFile(peerStateFile); string(data) != "marker" {
		t.Fatalf("written again within a minute: %s", data)
	}
	f.tick(at(start + 165*s))
	if data, _ := f.st.ReadFile(peerStateFile); string(data) != stored(f.sim(r02).counter, f.sim(r03).counter) {
		t.Fatalf("a minute later stored %s", data)
	}

	// Nothing accepted, nothing written.
	if err := f.st.WriteFileAtomic(peerStateFile, []byte("marker")); err != nil {
		t.Fatal(err)
	}
	for d := 170 * s; d <= 400*s; d += 10 * s {
		f.tab.Tick(at(start + d))
	}
	if data, _ := f.st.ReadFile(peerStateFile); string(data) != "marker" {
		t.Errorf("written with nothing new: %s", data)
	}
}

func TestPeerStateFileRejected(t *testing.T) {
	ms := members(3)
	id2 := ms[1].id.ID.String()
	b1 := bootID(1).String()
	entry := func(fields string) string { return `{"version":1,"peers":[{` + fields + `}]}` }
	cases := map[string]string{
		"not JSON":        "nope",
		"unknown field":   `{"version":1,"peers":[],"x":1}`,
		"unknown in peer": entry(`"id":"` + id2 + `","boot_seq":1,"boot":"` + b1 + `","counter":1,"x":1`),
		"version 2":       `{"version":2,"peers":[]}`,
		"no version":      `{"peers":[]}`,
		"zero ID":         entry(`"id":"00000000000000000000000000000000","boot_seq":1,"boot":"` + b1 + `","counter":1`),
		"short ID":        entry(`"id":"0102","boot_seq":1,"boot":"` + b1 + `","counter":1`),
		"same ID twice": `{"version":1,"peers":[{"id":"` + id2 + `","boot_seq":1,"boot":"` + b1 + `","counter":1},` +
			`{"id":"` + id2 + `","boot_seq":2,"boot":"` + b1 + `","counter":1}]}`,
		"boot seq 0": entry(`"id":"` + id2 + `","boot_seq":0,"boot":"` + b1 + `","counter":1`),
		"negative":   entry(`"id":"` + id2 + `","boot_seq":-1,"boot":"` + b1 + `","counter":1`),
		"zero boot":  entry(`"id":"` + id2 + `","boot_seq":1,"boot":"00000000000000000000000000000000","counter":1`),
		"no boot":    entry(`"id":"` + id2 + `","boot_seq":1,"counter":1`),
		"short boot": entry(`"id":"` + id2 + `","boot_seq":1,"boot":"01","counter":1`),
		"data after": `{"version":1,"peers":[]} {}`,
		"too large":  `{"version":1,"peers":[]}` + string(bytes.Repeat([]byte(" "), 64<<10)),
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			st, err := store.Open(filepath.Join(t.TempDir(), "state"))
			if err != nil {
				t.Fatal(err)
			}
			if err := st.WriteFileAtomic(peerStateFile, []byte(content)); err != nil {
				t.Fatal(err)
			}
			cfg := Config{Self: ms[0].id.ID, Boot: localBoot, BootSeq: 6, Roster: testRoster(ms), RosterHash: testRosterHash, Store: st}
			tab, err := New(cfg, at(start))
			if err != nil || !errors.Is(tab.StorageError(), ErrStateFile) {
				t.Fatalf("New = %v; StorageError %v, want ErrStateFile", err, tab.StorageError())
			}
			if data, err := st.ReadFile(peerStateFile + ".corrupt"); err != nil || string(data) != content {
				t.Errorf("set aside %d bytes, %v; want the %d bytes of the file", len(data), err, len(content))
			}
			if rep := tab.Report(ms[1].id.ID, at(start)); rep.BootSeq != 0 {
				t.Errorf("state used from a corrupt file: %+v", rep)
			}
		})
	}

	// A valid file that names a member no longer in the roster is fine.
	st, err := store.Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	x := stranger().id.ID.String()
	valid := `{"version":1,"peers":[{"id":"` + x + `","boot_seq":3,"boot":"` + b1 + `","counter":9},{"id":"` + id2 + `","boot_seq":4,"boot":"` + b1 + `","counter":2}]}`
	if err := st.WriteFileAtomic(peerStateFile, []byte(valid)); err != nil {
		t.Fatal(err)
	}
	cfg := Config{Self: ms[0].id.ID, Boot: localBoot, BootSeq: 6, Roster: testRoster(ms), RosterHash: testRosterHash, Store: st}
	tab, err := New(cfg, at(start))
	if err != nil || tab.StorageError() != nil {
		t.Fatalf("New with a former member in the file: %v, %v", err, tab.StorageError())
	}
	if rep := tab.Report(ms[1].id.ID, at(start)); rep.BootSeq != 4 || rep.Boot != bootID(1) {
		t.Errorf("Report after load %+v, want boot 4", rep)
	}
	if _, err := st.ReadFile(peerStateFile + ".corrupt"); err == nil {
		t.Error("a valid file was set aside")
	}
}

func TestSetRoster(t *testing.T) {
	ms := members(5)
	r01, r02, r03, r04, r05 := ms[0], ms[1], ms[2], ms[3], ms[4]
	h := start + s
	f := newFixtureOf(t, ms[:4], start)
	for _, m := range ms[1:4] {
		f.mustSend(m, at(h))
	}
	// r03 is the trusted peer for the offset; r02 goes silent first.
	_, sil := f.tab.Tick(at(h + 30*s))
	if len(sil) != 3 {
		t.Fatalf("silence: %s", describe(sil))
	}
	r03Beat := enc(t, f.beat(r03), r03)
	if _, err := f.tab.Observe(testEpoch, r03Beat, at(h+31*s)); err != nil {
		t.Fatal(err)
	}
	oldR02 := f.beat(r02)

	// r04 leaves and r05 joins at +40 s; r02's key changes.
	next := testRoster([]tm{r01, r02, r03, r05})
	newKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x77}, ed25519.SeedSize))
	next.Members[1].SignPub = newKey.Public().(ed25519.PublicKey)
	if err := f.tab.SetRoster(next, ids.Hash{7}, at(h+40*s)); err != nil {
		t.Fatalf("SetRoster: %v", err)
	}
	if _, err := f.send(r04, at(h+41*s)); !errors.Is(err, ErrUnknownMember) {
		t.Errorf("removed member: %v, want ErrUnknownMember", err)
	}
	if _, err := f.tab.Observe(testEpoch, enc(t, oldR02, r02), at(h+41*s)); !errors.Is(err, ErrSignature) {
		t.Errorf("r02 under its old key: %v, want ErrSignature", err)
	}
	b := f.beat(r02)
	obs, err := f.tab.Observe(testEpoch, handSign(handBody(b), newKey), at(h+41*s))
	if err != nil {
		t.Fatalf("r02 under its new key: %v", err)
	}
	// r02 kept its state: it was silent, so this is its return.
	if len(obs.Events) != 1 || obs.Events[0].Type != events.LinkLost {
		t.Errorf("r02's return: %s, want link_lost", describe(obs.Events))
	}
	if !obs.RosterMismatch {
		t.Error("the old hash is not flagged after SetRoster")
	}
	// r03 kept its replay window.
	if _, err := f.tab.Observe(testEpoch, r03Beat, at(h+41*s)); !errors.Is(err, ErrReplay) {
		t.Errorf("r03's heartbeat again after SetRoster: %v, want ErrReplay", err)
	}
	// r05 is new: heard-at starts at the change, so it is silent 30 s later,
	// not at once.
	if _, sil := f.tab.Tick(at(h + 70*s - 1)); hasSubject(sil, r05) {
		t.Errorf("r05 silent before 30 s of observation: %s", describe(sil))
	}
	_, sil = f.tab.Tick(at(h + 70*s))
	if !hasSubject(sil, r05) || hasSubject(sil, r04) {
		t.Errorf("at +70 s: %s, want r05 silent and nothing about r04", describe(sil))
	}

	// Refused: a roster without the local member, or one that does not
	// check. Nothing changes.
	if err := f.tab.SetRoster(testRoster([]tm{r02, r03}), ids.Hash{8}, at(h+71*s)); !errors.Is(err, ErrConfig) {
		t.Errorf("roster without self: %v, want ErrConfig", err)
	}
	broken := testRoster(ms)
	broken.Site = "Bad Site"
	if err := f.tab.SetRoster(broken, ids.Hash{8}, at(h+71*s)); !errors.Is(err, ErrConfig) {
		t.Errorf("roster that does not check: %v, want ErrConfig", err)
	}
	b = f.beat(r03)
	b.RosterHash = ids.Hash{7}
	if obs, err := f.tab.Observe(testEpoch, enc(t, b, r03), at(h+72*s)); err != nil || obs.RosterMismatch {
		t.Errorf("after refused changes: %v, mismatch %v; want the hash of the accepted change", err, obs.RosterMismatch)
	}
}

func hasSubject(evs []events.Event, m tm) bool {
	for _, e := range evs {
		if e.Subject == m.id.ID {
			return true
		}
	}
	return false
}

func TestSetRosterDropsOffsets(t *testing.T) {
	ms := members(3)
	f := newFixtureOf(t, ms, start)
	f.mustSend(ms[2], untrustedAt(start+s)) // fullBeat says its clock is trusted
	if _, ok := f.tab.Offset(); !ok {
		t.Fatal("no offset from a trusted peer")
	}
	if err := f.tab.SetRoster(testRoster(ms[:2]), testRosterHash, at(start+2*s)); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.tab.Offset(); ok {
		t.Error("the offset of a removed member is still used")
	}
}

func TestAdmitSharesWindow(t *testing.T) {
	f := newFixture(t, 2, start)
	r02 := f.ms[1]
	h := start + s
	f.mustSend(r02, at(h)) // counter 1
	calls := 0
	var gotKey ed25519.PublicKey
	ok := func(pub ed25519.PublicKey) bool { calls++; gotKey = pub; return true }
	boot := bootID(1)
	if _, err := f.tab.Admit(r02.id.ID, 1, boot, 1, ok); !errors.Is(err, ErrReplay) {
		t.Errorf("Admit of the heartbeat's counter: %v, want ErrReplay", err)
	}
	if calls != 0 {
		t.Error("the signature was checked for a replay")
	}
	if _, err := f.tab.Admit(r02.id.ID, 1, boot, 2, func(ed25519.PublicKey) bool { return false }); !errors.Is(err, ErrSignature) {
		t.Errorf("bad signature: %v, want ErrSignature", err)
	}
	if _, err := f.tab.Admit(r02.id.ID, 1, boot, 2, nil); !errors.Is(err, ErrSignature) {
		t.Errorf("no verifier: %v, want ErrSignature", err)
	}
	a, err := f.tab.Admit(r02.id.ID, 1, boot, 2, ok)
	if err != nil || a.From() != r02.id.ID {
		t.Fatalf("Admit = %v, %v", a.From(), err)
	}
	if !bytes.Equal(gotKey, r02.pub) {
		t.Errorf("verify got key %x, want r02's", gotKey)
	}
	gotKey[0] ^= 1 // the callback's copy is its own
	f.sim(r02).counter = 1
	if _, err := f.send(r02, at(h)); !errors.Is(err, ErrReplay) {
		t.Errorf("heartbeat with Admit's counter: %v, want ErrReplay", err)
	}
	if _, err := f.send(r02, at(h)); err != nil {
		t.Errorf("heartbeat with the next counter: %v (key changed by the callback?)", err)
	}
	if _, err := f.tab.Admit(stranger().id.ID, 1, boot, 9, ok); !errors.Is(err, ErrUnknownMember) {
		t.Errorf("stranger: %v", err)
	}
	if _, err := f.tab.Admit(f.self.id.ID, 1, boot, 9, ok); !errors.Is(err, ErrSelf) {
		t.Errorf("self: %v", err)
	}
	// A conflicting boot is only dropped here; heartbeats report it.
	if _, err := f.tab.Admit(r02.id.ID, 1, bootID(9), 9, ok); !errors.Is(err, ErrReplay) {
		t.Errorf("conflicting boot: %v, want ErrReplay", err)
	}
	// A newer boot through Admit raises the stored number.
	if _, err := f.tab.Admit(r02.id.ID, 4, bootID(4), 1, ok); err != nil {
		t.Fatal(err)
	}
	if rep := f.tab.Report(r02.id.ID, at(h)); rep.BootSeq != 4 || rep.Boot != bootID(4) {
		t.Errorf("Report %+v, want boot 4", rep)
	}
	var zero Admitted
	if zero.From() != (ids.MemberID{}) {
		t.Error("the zero Admitted names a member")
	}
}

func TestReport(t *testing.T) {
	f := newFixture(t, 3, start)
	r02, r03 := f.ms[1], f.ms[2]
	if rep := f.tab.Report(r02.id.ID, at(start+s)); !reflect.DeepEqual(rep, Report{Target: r02.id.ID}) {
		t.Errorf("unheard: %+v", rep)
	}
	f.sims[r02.id.ID] = &sim{seq: 4, boot: 4, version: "24.10.4"}
	b := enc(t, f.beat(r02), r02)
	if _, err := f.tab.Observe(testEpoch, b, at(start+2*s)); err != nil {
		t.Fatal(err)
	}
	want := Report{Target: r02.id.ID, Heartbeat: b, Ago: 7 * s, BootSeq: 4, Boot: bootID(4)}
	if rep := f.tab.Report(r02.id.ID, at(start+9*s)); !reflect.DeepEqual(rep, want) {
		t.Errorf("heard: %+v, want %+v", rep, want)
	}
	if rep := f.tab.Report(stranger().id.ID, at(start+9*s)); !reflect.DeepEqual(rep, Report{Target: stranger().id.ID}) {
		t.Errorf("stranger: %+v", rep)
	}
	if rep := f.tab.Report(f.self.id.ID, at(start+9*s)); !reflect.DeepEqual(rep, Report{Target: f.self.id.ID}) {
		t.Errorf("self: %+v", rep)
	}
	_ = r03
}

func TestNewRejectsConfig(t *testing.T) {
	ms := members(3)
	st, err := store.Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	good := Config{Self: ms[0].id.ID, Boot: localBoot, BootSeq: 6, Roster: testRoster(ms), RosterHash: testRosterHash, Store: st}
	if _, err := New(good, at(start)); err != nil {
		t.Fatalf("the good config: %v", err)
	}
	cases := map[string]func(c *Config){
		"no store":                 func(c *Config) { c.Store = nil },
		"zero boot":                func(c *Config) { c.Boot = ids.BootID{} },
		"boot seq 0":               func(c *Config) { c.BootSeq = 0 },
		"roster does not check":    func(c *Config) { c.Roster.Site = "" },
		"self not a member":        func(c *Config) { c.Self = stranger().id.ID },
		"negative interval":        func(c *Config) { c.Interval = -s },
		"negative suspect":         func(c *Config) { c.SuspectMissed = -1 },
		"negative silent":          func(c *Config) { c.SilentMissed = -1 },
		"silent before suspect":    func(c *Config) { c.SuspectMissed, c.SilentMissed = 4, 3 },
		"silent with suspect":      func(c *Config) { c.SuspectMissed, c.SilentMissed = 3, 3 },
		"default suspect too high": func(c *Config) { c.SilentMissed = 2 },
		"overflowing silence":      func(c *Config) { c.Interval, c.SilentMissed = math.MaxInt64/2, 7 },
	}
	for name, edit := range cases {
		c := good
		c.Roster = testRoster(ms)
		edit(&c)
		if tab, err := New(c, at(start)); !errors.Is(err, ErrConfig) || tab != nil {
			t.Errorf("%s: New = %v, %v; want nil, ErrConfig", name, tab, err)
		}
	}
}

// TestSignatureKind pins the domain of the heartbeat signature: a signature
// over the same bytes as another kind is refused.
func TestSignatureKind(t *testing.T) {
	f := newFixture(t, 2, start)
	r02 := f.ms[1]
	body := handBody(f.beat(r02))
	other := append(bytes.Clone(body), sig.Sign(r02.id.Sign, "entry", body)...)
	if _, err := f.tab.Observe(testEpoch, other, at(start+s)); !errors.Is(err, ErrSignature) {
		t.Errorf("signature of kind entry: %v, want ErrSignature", err)
	}
	right := append(bytes.Clone(body), sig.Sign(r02.id.Sign, "heartbeat", body)...)
	if _, err := f.tab.Observe(testEpoch, right, at(start+s)); err != nil {
		t.Errorf("signature of kind heartbeat: %v", err)
	}
}

// TestStoredFileShape decodes what the table writes with a strict decoder,
// independently of the package.
func TestStoredFileShape(t *testing.T) {
	f := newFixture(t, 3, start)
	f.mustSend(f.ms[2], at(start+s))
	f.tick(at(start + s))
	data, err := f.st.ReadFile(peerStateFile)
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Version int `json:"version"`
		Peers   []struct {
			ID      ids.MemberID `json:"id"`
			BootSeq uint64       `json:"boot_seq"`
			Boot    ids.BootID   `json:"boot"`
			Counter uint64       `json:"counter"`
		} `json:"peers"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		t.Fatal(err)
	}
	if v.Version != 1 || len(v.Peers) != 1 || v.Peers[0].ID != f.ms[2].id.ID || v.Peers[0].BootSeq != 1 || v.Peers[0].Boot != bootID(1) || v.Peers[0].Counter != 1 {
		t.Errorf("stored %+v", v)
	}
}

func TestRestoreBootSeqStorageError(t *testing.T) {
	ms := members(2)
	dir, seq := bootSeqDir(t, 5)
	f := newFixtureWith(t, ms, start, func(c *Config) { c.BootSeq = seq })
	rep := Report{Target: ms[0].id.ID, BootSeq: 9}
	if _, err := f.tab.RecordReport(f.admit(ms[1]), rep, at(start+s)); err != nil {
		t.Fatal(err)
	}
	// The identity directory is open to others: identity refuses it, and
	// the Table keeps its number and its evidence.
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	got, raised, err := f.tab.RestoreBootSeq(dir)
	if !errors.Is(err, identity.ErrPermissions) || raised || got != seq || f.tab.BootSeq() != seq {
		t.Errorf("RestoreBootSeq on a bad directory = %d, %v, %v; want %d, false, identity.ErrPermissions", got, raised, err, seq)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if got, raised, err := f.tab.RestoreBootSeq(dir); got != 10 || !raised || err != nil {
		t.Errorf("RestoreBootSeq once the directory is fixed = %d, %v, %v; want 10, true", got, raised, err)
	}
}

// relay has helper answer the probe about target with heartbeat, received ago
// before now.
func (f *fixture) relay(helper tm, target tm, heartbeat []byte, ago time.Duration, now clock.Stamp) ([]events.Event, error) {
	rep := Report{Target: target.id.ID, Ago: ago, Heartbeat: heartbeat}
	return f.tab.RecordReport(f.admit(helper), rep, now)
}

func TestRestoredCounterRefusesReplay(t *testing.T) {
	ms := members(2)
	r02 := ms[1]
	f := newFixtureOf(t, ms, start)
	h := start + s
	var beats [][]byte
	for c := 1; c <= 20; c++ {
		beats = append(beats, enc(t, f.beat(r02), r02))
	}
	observe := func(c int, now time.Duration) error {
		_, err := f.tab.Observe(testEpoch, beats[c-1], at(now))
		return err
	}
	for c := 1; c <= 15; c++ {
		if err := observe(c, h+time.Duration(c)*5*s); err != nil {
			t.Fatalf("heartbeat %d: %v", c, err)
		}
	}
	f.tab.Tick(at(h + 75*s)) // the store now holds counter 15
	for c := 16; c <= 20; c++ {
		if err := observe(c, h+time.Duration(c)*5*s); err != nil {
			t.Fatalf("heartbeat %d: %v", c, err)
		}
	}
	// No Tick within the minute: the store still says 15. The local member
	// restarts, and a recorder replays r02's heartbeats.
	f.restart(h + 110*s)
	for _, c := range []int{10, 15} {
		if err := observe(c, h+111*s); !errors.Is(err, ErrReplay) {
			t.Errorf("replay of %d after a restart that stored 15: %v, want ErrReplay", c, err)
		}
	}
	if err := observe(16, h+111*s); err != nil {
		t.Errorf("16 after a restart that stored 15: %v", err)
	}
	for _, c := range []int{16, 12, 1} {
		if err := observe(c, h+112*s); !errors.Is(err, ErrReplay) {
			t.Errorf("replay of %d after 16: %v, want ErrReplay", c, err)
		}
	}
	// The stored boot ID came back too: another boot under the stored
	// number is a second router, not a fresh start.
	f.restart(h + 120*s)
	other := fullBeat(r02)
	other.BootSeq, other.Boot, other.Counter, other.GoingDown = 1, bootID(9), 30, false
	obs, err := f.tab.Observe(testEpoch, enc(t, other, r02), at(h+121*s))
	if !errors.Is(err, ErrDuplicateIdentity) || len(obs.Events) != 1 {
		t.Errorf("another boot ID under the stored number: %v %s, want ErrDuplicateIdentity", err, describe(obs.Events))
	}
}

// liarSetup returns a group of 4 at +15 s: r02 suspect, its heartbeats since
// h lost on the way to the local member, r03 and r04 asked. beats are r02's
// heartbeats 1 to 6, sent every 5 s from h; the local member has only 1.
func liarSetup(t *testing.T) (*fixture, [][]byte, time.Duration) {
	t.Helper()
	f := newFixture(t, 4, start)
	r02, r03, r04 := f.ms[1], f.ms[2], f.ms[3]
	h := start + s
	var beats [][]byte
	for i := 0; i < 6; i++ {
		beats = append(beats, enc(t, f.beat(r02), r02))
	}
	if _, err := f.tab.Observe(testEpoch, beats[0], at(h)); err != nil {
		t.Fatal(err)
	}
	for d := time.Duration(0); d <= 15*s; d += 5 * s {
		f.mustSend(r03, at(h+d))
		f.mustSend(r04, at(h+d))
	}
	if sus := f.tick(at(h + 15*s)); !slices.Equal(sus, idsOf(r02)) {
		t.Fatalf("suspects %x", sus)
	}
	if got := f.tab.IndirectProbeRequest(r02.id.ID); !slices.Equal(got, idsOf(r03, r04)) {
		t.Fatalf("helpers %x", got)
	}
	return f, beats, h
}

func TestLyingHelperCannotPreventSilence(t *testing.T) {
	ms := members(4)
	r02, r03, r04 := ms[1], ms[2], ms[3]
	forged := fullBeat(r02)
	forged.BootSeq, forged.Boot, forged.Counter, forged.GoingDown = 1, bootID(1), 99, false
	cases := []struct {
		name    string
		beat    func(beats [][]byte) []byte
		wantErr error
	}{
		{"the heartbeat the asker holds", func(b [][]byte) []byte { return b[0] }, ErrReplay},
		{"a forged heartbeat", func([][]byte) []byte { return handSign(handBody(forged), strangerKey) }, ErrSignature},
		{"a heartbeat of another member", func([][]byte) []byte { return enc(t, fullBeat(r03), r03) }, ErrBadReport},
		{"garbage", func([][]byte) []byte { return []byte("heard it, honest") }, ErrMalformed},
		{"no heartbeat", func([][]byte) []byte { return nil }, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f, beats, h := liarSetup(t)
			if _, err := f.relay(r03, r02, c.beat(beats), 0, at(h+16*s)); !errors.Is(err, c.wantErr) {
				t.Errorf("RecordReport = %v, want %v", err, c.wantErr)
			}
			if _, err := f.relay(r04, r02, c.beat(beats), 0, at(h+20*s)); !errors.Is(err, c.wantErr) {
				t.Errorf("second RecordReport = %v, want %v", err, c.wantErr)
			}
			f.tick(at(h + 30*s - 1))
			_, sil := f.tab.Tick(at(h + 30*s))
			if len(sil) != 1 {
				t.Fatalf("want r02 silent at +30 s, got %s", describe(sil))
			}
			wantEvent(t, sil[0], events.MemberSilent, r02, f.self, at(h))
		})
	}

	// A heartbeat the local member never got, but older than the one it
	// holds, proves nothing new either.
	t.Run("older than the one held", func(t *testing.T) {
		f, beats, h := liarSetup(t)
		// r03 relays number 5, received 15 s ago: still suspect.
		if _, err := f.relay(r03, r02, beats[4], 15*s, at(h+16*s)); err != nil {
			t.Fatal(err)
		}
		if _, err := f.relay(r04, r02, beats[3], 0, at(h+16*s)); !errors.Is(err, ErrNotFresher) {
			t.Errorf("number 4 after 5: %v, want ErrNotFresher", err)
		}
	})

	// The genuine fresher heartbeat does save it.
	t.Run("genuine and fresher", func(t *testing.T) {
		f, beats, h := liarSetup(t)
		// Number 3 was sent at +10 s and reached r03 at once.
		if evs, err := f.relay(r03, r02, beats[2], 6*s, at(h+16*s)); err != nil || len(evs) != 0 {
			t.Fatalf("RecordReport = %s, %v", describe(evs), err)
		}
		f.tick(at(h + 40*s - 1))
		_, sil := f.tab.Tick(at(h + 40*s))
		if len(sil) != 1 {
			t.Fatalf("want r02 silent 30 s after +10 s, got %s", describe(sil))
		}
		wantEvent(t, sil[0], events.MemberSilent, r02, f.self, at(h+10*s))
		if c := f.tab.Counters(); c.Relayed != 1 {
			t.Errorf("counters %+v, want 1 relayed", c)
		}
	})
}

func TestRelayedHeartbeat(t *testing.T) {
	ms := members(4)
	r02, r03, r04 := ms[1], ms[2], ms[3]
	f, _, h := liarSetup(t)
	// r02 rebooted fast, and only r03 hears it.
	f.reboot(r02)
	nb := enc(t, f.beat(r02), r02)
	evs, err := f.relay(r03, r02, nb, 2*s, at(h+16*s))
	if err != nil || len(evs) != 1 {
		t.Fatalf("relayed reboot: %s, %v", describe(evs), err)
	}
	wantEvent(t, evs[0], events.RebootUnplanned, r02, f.self, at(h+14*s))
	// The relayed heartbeat is r02's latest for the local member's own
	// answers, but r02 is still not heard directly, so it is no helper.
	if rep := f.tab.Report(r02.id.ID, at(h+17*s)); !bytes.Equal(rep.Heartbeat, nb) || rep.Ago != 3*s || rep.BootSeq != 2 {
		t.Errorf("Report after a relay: %+v", rep)
	}
	f.mustSend(r03, at(h+20*s))
	f.mustSend(r04, at(h+20*s))
	f.tick(at(h + 20*s))
	// r04 goes quiet; r02 must not be named as a helper for it.
	if sus := f.tick(at(h + 35*s)); !slices.Contains(sus, r04.id.ID) && !slices.Contains(sus, r03.id.ID) {
		t.Fatalf("suspects %x", sus)
	}
	if got := f.tab.IndirectProbeRequest(r04.id.ID); slices.Contains(got, r02.id.ID) {
		t.Errorf("a member heard only through a helper is a helper: %x", got)
	}
	// Its direct heartbeats of that boot are no second reboot.
	if obs := f.mustSend(r02, at(h+36*s)); len(obs.Events) != 0 {
		t.Errorf("direct heartbeat after the relayed reboot: %s", describe(obs.Events))
	}
	// A helper's age cannot put the hearing before the local member's own.
	g, beats, gh := liarSetup(t)
	if _, err := g.relay(r03, r02, beats[1], time.Hour, at(gh+16*s)); err != nil {
		t.Fatal(err)
	}
	if rep := g.tab.Report(r02.id.ID, at(gh+16*s)); rep.Ago != 16*s {
		t.Errorf("Report after a relay claimed an hour old: ago %v, want 16 s (not before the last direct hearing)", rep.Ago)
	}
}

func TestCorruptStateFileSetAside(t *testing.T) {
	ms := members(2)
	r02 := ms[1]
	open := func(t *testing.T, content []byte, mode os.FileMode) (*fixture, *Table, error) {
		t.Helper()
		f := newFixtureOf(t, ms, start)
		if err := f.st.WriteFileAtomic(peerStateFile, content); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(filepath.Join(f.dir, peerStateFile), mode); err != nil {
			t.Fatal(err)
		}
		tab, err := New(f.cfg, at(start))
		return f, tab, err
	}

	t.Run("does not decode", func(t *testing.T) {
		f, tab, err := open(t, []byte("nope"), 0o600)
		if err != nil || tab == nil {
			t.Fatalf("New over a corrupt file = %v, %v; want a table", tab, err)
		}
		if err := tab.StorageError(); !errors.Is(err, ErrStateFile) {
			t.Errorf("StorageError = %v, want ErrStateFile", err)
		}
		if data, err := f.st.ReadFile(peerStateFile + ".corrupt"); err != nil || string(data) != "nope" {
			t.Errorf("set aside: %q, %v", data, err)
		}
		// It starts empty, and the next write replaces the corrupt file.
		f.tab = tab
		f.mustSend(r02, at(start+s))
		f.tick(at(start + s))
		next, err := New(f.cfg, at(start+2*s))
		if err != nil || next.StorageError() != nil {
			t.Errorf("after the next write: %v, %v", err, next.StorageError())
		}
	})

	t.Run("open to group", func(t *testing.T) {
		f, tab, err := open(t, []byte(`{"version":1,"peers":[]}`), 0o640)
		if err != nil || tab == nil {
			t.Fatalf("New over a group-readable file = %v, %v; want a table", tab, err)
		}
		if err := tab.StorageError(); !errors.Is(err, store.ErrPermissions) {
			t.Errorf("StorageError = %v, want store.ErrPermissions", err)
		}
		f.tab = tab
		f.mustSend(r02, at(start+s))
		f.tick(at(start + s))
		if fi, err := os.Stat(filepath.Join(f.dir, peerStateFile)); err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("after the next write: mode %v, %v; want 0600", fi.Mode().Perm(), err)
		}
	})

	t.Run("cannot be set aside", func(t *testing.T) {
		f := newFixtureOf(t, ms, start)
		// A directory where the copy would go: the store's rename fails.
		if err := os.Mkdir(filepath.Join(f.dir, peerStateFile+".corrupt"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := f.st.WriteFileAtomic(peerStateFile, []byte("nope")); err != nil {
			t.Fatal(err)
		}
		tab, err := New(f.cfg, at(start))
		if err != nil || tab == nil {
			t.Fatalf("New = %v, %v; want a table", tab, err)
		}
		serr := tab.StorageError()
		if !errors.Is(serr, ErrStateFile) || serr == nil || !strings.Contains(serr.Error(), "setting the corrupt file aside") {
			t.Errorf("StorageError = %v, want ErrStateFile and the failed copy", serr)
		}
	})

	t.Run("fine", func(t *testing.T) {
		f := newFixtureOf(t, ms, start)
		if err := f.tab.StorageError(); err != nil {
			t.Errorf("StorageError without a file = %v", err)
		}
	})
}

func TestRelayedHeartbeatCounted(t *testing.T) {
	ms := members(4)
	r02, r03 := ms[1], ms[2]

	// A relayed heartbeat teaches no clock offset: when the helper got it
	// is only its word.
	t.Run("no offset", func(t *testing.T) {
		f := newFixtureOf(t, ms[:3], start)
		h := start + s
		untrusted := func(m tm, now time.Duration) {
			b := f.beat(m)
			b.ClockTrusted = false
			if _, err := f.tab.Observe(testEpoch, enc(t, b, m), at(now)); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := f.tab.Observe(testEpoch, enc(t, f.beat(r02), r02), at(h)); err != nil { // trusted
			t.Fatal(err)
		}
		for d := time.Duration(0); d <= 15*s; d += 5 * s {
			untrusted(r03, h+d)
		}
		want, ok := f.tab.Offset()
		if !ok {
			t.Fatal("no offset from r02")
		}
		f.tick(at(h + 15*s))
		if got := f.tab.IndirectProbeRequest(r02.id.ID); !slices.Equal(got, idsOf(r03)) {
			t.Fatalf("helpers %x", got)
		}
		if _, err := f.relay(r03, r02, enc(t, f.beat(r02), r02), 2*s, at(h+16*s)); err != nil {
			t.Fatal(err)
		}
		if got, _ := f.tab.Offset(); got != want {
			t.Errorf("Offset after a relayed heartbeat %v, want %v", got, want)
		}
	})

	// Garbage in an answer is counted like garbage in a packet.
	t.Run("malformed counted", func(t *testing.T) {
		f, _, h := liarSetup(t)
		before := f.tab.Counters().Malformed
		if _, err := f.relay(r03, r02, []byte("heard it"), 0, at(h+16*s)); !errors.Is(err, ErrMalformed) {
			t.Fatalf("garbage: %v", err)
		}
		if c := f.tab.Counters(); c.Malformed != before+1 || c.Relayed != 0 {
			t.Errorf("counters %+v, want one more malformed, none relayed", c)
		}
	})
}
