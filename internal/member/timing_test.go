package member

import (
	"crypto/ed25519"
	"errors"
	"math"
	"slices"
	"testing"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/events"
	"github.com/TAIPANBOX/rollcall/internal/ids"
)

// rawBeat returns m's heartbeat with these numbers and this Mono, signed by
// m: a router whose clock the test spells out.
func rawBeat(t testing.TB, m tm, seq uint64, boot byte, counter uint64, mono time.Duration) []byte {
	t.Helper()
	h := fullBeat(m)
	h.BootSeq, h.Boot, h.Counter, h.Mono, h.GoingDown = seq, bootID(boot), counter, mono, false
	return enc(t, h, m)
}

// A router sends a packet per destination, not one per heartbeat, so a
// member never sees all of a neighbour's counters. An outsider who recorded
// one it did not see replays it after the neighbour rebooted: a genuine
// packet of the previous boot with a counter beyond the last one accepted.
// Its own Mono shows it was sent before the new boot started: a replay, not
// a second router.
func TestReplayedOldBootHeartbeatIsNoDuplicate(t *testing.T) {
	h := start + s

	t.Run("recorded up to the end of the boot", func(t *testing.T) {
		f := newFixture(t, 3, start)
		r02 := f.ms[1]
		// Boot 1: the local member hears r02 at h and h+5 s. Everything r02
		// sends after that goes elsewhere, and is recorded, up to the packet
		// it sent at the very moment the boot ended.
		f.mustSend(r02, at(h))
		f.mustSend(r02, at(h+5*s))
		var recorded [][]byte
		for d := 6 * s; d <= 30*s; d += s {
			recorded = append(recorded, enc(t, f.beatAt(r02, h+d), r02))
		}
		// Boot 2 started at h+30 s; the local member hears it at h+40 s.
		f.reboot(r02)
		f.mustSend(r02, at(h+40*s))
		for i, b := range recorded {
			o, err := f.tab.Observe(testEpoch, b, at(h+41*s))
			if !errors.Is(err, ErrReplay) || len(o.Events) != 0 {
				t.Errorf("replay of boot 1's packet sent at +%v: %v %s, want ErrReplay and no event", 6*s+time.Duration(i)*s, err, describe(o.Events))
			}
		}
		if c := f.tab.Counters(); c.Duplicate != 0 || c.Replay != uint64(len(recorded)) {
			t.Errorf("counters %+v, want %d replays and no duplicate", c, len(recorded))
		}
		if obs := f.mustSend(r02, at(h+45*s)); len(obs.Events) != 0 {
			t.Errorf("boot 2 after the replays: %s", describe(obs.Events))
		}
	})

	// The last heartbeat of boot 1 the local member heard reached it 3 s
	// late, a busy receiver: its arrival is no measure of when it was sent.
	t.Run("the last one heard came late", func(t *testing.T) {
		f := newFixture(t, 3, start)
		r02 := f.ms[1]
		late := enc(t, f.beatAt(r02, h+5*s), r02)
		if _, err := f.tab.Observe(testEpoch, late, at(h+8*s)); err != nil {
			t.Fatal(err)
		}
		recorded := enc(t, f.beatAt(r02, h+29*s), r02)
		f.reboot(r02)
		f.mustSend(r02, at(h+40*s)) // boot 2 started at h+30 s
		if o, err := f.tab.Observe(testEpoch, recorded, at(h+41*s)); !errors.Is(err, ErrReplay) || len(o.Events) != 0 {
			t.Errorf("replay: %v %s, want ErrReplay and no event", err, describe(o.Events))
		}
	})

	// An attacker on the path holds back only the last heartbeat of boot 1
	// the local member hears, by the reboot gap plus 10 s, so that it seems
	// sent late; the earlier ones, on time, still place the boot.
	t.Run("the last one heard held back", func(t *testing.T) {
		f := newFixture(t, 3, start)
		r02 := f.ms[1]
		for d := time.Duration(0); d <= 10*s; d += 5 * s {
			f.mustSend(r02, at(h+d))
		}
		held := enc(t, f.beatAt(r02, h+15*s), r02)
		recorded := enc(t, f.beatAt(r02, h+20*s), r02) // the last of boot 1
		// Boot 2 starts 3 s after it, at h+23 s, and is heard at h+33 s.
		gap := 3 * s
		if _, err := f.tab.Observe(testEpoch, held, at(h+15*s+gap+10*s)); err != nil {
			t.Fatal(err)
		}
		f.reboot(r02)
		f.mustSend(r02, at(h+20*s+gap+firstBeat))
		if o, err := f.tab.Observe(testEpoch, recorded, at(h+40*s)); !errors.Is(err, ErrReplay) || len(o.Events) != 0 {
			t.Errorf("replay: %v %s, want ErrReplay and no event", err, describe(o.Events))
		}
	})

	// r02's clock runs 0.1% fast. The local member heard it, then nothing for
	// three hours, in which its clock gained 10.8 s on the local one.
	t.Run("a clock 0.1% fast over three hours", func(t *testing.T) {
		f := newFixture(t, 3, start)
		r02 := f.ms[1]
		fast := func(d time.Duration) time.Duration { return d + d/1000 }
		m0 := 90 * time.Minute
		if _, err := f.tab.Observe(testEpoch, rawBeat(t, r02, 1, 1, 1, m0), at(h)); err != nil {
			t.Fatal(err)
		}
		gap := 3 * time.Hour
		recorded := rawBeat(t, r02, 1, 1, 5000, m0+fast(gap)) // its last packet of boot 1
		// Boot 2 starts 1 s later and is heard 10 s after that.
		if _, err := f.tab.Observe(testEpoch, rawBeat(t, r02, 2, 2, 1, fast(10*s)), at(h+gap+11*s)); err != nil {
			t.Fatal(err)
		}
		if o, err := f.tab.Observe(testEpoch, recorded, at(h+gap+12*s)); !errors.Is(err, ErrReplay) || len(o.Events) != 0 {
			t.Errorf("replay: %v %s, want ErrReplay and no event", err, describe(o.Events))
		}
	})

	// The daemon restarted without a reboot: a new boot sequence number, the
	// same kernel boot ID, counters from 1 again, and one clock that goes on.
	t.Run("a restart within one kernel boot", func(t *testing.T) {
		f := newFixture(t, 3, start)
		r02 := f.ms[1]
		f.mustSend(r02, at(h))
		f.mustSend(r02, at(h+5*s))
		recorded := enc(t, f.beatAt(r02, h+7*s), r02)
		p := f.sim(r02)
		p.seq, p.counter = 2, 0
		f.mustSend(r02, at(h+10*s))
		if o, err := f.tab.Observe(testEpoch, recorded, at(h+11*s)); !errors.Is(err, ErrReplay) || len(o.Events) != 0 {
			t.Errorf("replay: %v %s, want ErrReplay and no event", err, describe(o.Events))
		}
	})
}

// The same replay, carried in a helper's answer to an indirect probe: a
// stale or lying helper cannot raise a duplicate identity either.
func TestRelayedOldBootHeartbeatIsNoDuplicate(t *testing.T) {
	f := newFixture(t, 3, start)
	r02, r03 := f.ms[1], f.ms[2]
	h := start + s
	f.mustSend(r02, at(h))
	f.mustSend(r02, at(h+5*s))
	recorded := enc(t, f.beatAt(r02, h+25*s), r02) // went to r03 only
	f.reboot(r02)
	f.mustSend(r02, at(h+40*s)) // boot 2, started at h+30 s
	for d := time.Duration(0); d <= 55*s; d += 5 * s {
		f.mustSend(r03, at(h+d))
	}
	// r02 is not heard directly after h+40 s.
	if sus := f.tick(at(h + 55*s)); !slices.Equal(sus, idsOf(r02)) {
		t.Fatalf("suspects %x, want r02", sus)
	}
	if got := f.tab.IndirectProbeRequest(r02.id.ID); !slices.Equal(got, idsOf(r03)) {
		t.Fatalf("helpers %x, want r03", got)
	}
	evs, err := f.relay(r03, r02, recorded, 0, at(h+55*s))
	if !errors.Is(err, ErrReplay) || len(evs) != 0 {
		t.Errorf("relayed replay: %v %s, want ErrReplay and no event", err, describe(evs))
	}
	if c := f.tab.Counters(); c.Duplicate != 0 || c.Relayed != 0 {
		t.Errorf("counters %+v, want no duplicate and nothing relayed", c)
	}
	// It saved nothing either: r02 is silent 30 s after boot 2 was heard.
	f.tick(at(h + 70*s - 1))
	_, sil := f.tab.Tick(at(h + 70*s))
	if len(sil) != 1 {
		t.Fatalf("want r02 silent at +70 s, got %s", describe(sil))
	}
	wantEvent(t, sil[0], events.MemberSilent, r02, f.self, at(h+40*s))
}

// Two devices with one identity: A goes on in its boot after B started a
// later one. A's heartbeats carry A's clock, which shows them sent after B's
// boot began, and that proves a second router, however they arrive.
func TestCloneProvedByItsClock(t *testing.T) {
	ms := members(3)
	r02, r03 := ms[1], ms[2]
	h := start + s
	// A has run for two hours at h; B starts at h+20 s.
	monoA := func(local time.Duration) time.Duration { return local - (h - 2*time.Hour) }
	monoB := func(local time.Duration) time.Duration { return local - (h + 20*s) }
	// interleave has the local member hear A (and r03) every 5 s from h to
	// h+50 s, then B at h+50 s, after A: B's boot is the current one.
	interleave := func(t *testing.T, f *fixture) uint64 {
		t.Helper()
		c := uint64(0)
		for d := time.Duration(0); d <= 50*s; d += 5 * s {
			c++
			f.mustSend(r03, at(h+d))
			if _, err := f.tab.Observe(testEpoch, rawBeat(t, r02, 10, 0xa, c, monoA(h+d)), at(h+d)); err != nil {
				t.Fatalf("A at +%v: %v", d, err)
			}
		}
		if _, err := f.tab.Observe(testEpoch, rawBeat(t, r02, 11, 0xb, 1, monoB(h+50*s)), at(h+50*s)); err != nil {
			t.Fatalf("B: %v", err)
		}
		return c
	}

	t.Run("directly", func(t *testing.T) {
		f := newFixture(t, 3, start)
		c := interleave(t, f)
		o, err := f.tab.Observe(testEpoch, rawBeat(t, r02, 10, 0xa, c+1, monoA(h+55*s)), at(h+55*s))
		if !errors.Is(err, ErrDuplicateIdentity) || len(o.Events) != 1 {
			t.Fatalf("A after B started: %v %s, want ErrDuplicateIdentity and one event", err, describe(o.Events))
		}
		wantEvent(t, o.Events[0], events.DuplicateIdentity, r02, f.self, at(h+55*s))
	})

	t.Run("through a helper", func(t *testing.T) {
		f := newFixture(t, 3, start)
		c := interleave(t, f)
		// The local member's link to both devices breaks; r03 hears them.
		for d := 55 * s; d <= 65*s; d += 5 * s {
			f.mustSend(r03, at(h+d))
		}
		if sus := f.tick(at(h + 65*s)); !slices.Equal(sus, idsOf(r02)) {
			t.Fatalf("suspects %x, want r02", sus)
		}
		f.tab.IndirectProbeRequest(r02.id.ID)
		evs, err := f.relay(r03, r02, rawBeat(t, r02, 10, 0xa, c+2, monoA(h+60*s)), 5*s, at(h+65*s))
		if !errors.Is(err, ErrDuplicateIdentity) || len(evs) != 1 {
			t.Fatalf("A relayed after B started: %v %s, want ErrDuplicateIdentity and one event", err, describe(evs))
		}
		wantEvent(t, evs[0], events.DuplicateIdentity, r02, f.self, at(h+65*s))
	})

	// A ran for 30 days, heard all along; B appears and A's next heartbeat
	// comes 30 s after B's boot started. Only the hearings of A's last 10
	// minutes place it, so 30 days of drift allowance do not hide B.
	t.Run("after a boot of 30 days", func(t *testing.T) {
		f := newFixture(t, 3, start)
		month := 30 * 24 * time.Hour
		bootB := h + month
		mono := func(local time.Duration) time.Duration { return local - (h - time.Minute) }
		c := uint64(0)
		hearA := func(local time.Duration) {
			t.Helper()
			c++
			if _, err := f.tab.Observe(testEpoch, rawBeat(t, r02, 10, 0xa, c, mono(local)), at(local)); err != nil {
				t.Fatalf("A at +%v: %v", local-h, err)
			}
		}
		for d := time.Duration(0); d < month-time.Hour; d += time.Hour {
			hearA(h + d)
		}
		for local := bootB - 10*time.Minute; local <= bootB+20*s; local += 5 * s {
			hearA(local)
		}
		if _, err := f.tab.Observe(testEpoch, rawBeat(t, r02, 11, 0xb, 1, 25*s), at(bootB+25*s)); err != nil {
			t.Fatalf("B: %v", err)
		}
		o, err := f.tab.Observe(testEpoch, rawBeat(t, r02, 10, 0xa, c+1, mono(bootB+30*s)), at(bootB+30*s))
		if !errors.Is(err, ErrDuplicateIdentity) || len(o.Events) != 1 {
			t.Fatalf("A 30 s after B started: %v %s, want ErrDuplicateIdentity and one event", err, describe(o.Events))
		}
	})

	// Within one kernel boot both runs read one clock: the old run goes on
	// after the new one sent a heartbeat. A few seconds of overlap are a
	// daemon handing over to the next, not a second router.
	t.Run("two runs in one kernel boot", func(t *testing.T) {
		f := newFixture(t, 3, start)
		f.mustSend(r02, at(h))
		f.mustSend(r02, at(h+5*s))
		oldRun := *f.sim(r02)
		handover := enc(t, f.beatAt(r02, h+14*s), r02)
		alive := enc(t, f.beatAt(r02, h+20*s), r02)
		*f.sim(r02) = oldRun
		p := f.sim(r02)
		p.seq, p.counter = 2, 0
		f.mustSend(r02, at(h+10*s))
		if o, err := f.tab.Observe(testEpoch, handover, at(h+14*s)); !errors.Is(err, ErrReplay) || len(o.Events) != 0 {
			t.Errorf("old run 4 s into the new one: %v %s, want ErrReplay and no event", err, describe(o.Events))
		}
		o, err := f.tab.Observe(testEpoch, alive, at(h+20*s))
		if !errors.Is(err, ErrDuplicateIdentity) || len(o.Events) != 1 {
			t.Fatalf("old run 10 s into the new one: %v %s, want ErrDuplicateIdentity and one event", err, describe(o.Events))
		}
	})
}

// A compromised helper that hears the target keeps its genuine heartbeats
// back and, after the target died, relays one per probe round as if it had
// just received it. The target's own clock bounds each: it was alive when it
// sent them, never later, so its death is reported at most one probe cycle
// late (30 s of silence after its last heartbeat, plus one interval).
func TestLyingHelperDripCannotHideDeath(t *testing.T) {
	f := newFixture(t, 3, start)
	r02, r03 := f.ms[1], f.ms[2]
	h := start + s
	died := h + 100*s
	f.mustSend(r02, at(h))
	f.mustSend(r03, at(h))
	var stash [][]byte
	relayed := 0
	var silent []events.Event
	var noticed time.Duration
	for step := s; step <= 900*s && len(silent) == 0; step += s {
		now := h + step
		if step%(5*s) == 0 {
			f.mustSend(r03, at(now))
			if now <= died {
				// Reaches r03 only.
				stash = append(stash, enc(t, f.beatAt(r02, now), r02))
			}
		}
		sus, sil := f.tab.Tick(at(now))
		silent, noticed = sil, now
		for _, id := range sus {
			if id != r02.id.ID {
				t.Fatalf("at +%v suspect %x, want only r02", step, id)
			}
			if !slices.Contains(f.tab.IndirectProbeRequest(id), r03.id.ID) || relayed == len(stash) {
				continue
			}
			if _, err := f.relay(r03, r02, stash[relayed], 0, at(now)); err != nil {
				t.Fatalf("at +%v relay of stashed heartbeat %d: %v", step, relayed, err)
			}
			relayed++
		}
	}
	if len(silent) != 1 {
		t.Fatalf("r02 never reported silent; %d of %d stashed heartbeats relayed", relayed, len(stash))
	}
	if limit := died + 6*DefaultInterval + DefaultInterval; noticed > limit {
		t.Errorf("r02 died at +%v, reported silent at +%v, after +%v (30 s and one probe cycle); %d heartbeats dripped", died-h, noticed-h, limit-h, relayed)
	}
	if st := silent[0].At.Mono; st < died || st > died+s {
		t.Errorf("silence stamped at +%v, want when r02 died, +%v", st-h, died-h)
	}
}

func TestRelayedHeartbeatBoundByTargetClock(t *testing.T) {
	// The heartbeat r02 sent at +5 s, relayed at +29 s as just received:
	// r02 was alive at +5 s, not at +29 s.
	t.Run("claimed fresher than its clock allows", func(t *testing.T) {
		f, beats, h := liarSetup(t)
		r02, r03 := f.ms[1], f.ms[2]
		if _, err := f.relay(r03, r02, beats[1], 0, at(h+29*s)); err != nil {
			t.Fatal(err)
		}
		_, sil := f.tab.Tick(at(h + 36*s))
		if len(sil) != 1 {
			t.Fatalf("want r02 silent 30 s after +5 s, got %s", describe(sil))
		}
		if st := sil[0].At.Mono; st < h+5*s || st > h+5*s+50*time.Millisecond {
			t.Errorf("silence stamped at +%v, want +5 s", st-h)
		}
	})

	// A packet r02 sent together with the heartbeat the local member holds
	// (a copy to another peer: the next counter, the same Mono) shows nothing
	// newer.
	t.Run("a copy of the one held", func(t *testing.T) {
		f, _, h := liarSetup(t)
		r02, r03 := f.ms[1], f.ms[2]
		copied := enc(t, f.beatAt(r02, h), r02)
		if _, err := f.relay(r03, r02, copied, 0, at(h+16*s)); !errors.Is(err, ErrNotFresher) {
			t.Errorf("relayed copy: %v, want ErrNotFresher", err)
		}
		f.tick(at(h + 30*s - 1))
		_, sil := f.tab.Tick(at(h + 30*s))
		if len(sil) != 1 {
			t.Fatalf("want r02 silent at +30 s, got %s", describe(sil))
		}
		wantEvent(t, sil[0], events.MemberSilent, r02, f.self, at(h))
	})

	// A helper that says it heard r02 long ago, true or not, does not move
	// the bound for another helper's honest answer: only the moment an
	// answer arrives bounds the target's clock.
	t.Run("an understated answer does not silence an honest one", func(t *testing.T) {
		f, beats, h := liarSetup(t)
		r02, r03, r04 := f.ms[1], f.ms[2], f.ms[3]
		if _, err := f.relay(r03, r02, beats[1], time.Hour, at(h+16*s)); err != nil {
			t.Fatal(err)
		}
		if _, err := f.relay(r04, r02, beats[3], 2*s, at(h+17*s)); err != nil {
			t.Fatal(err)
		}
		for d := 20 * s; d <= 40*s; d += 5 * s {
			f.mustSend(r03, at(h+d))
			f.mustSend(r04, at(h+d))
		}
		f.tick(at(h + 45*s - 1))
		_, sil := f.tab.Tick(at(h + 45*s))
		if len(sil) != 1 {
			t.Fatalf("want r02 silent 30 s after +15 s, got %s", describe(sil))
		}
		wantEvent(t, sil[0], events.MemberSilent, r02, f.self, at(h+15*s))
	})
}

// Without a heartbeat of the previous boot received directly, or of the
// current boot at all, there is no timing to prove a second router with, so
// a packet of the previous boot beyond its last counter is only a replay.
func TestOverlapWithoutTimingIsReplay(t *testing.T) {
	h := start + s
	ok := func(ed25519.PublicKey) bool { return true }

	// The local member restarted: it knows boot 1 from the store only.
	t.Run("previous boot only from the store", func(t *testing.T) {
		f := newFixture(t, 3, start)
		r02 := f.ms[1]
		f.mustSend(r02, at(h))
		f.tick(at(h)) // stored
		recorded := enc(t, f.beatAt(r02, h+5*s), r02)
		f.restart(h + 10*s)
		f.reboot(r02)
		f.mustSend(r02, at(h+40*s))
		if o, err := f.tab.Observe(testEpoch, recorded, at(h+41*s)); !errors.Is(err, ErrReplay) || len(o.Events) != 0 {
			t.Errorf("replay: %v %s, want ErrReplay and no event", err, describe(o.Events))
		}
	})

	// Boot 2 is known only from a probe answer, which carries no clock.
	t.Run("current boot only through Admit", func(t *testing.T) {
		f := newFixture(t, 3, start)
		r02 := f.ms[1]
		f.mustSend(r02, at(h))
		recorded := enc(t, f.beatAt(r02, h+20*s), r02)
		if _, err := f.tab.Admit(r02.id.ID, 2, bootID(2), 1, ok); err != nil {
			t.Fatal(err)
		}
		if o, err := f.tab.Observe(testEpoch, recorded, at(h+41*s)); !errors.Is(err, ErrReplay) || len(o.Events) != 0 {
			t.Errorf("replay: %v %s, want ErrReplay and no event", err, describe(o.Events))
		}
	})

	// A packet whose Mono is behind the one heard was sent before it.
	t.Run("Mono behind the one heard", func(t *testing.T) {
		f := newFixture(t, 3, start)
		r02 := f.ms[1]
		if _, err := f.tab.Observe(testEpoch, rawBeat(t, r02, 1, 1, 1, 2*time.Hour), at(h)); err != nil {
			t.Fatal(err)
		}
		if _, err := f.tab.Observe(testEpoch, rawBeat(t, r02, 2, 2, 1, 10*s), at(h+40*s)); err != nil {
			t.Fatal(err)
		}
		earlier := rawBeat(t, r02, 1, 1, 9, time.Hour)
		if o, err := f.tab.Observe(testEpoch, earlier, at(h+41*s)); !errors.Is(err, ErrReplay) || len(o.Events) != 0 {
			t.Errorf("an hour behind: %v %s, want ErrReplay and no event", err, describe(o.Events))
		}
	})

	// Validly signed, but a field out of range: dropped as malformed.
	t.Run("signed but malformed", func(t *testing.T) {
		f := newFixture(t, 3, start)
		r02 := f.ms[1]
		f.mustSend(r02, at(h))
		bad := f.beatAt(r02, h+60*s)
		bad.Name = "BAD"
		f.reboot(r02)
		f.mustSend(r02, at(h+40*s))
		before := f.tab.Counters()
		o, err := f.tab.Observe(testEpoch, handSign(handBody(bad), r02.id.Sign), at(h+60*s))
		if !errors.Is(err, ErrMalformed) || len(o.Events) != 0 {
			t.Errorf("malformed: %v %s, want ErrMalformed and no event", err, describe(o.Events))
		}
		if c := f.tab.Counters(); c.Malformed != before.Malformed+1 || c.Duplicate != 0 {
			t.Errorf("counters %+v, want one more malformed and no duplicate", c)
		}
	})
}

// The bounds are sums of readings a peer chooses; none of them may wrap.
func TestTimingArithmeticSaturates(t *testing.T) {
	const top, bottom = time.Duration(math.MaxInt64), time.Duration(math.MinInt64)
	cases := []struct {
		name      string
		got, want time.Duration
	}{
		{"addSat up", addSat(top-s, 2*s), top},
		{"addSat down", addSat(bottom+s, -2*s), bottom},
		{"addSat plain", addSat(-s, 3*s), 2 * s},
		{"stretch top", stretch(top), top},
		{"stretch", stretch(500 * s), 501 * s},
		{"shrink", shrink(500 * s), 499 * s},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}
}

// An honest helper relays, as soon as it gets them, the heartbeats of a
// router whose clock runs 0.1% slow: their Mono advances less than the local
// clock. The drift allowance keeps each relayed heartbeat at the moment the
// helper received it, so the bound never cuts an honest relay short.
func TestRelayedSlowClockKeepsItsTime(t *testing.T) {
	f := newFixture(t, 3, start)
	r02, r03 := f.ms[1], f.ms[2]
	h := start + s
	slow := func(local time.Duration) time.Duration {
		d := local - h
		return 90*time.Minute + d - d/1000
	}
	if _, err := f.tab.Observe(testEpoch, rawBeat(t, r02, 1, 1, 1, slow(h)), at(h)); err != nil {
		t.Fatal(err)
	}
	c, last := uint64(1), h
	var sil []events.Event
	for step := s; len(sil) == 0; step += s {
		now := h + step
		if step%(5*s) == 0 {
			f.mustSend(r03, at(now))
		}
		var sus []ids.MemberID
		sus, sil = f.tab.Tick(at(now))
		for range sus {
			if step > 300*s {
				break // r02 is gone
			}
			if !slices.Equal(f.tab.IndirectProbeRequest(r02.id.ID), idsOf(r03)) {
				t.Fatalf("at +%v r03 not asked", step)
			}
			c++
			if _, err := f.relay(r03, r02, rawBeat(t, r02, 1, 1, c, slow(now-s)), s, at(now)); err != nil {
				t.Fatalf("at +%v: %v", step, err)
			}
			last = now - s
		}
	}
	if len(sil) != 1 || last < h+250*s {
		t.Fatalf("silent %s, last relayed heartbeat sent at +%v", describe(sil), last-h)
	}
	wantEvent(t, sil[0], events.MemberSilent, r02, f.self, at(last))
}
