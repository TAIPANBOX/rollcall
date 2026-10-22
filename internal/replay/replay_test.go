package replay

import (
	"math"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/TAIPANBOX/rollcall/internal/ids"
)

var (
	bootA = ids.BootID{0xaa, 1}
	bootB = ids.BootID{0xbb, 2}
	bootC = ids.BootID{0xcc, 3}
)

// accept calls w.Accept and fails the test unless it returns want.
func accept(t *testing.T, w *Window, bootSeq uint64, boot ids.BootID, counter uint64, want bool) {
	t.Helper()
	if got := w.Accept(bootSeq, boot, counter); got != want {
		t.Fatalf("Accept(boot seq %d, boot %s, counter %d) = %v, want %v", bootSeq, boot, counter, got, want)
	}
}

// check calls w.Check and fails the test unless it returns want.
func check(t *testing.T, w *Window, bootSeq uint64, boot ids.BootID, counter uint64, want bool) {
	t.Helper()
	if got := w.Check(bootSeq, boot, counter); got != want {
		t.Fatalf("Check(boot seq %d, boot %s, counter %d) = %v, want %v", bootSeq, boot, counter, got, want)
	}
}

func TestWindowSize(t *testing.T) {
	if WindowSize != 64 {
		t.Fatalf("WindowSize = %d, the spec says 64", WindowSize)
	}
}

func TestReplayRejectsDuplicate(t *testing.T) {
	var w Window
	accept(t, &w, 1, bootA, 10, true)
	accept(t, &w, 1, bootA, 10, false) // the same packet again
	accept(t, &w, 1, bootA, 8, true)   // late, but never seen
	accept(t, &w, 1, bootA, 8, false)
	accept(t, &w, 1, bootA, 9, true)
	accept(t, &w, 1, bootA, 9, false)
	accept(t, &w, 1, bootA, 11, true)
	for _, c := range []uint64{8, 9, 10, 11} {
		accept(t, &w, 1, bootA, c, false)
	}

	// The very first packet a window sees is recorded too.
	var first Window
	accept(t, &first, 7, bootB, 0, true)
	accept(t, &first, 7, bootB, 0, false)
}

func TestReplayRejectsOldBootSeq(t *testing.T) {
	var w Window
	accept(t, &w, 5, bootA, 100, true)
	accept(t, &w, 4, bootB, 0, false)
	accept(t, &w, 4, bootB, 1000, false) // a higher counter does not help an older boot
	accept(t, &w, 4, bootA, 101, false)  // nor does the current boot ID
	accept(t, &w, 0, bootA, 0, false)
	accept(t, &w, 5, bootA, 101, true) // the current boot is not disturbed

	// Once boot 6 is seen, boot 5 is old, even with a counter never used.
	accept(t, &w, 6, bootB, 0, true)
	accept(t, &w, 5, bootA, 102, false)
	accept(t, &w, 5, bootA, math.MaxUint64, false)
	accept(t, &w, 6, bootB, 1, true)
}

func TestReplayAcceptsNewBoot(t *testing.T) {
	var w Window
	for c := uint64(0); c < 100; c++ {
		accept(t, &w, 5, bootA, c, true)
	}
	// Counter 0 is far below 99, but it opens boot 6, which resets the window.
	accept(t, &w, 6, bootB, 0, true)
	accept(t, &w, 6, bootB, 0, false) // and the window now belongs to boot 6
	accept(t, &w, 6, bootB, 1, true)
	accept(t, &w, 6, bootB, 1, false)
	// Counters boot 5 used are fresh in boot 6.
	accept(t, &w, 6, bootB, 50, true)
	accept(t, &w, 6, bootB, 2, true) // 48 below 50: inside the window, never seen
	accept(t, &w, 6, bootB, 2, false)

	// A jump of many boots, straight to the top counter.
	accept(t, &w, 1000, bootC, math.MaxUint64, true)
	accept(t, &w, 1000, bootC, math.MaxUint64-63, true)
	accept(t, &w, 1000, bootC, math.MaxUint64-64, false)
	accept(t, &w, 6, bootB, 51, false)

	// A higher boot seq resets the window even if it reuses a boot ID.
	accept(t, &w, 1001, bootC, 0, true)
	accept(t, &w, 1001, bootC, 0, false)
}

func TestReplayWindowEdge(t *testing.T) {
	var w Window
	accept(t, &w, 1, bootA, 100, true)
	accept(t, &w, 1, bootA, 36, false) // 64 behind the highest
	accept(t, &w, 1, bootA, 37, true)  // 63 behind
	accept(t, &w, 1, bootA, 37, false)
	accept(t, &w, 1, bootA, 0, false)
	accept(t, &w, 1, bootA, 101, true) // the window slides by one
	accept(t, &w, 1, bootA, 37, false) // now 64 behind, and seen
	accept(t, &w, 1, bootA, 38, true)  // 63 behind 101

	// A slide by exactly 64 forgets the old highest and keeps the edge.
	var exact Window
	accept(t, &exact, 1, bootA, 0, true)
	accept(t, &exact, 1, bootA, 64, true)
	accept(t, &exact, 1, bootA, 0, false) // 64 behind
	accept(t, &exact, 1, bootA, 1, true)  // 63 behind, never seen

	// A slide by more than 64 clears the whole bitmap.
	var far Window
	accept(t, &far, 1, bootA, 10, true)
	accept(t, &far, 1, bootA, 1000, true)
	accept(t, &far, 1, bootA, 10, false)
	accept(t, &far, 1, bootA, 937, true) // 63 behind
	accept(t, &far, 1, bootA, 936, false)

	// A slide by 63 keeps the old highest as the bottom of the window.
	var keep Window
	accept(t, &keep, 1, bootA, 0, true)
	accept(t, &keep, 1, bootA, 63, true)
	accept(t, &keep, 1, bootA, 0, false) // seen, 63 behind

	// Near the top of the counter space nothing wraps.
	var top Window
	accept(t, &top, 1, bootA, math.MaxUint64, true)
	accept(t, &top, 1, bootA, math.MaxUint64, false)
	accept(t, &top, 1, bootA, math.MaxUint64-63, true)
	accept(t, &top, 1, bootA, math.MaxUint64-64, false)
	accept(t, &top, 1, bootA, 0, false)
}

func TestReplayRejectsCloneBootID(t *testing.T) {
	var w Window
	accept(t, &w, 5, bootA, 1, true)
	accept(t, &w, 5, bootB, 2, false)
	accept(t, &w, 5, bootB, 1, false)
	accept(t, &w, 5, bootB, 0, false)
	accept(t, &w, 5, bootB, math.MaxUint64, false)
	// The rejected packets changed nothing: boot A carries on.
	accept(t, &w, 5, bootA, 2, true)
	accept(t, &w, 5, bootA, 1, false)
	accept(t, &w, 5, bootA, 3, true)

	// Whichever boot ID arrives first owns the boot seq.
	var w2 Window
	accept(t, &w2, 5, bootB, 7, true)
	accept(t, &w2, 5, bootA, 8, false)
}

func TestReplayFirstPacket(t *testing.T) {
	cases := []struct {
		bootSeq uint64
		boot    ids.BootID
		counter uint64
	}{
		{0, ids.BootID{}, 0},
		{1, bootA, 0},
		{1, bootA, 63},
		{1, bootA, 64},
		{math.MaxUint64, bootB, math.MaxUint64},
	}
	for _, c := range cases {
		var w Window
		accept(t, &w, c.bootSeq, c.boot, c.counter, true)
		accept(t, &w, c.bootSeq, c.boot, c.counter, false)
	}
}

func TestReplayCheckRecordsNothing(t *testing.T) {
	var w Window
	check(t, &w, 1, bootA, 5, true)
	check(t, &w, 1, bootA, 5, true) // checking twice records nothing
	accept(t, &w, 1, bootA, 5, true)
	check(t, &w, 1, bootA, 5, false)
	check(t, &w, 1, bootA, 6, true)
	check(t, &w, 2, bootB, 0, true) // a newer boot is not adopted by Check
	check(t, &w, 1, bootA, 6, true)
	check(t, &w, 1, bootB, 6, false)
	check(t, &w, 0, bootA, 6, false)
	check(t, &w, 1, bootA, 4, true)
	accept(t, &w, 1, bootA, 6, true)
	accept(t, &w, 1, bootA, 4, true)
}

// model is the reference the window is compared with: it keeps every
// accepted counter of the current boot in a map instead of a bitmap.
type model struct {
	seen    bool
	bootSeq uint64
	boot    ids.BootID
	highest uint64
	got     map[uint64]bool
}

func (m *model) accept(bootSeq uint64, boot ids.BootID, counter uint64) bool {
	if !m.seen || bootSeq > m.bootSeq {
		*m = model{seen: true, bootSeq: bootSeq, boot: boot, highest: counter, got: map[uint64]bool{counter: true}}
		return true
	}
	if bootSeq < m.bootSeq || boot != m.boot || m.got[counter] {
		return false
	}
	if counter < m.highest && m.highest-counter > 63 {
		return false
	}
	m.got[counter] = true
	if counter > m.highest {
		m.highest = counter
	}
	return true
}

// TestReplayMatchesModel drives the window and the model with the same
// random packets, 200 seeds of 2000 packets each, and requires the same
// verdict every time. Check must predict Accept and record nothing.
func TestReplayMatchesModel(t *testing.T) {
	boots := []ids.BootID{bootA, bootB, bootC}
	for seed := uint64(1); seed <= 200; seed++ {
		r := rand.New(rand.NewPCG(seed, 0x5eed))
		var w Window
		var m model
		bootSeq, counter := uint64(r.IntN(3)), uint64(r.IntN(200))
		boot := boots[0]
		accepted := 0
		for i := 0; i < 2000; i++ {
			switch p := r.IntN(100); {
			case p < 3: // a newer boot
				bootSeq += uint64(1 + r.IntN(2))
				boot = boots[r.IntN(len(boots))]
				counter = uint64(r.IntN(100))
			case p < 6: // an older boot seq
				if bootSeq > 0 {
					bootSeq--
				}
			case p < 9: // a clone or forgery with another boot ID
				boot = boots[r.IntN(len(boots))]
			case p < 11: // a far jump of the counter
				counter += uint64(64 + r.IntN(1000))
			case p < 12: // the top of the counter space
				counter = math.MaxUint64 - uint64(r.IntN(130))
			default: // around the window edge, either side
				d := uint64(r.IntN(140))
				if r.IntN(2) == 0 && counter >= d {
					counter -= d
				} else if counter <= math.MaxUint64-d {
					counter += d
				}
			}
			predicted := w.Check(bootSeq, boot, counter)
			if again := w.Check(bootSeq, boot, counter); again != predicted {
				t.Fatalf("seed %d packet %d: Check changed its answer from %v to %v", seed, i, predicted, again)
			}
			want := m.accept(bootSeq, boot, counter)
			got := w.Accept(bootSeq, boot, counter)
			if got != want || predicted != want {
				t.Fatalf("seed %d packet %d (boot seq %d, boot %s, counter %d): Check %v, Accept %v, model %v",
					seed, i, bootSeq, boot, counter, predicted, got, want)
			}
			if got {
				accepted++
			}
		}
		// Each seed must exercise both verdicts, or it measured nothing.
		if accepted == 0 || accepted == 2000 {
			t.Fatalf("seed %d: %d of 2000 packets accepted; the generator does not exercise the window", seed, accepted)
		}
	}
}

// TestReplayConcurrent offers each of the counters 0..63 of one boot to the
// window from 8 goroutines at once. All 64 stay inside the window whatever
// the order, so each must be accepted exactly once.
func TestReplayConcurrent(t *testing.T) {
	const workers, counters = 8, 64
	for round := 0; round < 100; round++ {
		var w Window
		var hits [counters]atomic.Int32
		var wg sync.WaitGroup
		start := make(chan struct{})
		for g := 0; g < workers; g++ {
			order := rand.New(rand.NewPCG(uint64(round), uint64(g))).Perm(counters)
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				for _, c := range order {
					w.Check(1, bootA, uint64(c))
					if w.Accept(1, bootA, uint64(c)) {
						hits[c].Add(1)
					}
				}
			}()
		}
		close(start)
		wg.Wait()
		for c := range hits {
			if n := hits[c].Load(); n != 1 {
				t.Fatalf("round %d: counter %d accepted %d times by %d goroutines, want exactly once", round, c, n, workers)
			}
		}
	}
}
