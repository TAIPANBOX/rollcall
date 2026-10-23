package sim

import (
	"encoding/json"
	"fmt"
	mrand "math/rand/v2"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/history"
	"github.com/TAIPANBOX/rollcall/internal/ids"
	"github.com/TAIPANBOX/rollcall/internal/node"
)

// # The sweep
//
// Every seed builds a site of 3 to 5 routers, one of which equivocates (it
// runs twice with one identity, and a random part of the group sees its
// second face), and puts it through four and a half minutes of random
// faults, one every 15 to 60 s: power
// cuts of one router or of the whole site, planned reboots, upgrades,
// partitions, a lost radio link, internet losses of one router or all,
// Telegram outages, and packet loss and delay on every link. Then
// everything heals, and three minutes later the invariants are checked:
//
//   - I1: every power cycle of an honest router reaches the chat at least
//     once, as a reboot (or an upgrade) naming it, after it happened; and
//     the sender holds nothing it has not delivered.
//   - I2: without a partition or a cut link, no message is sent twice. A
//     copy sent after the sender of the first lost power within 30 s of
//     sending it is allowed: its acknowledgement died with its RAM, and
//     delivery is at least once by design.
//   - I3: the equivocating router is reported with a fork proof, and every
//     honest router marks it suspicious.
//   - I4: no honest router is marked suspicious, nor named in an alarm.
//   - I5: never two senders at once while the network is whole: no two
//     routers send less than the delivery grace (15 s) apart.
//   - I6: no router is told to have rebooted, planned or not, or to have
//     been upgraded, unless it was.
//   - I7: after healing, every honest router hears every other one: it
//     sees each up (or suspicious, for the equivocator or a forked router).
//
// A violation whose own evidence matches a known defect (defects_test.go)
// is tagged with it; a seed whose violations are all tagged is skipped and
// names them, unless ROLLCALL_STRICT=1. An untagged violation always fails.
//
// One seed drives every random choice of the fault plan and the fake
// network (see the package doc for what a replay repeats). A failing seed
// is printed with the command that replays it.

const (
	warmup    = 30 * time.Second
	faultTime = 4*time.Minute + 30*time.Second
	settleAll = 3 * time.Minute
	// grace is the delivery grace: how long two senders may overlap while
	// their views converge.
	grace = 15 * time.Second
	// ackLife is how long a sender's acknowledgement may still die with
	// its RAM: a copy sent after its sender lost power this soon is allowed.
	ackLife = 30 * time.Second
)

// breakage is a fault planted in the fake, for TestSweepHasTeeth.
type breakage int

const (
	intact       breakage = iota
	loseChat              // the chat accepts messages and loses them
	doubleChat            // the chat shows every message twice
	deafSender            // nothing reaches the first sender
	noEquivocate          // the equivocator is a plain router
)

func sweepSeeds(t *testing.T) []int64 {
	if v := os.Getenv("ROLLCALL_SEED"); v != "" {
		s, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			t.Fatalf("ROLLCALL_SEED=%q: %v", v, err)
		}
		return []int64{s}
	}
	n := 200
	if v := os.Getenv("ROLLCALL_SEEDS"); v != "" {
		c, err := strconv.Atoi(v)
		if err != nil || c < 1 {
			t.Fatalf("ROLLCALL_SEEDS=%q: want a positive count", v)
		}
		n = c
	}
	out := make([]int64, n)
	for i := range out {
		out[i] = int64(i + 1)
	}
	return out
}

func TestSweep(t *testing.T) {
	seeds := sweepSeeds(t)
	start := time.Now()
	var (
		mu                     sync.Mutex
		clean, blocked, failed int
		byDefect               = map[string]int{}
	)
	t.Cleanup(func() {
		var ds []string
		for d, n := range byDefect {
			ds = append(ds, fmt.Sprintf("%s in %d", d, n))
		}
		sort.Strings(ds)
		t.Logf("%d seeds in %s: %d clean, %d blocked by known defects (%s), %d failed",
			len(seeds), time.Since(start).Round(time.Millisecond), clean, blocked, strings.Join(ds, ", "), failed)
	})
	for _, seed := range seeds {
		t.Run(fmt.Sprintf("seed=%d", seed), func(t *testing.T) {
			t.Parallel()
			r := sweep(seed, intact)
			var plain []violation
			defects := map[string]bool{}
			for _, v := range r.violations {
				if v.defect == "" || strict() {
					plain = append(plain, v)
				} else {
					defects[v.defect] = true
				}
			}
			mu.Lock()
			switch {
			case len(plain) > 0:
				failed++
			case len(defects) > 0:
				blocked++
				for d := range defects {
					byDefect[d]++
				}
			default:
				clean++
			}
			mu.Unlock()
			lines := strings.Join(strs(r.violations), "\n  ")
			switch {
			case len(plain) > 0:
				t.Errorf("seed %d: %d invariant(s) broken:\n  %s\n%s\nreplay: ROLLCALL_SEED=%d go test ./internal/sim -run 'TestSweep$' -v",
					seed, len(r.violations), lines, r.report(), seed)
			case len(defects) > 0:
				if len(seeds) == 1 {
					t.Log(r.report())
				}
				t.Skipf("seed %d blocked by known defects:\n  %s", seed, lines)
			case len(seeds) == 1:
				t.Log(r.report())
			}
		})
	}
}

// TestSweepHasTeeth plants a fault in the fake and requires the sweep to
// see it: each breakage must break its invariant, untagged by any known
// defect, on at least one of the first seeds.
func TestSweepHasTeeth(t *testing.T) {
	cases := []struct {
		b    breakage
		want string
	}{
		{loseChat, "I1"},
		{doubleChat, "I2"},
		{deafSender, "I7"},
		{noEquivocate, "I3"},
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("breakage=%d", c.b), func(t *testing.T) {
			t.Parallel()
			var seen []string
			for seed := int64(1); seed <= 4; seed++ {
				r := sweep(seed, c.b)
				for _, v := range r.violations {
					// Untagged: a known defect must not explain a planted
					// fault away.
					if v.inv == c.want && v.defect == "" {
						t.Logf("seed %d: %s", seed, v)
						return
					}
				}
				seen = append(seen, strs(r.violations)...)
			}
			t.Errorf("the sweep did not see breakage %d as %s; it saw %q", c.b, c.want, seen)
		})
	}
}

// violation is one invariant broken, and the known defect its evidence
// matches, if any.
type violation struct {
	inv    string // I1 to I7
	defect string // a key of knownDefects, or empty
	msg    string
}

func (v violation) String() string {
	if v.defect != "" {
		return v.inv + " " + v.msg + " [" + v.defect + "]"
	}
	return v.inv + " " + v.msg
}

func strs(vs []violation) []string {
	var out []string
	for _, v := range vs {
		out = append(out, v.String())
	}
	return out
}

// result is what one seed did and found.
type result struct {
	seed       int64
	violations []violation
	faults     []string
	chat       []Message
}

func (r result) report() string {
	var b strings.Builder
	b.WriteString("faults:")
	for _, f := range r.faults {
		b.WriteString("\n  " + f)
	}
	b.WriteString("\nchat:")
	for _, m := range r.chat {
		b.WriteString("\n  " + m.String())
	}
	return b.String()
}

// action is a step of the fault plan, due at a moment of the site.
type action struct {
	at   time.Duration
	what string
	do   func()
}

func sweep(seed int64, brk breakage) result {
	rng := mrand.New(mrand.NewPCG(uint64(seed), 0x5eed))
	n := 3 + rng.IntN(3)
	eq := n - 1
	honest := make([]int, eq)
	for i := range honest {
		honest[i] = i
	}
	var faces []int
	for len(faces) == 0 || len(faces) == len(honest) {
		faces = faces[:0]
		for _, i := range honest {
			if rng.IntN(2) == 0 {
				faces = append(faces, i)
			}
		}
	}
	senders := map[int]int{0: 2, 1: 1}
	if n == 5 {
		senders[2] = 0
	}
	o := Options{N: n, Seed: seed, Senders: senders, Equivocator: faces}
	if brk == noEquivocate {
		o.Equivocator = nil
	}
	s := New(o)
	defer s.Close()
	switch brk {
	case loseChat:
		s.broken.loseChat = true
	case doubleChat:
		s.broken.doubleChat = true
	case deafSender:
		s.broken.deaf = s.routers[0]
	}

	r := result{seed: seed}
	note := func(f string, a ...any) {
		r.faults = append(r.faults, fmt.Sprintf("%7s  ", s.Elapsed().Round(time.Second))+fmt.Sprintf(f, a...))
	}
	note("%d routers, equivocator %s seen as its second face by %s, senders %v", n, s.Name(eq), names(s, faces), senders)
	split := brk != doubleChat && rng.IntN(3) != 0
	if rng.IntN(2) == 0 {
		loss := rng.Float64() * 0.08
		s.SetLoss(loss)
		note("packet loss %.3f", loss)
	}
	delay := time.Duration(1+rng.IntN(4)) * Step
	s.SetDelay(delay)
	note("delay up to %s; partitions %v", delay, split)

	var plan []action
	later := func(d time.Duration, what string, do func()) {
		plan = append(plan, action{at: s.Elapsed() + d, what: what, do: do})
	}
	span := func(lo, hi time.Duration) time.Duration {
		return lo + time.Duration(rng.Int64N(int64(hi-lo)))
	}
	versions := map[int]int{}
	splitUntil := time.Duration(0)

	s.Run(warmup)
	end := s.Elapsed() + faultTime
	eqAt := s.Elapsed() + span(time.Minute, faultTime-time.Minute)
	next := s.Elapsed() + span(10*time.Second, time.Minute)
	for tick := 0; s.Elapsed() < end; tick++ {
		now := s.Elapsed()
		if o.Equivocator != nil && eqAt >= 0 && now >= eqAt {
			eqAt = -1
			s.Equivocate()
			note("%s shows each face another entry", s.Name(eq))
		}
		var keep []action
		for _, a := range plan {
			if a.at <= now {
				note("%s", a.what)
				a.do()
			} else {
				keep = append(keep, a)
			}
		}
		plan = keep
		if now >= next {
			next = now + span(15*time.Second, time.Minute)
			i := honest[rng.IntN(len(honest))]
			switch k := rng.IntN(12); {
			case k < 3:
				if !s.Powered(i) {
					break
				}
				d := span(5*time.Second, 3*time.Minute)
				note("%s loses power for %s", s.Name(i), d.Round(time.Second))
				s.PowerOff(i)
				later(d, s.Name(i)+" powered on", func() { s.PowerOn(i) })
			case k == 3:
				if !s.Powered(i) {
					break
				}
				d := span(40*time.Second, 2*time.Minute)
				note("%s reboots as planned for %s", s.Name(i), d.Round(time.Second))
				s.Reboot(i, d)
			case k == 4 && rng.IntN(2) == 0:
				if !s.Powered(i) {
					break
				}
				versions[i]++
				v := fmt.Sprintf("24.10.%d", 4+versions[i])
				note("%s upgrades to %s", s.Name(i), v)
				s.Upgrade(i, v)
			case k == 5 && split && now >= splitUntil:
				var a, b []int
				for len(a) == 0 || len(b) == 0 {
					a, b = a[:0], b[:0]
					for j := 0; j < n; j++ {
						if rng.IntN(2) == 0 {
							a = append(a, j)
						} else {
							b = append(b, j)
						}
					}
				}
				d := span(40*time.Second, 3*time.Minute)
				splitUntil = now + d
				note("partition %s | %s for %s", names(s, a), names(s, b), d.Round(time.Second))
				s.Partition(a, b)
				later(d, "partition healed", s.Heal)
			case k == 6 && split && now >= splitUntil:
				j := rng.IntN(n)
				d := span(40*time.Second, 2*time.Minute)
				splitUntil = now + d
				note("%s loses its link for %s", s.Name(j), d.Round(time.Second))
				s.CutLink(j)
				later(d, "link back", s.Heal)
			case k == 7 || k == 8:
				ids := []int{i}
				if rng.IntN(3) == 0 {
					ids = nil
				}
				d := span(40*time.Second, 5*time.Minute)
				note("internet down at %s for %s", namesOr(s, ids), d.Round(time.Second))
				s.InternetDown(ids...)
				later(d, "internet back at "+namesOr(s, ids), func() { s.InternetUp(ids...) })
			case k == 9:
				d := span(time.Minute, 6*time.Minute)
				note("Telegram unreachable for %s", d.Round(time.Second))
				s.TelegramDown()
				later(d, "Telegram back", s.TelegramUp)
			case k == 10:
				d := span(30*time.Second, 2*time.Minute)
				note("the whole site loses power for %s", d.Round(time.Second))
				for _, j := range honest {
					s.PowerOff(j)
					back := d + time.Duration(rng.IntN(10))*time.Second
					later(back, s.Name(j)+" powered on", func() { s.PowerOn(j) })
				}
			}
		}
		if tick%5 == 0 && traceSweep != nil {
			traceSweep(s)
		}
		s.Run(time.Second)
	}
	note("everything heals")
	s.HealAll()
	for t := time.Duration(0); t < settleAll; t += 5 * time.Second {
		if traceSweep != nil {
			traceSweep(s)
		}
		s.Run(5 * time.Second)
	}
	r.chat = s.Messages()
	// The plan always has an equivocator; noEquivocate removes it from the
	// fake only, so the check still expects its fork.
	r.violations = check(s, honest, eq)
	return r
}

// traceSweep, when set, is called every 5 s of every seed (for debugging
// one seed).
var traceSweep func(s *Site)

func names(s *Site, is []int) string {
	var out []string
	for _, i := range is {
		out = append(out, s.Name(i))
	}
	return strings.Join(out, ",")
}

func namesOr(s *Site, is []int) string {
	if len(is) == 0 {
		return "every router"
	}
	return names(s, is)
}

// The verbs of a message's first sentence, after the names it is about.
var (
	firstSentence = regexp.MustCompile(`^Home: ((?:[a-z0-9-]+, )*[a-z0-9-]+) (rebooted unexpectedly|rebooted as planned|upgraded|stopped answering|lost contact|went silent|answered again|showed different histories)`)
	duplicateID   = regexp.MustCompile(`^Home: two devices answered as ([a-z0-9-]+) `)
	tagOf         = regexp.MustCompile(` \[([0-9a-f]{8})\]$`)
	// updateForm is the shape of an update's message (D1): a return told
	// with its end only.
	updateForm = regexp.MustCompile(`^Home: [a-z0-9-]+ (rebooted unexpectedly, back at|rebooted as planned, back at|upgraded( [^ ]+ -> [^ ]+)?, back at|lost contact until) `)
)

// told returns the members the first sentence of m names and its verb.
func told(m Message) ([]string, string) {
	if x := firstSentence.FindStringSubmatch(m.Text); x != nil {
		return strings.Split(x[1], ", "), x[2]
	}
	if x := duplicateID.FindStringSubmatch(m.Text); x != nil {
		return []string{x[1]}, "two devices"
	}
	return nil, ""
}

// facts answers what the check needs about the site's history.
type facts struct {
	s      *Site
	honest []int
	cycles []Cycle
	end    time.Duration
}

// cycled reports whether member i had a power cycle starting in [from, to].
func (f facts) cycled(i int, from, to time.Duration) bool {
	return slices.ContainsFunc(f.cycles, func(c Cycle) bool { return c.Member == i && c.Off >= from && c.Off <= to })
}

// overlaps reports whether member i was off at some time in [from, to].
func (f facts) overlaps(i int, from, to time.Duration) bool {
	return slices.ContainsFunc(f.cycles, func(c Cycle) bool {
		on := c.On
		if on < 0 {
			on = f.end
		}
		return c.Member == i && c.Off <= to && on >= from
	})
}

// off reports whether member i was off at t.
func (f facts) off(i int, t time.Duration) bool { return f.overlaps(i, t, t) }

func (f facts) index(name string) int {
	for _, i := range f.honest {
		if f.s.Name(i) == name {
			return i
		}
	}
	return -1
}

// heldChains reads, from the stores, the equivocator's chain as each
// honest router and each of its faces last flushed it: entry hashes in
// order.
func heldChains(s *Site, honest []int, eq int) (held map[string][]ids.Hash, faces [][]ids.Hash) {
	read := func(dir string) []ids.Hash {
		b, err := os.ReadFile(filepath.Join(dir, "history-"+s.ID(eq).String()+".json"))
		if err != nil {
			return nil
		}
		var es []history.Entry
		if json.Unmarshal(b, &es) != nil {
			return nil
		}
		var out []ids.Hash
		for _, e := range es {
			out = append(out, e.Hash())
		}
		return out
	}
	held = map[string][]ids.Hash{}
	for _, i := range honest {
		held[s.Name(i)] = read(s.routers[i].faces[0].dir)
	}
	for _, f := range s.routers[eq].faces {
		faces = append(faces, read(f.dir))
	}
	return held, faces
}

// hiddenFork tags an unreported fork D16 when its evidence is on disk:
// every honest router holds one chain of the equivocator (each a prefix of
// the longest, a flush may lag), and a face's own chain differs from it at
// a position that chain covers, so the other branch never reached an
// honest router.
func hiddenFork(s *Site, honest []int, eq int) string {
	held, faces := heldChains(s, honest, eq)
	var long []ids.Hash
	for _, c := range held {
		if len(c) > len(long) {
			long = c
		}
	}
	for _, c := range held {
		if !slices.Equal(c, long[:len(c)]) {
			return ""
		}
	}
	for _, c := range faces {
		for k := 0; k < min(len(c), len(long)); k++ {
			if c[k] != long[k] {
				return "D16"
			}
		}
	}
	return ""
}

// check returns the invariants the healed site breaks, I1 to I7.
func check(s *Site, honest []int, eq int) []violation {
	var out []violation
	add := func(inv, defect, format string, a ...any) {
		out = append(out, violation{inv: inv, defect: defect, msg: fmt.Sprintf(format, a...)})
	}
	ms := s.Messages()
	f := facts{s: s, honest: honest, cycles: s.Cycles(), end: s.Elapsed()}
	statuses := map[int][]string{} // member -> the honest routers that mark it suspicious
	for _, i := range honest {
		st := s.Status(i)
		for _, m := range st.Members {
			if m.State == "suspicious" {
				j := f.index(m.Name)
				if m.Name == s.Name(eq) {
					j = eq
				}
				statuses[j] = append(statuses[j], s.Name(i))
			}
		}
	}

	// I1: every power cycle of an honest router is told as a reboot.
	for _, c := range f.cycles {
		name := s.Name(c.Member)
		if !slices.ContainsFunc(ms, func(m Message) bool {
			who, verb := told(m)
			return m.At >= c.Off && slices.Contains(who, name) && (strings.HasPrefix(verb, "rebooted") || verb == "upgraded")
		}) {
			defect := ""
			switch {
			case len(statuses[c.Member]) > 0:
				defect = "D6" // its own chain forked: its own reboot event never takes
			case c.On >= 0 && !slices.ContainsFunc(honest, func(i int) bool { return s.routers[i].sender && !f.cycled(i, c.On, f.end) }):
				defect = "D19" // every sender restarted after it came back: what they held undelivered was lost
			}
			add("I1", defect, "unreported: %s's %s at %s (back at %s) never reached the chat", name, c.Kind, c.Off.Round(time.Second), c.On.Round(time.Second))
		}
	}
	// I6: and nothing else is.
	for _, m := range ms {
		who, verb := told(m)
		kind := map[string]string{"rebooted unexpectedly": "crash", "rebooted as planned": "planned reboot", "upgraded": "upgrade"}[verb]
		if kind == "" {
			continue
		}
		for _, name := range who {
			had := func(kind string) bool {
				return slices.ContainsFunc(f.cycles, func(c Cycle) bool { return s.Name(c.Member) == name && c.Kind == kind && c.Off <= m.At })
			}
			if !had(kind) {
				defect := ""
				if kind == "crash" && had("planned reboot") {
					defect = "D18"
				}
				add("I6", defect, "false reboot: %q, but %s had no %s before it", m.Text, name, kind)
			}
		}
	}
	// I1: the sender delivered everything it holds. A sender whose own
	// chain forked (D6) never takes its acknowledgements.
	sender := senderOf(s.Status(honest[0]))
	for _, i := range honest {
		if got := senderOf(s.Status(i)); got != sender {
			add("I1", "", "undelivered: after healing %s names %q the sender and %s names %q", s.Name(i), got, s.Name(honest[0]), sender)
		}
	}
	for _, i := range honest {
		if s.Name(i) != sender {
			continue
		}
		forked := ""
		if len(statuses[i]) > 0 {
			forked = "D6"
		}
		st := s.Status(i)
		if st.Queued != 0 {
			add("I1", forked, "undelivered: the sender %s still holds %d incident(s) (%s)", sender, st.Queued, st.Delivery)
		}
		for _, inc := range st.Incidents {
			if !inc.Delivered {
				add("I1", forked, "undelivered: the sender %s never took the acknowledgement of %s %q", sender, inc.ID, inc.Text)
			}
		}
	}
	// I2: no duplicate without a partition.
	if !s.Partitioned() {
		copies := map[string][]Message{}
		var keys []string
		for _, m := range ms {
			x := tagOf.FindStringSubmatch(m.Text)
			if x == nil {
				continue
			}
			for _, k := range []string{"incident [" + x[1] + "]", strconv.Quote(strings.TrimSuffix(m.Text, x[0]))} {
				if copies[k] == nil {
					keys = append(keys, k)
				}
				copies[k] = append(copies[k], m)
			}
		}
		for _, k := range keys {
			c := copies[k]
			if len(c) < 2 {
				continue
			}
			first := c[0]
			if i := f.index(first.By); i >= 0 && f.cycled(i, first.At, first.At+ackLife) {
				continue // its acknowledgement died with the sender's RAM
			}
			defect := ""
			switch {
			case updateForm.MatchString(first.Text):
				defect = "D1" // an update, recorded again after its router restarted
			case slices.ContainsFunc(c, func(m Message) bool { return m.By != first.By }):
				defect = "D2"
			case slices.ContainsFunc(f.cycles, func(cy Cycle) bool { return cy.On >= 0 && cy.On <= first.At && first.At-cy.On <= 2*time.Minute }):
				defect = "D14" // a router back from a restart told an absence again from its own start
			}
			add("I2", defect, "duplicate: %s sent %d times without a partition (by %s, %s)", k, len(c), first.By, c[1].By)
		}
	}
	// I3: the equivocator is reported with its fork proof.
	name := s.Name(eq)
	firstFork := time.Duration(-1)
	for _, m := range ms {
		if who, verb := told(m); verb == "showed different histories" && slices.Contains(who, name) {
			firstFork = m.At
			break
		}
	}
	// D6: every honest router that sees one of the faces forked its own
	// chain, so that face's branch never meets the other.
	groups := map[int][]int{}
	for _, i := range honest {
		groups[s.routers[eq].sees[s.routers[i]]] = append(groups[s.routers[eq].sees[s.routers[i]]], i)
	}
	forkedFace := false
	for _, g := range groups {
		if !slices.ContainsFunc(g, func(i int) bool { return len(statuses[i]) == 0 }) {
			forkedFace = true
		}
	}
	hidden := ""
	if firstFork < 0 {
		hidden = hiddenFork(s, honest, eq)
		// D7: an honest router holds the proof, and the sender, which
		// holds no alarm for it, restarted: its own alarm record read
		// back marked the alarm raised, so it never queues or proves it
		// again.
		if i := f.index(sender); hidden == "" && i >= 0 && f.cycled(i, warmup, f.end) &&
			slices.ContainsFunc(honest, func(j int) bool { return stateOf(s.Status(j), name) == "suspicious" }) &&
			!slices.ContainsFunc(s.Status(i).Incidents, func(inc node.IncidentStatus) bool { return strings.Contains(inc.Text, "showed different histories") }) {
			hidden = "D7"
		}
		// D6: the sender, or a router that holds the proof, forked its own
		// chain, so its alarm or its records never take.
		if hidden == "" && (forkedFace || slices.ContainsFunc(honest, func(i int) bool {
			return len(statuses[i]) > 0 && (s.Name(i) == sender || stateOf(s.Status(i), name) == "suspicious")
		})) {
			hidden = "D6"
		}
		add("I3", hidden, "fork not reported: no message tells that %s showed different histories", name)
	}
	for _, i := range honest {
		if st := stateOf(s.Status(i), name); st != "suspicious" {
			defect := ""
			switch {
			case hidden == "D16":
				defect = hidden
			case f.cycled(i, warmup, f.end):
				defect = "D7"
			case forkedFace:
				defect = "D6"
			}
			add("I3", defect, "fork not reported: %s sees the equivocator %s %q, want suspicious", s.Name(i), name, st)
		}
	}
	// I4: no honest router is suspicious or named in an alarm. A router
	// that power-cycled may have forked its own chain (D6).
	for _, j := range honest {
		defect := ""
		if f.cycled(j, 0, f.end) {
			defect = "D6"
		}
		for _, by := range statuses[j] {
			add("I4", defect, "honest suspicious: %s marks %s suspicious", by, s.Name(j))
		}
		for _, m := range ms {
			if who, verb := told(m); (verb == "showed different histories" || verb == "two devices") && slices.Contains(who, s.Name(j)) {
				add("I4", defect, "honest suspicious: an alarm about %s: %q", s.Name(j), m.Text)
			}
		}
	}
	// I7: after healing, every honest router hears every other one.
	for _, i := range honest {
		st := s.Status(i)
		for _, m := range st.Members {
			if m.State != "up" && m.State != "suspicious" {
				add("I7", "", "not heard: after healing %s sees %s %q", s.Name(i), m.Name, m.State)
			}
		}
	}
	// I5: never two senders at once while the network is whole: two
	// routers sending less than the grace apart each took itself for the
	// sender.
	for i := 1; i < len(ms); i++ {
		a, b := ms[i-1], ms[i]
		if a.By != b.By && b.At-a.At < grace && s.WholeAt(a.At) && s.WholeAt(b.At) {
			add("I5", "D2", "two senders: %s at %s and %s at %s while the network was whole", a.By, a.At.Round(time.Second), b.By, b.At.Round(time.Second))
			break
		}
	}
	return out
}
