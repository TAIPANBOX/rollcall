package clock

import (
	"testing"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/ids"
)

// boot returns a test boot ID that is never zero.
func boot(n byte) ids.BootID {
	var b ids.BootID
	b[0] = n
	b[15] = 0xb0
	return b
}

// t0 is a wall time in the plausible range of a trusted clock.
var t0 = time.Date(2026, 10, 22, 14, 2, 0, 0, time.UTC)

// threeYears is the size of the clock step of Review Focus 2.
const threeYears = 3 * 365 * 24 * time.Hour

func TestDurationSameBoot(t *testing.T) {
	b := boot(1)
	cases := []struct {
		name   string
		a, b   Stamp
		want   time.Duration
		approx bool
	}{
		{"wall agrees with mono",
			Stamp{Wall: t0, Mono: 100 * time.Second, Trusted: true, Boot: b},
			Stamp{Wall: t0.Add(65 * time.Second), Mono: 165 * time.Second, Trusted: true, Boot: b},
			65 * time.Second, false},
		{"wall jumps three years forward between the stamps",
			Stamp{Wall: t0, Mono: 100 * time.Second, Trusted: false, Boot: b},
			Stamp{Wall: t0.Add(threeYears + 6*time.Second), Mono: 106 * time.Second, Trusted: true, Boot: b},
			6 * time.Second, false},
		{"wall jumps three years back between the stamps",
			Stamp{Wall: t0.Add(threeYears), Mono: 100 * time.Second, Trusted: false, Boot: b},
			Stamp{Wall: t0.Add(6 * time.Second), Mono: 106 * time.Second, Trusted: true, Boot: b},
			6 * time.Second, false},
		{"neither wall clock trusted",
			Stamp{Wall: t0, Mono: time.Second, Trusted: false, Boot: b},
			Stamp{Wall: t0.Add(time.Hour), Mono: 3 * time.Second, Trusted: false, Boot: b},
			2 * time.Second, false},
		{"no wall time at all",
			Stamp{Mono: time.Second, Boot: b},
			Stamp{Mono: time.Minute, Boot: b},
			59 * time.Second, false},
		{"the same moment",
			Stamp{Wall: t0, Mono: time.Second, Trusted: true, Boot: b},
			Stamp{Wall: t0, Mono: time.Second, Trusted: true, Boot: b},
			0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, approx := Duration(c.a, c.b)
			if got != c.want || approx != c.approx {
				t.Errorf("Duration = %v, approximate %v; want %v, approximate %v (monotonic, same boot)",
					got, approx, c.want, c.approx)
			}
		})
	}
}

func TestDurationDifferentBoots(t *testing.T) {
	cases := []struct {
		name   string
		a, b   Stamp
		want   time.Duration
		approx bool
	}{
		{"both trusted: the wall difference, exact",
			Stamp{Wall: t0, Mono: 500 * time.Second, Trusted: true, Boot: boot(1)},
			Stamp{Wall: t0.Add(65 * time.Second), Mono: 20 * time.Second, Trusted: true, Boot: boot(2)},
			65 * time.Second, false},
		{"first untrusted",
			Stamp{Wall: t0, Mono: 500 * time.Second, Trusted: false, Boot: boot(1)},
			Stamp{Wall: t0.Add(65 * time.Second), Mono: 20 * time.Second, Trusted: true, Boot: boot(2)},
			65 * time.Second, true},
		{"second untrusted",
			Stamp{Wall: t0, Mono: 500 * time.Second, Trusted: true, Boot: boot(1)},
			Stamp{Wall: t0.Add(65 * time.Second), Mono: 20 * time.Second, Trusted: false, Boot: boot(2)},
			65 * time.Second, true},
		{"monotonic readings of two boots are never subtracted",
			Stamp{Wall: t0, Mono: 10 * time.Second, Trusted: true, Boot: boot(1)},
			Stamp{Wall: t0.Add(time.Minute), Mono: 11 * time.Second, Trusted: true, Boot: boot(2)},
			time.Minute, false},
		{"the same router's next boot",
			Stamp{Wall: t0, Mono: 3600 * time.Second, Trusted: true, Boot: boot(1)},
			Stamp{Wall: t0.Add(90 * time.Second), Mono: 30 * time.Second, Trusted: true, Boot: boot(3)},
			90 * time.Second, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, approx := Duration(c.a, c.b)
			if got != c.want || approx != c.approx {
				t.Errorf("Duration = %v, approximate %v; want %v, approximate %v (wall, different boots)",
					got, approx, c.want, c.approx)
			}
		})
	}
}

// TestDurationUnknownBoot: a zero boot ID is unknown, so two stamps that
// both carry it are not known to share a boot and their monotonic readings
// are not compared.
func TestDurationUnknownBoot(t *testing.T) {
	var zero ids.BootID
	cases := []struct {
		name string
		a, b Stamp
	}{
		{"both unknown",
			Stamp{Wall: t0, Mono: time.Second, Trusted: true, Boot: zero},
			Stamp{Wall: t0.Add(time.Minute), Mono: 2 * time.Second, Trusted: true, Boot: zero}},
		{"first unknown",
			Stamp{Wall: t0, Mono: time.Second, Trusted: true, Boot: zero},
			Stamp{Wall: t0.Add(time.Minute), Mono: 2 * time.Second, Trusted: true, Boot: boot(1)}},
		{"second unknown",
			Stamp{Wall: t0, Mono: time.Second, Trusted: true, Boot: boot(1)},
			Stamp{Wall: t0.Add(time.Minute), Mono: 2 * time.Second, Trusted: true, Boot: zero}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, approx := Duration(c.a, c.b)
			if got != time.Minute || approx {
				t.Errorf("Duration = %v, approximate %v; want 1m0s from the wall clocks, exact", got, approx)
			}
		})
	}
}

// TestDurationNeverNegative: a stamp b before a gives zero, marked
// approximate, on either path. A negative length would render as nonsense
// ("back after -5 s") and could pass a "shorter than" check downstream.
func TestDurationNeverNegative(t *testing.T) {
	cases := []struct {
		name string
		a, b Stamp
	}{
		{"same boot, b earlier",
			Stamp{Wall: t0, Mono: 106 * time.Second, Trusted: true, Boot: boot(1)},
			Stamp{Wall: t0.Add(time.Hour), Mono: 100 * time.Second, Trusted: true, Boot: boot(1)}},
		{"same boot, one nanosecond earlier",
			Stamp{Wall: t0, Mono: 100*time.Second + 1, Trusted: true, Boot: boot(1)},
			Stamp{Wall: t0, Mono: 100 * time.Second, Trusted: true, Boot: boot(1)}},
		{"different boots, b earlier",
			Stamp{Wall: t0.Add(5 * time.Second), Mono: time.Second, Trusted: true, Boot: boot(1)},
			Stamp{Wall: t0, Mono: time.Hour, Trusted: true, Boot: boot(2)}},
		{"different boots, one nanosecond earlier",
			Stamp{Wall: t0.Add(1), Mono: time.Second, Trusted: true, Boot: boot(1)},
			Stamp{Wall: t0, Mono: time.Hour, Trusted: true, Boot: boot(2)}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, approx := Duration(c.a, c.b)
			if got != 0 || !approx {
				t.Errorf("Duration = %v, approximate %v; want 0s, approximate true", got, approx)
			}
		})
	}
}
