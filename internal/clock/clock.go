// Package clock holds the time stamps rollcall puts on events and the one
// rule for measuring between two of them.
//
// Most routers have no real-time clock. After a power cut the wall clock is
// wrong until NTP answers, and then it steps, possibly by years (design 3 and
// 4.4). A stamp therefore carries both clocks: the wall clock, which says
// when, and the monotonic clock since boot, which says how long and never
// steps. Monotonic readings compare only within one boot.
package clock

import (
	"time"

	"github.com/TAIPANBOX/rollcall/internal/ids"
)

// Stamp is one moment as one router saw it.
type Stamp struct {
	Wall    time.Time     // wall clock; may be far off while Trusted is false
	Mono    time.Duration // monotonic clock since boot; never steps
	Trusted bool          // the wall clock was NTP-synced during this boot
	Boot    ids.BootID    // the boot Mono counts from; zero means unknown
}

// Duration returns how long passed from a to b, and whether that length is
// approximate.
//
//   - Same boot: b.Mono - a.Mono, exact whatever the wall clocks did in
//     between (trusted or not, stepped by years or not).
//   - Different boots, or a boot unknown: b.Wall - a.Wall, approximate unless
//     both wall clocks are trusted. Two zero boot IDs are unknown, not equal.
//   - Never negative: when b is before a the result is zero, marked
//     approximate, on either path.
//
// When both Wall values were read by time.Now in this process, time.Time.Sub
// measures them on Go's own monotonic reading; that only makes the wall
// difference more exact.
func Duration(a, b Stamp) (d time.Duration, approximate bool) {
	if a.Boot != (ids.BootID{}) && a.Boot == b.Boot {
		d = b.Mono - a.Mono
	} else {
		d = b.Wall.Sub(a.Wall)
		approximate = !a.Trusted || !b.Trusted
	}
	if d < 0 {
		return 0, true
	}
	return d, approximate
}
