// Package quiet holds the quiet hours: a span of the day, on the router's
// local wall clock, in which the chat messages go out without a sound.
//
// Only the sound changes. A message sent within the quiet hours reaches the
// chat at once, with the text it would have at any other hour; nothing waits
// for the span to end and nothing is dropped. Whether a message is silent is
// decided by the moment it is sent (deliver.Queue.SetQuiet), not by the moment
// its incident began.
package quiet

import (
	"fmt"
	"strings"
	"time"
)

// Form is how quiet hours are written: the start and the end in 24-hour local
// time, for example 23:00-07:00.
const Form = "HH:MM-HH:MM"

// Hours is a daily span of local time, from its start, included, to its end,
// left out, that may run across midnight: 23:00-07:00 holds 23:00:00 and
// 06:59:59, and not 22:59:59 or 07:00:00. The zero Hours holds no moment: no
// quiet hours. Make one with Parse.
type Hours struct {
	start, end int // minutes after midnight, 0 to 1439, never equal
	on         bool
}

// Parse reads quiet hours written in Form: two digits for each hour (00 to 23)
// and minute (00 to 59), and nothing else, no spaces. The empty string is no
// quiet hours. A span that starts and ends at the same minute is refused, as
// it says neither the whole day nor none.
func Parse(s string) (Hours, error) {
	if s == "" {
		return Hours{}, nil
	}
	from, to, ok := strings.Cut(s, "-")
	start, okStart := minuteOfDay(from)
	end, okEnd := minuteOfDay(to)
	if !ok || !okStart || !okEnd {
		return Hours{}, fmt.Errorf("%q is not %s in 24-hour local time, for example 23:00-07:00", s, Form)
	}
	if start == end {
		return Hours{}, fmt.Errorf("%q starts and ends at the same minute; write the span as %s, for example 23:00-07:00, or leave the option out", s, Form)
	}
	return Hours{start: start, end: end, on: true}, nil
}

// minuteOfDay reads HH:MM, two ASCII digits each, 00:00 to 23:59, as minutes
// after midnight.
func minuteOfDay(s string) (int, bool) {
	if len(s) != 5 || s[2] != ':' {
		return 0, false
	}
	for _, i := range []int{0, 1, 3, 4} {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	h := int(s[0]-'0')*10 + int(s[1]-'0')
	m := int(s[3]-'0')*10 + int(s[4]-'0')
	if h > 23 || m > 59 {
		return 0, false
	}
	return h*60 + m, true
}

// On reports whether h is a span of the day, not the zero Hours.
func (h Hours) On() bool { return h.on }

// Contains reports whether t falls within h on the wall clock of loc, the
// zone the messages show their times in; a nil loc is UTC. Seconds count: in
// 23:00-07:00, 06:59:59 is within and 07:00:00 is not.
func (h Hours) Contains(t time.Time, loc *time.Location) bool {
	if !h.on {
		return false
	}
	if loc == nil {
		loc = time.UTC
	}
	l := t.In(loc)
	m := l.Hour()*60 + l.Minute()
	if h.start < h.end {
		return m >= h.start && m < h.end
	}
	return m >= h.start || m < h.end // across midnight
}

// String writes h in Form, as Parse reads it, or "" for no quiet hours.
func (h Hours) String() string {
	if !h.on {
		return ""
	}
	return fmt.Sprintf("%02d:%02d-%02d:%02d", h.start/60, h.start%60, h.end/60, h.end%60)
}
