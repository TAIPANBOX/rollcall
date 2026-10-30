package quiet

import (
	"strings"
	"testing"
	"time"
	_ "time/tzdata" // Europe/Kyiv on a machine without a zone database
)

// at is 23 October 2026 at hh:mm:ss in loc.
func at(hh, mm, ss int, loc *time.Location) time.Time {
	return time.Date(2026, 10, 23, hh, mm, ss, 0, loc)
}

func mustParse(t *testing.T, s string) Hours {
	t.Helper()
	h, err := Parse(s)
	if err != nil {
		t.Fatalf("Parse(%q): %v", s, err)
	}
	if !h.On() {
		t.Fatalf("Parse(%q) gave no quiet hours", s)
	}
	return h
}

// TestQuietHoursAcrossMidnight: 23:00-07:00 holds the night on both sides of
// midnight and nothing of the day; quiet hours within one day (01:00-05:00)
// hold only their own span, not the hours before their start.
func TestQuietHoursAcrossMidnight(t *testing.T) {
	night := mustParse(t, "23:00-07:00")
	for _, c := range []struct {
		hh, mm int
		quiet  bool
	}{
		{23, 30, true}, {0, 0, true}, {3, 0, true}, {6, 59, true},
		{7, 1, false}, {12, 0, false}, {22, 59, false}, {7, 30, false}, {15, 0, false},
	} {
		if got := night.Contains(at(c.hh, c.mm, 0, time.UTC), time.UTC); got != c.quiet {
			t.Errorf("23:00-07:00 at %02d:%02d: quiet %v, want %v", c.hh, c.mm, got, c.quiet)
		}
	}
	early := mustParse(t, "01:00-05:00")
	for _, c := range []struct {
		hh, mm int
		quiet  bool
	}{
		{1, 0, true}, {3, 0, true}, {4, 59, true},
		{0, 59, false}, {5, 0, false}, {12, 0, false}, {23, 30, false},
	} {
		if got := early.Contains(at(c.hh, c.mm, 0, time.UTC), time.UTC); got != c.quiet {
			t.Errorf("01:00-05:00 at %02d:%02d: quiet %v, want %v", c.hh, c.mm, got, c.quiet)
		}
	}
}

// TestQuietHoursEdges: the start is included and the end is not, to the
// second: 23:00:00 is quiet and 22:59:59 is not, 06:59:59 is quiet and
// 07:00:00 is not.
func TestQuietHoursEdges(t *testing.T) {
	h := mustParse(t, "23:00-07:00")
	for _, c := range []struct {
		t     time.Time
		quiet bool
	}{
		{at(22, 59, 59, time.UTC), false},
		{at(22, 59, 59, time.UTC).Add(999 * time.Millisecond), false},
		{at(23, 0, 0, time.UTC), true},
		{at(6, 59, 59, time.UTC), true},
		{at(6, 59, 59, time.UTC).Add(999 * time.Millisecond), true},
		{at(7, 0, 0, time.UTC), false},
	} {
		if got := h.Contains(c.t, time.UTC); got != c.quiet {
			t.Errorf("23:00-07:00 at %s: quiet %v, want %v", c.t.Format("15:04:05.000"), got, c.quiet)
		}
	}
}

// TestQuietHoursLocalTime: the quiet hours are read on the wall clock of the
// zone given, the one the messages show their times in, never in UTC or the
// zone of the machine. On 23 October 2026 Kyiv is three hours ahead of UTC.
func TestQuietHoursLocalTime(t *testing.T) {
	kyiv, err := time.LoadLocation("Europe/Kyiv")
	if err != nil {
		t.Fatal(err)
	}
	h := mustParse(t, "23:00-07:00")
	evening := at(20, 20, 0, time.UTC) // 23:20 in Kyiv
	morning := at(4, 20, 0, time.UTC)  // 07:20 in Kyiv
	if !h.Contains(evening, kyiv) {
		t.Errorf("20:20 UTC is 23:20 in Kyiv, within 23:00-07:00 there; not quiet")
	}
	if h.Contains(morning, kyiv) {
		t.Errorf("04:20 UTC is 07:20 in Kyiv, after 23:00-07:00 there; quiet")
	}
	if h.Contains(evening, time.UTC) || !h.Contains(morning, time.UTC) {
		t.Errorf("in UTC 20:20 is outside 23:00-07:00 and 04:20 within")
	}
	// The same moment, written in another zone, is the same moment.
	if !h.Contains(evening.In(time.FixedZone("elsewhere", -5*3600)), kyiv) {
		t.Errorf("the zone a time is written in changed the answer")
	}
	// No zone reads the time in UTC.
	if h.Contains(evening, nil) || !h.Contains(morning, nil) {
		t.Errorf("a nil zone is not UTC")
	}
}

// TestParseQuietHours: only HH:MM-HH:MM in 24-hour time is read, two digits
// each, 00:00 to 23:59; the empty string is no quiet hours, and a span that
// starts and ends at the same minute is refused, as it says neither the whole
// day nor none.
func TestParseQuietHours(t *testing.T) {
	for _, s := range []string{"23:00-07:00", "00:00-23:59", "07:30-08:15", "23:59-00:00"} {
		h := mustParse(t, s)
		if h.String() != s {
			t.Errorf("Parse(%q).String() = %q", s, h.String())
		}
	}
	if h, err := Parse(""); err != nil || h.On() || h.String() != "" {
		t.Errorf("Parse(\"\") = %v, %v; want no quiet hours and no error", h, err)
	}
	for _, s := range []string{
		"23:00", "23-07", "23:00-7:00", "7:00-23:00", "24:00-07:00", "23:00-24:00", "23:60-07:00",
		"23:00 - 07:00", " 23:00-07:00", "23:00-07:00 ", "23:00-07:00-08:00", "ab:cd-ef:gh",
		"23:00–07:00", "+1:00-07:00", "23.00-07.00", "-", "23:00-", "-07:00", "2300-0700",
		"２３:00-07:00",
	} {
		h, err := Parse(s)
		if err == nil {
			t.Errorf("Parse(%q) accepted it: %v", s, h)
			continue
		}
		if h.On() {
			t.Errorf("Parse(%q) failed but gave quiet hours %v", s, h)
		}
		if !strings.Contains(err.Error(), "HH:MM-HH:MM") {
			t.Errorf("Parse(%q): %q does not name the form HH:MM-HH:MM", s, err)
		}
	}
	for _, s := range []string{"07:00-07:00", "00:00-00:00"} {
		if h, err := Parse(s); err == nil || h.On() || !strings.Contains(err.Error(), "same minute") {
			t.Errorf("Parse(%q) = %v, %v; want it refused as starting and ending at the same minute", s, h, err)
		}
	}
}

// TestZeroHoursHoldNothing: the zero Hours, no quiet hours, holds no minute
// of the day.
func TestZeroHoursHoldNothing(t *testing.T) {
	var h Hours
	for m := 0; m < 24*60; m++ {
		if h.Contains(at(m/60, m%60, 0, time.UTC), time.UTC) {
			t.Fatalf("no quiet hours, yet %02d:%02d is quiet", m/60, m%60)
		}
	}
}
