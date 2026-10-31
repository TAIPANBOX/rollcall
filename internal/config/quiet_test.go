package config

import (
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/quiet"
)

// TestQuietHoursInvalidRefused: option quiet_hours takes HH:MM-HH:MM in local
// time; anything else refuses the whole configuration, with the line, the
// option and the form, as every other option does. A valid one is read.
func TestQuietHoursInvalidRefused(t *testing.T) {
	for _, c := range []struct{ value, want string }{
		{"25:00-07:00", `line 1: quiet_hours "25:00-07:00"`},
		{"23:00", "HH:MM-HH:MM"},
		{"11pm-7am", "HH:MM-HH:MM"},
		{"23:00-7:00", "HH:MM-HH:MM"},
		{"23:00-23:00", "same minute"},
	} {
		rp, fp, sp, np := files(t, "config rollcall\n\toption quiet_hours '"+c.value+"'\n", fixtureFirewall, fixtureSystem, fixtureNetwork)
		cfg, _, err := Load(rp, fp, sp, np)
		if err == nil {
			t.Errorf("quiet_hours %q was accepted: %v", c.value, cfg.QuietHours)
			continue
		}
		for _, w := range []string{c.want, "quiet_hours", rp} {
			if !strings.Contains(err.Error(), w) {
				t.Errorf("quiet_hours %q: error %q does not say %q", c.value, err, w)
			}
		}
	}
	if _, _, err := Load(files(t, "config rollcall\n\tlist quiet_hours '23:00-07:00'\n", fixtureFirewall, fixtureSystem, fixtureNetwork)); err == nil ||
		!strings.Contains(err.Error(), `"quiet_hours" must be an option`) {
		t.Errorf("quiet_hours as a list: %v, want it refused as one that must be an option", err)
	}

	cfg, _, err := Load(files(t, "config rollcall\n\toption quiet_hours '23:00-07:00'\n", fixtureFirewall, fixtureSystem, fixtureNetwork))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want, _ := quiet.Parse("23:00-07:00")
	if cfg.QuietHours != want || !cfg.QuietHours.Contains(time.Date(2026, 10, 23, 23, 30, 0, 0, time.UTC), time.UTC) {
		t.Fatalf("quiet_hours '23:00-07:00' read as %v", cfg.QuietHours)
	}
}

// TestQuietHoursOffByDefault: without the option, or with it empty, there are
// no quiet hours, and no moment of the day is quiet.
func TestQuietHoursOffByDefault(t *testing.T) {
	for _, rc := range []string{"config rollcall\n", "config rollcall\n\toption quiet_hours ''\n"} {
		cfg, _, err := Load(files(t, rc, fixtureFirewall, fixtureSystem, fixtureNetwork))
		if err != nil {
			t.Fatalf("Load %q: %v", rc, err)
		}
		if cfg.QuietHours.On() || cfg.QuietHours != (quiet.Hours{}) {
			t.Errorf("%q: quiet hours %v, want none", rc, cfg.QuietHours)
		}
		for m := 0; m < 24*60; m++ {
			if at := time.Date(2026, 10, 23, m/60, m%60, 0, 0, time.UTC); cfg.QuietHours.Contains(at, time.UTC) {
				t.Fatalf("%q: no quiet hours set, yet %s is quiet", rc, at.Format("15:04"))
			}
		}
	}
}
