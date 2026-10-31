package node

import (
	"slices"
	"strings"
	"testing"
	"time"
	_ "time/tzdata" // Europe/Kyiv on a machine without a zone database

	"github.com/TAIPANBOX/rollcall/internal/quiet"
)

// quietGroup is a group of two, r01 the sender, whose clock starts at start
// and whose nodes show their times in loc and keep the quiet hours h.
func quietGroup(t *testing.T, start time.Time, loc *time.Location, h quiet.Hours) *group {
	t.Helper()
	g := newGroup(t, setup{n: 2, running: []bool{false, false}, senders: map[int]int{0: 1}})
	g.clk.wall = start
	for i := range g.cfgs {
		g.cfgs[i].TZ, g.cfgs[i].Quiet = loc, h
		g.start(i)
	}
	return g
}

// silentRouter runs g until r02 has been silent for two minutes and returns
// what reached the chat.
func silentRouter(t *testing.T, g *group) []chatMsg {
	t.Helper()
	g.run(90 * sec)
	g.stop(1)
	g.run(2 * time.Minute)
	g.chat.mu.Lock()
	defer g.chat.mu.Unlock()
	msgs := slices.Clone(g.chat.msgs)
	if !slices.ContainsFunc(msgs, func(m chatMsg) bool { return strings.Contains(m.text, "r02") }) {
		t.Fatalf("nothing about r02 reached the chat: the case did not happen: %+v", msgs)
	}
	return msgs
}

// TestQuietHoursFollowTheMessagesZone: the node keeps the quiet hours in the
// zone its messages show their times in. With Europe/Kyiv, three hours ahead
// of UTC on 23 October 2026, and quiet hours 23:00-07:00, a router that stops
// answering at 20:21 UTC is told as stopped at 23:21 without a sound, and one
// that stops at 04:21 UTC, 07:21 in Kyiv, with one, though 04:21 is within
// 23:00-07:00 in UTC. The texts are those of the same group without quiet
// hours.
func TestQuietHoursFollowTheMessagesZone(t *testing.T) {
	kyiv, err := time.LoadLocation("Europe/Kyiv")
	if err != nil {
		t.Fatal(err)
	}
	h, err := quiet.Parse("23:00-07:00")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name   string
		start  time.Time
		shows  string
		silent bool
	}{
		{"stopped at 23:21 in Kyiv", time.Date(2026, 10, 23, 20, 20, 0, 0, time.UTC), " 23:21", true},
		{"stopped at 07:21 in Kyiv", time.Date(2026, 10, 24, 4, 20, 0, 0, time.UTC), " 07:21", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			msgs := silentRouter(t, quietGroup(t, c.start, kyiv, h))
			plain := silentRouter(t, quietGroup(t, c.start, kyiv, quiet.Hours{}))
			for _, m := range msgs {
				t.Logf("silent %v: %s", m.silent, m.text)
				if m.silent != c.silent {
					t.Errorf("%q: silent %v, want %v", m.text, m.silent, c.silent)
				}
				if strings.Contains(m.text, "r02") && !strings.Contains(m.text, c.shows) {
					t.Errorf("%q does not show the Kyiv time%s", m.text, c.shows)
				}
			}
			for _, m := range plain {
				if m.silent {
					t.Errorf("without quiet hours %q was silent", m.text)
				}
			}
			// The tags differ, as the two groups' routers have their own IDs.
			texts := func(ms []chatMsg) []string {
				var out []string
				for _, m := range ms {
					out = append(out, chatTag.ReplaceAllString(m.text, "[tag]"))
				}
				return out
			}
			if !slices.Equal(texts(msgs), texts(plain)) {
				t.Errorf("texts with quiet hours %q, without %q; want the same", texts(msgs), texts(plain))
			}
		})
	}
}
