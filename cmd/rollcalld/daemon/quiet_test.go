package daemon

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
	_ "time/tzdata" // Europe/Kyiv on a machine without a zone database

	"github.com/TAIPANBOX/rollcall/internal/config"
	"github.com/TAIPANBOX/rollcall/internal/ids"
	"github.com/TAIPANBOX/rollcall/internal/node"
	"github.com/TAIPANBOX/rollcall/internal/quiet"
	"github.com/TAIPANBOX/rollcall/internal/store"
)

// sendsRecorder is the Bot API answering every call, keeping the body of each
// sendMessage.
type sendsRecorder struct {
	srv   *httptest.Server
	mu    sync.Mutex
	sends []string
}

func newSendsRecorder(t *testing.T) *sendsRecorder {
	t.Helper()
	r := &sendsRecorder{}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		if strings.HasSuffix(req.URL.Path, "/sendMessage") {
			r.mu.Lock()
			r.sends = append(r.sends, string(b))
			r.mu.Unlock()
		}
		fmt.Fprint(w, `{"ok":true,"result":{"id":1,"is_bot":true}}`)
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *sendsRecorder) all() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.sends...)
}

// startAt is start with the wall clock at wall.
func startAt(t *testing.T, dir string, wall time.Time, edit func(*Options)) *harness {
	t.Helper()
	h := &harness{t: t, clk: &fakeClock{wall: wall, mono: 1000 * time.Second}, net: &recNet{}}
	o := Options{StateDir: dir, Net: h.net, Clock: h.clk, Boot: ids.BootID{1, 15: 1}, Logf: t.Logf}
	edit(&o)
	d, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	h.d = d
	d.Step()
	return h
}

// TestQuietHoursReachTelegram: the daemon gives the node the quiet hours of
// option quiet_hours and the zone of the system configuration, and the
// sender's Telegram request carries the result. With Europe/Kyiv and
// 23:00-07:00, a roster change announced at 20:20 UTC, 23:20 in Kyiv, reaches
// Telegram with disable_notification; one at 04:20 UTC, 07:20 in Kyiv, without
// it, though 04:20 is within 23:00-07:00 in UTC.
func TestQuietHoursReachTelegram(t *testing.T) {
	h, err := quiet.Parse("23:00-07:00")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name   string
		wall   time.Time
		silent bool
	}{
		{"23:20 in Kyiv", time.Date(2026, 10, 23, 20, 20, 0, 0, time.UTC), true},
		{"07:20 in Kyiv", time.Date(2026, 10, 24, 4, 20, 0, 0, time.UTC), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			tg := newSendsRecorder(t)
			f := newFixture(t, true, true)
			st, err := store.Open(f.dir)
			if err != nil {
				t.Fatal(err)
			}
			if err := node.SaveSecrets(st, canary, 4242); err != nil {
				t.Fatal(err)
			}
			hh := startAt(t, f.dir, c.wall, func(o *Options) {
				o.TelegramURL, o.HTTP = tg.srv.URL, tg.srv.Client()
				o.Config = config.Config{Site: "Home", Port: 7432, Heartbeat: 5 * time.Second, SilentAfter: 30 * time.Second,
					Sender: true, TZ: "Europe/Kyiv", QuietHours: h}
			})
			hh.run(5 * time.Second)
			if _, err := hh.handle("roles", "backup", "ap-office"); err != nil {
				t.Fatal(err)
			}
			hh.run(30 * time.Second)
			sends := tg.all()
			if len(sends) == 0 {
				t.Fatal("nothing was sent to Telegram: the case did not happen")
			}
			for _, s := range sends {
				var body map[string]any
				if err := json.Unmarshal([]byte(s), &body); err != nil {
					t.Fatalf("sendMessage body %q: %v", s, err)
				}
				got, present := body["disable_notification"]
				switch {
				case c.silent && got != true:
					t.Errorf("sent at %s: %s; want disable_notification true", c.name, s)
				case !c.silent && present:
					t.Errorf("sent at %s: %s; want no disable_notification field", c.name, s)
				}
			}
		})
	}
}
