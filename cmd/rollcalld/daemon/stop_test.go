package daemon

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/events"
)

// recentIncidents returns the event types of the incidents the node's state
// file on flash keeps.
func recentIncidents(t *testing.T, dir string) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Recent []struct {
			Inc struct {
				Events []string
			} `json:"inc"`
		} `json:"recent"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, r := range f.Recent {
		out = append(out, strings.Join(r.Inc.Events, "+"))
	}
	return out
}

// TestCloseStopsTheNode (Q5): a clean shutdown of the daemon writes what the
// node keeps on flash at once (node.Stop), not at the next minute's flush:
// an incident made seconds before is in the state file after Close.
func TestCloseStopsTheNode(t *testing.T) {
	f := newFixture(t, false, false)
	h := start(t, f.dir, nil)
	h.run(70 * time.Second) // the first flushes are behind
	h.d.localEvent(events.InternetLost, time.Time{}, nil)
	h.run(35 * time.Second) // the incident is made (a link change waits 30 s); the next flush is a minute away
	if got := recentIncidents(t, f.dir); len(got) != 0 {
		t.Fatalf("the state file holds %v before the shutdown: the case did not happen", got)
	}
	h.d.Close()
	if got := recentIncidents(t, f.dir); len(got) != 1 || got[0] != string(events.InternetLost) {
		t.Fatalf("after Close the state file holds %v, want the internet loss", got)
	}
	if st := h.d.current().Status(); st.State != "stopped" {
		t.Fatalf("the node is %q after Close, want stopped", st.State)
	}
}
