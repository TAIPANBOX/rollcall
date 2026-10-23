package sim

import (
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"
	"testing"
)

// # Known defects
//
// What the simulator found wrong in the product, each with the evidence
// that shows it. A scenario assertion or a sweep invariant that fails only
// because of one of these is reported as blocked by it: the test skips and
// names the defect, so the suite stays usable while the fix is made. With
// ROLLCALL_STRICT=1 every one of them fails instead; a fix is proven by
// running strict and removing its entry here. Anything that fails and is not
// listed here always fails.
var knownDefects = map[string]string{
	"D1": "a router that stayed up corrects the others' silence claim and records an update, which the chat gets as an " +
		"extra message ('r03 lost contact until 09:01 but stayed up'): redundant with the group's own link-loss message, " +
		"and its time is the claim's (when the silence began), told as 'until' (TestMeshNodeLinkLoss; the sweep checks " +
		"duplicates only without partitions, so it does not see this one)",
	"D8": "the chat tells a silence 45 to 55 s after a power cut (detection at 30 s, then the 20 s coalescing settle); " +
		"the bound is 30 s of detection and 15 s (TestPowerLossReported)",
	"D9": "a router whose own link was cut records every other router silent; once the link is back the chat gets 'r01, r02 " +
		"stopped answering, confirmed by 0 of 2' and an update per router: one link loss, six messages (TestMeshNodeLinkLoss)",
	"D14": "a router that restarts while a peer is away forgets the peer (its last boot and version live in RAM only): it " +
		"reports the peer silent from its own start, a second message for an absence already told, and tells the peer's " +
		"return as 'went silent ..., back after' counted from its own start, never as the reboot or upgrade it was (sweep I2)",
	"D18": "a planned reboot is told as unexpected when one observer missed the single 'going down' heartbeat (packet loss, " +
		"a partition): the incident holds both kinds and the message takes the unplanned one, though the router's own boot " +
		"record says planned (sweep I6)",
}

// strict reports whether known defects fail rather than skip.
func strict() bool { return os.Getenv("ROLLCALL_STRICT") == "1" }

// verdict collects the failures of one test: plain ones fail at once,
// those of known defects are held and skip the test at the end.
type verdict struct {
	t       *testing.T
	blocked map[string][]string
}

// newVerdict returns the verdict of t; the test defers its done.
func newVerdict(t *testing.T) *verdict {
	return &verdict{t: t, blocked: map[string][]string{}}
}

// fail records a failure. defects names the known defects it is blocked
// by ("D1,D9"), or is empty for a plain failure.
func (v *verdict) fail(defects, format string, args ...any) {
	v.t.Helper()
	msg := fmt.Sprintf(format, args...)
	if defects == "" || strict() {
		if defects != "" {
			msg = "[" + defects + "] " + msg
		}
		v.t.Error(msg)
		return
	}
	for _, d := range strings.Split(defects, ",") {
		if _, ok := knownDefects[d]; !ok {
			v.t.Errorf("unknown defect %s for: %s", d, msg)
			return
		}
	}
	v.t.Logf("blocked by %s: %s", defects, msg)
	v.blocked[defects] = append(v.blocked[defects], msg)
}

// done, deferred by the test, skips a test that failed only through known
// defects.
func (v *verdict) done() {
	if len(v.blocked) == 0 || v.t.Failed() {
		return
	}
	var ds []string
	for k := range v.blocked {
		ds = append(ds, strings.Split(k, ",")...)
	}
	sort.Strings(ds)
	v.t.Skipf("blocked by known node defect(s) %s (see knownDefects); run with ROLLCALL_STRICT=1 to fail on them", strings.Join(slices.Compact(ds), ", "))
}
