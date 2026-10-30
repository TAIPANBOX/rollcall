package control

import (
	"strings"
	"testing"
)

// TestRunsLineIsRoutine: the line each command a caller runs leaves goes to
// the routine logger; refusals stay with WithLogf's. The ntp hotplug hook
// runs notify every 11 minutes, and on a router on 2026-10-30 its line was
// logged as an error each time.
func TestRunsLineIsRoutine(t *testing.T) {
	rec := &recorder{}
	problems, info := &logBuf{}, &logBuf{}
	path := serve(t, rec.handler("ran", nil), withCred(fixedCred(0, nil)), WithLogf(problems.logf), WithInfof(info.logf))
	if _, err := Client(path).Call("notify", ""); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(info.String(), "uid 0 runs notify") {
		t.Errorf("routine log %q; want the line of the command run", info)
	}
	if strings.Contains(problems.String(), "runs") {
		t.Errorf("problem log %q holds the routine line", problems)
	}
}
