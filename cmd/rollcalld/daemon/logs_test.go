package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// TestProblemsGoToErrorf: state the daemon cannot read is logged through
// Errorf, which rollcalld sends to stderr (daemon.err), and not through Logf,
// which carries the routine lines (daemon.info).
func TestProblemsGoToErrorf(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a file whatever its mode")
	}
	f := newFixture(t, false, false)
	if err := os.Chmod(filepath.Join(f.dir, "identity.json"), 0); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var info, problems []string
	capture := func(to *[]string) func(string, ...any) {
		return func(format string, args ...any) {
			mu.Lock()
			defer mu.Unlock()
			*to = append(*to, fmt.Sprintf(format, args...))
		}
	}
	h := start(t, f.dir, func(o *Options) { o.Logf, o.Errorf = capture(&info), capture(&problems) })
	h.run(2 * pollEvery)
	mu.Lock()
	defer mu.Unlock()
	if !strings.Contains(strings.Join(problems, "\n"), "the state cannot be read yet") {
		t.Errorf("problems %q; want the state that cannot be read", problems)
	}
	if strings.Contains(strings.Join(info, "\n"), "cannot be read") {
		t.Errorf("routine lines %q hold the problem", info)
	}
}
