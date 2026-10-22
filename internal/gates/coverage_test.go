package gates

import (
	"bufio"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const (
	coverageProfileName  = "coverage.out"
	coverageBaselineName = "coverage-baseline.txt"
)

// TestCoverageNotBelowBaseline fails when total statement coverage in
// coverage.out is below the committed number in coverage-baseline.txt. It runs
// only when ROLLCALL_COVERAGE=1, after go test -coverprofile=coverage.out ./...
//
// The total is rounded to one decimal place, the precision the baseline is
// written in, so a total of 85.66 does not fail against a baseline of 85.7.
func TestCoverageNotBelowBaseline(t *testing.T) {
	if os.Getenv("ROLLCALL_COVERAGE") != "1" {
		t.Skip("set ROLLCALL_COVERAGE=1 after go test -coverprofile=coverage.out ./... to check the baseline")
	}
	root := requireRoot(t)

	total, err := statementCoverage(filepath.Join(root, coverageProfileName))
	if err != nil {
		t.Fatalf("measured nothing: %v", err)
	}
	baseline, err := readBaseline(filepath.Join(root, coverageBaselineName))
	if err != nil {
		t.Fatalf("measured nothing: %v", err)
	}

	rounded := math.Round(total*10) / 10
	t.Logf("total statement coverage %.1f%%, committed baseline %.1f%%", rounded, baseline)
	if rounded < baseline {
		t.Errorf("total statement coverage %.1f%% is below the committed baseline %.1f%% in %s",
			rounded, baseline, coverageBaselineName)
	}
}

// statementCoverage returns the statement-weighted coverage percentage of a
// Go coverage profile. A block that appears more than once counts as covered
// if any copy has a non-zero count.
func statementCoverage(path string) (float64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	type block struct {
		stmts   int
		covered bool
	}
	blocks := map[string]*block{}
	sc := bufio.NewScanner(f)
	for line := 1; sc.Scan(); line++ {
		text := sc.Text()
		if line == 1 {
			if !strings.HasPrefix(text, "mode: ") {
				return 0, fmt.Errorf("%s: first line is not a mode line", path)
			}
			continue
		}
		if text == "" {
			continue
		}
		fields := strings.Fields(text)
		if len(fields) != 3 {
			return 0, fmt.Errorf("%s:%d: want 3 fields, got %d", path, line, len(fields))
		}
		stmts, errStmts := strconv.Atoi(fields[1])
		count, errCount := strconv.Atoi(fields[2])
		if errStmts != nil || errCount != nil {
			return 0, fmt.Errorf("%s:%d: statement or count is not a number", path, line)
		}
		b := blocks[fields[0]]
		if b == nil {
			b = &block{stmts: stmts}
			blocks[fields[0]] = b
		}
		if count > 0 {
			b.covered = true
		}
	}
	if err := sc.Err(); err != nil {
		return 0, fmt.Errorf("%s: %w", path, err)
	}

	total, covered := 0, 0
	for _, b := range blocks {
		total += b.stmts
		if b.covered {
			covered += b.stmts
		}
	}
	if total == 0 {
		return 0, fmt.Errorf("%s has no statements", path)
	}
	return 100 * float64(covered) / float64(total), nil
}

// readBaseline reads the committed coverage percentage.
func readBaseline(path string) (float64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	value, err := strconv.ParseFloat(strings.TrimSpace(string(data)), 64)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", path, err)
	}
	return value, nil
}
