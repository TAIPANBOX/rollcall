package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The tests here render the LuCI pages of luci-app-rollcall with
// testdata/luci_render.js, which stands in for LuCI's modules, and read what
// a person would see. They need node; without it they skip and say so.

const (
	luciViews     = "../../luci-app-rollcall/htdocs/luci-static/resources/view/rollcall"
	luciStatusJS  = luciViews + "/status.js"
	luciAdminJS   = luciViews + "/admin.js"
	luciACLPath   = "../../luci-app-rollcall/root/usr/share/rpcd/acl.d/luci-app-rollcall.json"
	luciStatusDoc = "../../luci-app-rollcall/STATUS-JSON.md"
)

// luciPage is what luci_render.js prints.
type luciPage struct {
	Page   string `json:"page"`
	Modal  string `json:"modal"`
	Alerts []struct {
		Class string `json:"class"`
		Text  string `json:"text"`
	} `json:"alerts"`
	Strong []string `json:"strong"`
	Execs  []struct {
		Command string            `json:"command"`
		Params  []string          `json:"params"`
		Env     map[string]string `json:"env"`
	} `json:"execs"`
	Notes    []string `json:"notes"`
	Problems []string `json:"problems"`
}

// luciAction is one step of a scenario: {"click": label}, {"check": id} or
// {"set": [id, value]}.
type luciAction map[string]any

func click(label string) luciAction   { return luciAction{"click": label} }
func check(id string) luciAction      { return luciAction{"check": id} }
func set(id, value string) luciAction { return luciAction{"set": []string{id, value}} }

// renderLuCI renders view with status, runs actions, and returns the page.
func renderLuCI(t *testing.T, view string, status map[string]any, replies map[string]any, actions ...luciAction) luciPage {
	t.Helper()
	nodeBin, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed: the LuCI pages were not rendered")
	}
	abs, err := filepath.Abs(view)
	if err != nil {
		t.Fatal(err)
	}
	sc, err := json.Marshal(map[string]any{"view": abs, "status": status, "replies": replies, "actions": actions})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "scenario.json")
	if err := os.WriteFile(path, sc, 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	cmd := exec.Command(nodeBin, "testdata/luci_render.js", path)
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		t.Fatalf("rendering %s: %v\n%s", filepath.Base(view), err, errb.String())
	}
	var p luciPage
	if err := json.Unmarshal(out.Bytes(), &p); err != nil {
		t.Fatalf("rendering %s printed %q: %v", filepath.Base(view), out.String(), err)
	}
	if len(p.Problems) > 0 {
		t.Fatalf("rendering %s: %q", filepath.Base(view), p.Problems)
	}
	return p
}

// fullReport returns the full report of STATUS-JSON.md, with edit applied.
func fullReport(t *testing.T, edit func(map[string]any)) map[string]any {
	t.Helper()
	_, full := jsonBlocks(t)
	var m map[string]any
	if err := json.Unmarshal([]byte(full), &m); err != nil {
		t.Fatal(err)
	}
	if edit != nil {
		edit(m)
	}
	return m
}

func (p luciPage) alert(class, sub string) bool {
	for _, a := range p.Alerts {
		if strings.Contains(a.Class, class) && strings.Contains(a.Text, sub) {
			return true
		}
	}
	return false
}

// TestLuCIReadsEveryReportField: every top-level field of the full report
// in STATUS-JSON.md is read by one of the LuCI pages, so a field added to
// the contract is not one the pages leave out.
func TestLuCIReadsEveryReportField(t *testing.T) {
	var js []byte
	for _, f := range []string{luciStatusJS, luciAdminJS} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("measured nothing: %v", err)
		}
		js = append(js, b...)
	}
	example := fullReport(t, nil)
	if len(example) < 10 {
		t.Fatalf("measured nothing: %d fields in the full report", len(example))
	}
	for k := range example {
		if !regexp.MustCompile(`\bst\.` + regexp.QuoteMeta(k) + `\b`).Match(js) {
			t.Errorf("no LuCI page reads %q of the status report", k)
		}
	}
}

// TestLuCIStatusShowsFlood: a router under a flood shows a warning on the
// status page; one that is not shows none.
func TestLuCIStatusShowsFlood(t *testing.T) {
	calm := renderLuCI(t, luciStatusJS, fullReport(t, func(m map[string]any) { m["under_flood"] = false }), nil)
	if calm.alert("", "flood") {
		t.Fatalf("a flood warning without a flood: %+v", calm.Alerts)
	}
	flooded := renderLuCI(t, luciStatusJS, fullReport(t, func(m map[string]any) { m["under_flood"] = true }), nil)
	if !flooded.alert("warning", "fail authentication") {
		t.Fatalf("no flood warning on the status page:\n%s", flooded.Page)
	}
}
