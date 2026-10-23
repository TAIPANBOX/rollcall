package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
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

// TestLuCIStatusShowsConfirmation (A4): the status page shows until when a
// confirmation of a takeover is held, or that it lapsed, as text, and no such
// line when there is none.
func TestLuCIStatusShowsConfirmation(t *testing.T) {
	for _, tc := range confirmationCases {
		p := renderLuCI(t, luciStatusJS, fullReport(t, func(m map[string]any) { m["confirmation"] = tc.conf }), nil)
		if tc.want == "" && strings.Contains(p.Page, "onfirmation") {
			t.Errorf("%s: the page speaks of a confirmation:\n%s", tc.name, p.Page)
		}
		if tc.want != "" && !strings.Contains(p.Page, tc.want) {
			t.Errorf("%s: the page lacks %q:\n%s", tc.name, tc.want, p.Page)
		}
	}
	// A name or time carrying markup stays text: the renderer fails on any
	// child E() would insert as markup.
	evil := map[string]any{"state": "held", "of": "<b>x</b>", "from": "<img src=x>"}
	if p := renderLuCI(t, luciStatusJS, fullReport(t, func(m map[string]any) { m["confirmation"] = evil }), nil); !strings.Contains(p.Page, "<img src=x>") {
		t.Errorf("the time is not shown as text:\n%s", p.Page)
	}
}

// TestLuCIStatusHighlightsOldGroupKey: a group key older than its rotation
// period (30 days) is highlighted on the status page, since rotation may
// have stopped; a key within the period is shown plainly.
func TestLuCIStatusHighlightsOldGroupKey(t *testing.T) {
	withKey := func(gk any) map[string]any {
		return fullReport(t, func(m map[string]any) { m["group_key"] = gk })
	}
	key := func(age int) map[string]any {
		return map[string]any{"created": "2026-09-01T03:00:00+01:00", "age_days": age, "rotates_every_days": 30}
	}
	for _, age := range []int{0, 22, 30} {
		p := renderLuCI(t, luciStatusJS, withKey(key(age)), nil)
		if p.alert("", "group key") || slices.ContainsFunc(p.Strong, func(s string) bool { return strings.Contains(s, "days old") }) {
			t.Errorf("a key %d days old is highlighted: %+v %q", age, p.Alerts, p.Strong)
		}
	}
	if p := renderLuCI(t, luciStatusJS, withKey(nil), nil); p.alert("", "group key") {
		t.Errorf("no key yet, but a warning: %+v", p.Alerts)
	}
	old := renderLuCI(t, luciStatusJS, withKey(key(31)), nil)
	if !old.alert("warning", "31 days old") {
		t.Errorf("no warning for a key 31 days old: %+v", old.Alerts)
	}
	if !slices.ContainsFunc(old.Strong, func(s string) bool { return strings.Contains(s, "31 days old") }) {
		t.Errorf("the group key row is not highlighted: %q", old.Strong)
	}
}

// adminACL returns the command lines the admin group of the rpcd ACL allows.
func adminACL(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(luciACLPath)
	if err != nil {
		t.Fatalf("measured nothing: %v", err)
	}
	var acl map[string]struct {
		Write struct {
			File map[string][]string `json:"file"`
		} `json:"write"`
	}
	if err := json.Unmarshal(raw, &acl); err != nil {
		t.Fatal(err)
	}
	var out []string
	for k := range acl["luci-app-rollcall-admin"].Write.File {
		out = append(out, k)
	}
	if len(out) == 0 {
		t.Fatal("measured nothing: no admin entries in the ACL")
	}
	return out
}

// allowed reports whether the command line of params matches an ACL entry,
// with '*' standing for any text as rpcd's pattern match has it.
func allowed(acl []string, params []string) bool {
	line := "/usr/bin/rollcall " + strings.Join(params, " ")
	for _, k := range acl {
		re := "^" + strings.ReplaceAll(regexp.QuoteMeta(k), `\*`, ".*") + "$"
		if regexp.MustCompile(re).MatchString(line) {
			return true
		}
	}
	return false
}

// TestLuCIInviteSenderAndAddress: the invite dialog of the admin page gives
// the sender role and the address of this router through the CLI's flags,
// in forms the ACL allows, and shows the join code.
func TestLuCIInviteSenderAndAddress(t *testing.T) {
	acl := adminACL(t)
	report := fullReport(t, nil)
	replies := map[string]any{"invite": map[string]any{"ok": true, "message": "Join window open for 10 minutes.", "join_code": "TEST-JOIN-CODE"}}
	open, submit := click("Invite a router"), click("Open join window")
	for _, tc := range []struct {
		name    string
		actions []luciAction
		want    []string
	}{
		{"as it was", []luciAction{open, submit}, []string{"invite", "--json"}},
		{"sender", []luciAction{open, check("rollcall-invite-sender"), submit}, []string{"invite", "--json", "--sender"}},
		{"address", []luciAction{open, set("rollcall-invite-address", " 192.0.2.7 "), submit}, []string{"invite", "--json", "--", "192.0.2.7"}},
		{"both", []luciAction{open, check("rollcall-invite-sender"), set("rollcall-invite-address", "2001:db8::7"), submit},
			[]string{"invite", "--json", "--sender", "--", "2001:db8::7"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := renderLuCI(t, luciAdminJS, report, replies, tc.actions...)
			var invites [][]string
			for _, e := range p.Execs {
				if len(e.Params) > 0 && e.Params[0] == "invite" {
					invites = append(invites, e.Params)
				}
			}
			if len(invites) != 1 || !slices.Equal(invites[0], tc.want) {
				t.Fatalf("the page ran %q, want %q", invites, tc.want)
			}
			if !allowed(acl, invites[0]) {
				t.Errorf("the ACL does not allow %q", invites[0])
			}
			if !strings.Contains(p.Modal, "TEST-JOIN-CODE") {
				t.Errorf("the join code is not shown: %q", p.Modal)
			}
		})
	}
}
