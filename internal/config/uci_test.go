package config

import (
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
	"testing/iotest"
)

// docSample follows the example on the OpenWrt UCI documentation page
// (https://openwrt.org/docs/guide-user/base-system/uci): quoted keywords
// arguments, a named section, options and a list. The second section adds
// the other forms the parser accepts.
const docSample = `# a comment line
config 'example' 'test'
        option   'string'      'some value'
        option   'boolean'     '1'
        list     'collection'  'first item'
        list     'collection'  'second item'

config example
	option string "double \"quoted\" value"
	option escaped 'it'\''s'
	option empty ''
	option bare value   # a trailing comment
	option backslash "a\\b"
	option single 'a\b'
	option twice first
	option twice second
	list collection only
`

func TestParseUCI(t *testing.T) {
	got, err := ParseUCI(strings.NewReader(docSample))
	if err != nil {
		t.Fatalf("ParseUCI: %v", err)
	}
	want := []Section{
		{
			Type: "example", Name: "test", Line: 2,
			Options: map[string]string{"string": "some value", "boolean": "1"},
			Lists:   map[string][]string{"collection": {"first item", "second item"}},
		},
		{
			Type: "example", Name: "", Line: 8,
			Options: map[string]string{
				"string":    `double "quoted" value`,
				"escaped":   "it's",
				"empty":     "",
				"bare":      "value",
				"backslash": `a\b`,
				"single":    `a\b`,
				"twice":     "second", // the last one wins, as in uci
			},
			Lists: map[string][]string{"collection": {"only"}},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ParseUCI:\n got %#v\nwant %#v", got, want)
	}
}

func TestParseUCIEmpty(t *testing.T) {
	for _, in := range []string{"", "\n\n", "# only a comment\n", "   \t\n"} {
		got, err := ParseUCI(strings.NewReader(in))
		if err != nil || len(got) != 0 {
			t.Errorf("ParseUCI(%q) = %v, %v; want no sections, no error", in, got, err)
		}
	}
}

func TestParseUCICRLF(t *testing.T) {
	got, err := ParseUCI(strings.NewReader("config rollcall 'main'\r\n\toption port '7432'\r\n"))
	if err != nil {
		t.Fatalf("ParseUCI: %v", err)
	}
	if len(got) != 1 || got[0].Name != "main" || got[0].Options["port"] != "7432" {
		t.Fatalf("ParseUCI = %#v; want section main with port 7432", got)
	}
}

func TestParseUCIRefuses(t *testing.T) {
	cases := []struct {
		name, in string
		line     int
	}{
		{"option before config", "option x y\n", 1},
		{"list before config", "\n\nlist x y\n", 3},
		{"unknown statement", "config a\n\tfoo x y\n", 2},
		{"package statement", "package rollcall\n", 1},
		{"option without value", "config a\n\toption x\n", 2},
		{"option without name", "config a\n\toption\n", 2},
		{"option with an extra token", "config a\n\toption x y z\n", 2},
		{"list with an extra token", "config a\n\tlist x y z\n", 2},
		{"config without type", "config\n", 1},
		{"config with an extra token", "config a b c\n", 1},
		{"unterminated single quote", "config a\n\toption x 'y\n", 2},
		{"unterminated double quote", "config a\n\toption x \"y\n", 2},
		{"line continuation", "config a\n\toption x y\\\n\toption z w\n", 2},
		{"continuation in double quotes", "config a\n\toption x \"y\\\n", 2},
		{"statement separator", "config a\n\toption x y; option z w\n", 2},
		{"hash inside a word", "config a\n\toption x foo#bar\n", 2},
		{"bad option name", "config a\n\toption x-y z\n", 2},
		{"empty option name", "config a\n\toption '' z\n", 2},
		{"bad section name", "config a 'b-c'\n", 1},
		{"empty section name", "config a ''\n", 1},
		{"empty type", "config ''\n", 1},
		{"space in type", "config 'a b'\n", 1},
		{"error after comments and blanks", "config a\n\n# c\n\n\tbogus\n", 5},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseUCI(strings.NewReader(tc.in))
			if err == nil {
				t.Fatalf("ParseUCI(%q) = %#v, nil; want an error", tc.in, got)
			}
			if got != nil {
				t.Errorf("ParseUCI(%q) returned sections with the error: %#v", tc.in, got)
			}
			var se *SyntaxError
			if !errors.As(err, &se) {
				t.Fatalf("ParseUCI(%q) error %v is not a *SyntaxError", tc.in, err)
			}
			if se.Line != tc.line {
				t.Errorf("ParseUCI(%q) error at line %d, want line %d (%v)", tc.in, se.Line, tc.line, err)
			}
			if want := fmt.Sprintf("line %d: ", tc.line); !strings.HasPrefix(err.Error(), want) {
				t.Errorf("error %q does not start with %q", err, want)
			}
		})
	}
}

func TestParseUCIReadError(t *testing.T) {
	boom := errors.New("disk on fire")
	if got, err := ParseUCI(iotest.ErrReader(boom)); !errors.Is(err, boom) || got != nil {
		t.Fatalf("ParseUCI on a failing reader = %v, %v; want the reader's error", got, err)
	}
}

func TestParseUCISizeLimit(t *testing.T) {
	line := "# " + strings.Repeat("x", 1000) + "\n"
	big := strings.Repeat(line, MaxUCISize/len(line)+1)
	if _, err := ParseUCI(strings.NewReader(big)); err == nil {
		t.Fatalf("ParseUCI accepted %d bytes; the limit is %d", len(big), MaxUCISize)
	}
	fits := strings.Repeat(line, MaxUCISize/len(line))
	if _, err := ParseUCI(strings.NewReader(fits)); err != nil {
		t.Fatalf("ParseUCI refused %d bytes (limit %d): %v", len(fits), MaxUCISize, err)
	}
}

// formatUCI writes sections back as UCI text, quoting every token in single
// quotes the way uci export does, so a parse of its output must give the
// same sections.
func formatUCI(secs []Section) string {
	quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
	var b strings.Builder
	for _, s := range secs {
		b.WriteString("config " + quote(s.Type))
		if s.Name != "" {
			b.WriteString(" " + quote(s.Name))
		}
		b.WriteString("\n")
		for _, k := range sortedKeys(s.Options) {
			fmt.Fprintf(&b, "\toption %s %s\n", quote(k), quote(s.Options[k]))
		}
		lists := make([]string, 0, len(s.Lists))
		for k := range s.Lists {
			lists = append(lists, k)
		}
		sort.Strings(lists)
		for _, k := range lists {
			for _, v := range s.Lists[k] {
				fmt.Fprintf(&b, "\tlist %s %s\n", quote(k), quote(v))
			}
		}
	}
	return b.String()
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// withoutLines drops the line numbers, which a reformat changes.
func withoutLines(secs []Section) []Section {
	out := make([]Section, len(secs))
	for i, s := range secs {
		s.Line = 0
		out[i] = s
	}
	return out
}

// FuzzParseUCI feeds ParseUCI arbitrary text. A refusal must be a
// *SyntaxError (or the size error) with no sections; an accepted file must
// hold only valid names and must survive a format and a second parse
// unchanged.
func FuzzParseUCI(f *testing.F) {
	f.Add(docSample)
	f.Add("config rollcall 'main'\n\tlist peer_zone 'lan'\n\toption port '7432'\n")
	f.Add("config zone\n\toption name 'wan'\n\toption network 'wan wan6'\n")
	f.Add("config a\n\toption x 'it'\\''s'\n")
	f.Add("config a\n\toption x \"a\\\"b\"\n")
	f.Add("config a\n\toption x y\\\n")
	f.Add("config a b c\n")
	f.Add("\x00config\x00")
	f.Fuzz(func(t *testing.T, in string) {
		secs, err := ParseUCI(strings.NewReader(in))
		if err != nil {
			if secs != nil {
				t.Fatalf("sections returned with error %v", err)
			}
			var se *SyntaxError
			if !errors.As(err, &se) && !errors.Is(err, ErrTooLarge) {
				t.Fatalf("error %v is neither a *SyntaxError nor ErrTooLarge", err)
			}
			if se != nil && (se.Line < 1 || se.Line > strings.Count(in, "\n")+1) {
				t.Fatalf("error line %d outside the input's %d lines", se.Line, strings.Count(in, "\n")+1)
			}
			return
		}
		for _, s := range secs {
			if !validType(s.Type) || (s.Name != "" && !validName(s.Name)) {
				t.Fatalf("accepted an invalid section %q %q", s.Type, s.Name)
			}
			for k := range s.Options {
				if !validName(k) {
					t.Fatalf("accepted an invalid option name %q", k)
				}
			}
			for k, v := range s.Lists {
				if !validName(k) || len(v) == 0 {
					t.Fatalf("accepted an invalid list %q %q", k, v)
				}
			}
		}
		text := formatUCI(secs)
		again, err := ParseUCI(strings.NewReader(text))
		if err != nil {
			t.Fatalf("formatted output does not parse: %v\n%s", err, text)
		}
		if !reflect.DeepEqual(withoutLines(again), withoutLines(secs)) {
			t.Fatalf("round trip changed the sections:\n got %#v\nwant %#v", again, secs)
		}
	})
}
