package config

import (
	"errors"
	"fmt"
	"io"
	"strings"
)

// MaxUCISize bounds one UCI file. OpenWrt configuration files are a few
// kilobytes; anything near this size is not a configuration file.
const MaxUCISize = 1 << 20

// ErrTooLarge is returned for a file larger than MaxUCISize.
var ErrTooLarge = fmt.Errorf("larger than %d bytes", MaxUCISize)

// Section is one `config <type> ['<name>']` block of a UCI file.
type Section struct {
	Type    string
	Name    string              // empty for an anonymous section
	Line    int                 // line of the config statement, from 1
	Options map[string]string   // option <name> <value>; the last one wins, as in uci
	Lists   map[string][]string // list <name> <value>, in file order
}

// SyntaxError is a line ParseUCI refuses.
type SyntaxError struct {
	Line int // from 1
	Msg  string
}

func (e *SyntaxError) Error() string { return fmt.Sprintf("line %d: %s", e.Line, e.Msg) }

// ParseUCI reads the minimal UCI syntax rollcall needs, and refuses anything
// else with the line it is on:
//
//	# comment
//	config <type> ['<name>']
//		option <name> <value>
//		list <name> <value>
//
// A word is a run of plain characters, 'single-quoted' text (no escapes),
// "double-quoted" text (a backslash takes the next character literally) and
// backslash-escaped characters, joined until white space; so the way uci
// itself writes a quote inside a value reads back as it was:
//
//	option name 'it'\''s'
//
// A # at the start of a word begins a comment.
// Refused: package lines, the ; separator, a # inside a word, line
// continuation, a quote left open at the end of a line, and names outside
// uci's rules (section and option names [A-Za-z0-9_]+, types printable
// ASCII).
func ParseUCI(r io.Reader) ([]Section, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxUCISize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxUCISize {
		return nil, ErrTooLarge
	}
	var secs []Section
	for i, line := range strings.Split(string(data), "\n") {
		n := i + 1
		words, err := splitWords(line)
		if err != nil {
			return nil, &SyntaxError{Line: n, Msg: err.Error()}
		}
		if len(words) == 0 {
			continue
		}
		switch words[0] {
		case "config":
			if len(words) < 2 || len(words) > 3 {
				return nil, &SyntaxError{Line: n, Msg: "config takes a type and an optional name"}
			}
			s := Section{Type: words[1], Line: n, Options: map[string]string{}, Lists: map[string][]string{}}
			if !validType(s.Type) {
				return nil, &SyntaxError{Line: n, Msg: fmt.Sprintf("invalid section type %q", s.Type)}
			}
			if len(words) == 3 {
				if s.Name = words[2]; !validName(s.Name) {
					return nil, &SyntaxError{Line: n, Msg: fmt.Sprintf("invalid section name %q", s.Name)}
				}
			}
			secs = append(secs, s)
		case "option", "list":
			if len(secs) == 0 {
				return nil, &SyntaxError{Line: n, Msg: words[0] + " before any config section"}
			}
			if len(words) != 3 {
				return nil, &SyntaxError{Line: n, Msg: words[0] + " takes a name and one value"}
			}
			if !validName(words[1]) {
				return nil, &SyntaxError{Line: n, Msg: fmt.Sprintf("invalid %s name %q", words[0], words[1])}
			}
			s := &secs[len(secs)-1]
			if words[0] == "option" {
				s.Options[words[1]] = words[2]
			} else {
				s.Lists[words[1]] = append(s.Lists[words[1]], words[2])
			}
		default:
			return nil, &SyntaxError{Line: n, Msg: fmt.Sprintf("unknown statement %q", words[0])}
		}
	}
	return secs, nil
}

var (
	errOpenSingle   = errors.New("single quote not closed on this line")
	errOpenDouble   = errors.New("double quote not closed on this line")
	errContinuation = errors.New("line continuation is not supported")
	errSeparator    = errors.New("the ; separator is not supported")
	errHashInWord   = errors.New("# inside a word; quote the value")
)

// splitWords splits one line into words by the rules in ParseUCI.
func splitWords(line string) ([]string, error) {
	var words []string
	i := 0
	for {
		for i < len(line) && isSpace(line[i]) {
			i++
		}
		if i == len(line) || line[i] == '#' {
			return words, nil
		}
		var w strings.Builder
		for i < len(line) && !isSpace(line[i]) {
			switch c := line[i]; c {
			case '\'':
				end := strings.IndexByte(line[i+1:], '\'')
				if end < 0 {
					return nil, errOpenSingle
				}
				w.WriteString(line[i+1 : i+1+end])
				i += end + 2
			case '"':
				i++
				for {
					if i == len(line) {
						return nil, errOpenDouble
					}
					if line[i] == '"' {
						i++
						break
					}
					if line[i] == '\\' {
						if i+1 == len(line) {
							return nil, errContinuation
						}
						i++
					}
					w.WriteByte(line[i])
					i++
				}
			case '\\':
				if i+1 == len(line) {
					return nil, errContinuation
				}
				w.WriteByte(line[i+1])
				i += 2
			case ';':
				return nil, errSeparator
			case '#':
				return nil, errHashInWord
			default:
				w.WriteByte(c)
				i++
			}
		}
		words = append(words, w.String())
	}
}

// isSpace is uci's white space; a carriage return counts, so CRLF files read.
func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\v' || c == '\f'
}

// validName is uci's rule for section and option names.
func validName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

// validType is uci's rule for section types: printable ASCII without space.
func validType(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 33 || s[i] > 126 {
			return false
		}
	}
	return true
}
