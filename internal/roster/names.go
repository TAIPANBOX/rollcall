package roster

import (
	"errors"
	"fmt"
)

// MaxNameLen is the longest site or member name, in characters.
const MaxNameLen = 32

// ErrName reports a site or member name that ValidName refuses.
var ErrName = errors.New("roster: invalid name")

// ValidName returns nil if s can name a site or a member: 1 to MaxNameLen
// characters from a-z, 0-9 and '-', not starting with '-' (so that a name is
// never read as an option on the command line). Anything else is refused
// whole, never shortened or folded to lower case. The error says what is
// wrong without repeating s, so that a hostile name never reaches a log, a
// chat message or LuCI through it.
func ValidName(s string) error {
	if s == "" {
		return fmt.Errorf("%w: empty", ErrName)
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !('a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-') {
			return fmt.Errorf("%w: byte %d is not a-z, 0-9 or '-'", ErrName, i)
		}
	}
	if len(s) > MaxNameLen {
		return fmt.Errorf("%w: %d characters, at most %d", ErrName, len(s), MaxNameLen)
	}
	if s[0] == '-' {
		return fmt.Errorf("%w: starts with '-'", ErrName)
	}
	return nil
}
