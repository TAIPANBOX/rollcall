package roster

import (
	"errors"
	"strings"
	"testing"
	"unicode/utf8"
)

// TestNames covers the names of Review Focus 1: a hostile name is refused
// whole, never truncated, and the error does not carry it.
func TestNames(t *testing.T) {
	ok := []string{
		"ap-office",
		"a",
		"0",
		"gateway2",
		"a-b-c",
		"ap-",
		"9lives",
		strings.Repeat("a", MaxNameLen),
		strings.Repeat("z", MaxNameLen-1) + "-",
	}
	for _, s := range ok {
		if err := ValidName(s); err != nil {
			t.Errorf("ValidName(%+q) = %v, want nil", s, err)
		}
	}

	bad := []string{
		"",
		strings.Repeat("a", MaxNameLen+1),
		strings.Repeat("a", 200),
		"\u041a\u0443\u0445\u043d\u044f",
		"a b",
		"ap\u202e",
		"ap\u202eeciffo",
		"AP",
		"Ap-office",
		"ap_office",
		"ap.office",
		"ap/office",
		"ap\x00",
		"ap\n",
		"ap\t",
		"-ap",
		"-",
		"ap-offic\u0435", // Cyrillic small ie looks like "e"
		"\uff41\uff50",   // fullwidth "ap"
		"ap\U0001F600",
		"ap\xff",
		"<b>",
		"ap\u200b",
	}
	for _, s := range bad {
		err := ValidName(s)
		if !errors.Is(err, ErrName) {
			t.Errorf("ValidName(%+q) = %v, want ErrName", s, err)
			continue
		}
		msg := err.Error()
		if !isPlainASCII(msg) {
			t.Errorf("ValidName(%+q): error %+q is not plain printable ASCII", s, msg)
		}
		if len(s) > 1 && strings.Contains(msg, s) {
			t.Errorf("ValidName(%+q): error %q repeats the name", s, msg)
		}
	}
}

// TestNameMessages pins the message for each kind of fault, so that the
// owner sees why a name was refused.
func TestNameMessages(t *testing.T) {
	cases := []struct {
		name, want string
	}{
		{"", "roster: invalid name: empty"},
		{strings.Repeat("a", 33), "roster: invalid name: 33 characters, at most 32"},
		{strings.Repeat("b", 200), "roster: invalid name: 200 characters, at most 32"},
		{"a b", "roster: invalid name: byte 1 is not a-z, 0-9 or '-'"},
		{"\u041a\u0443\u0445\u043d\u044f", "roster: invalid name: byte 0 is not a-z, 0-9 or '-'"},
		{"ap\u202e", "roster: invalid name: byte 2 is not a-z, 0-9 or '-'"},
		{"-ap", "roster: invalid name: starts with '-'"},
	}
	for _, c := range cases {
		err := ValidName(c.name)
		if err == nil || err.Error() != c.want {
			t.Errorf("ValidName(%+q) = %v, want %q", c.name, err, c.want)
		}
	}
}

// TestNameByteSweep tries every byte value in the middle and at the start of
// a name: exactly a-z, 0-9 and '-' pass in the middle, and '-' fails at the
// start.
func TestNameByteSweep(t *testing.T) {
	for b := 0; b < 256; b++ {
		c := byte(b)
		allowed := 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-'
		mid := "a" + string([]byte{c}) + "a"
		if err := ValidName(mid); (err == nil) != allowed {
			t.Errorf("ValidName(%+q) = %v, want allowed=%v", mid, err, allowed)
		}
		first := string([]byte{c}) + "a"
		if err := ValidName(first); (err == nil) != (allowed && c != '-') {
			t.Errorf("ValidName(%+q) = %v, want allowed=%v", first, err, allowed && c != '-')
		}
	}
}

// TestNameLengthSweep checks every length from 0 to 64 characters.
func TestNameLengthSweep(t *testing.T) {
	for n := 0; n <= 64; n++ {
		s := strings.Repeat("x", n)
		if err := ValidName(s); (err == nil) != (n >= 1 && n <= MaxNameLen) {
			t.Errorf("ValidName of %d characters = %v", n, err)
		}
	}
}

// isPlainASCII reports whether s holds only printable ASCII.
func isPlainASCII(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}
