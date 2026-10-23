package ids

import (
	"encoding"
	"strings"
	"testing"
)

func TestIDTextRoundTrip(t *testing.T) {
	a, err := NewMemberID()
	if err != nil {
		t.Fatalf("NewMemberID: %v", err)
	}
	b, err := NewMemberID()
	if err != nil {
		t.Fatalf("NewMemberID: %v", err)
	}
	if a == b {
		t.Fatalf("two NewMemberID calls returned the same value %s", a)
	}

	text, err := a.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText: %v", err)
	}
	var back MemberID
	if err := back.UnmarshalText(text); err != nil {
		t.Fatalf("UnmarshalText(%q): %v", text, err)
	}
	if back != a {
		t.Fatalf("MemberID round trip: got %s, want %s", back, a)
	}

	if err := back.UnmarshalText([]byte("zz")); err == nil {
		t.Fatal(`UnmarshalText("zz") returned no error`)
	}
	if err := back.UnmarshalText([]byte("00")); err == nil {
		t.Fatal(`UnmarshalText("00") returned no error for a short value`)
	}
	if err := back.UnmarshalText([]byte(strings.Repeat("z", 32))); err == nil {
		t.Fatal("UnmarshalText of 32 non-hex digits returned no error")
	}

	boot, err := NewBootID()
	if err != nil {
		t.Fatalf("NewBootID: %v", err)
	}
	bootText, err := boot.MarshalText()
	if err != nil {
		t.Fatalf("BootID MarshalText: %v", err)
	}
	var bootBack BootID
	if err := bootBack.UnmarshalText(bootText); err != nil {
		t.Fatalf("BootID UnmarshalText(%q): %v", bootText, err)
	}
	if bootBack != boot {
		t.Fatalf("BootID round trip: got %s, want %s", bootBack, boot)
	}

	var h Hash
	h[0] = 0xab
	hashText, err := h.MarshalText()
	if err != nil {
		t.Fatalf("Hash MarshalText: %v", err)
	}
	var hashBack Hash
	if err := hashBack.UnmarshalText(hashText); err != nil {
		t.Fatalf("Hash UnmarshalText(%q): %v", hashText, err)
	}
	if hashBack != h {
		t.Fatalf("Hash round trip: got %s, want %s", hashBack, h)
	}
}

// marshalText returns the MarshalText output as a string, or fails the test.
func marshalText(t *testing.T, m encoding.TextMarshaler) string {
	t.Helper()
	b, err := m.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText: %v", err)
	}
	return string(b)
}

// TestIDTextIsLowercaseHex pins the output form: String and MarshalText
// emit lowercase hex for all three types.
func TestIDTextIsLowercaseHex(t *testing.T) {
	var m MemberID
	m[0], m[15] = 0xAB, 0xCD
	var b BootID
	b[0], b[15] = 0xAB, 0xCD
	var h Hash
	h[0], h[31] = 0xAB, 0xCD

	wantID := "ab" + strings.Repeat("00", 14) + "cd"
	wantHash := "ab" + strings.Repeat("00", 30) + "cd"

	checks := []struct {
		name string
		got  string
		want string
	}{
		{"MemberID.String", m.String(), wantID},
		{"MemberID.MarshalText", marshalText(t, m), wantID},
		{"BootID.String", b.String(), wantID},
		{"BootID.MarshalText", marshalText(t, b), wantID},
		{"Hash.String", h.String(), wantHash},
		{"Hash.MarshalText", marshalText(t, h), wantHash},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.name, c.got, c.want)
		}
	}
}

// TestUnmarshalRejectedInputLeavesReceiver feeds each type input of the
// right length whose first digits are valid and whose last pair is not.
// The decoder fails after it has read valid bytes, so a receiver written
// in place would change. The receiver must stay as it was.
func TestUnmarshalRejectedInputLeavesReceiver(t *testing.T) {
	t.Run("MemberID", func(t *testing.T) {
		var id MemberID
		for i := range id {
			id[i] = 0xff
		}
		before := id
		if err := id.UnmarshalText([]byte(strings.Repeat("0", 30) + "zz")); err == nil {
			t.Fatal("UnmarshalText returned no error for invalid hex digits")
		}
		if id != before {
			t.Fatalf("receiver changed after rejected input: got %s, want %s", id, before)
		}
	})
	t.Run("BootID", func(t *testing.T) {
		var id BootID
		for i := range id {
			id[i] = 0xff
		}
		before := id
		if err := id.UnmarshalText([]byte(strings.Repeat("0", 30) + "zz")); err == nil {
			t.Fatal("UnmarshalText returned no error for invalid hex digits")
		}
		if id != before {
			t.Fatalf("receiver changed after rejected input: got %s, want %s", id, before)
		}
	})
	t.Run("Hash", func(t *testing.T) {
		var h Hash
		for i := range h {
			h[i] = 0xff
		}
		before := h
		if err := h.UnmarshalText([]byte(strings.Repeat("0", 62) + "zz")); err == nil {
			t.Fatal("UnmarshalText returned no error for invalid hex digits")
		}
		if h != before {
			t.Fatalf("receiver changed after rejected input: got %s, want %s", h, before)
		}
	})
}
