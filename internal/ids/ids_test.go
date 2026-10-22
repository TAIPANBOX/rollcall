package ids

import (
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
