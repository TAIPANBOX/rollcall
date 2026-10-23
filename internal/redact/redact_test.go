package redact

import "testing"

func TestRedactReplacesEverySecret(t *testing.T) {
	got := Redact("a CANARY-123:abc b xyz", "CANARY-123:abc", "xyz")
	want := "a [redacted] b [redacted]"
	if got != want {
		t.Fatalf("Redact = %q, want %q", got, want)
	}
}

func TestRedactIgnoresEmptySecret(t *testing.T) {
	// An empty secret must not be inserted between every byte.
	if got := Redact("keep me", ""); got != "keep me" {
		t.Fatalf("Redact with an empty secret = %q, want unchanged", got)
	}
}

func TestRedactLongestSecretFirst(t *testing.T) {
	// The short secret is a prefix of the long one: the long one must go whole.
	got := Redact("tok-long", "tok", "tok-long")
	if got != "[redacted]" {
		t.Fatalf("Redact = %q, want the whole long secret replaced", got)
	}
}

func TestRedactIsOnePass(t *testing.T) {
	// The replacement text itself contains "red", which is a secret here: a
	// second pass would mangle the marker. One pass leaves it intact.
	got := Redact("CANARY", "CANARY", "red")
	if got != "[redacted]" {
		t.Fatalf("Redact = %q, want %q", got, "[redacted]")
	}
}

func TestRedactNoSecretsLeavesTextAlone(t *testing.T) {
	if got := Redact("plain text"); got != "plain text" {
		t.Fatalf("Redact = %q, want unchanged", got)
	}
}
