package pairing

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/TAIPANBOX/rollcall/internal/ids"
	"github.com/TAIPANBOX/rollcall/internal/roster"
	"github.com/TAIPANBOX/rollcall/internal/sig"
)

// normalize is what ParseCode forgives in a copied code: white space around
// it, dashes anywhere, letter case, and O for 0, I and L for 1.
func normalize(s string) string {
	s = strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(s), "-", ""))
	return group(strings.NewReplacer("O", "0", "I", "1", "L", "1").Replace(s))
}

// FuzzDecodeCode feeds ParseCode arbitrary text. A code it accepts must be
// exactly the normalized input, and must parse again to itself; a refusal
// must be one of its three errors and return the zero Code.
func FuzzDecodeCode(f *testing.F) {
	for _, ap := range []string{fmtTestBootstrap, "[2001:db8::1]:7432", "[fe80::1]:1"} {
		s := testCode(ap).String()
		f.Add(s)
		f.Add(strings.ToLower(s))
		f.Add(strings.ReplaceAll(s, "-", ""))
		f.Add(s[:len(s)-1])
	}
	f.Add("")
	f.Add("-")
	f.Add("0")
	f.Add("OIL-oil-u")
	f.Add(strings.Repeat("Z", 84))
	f.Add(strings.Repeat("0", 300))
	f.Fuzz(func(t *testing.T, s string) {
		c, err := ParseCode(s)
		if err != nil {
			if !errors.Is(err, ErrCodeTypo) && !errors.Is(err, ErrCodeVersion) && !errors.Is(err, ErrCodeInvalid) {
				t.Fatalf("ParseCode error %v is none of ErrCodeTypo, ErrCodeVersion, ErrCodeInvalid", err)
			}
			if c.Bootstrap.IsValid() || c.Secret != ([16]byte{}) || c.AdminFP != ([16]byte{}) || !c.Expires.IsZero() {
				t.Fatalf("ParseCode returned a non-zero Code with an error")
			}
			return
		}
		text := c.String()
		if text == "" {
			t.Fatalf("ParseCode accepted a code that has no text")
		}
		if n := normalize(s); n != text {
			t.Fatalf("ParseCode(%q) accepted a code whose text is %q, not the input normalized (%q)", s, text, n)
		}
		again, err := ParseCode(text)
		if err != nil || !sameCodeFields(c, again) {
			t.Fatalf("the code's own text does not parse to it: %v", err)
		}
	})
}

// FuzzOpenJoinRequest feeds OpenJoinRequest arbitrary bytes, and arbitrary
// plaintexts sealed under the right join key so that the content checks are
// reached past the AEAD. An accepted request must be valid in every field
// and must be exactly the plaintext it came from.
func FuzzOpenJoinRequest(f *testing.F) {
	fx := newFixture(f)
	_, c := fx.open(f)
	good := handRequestPlain(fx.joiner.ID, pubOf(fx.joiner), recvOf(fx.joiner), "ap-garden")
	f.Add(mustRequest(f, c, fx.joiner), good)
	f.Add([]byte{}, []byte{})
	f.Add([]byte{1}, good[:len(good)-9])
	f.Add(bytes.Repeat([]byte{1}, MaxRequestSize), withName(good, strings.Repeat("a", 33)))
	f.Add(bytes.Repeat([]byte{0}, 1310), withName(good, "AP"))
	f.Fuzz(func(t *testing.T, raw, pt []byte) {
		check := func(what string, req JoinRequest, err error) {
			if err != nil {
				if req.ID != (ids.MemberID{}) || req.Name != "" || req.SignPub != nil || req.RecvPub != nil {
					t.Fatalf("%s: a refused request returned fields", what)
				}
				return
			}
			if req.ID == (ids.MemberID{}) || roster.ValidName(req.Name) != nil || sig.ValidPublicKey(req.SignPub) != nil ||
				checkRecvKey(req.RecvPub) != nil || req.accepted || req.adminFP != c.AdminFP {
				t.Fatalf("%s: accepted a request with an invalid field", what)
			}
		}
		req, err := OpenJoinRequest(c, raw)
		check("raw", req, err)
		req, err = OpenJoinRequest(c, handRequest(t, c, pt))
		check("sealed", req, err)
		if err == nil && !bytes.Equal(handRequestPlain(req.ID, req.SignPub, req.RecvPub, req.Name), pt) {
			t.Fatalf("accepted a plaintext that is not the request it returned")
		}
	})
}

func withName(pt []byte, name string) []byte {
	return append(bytes.Clone(pt[:16+32+fmtRecvKeySize]), name...)
}

// FuzzOpenJoinResponse seals arbitrary payloads to the joiner under the
// code's admin key, so that the payload decoder, the binding and the
// anchored roster check all see hostile input past the signature and HPKE.
// An accepted payload must be exactly what handPayload writes for the
// values returned, and the secrets may only reach a sender.
func FuzzOpenJoinResponse(f *testing.F) {
	fx := newFixture(f)
	_, c := fx.open(f)
	binding := handBinding(f, c.Secret)
	_, sender := fx.withJoiner(f, fx.admin, roster.RoleSender)
	_, plain := fx.withJoiner(f, fx.admin)
	f.Add(handPayload(binding, fx.ek, &Secrets{BotToken: canary, ChatID: -5}, sender))
	f.Add(handPayload(binding, fx.ek, nil, plain))
	f.Add(handPayload(binding, fx.ek, &Secrets{BotToken: canary, ChatID: 1}, plain))
	f.Add([]byte{})
	f.Add(binding)
	f.Fuzz(func(t *testing.T, payload []byte) {
		if len(payload) > MaxResponseSize {
			return
		}
		blob := handResponse(t, fx.admin.Sign, pubOf(fx.admin), fx.joiner, payload)
		s, ek, sec, err := OpenJoinResponse(c, blob, fx.joiner)
		if err != nil {
			if sec != nil || ek.Secret != nil || s.Body != nil {
				t.Fatalf("a refused response returned values")
			}
			return
		}
		if !bytes.Equal(handPayload(binding, ek, sec, s), payload) {
			t.Fatalf("accepted a payload that is not the encoding of what it returned")
		}
		r, err := s.Verify(&fx.s1)
		if err != nil {
			// Any version is accepted at join; only the anchor is checked.
			r, err = rosterOf(s)
			if err != nil {
				t.Fatalf("accepted roster does not decode: %v", err)
			}
		}
		for _, m := range r.Members {
			if m.ID == fx.joiner.ID && sec != nil && !hasRole(m.Roles, roster.RoleSender) {
				t.Fatalf("secrets reached a non-sender")
			}
		}
	})
}

func hasRole(roles []roster.Role, want roster.Role) bool {
	for _, r := range roles {
		if r == want {
			return true
		}
	}
	return false
}

// rosterOf decodes a body that the package already accepted.
func rosterOf(s roster.Signed) (roster.Roster, error) { return decodeRoster(s.Body) }
