package pairing

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/identity"
)

var codeShape = regexp.MustCompile(`^[0-9A-HJKMNP-TV-Z]{5}(-[0-9A-HJKMNP-TV-Z]{5})*(-[0-9A-HJKMNP-TV-Z]{1,5})?$`)

func testCode(ap string) Code {
	var fp, secret [16]byte
	for i := range fp {
		fp[i] = byte(0x10 + i)
		secret[i] = byte(0xa0 + i)
	}
	return Code{
		Bootstrap: netip.MustParseAddrPort(ap),
		AdminFP:   fp,
		Secret:    secret,
		Expires:   t0.Add(JoinWindow),
	}
}

func sameCodeFields(a, b Code) bool {
	return a.Bootstrap == b.Bootstrap && a.AdminFP == b.AdminFP && a.Secret == b.Secret &&
		a.Expires.Equal(b.Expires) && b.Expires.Location() == time.UTC
}

func TestConstants(t *testing.T) {
	if JoinWindow != 10*time.Minute {
		t.Errorf("JoinWindow = %v, want 10m", JoinWindow)
	}
	if MaxRequestSize != 1+24+16+32+1216+32+16 {
		t.Errorf("MaxRequestSize = %d, want %d", MaxRequestSize, 1+24+16+32+1216+32+16)
	}
	if MaxResponseSize != 64512 {
		t.Errorf("MaxResponseSize = %d, want 64512 (1 KiB below the 64 KiB frame)", MaxResponseSize)
	}
	if MaxTokenLen != 128 {
		t.Errorf("MaxTokenLen = %d, want 128", MaxTokenLen)
	}
}

func TestCodeRoundTrip(t *testing.T) {
	for _, ap := range []string{fmtTestBootstrap, "10.0.0.254:1", "[2001:db8::1]:7432", "[fe80::1]:65535", "[fd00:1:2::3]:7432"} {
		c := testCode(ap)
		s := c.String()
		if !codeShape.MatchString(s) {
			t.Errorf("%s: %q is not Crockford base32 in groups of five", ap, s)
		}
		got, err := ParseCode(s)
		if err != nil {
			t.Errorf("%s: ParseCode(String()): %v", ap, err)
			continue
		}
		if !sameCodeFields(c, got) {
			t.Errorf("%s: round trip = %+v, want the same fields as %+v", ap, got.Bootstrap, c.Bootstrap)
		}
		if again := got.String(); again != s {
			t.Errorf("%s: String after ParseCode = %q, want %q", ap, again, s)
		}

		// The reader is forgiving about how the code was copied.
		noDash := strings.ReplaceAll(s, "-", "")
		variants := map[string]string{
			"lower case":         strings.ToLower(s),
			"no dashes":          noDash,
			"dashes moved":       group(noDash[:3]) + "-" + group(noDash[3:]),
			"white space around": " \t" + s + "\r\n",
			"O for 0, I/L for 1": strings.NewReplacer("0", "O", "1", "l").Replace(s),
			"o and i lower case": strings.NewReplacer("0", "o", "1", "i").Replace(strings.ToLower(s)),
		}
		for name, v := range variants {
			got, err := ParseCode(v)
			if err != nil || !sameCodeFields(c, got) {
				t.Errorf("%s, %s: ParseCode = %+v, %v; want the code back", ap, name, got.Bootstrap, err)
			}
		}
	}

	// The expiry travels in whole seconds.
	c := testCode(fmtTestBootstrap)
	c.Expires = t0.Add(700 * time.Millisecond).In(time.FixedZone("x", 3600))
	got, err := ParseCode(c.String())
	if err != nil || !got.Expires.Equal(t0) || got.Expires.Location() != time.UTC {
		t.Errorf("fractional expiry: got %v, %v; want %v UTC", got.Expires, err, t0)
	}
}

// TestCodeFormat pins the layout: the string is the brief's payload, its
// checksum, and encoding/base32 under the Crockford alphabet.
func TestCodeFormat(t *testing.T) {
	for _, ap := range []string{fmtTestBootstrap, "[2001:db8::1]:7432"} {
		c := testCode(ap)
		body := handCodeBody(1, c.Bootstrap, c.AdminFP, c.Secret, c.Expires.Unix())
		want := handCodeText(body)
		if got := c.String(); got != want {
			t.Errorf("%s: String = %q, want %q", ap, got, want)
		}
	}
	if n := len(strings.ReplaceAll(testCode(fmtTestBootstrap).String(), "-", "")); n != 84 {
		t.Errorf("an IPv4 code has %d symbols, want 84 (52 bytes)", n)
	}
}

func TestCodeTypo(t *testing.T) {
	c := testCode(fmtTestBootstrap)
	s := strings.ReplaceAll(c.String(), "-", "")
	tried := 0
	for i := 0; i < len(s); i++ {
		for _, r := range fmtCrockford {
			if byte(r) == s[i] {
				continue
			}
			typo := s[:i] + string(r) + s[i+1:]
			tried++
			if _, err := ParseCode(typo); !errors.Is(err, ErrCodeTypo) {
				t.Fatalf("symbol %d changed to %c: err = %v, want ErrCodeTypo", i, r, err)
			}
		}
		if i+1 < len(s) && s[i] != s[i+1] {
			swapped := s[:i] + string(s[i+1]) + string(s[i]) + s[i+2:]
			tried++
			if _, err := ParseCode(swapped); !errors.Is(err, ErrCodeTypo) {
				t.Fatalf("symbols %d and %d swapped: err = %v, want ErrCodeTypo", i, i+1, err)
			}
		}
		tried++
		if _, err := ParseCode(s[:i] + s[i+1:]); !errors.Is(err, ErrCodeTypo) {
			t.Fatalf("symbol %d left out: err = %v, want ErrCodeTypo", i, err)
		}
	}
	t.Logf("%d single typos, all reported as typos", tried)

	for name, bad := range map[string]string{
		"empty":            "",
		"only dashes":      "-----",
		"U is not a digit": s[:10] + "U" + s[11:],
		"punctuation":      s[:10] + "*" + s[11:],
		"space inside":     s[:10] + " " + s[10:],
		"a symbol added":   s + "0",
		"far too long":     strings.Repeat(s, 4),
		"not a code":       "hello world",
		"non-ASCII":        s[:10] + "Ø" + s[11:],
	} {
		if _, err := ParseCode(bad); !errors.Is(err, ErrCodeTypo) {
			t.Errorf("%s: err = %v, want ErrCodeTypo", name, err)
		}
	}

	// Trailing bits that carry no data must be zero: one symbol, one string.
	last := strings.IndexByte(fmtCrockford, s[len(s)-1])
	for v := 0; v < 32; v++ {
		if v == last || v>>4 != last>>4 {
			continue // same symbol, or a change in the one data bit (a checksum typo)
		}
		alt := s[:len(s)-1] + string(fmtCrockford[v])
		if _, err := ParseCode(alt); !errors.Is(err, ErrCodeTypo) {
			t.Errorf("non-zero padding bits %05b: err = %v, want ErrCodeTypo", v, err)
		}
	}
}

// TestParseCodeLengthCap pins the cap on the text ParseCode reads: dashes
// may pad a code to maxCodeText bytes, one more is refused, and a refused
// oversized text costs no allocation.
func TestParseCodeLengthCap(t *testing.T) {
	c := testCode(fmtTestBootstrap)
	s := c.String()
	padded := strings.Repeat("-", maxCodeText-len(s)) + s
	if got, err := ParseCode(padded); err != nil || !sameCodeFields(c, got) {
		t.Errorf("code padded to %d bytes: %v", maxCodeText, err)
	}
	if _, err := ParseCode("-" + padded); !errors.Is(err, ErrCodeTypo) {
		t.Errorf("code padded to %d bytes: err = %v, want ErrCodeTypo", maxCodeText+1, err)
	}
	huge := strings.Repeat("0", 1<<20)
	if n := testing.AllocsPerRun(5, func() { ParseCode(huge) }); n != 0 {
		t.Errorf("a 1 MiB text costs %v allocations before it is refused, want 0", n)
	}
}

func TestCodeVersion(t *testing.T) {
	c := testCode(fmtTestBootstrap)
	for _, v := range []byte{0, 2, 255} {
		s := handCodeText(handCodeBody(v, c.Bootstrap, c.AdminFP, c.Secret, c.Expires.Unix()))
		if _, err := ParseCode(s); !errors.Is(err, ErrCodeVersion) {
			t.Errorf("version %d: err = %v, want ErrCodeVersion", v, err)
		}
	}
}

func TestCodeInvalidFields(t *testing.T) {
	good := testCode(fmtTestBootstrap)
	body := func(edit func(c *Code)) []byte {
		c := good
		edit(&c)
		return handCodeBody(1, c.Bootstrap, c.AdminFP, c.Secret, c.Expires.Unix())
	}
	cases := map[string][]byte{
		"zero secret":      body(func(c *Code) { c.Secret = [16]byte{} }),
		"zero fingerprint": body(func(c *Code) { c.AdminFP = [16]byte{} }),
		"port 0":           body(func(c *Code) { c.Bootstrap = netip.MustParseAddrPort("192.168.1.1:0") }),
		"IPv4 unspecified": body(func(c *Code) { c.Bootstrap = netip.MustParseAddrPort("0.0.0.0:7432") }),
		"IPv6 unspecified": body(func(c *Code) { c.Bootstrap = netip.MustParseAddrPort("[::]:7432") }),
		"IPv4 multicast":   body(func(c *Code) { c.Bootstrap = netip.MustParseAddrPort("224.0.0.1:7432") }),
		"IPv6 multicast":   body(func(c *Code) { c.Bootstrap = netip.MustParseAddrPort("[ff02::114]:7432") }),
		"IPv4 in IPv6":     body(func(c *Code) { c.Bootstrap = netip.MustParseAddrPort("[::ffff:192.168.1.1]:7432") }),
		"expires 0":        handCodeBody(1, good.Bootstrap, good.AdminFP, good.Secret, 0),
		"expires negative": handCodeBody(1, good.Bootstrap, good.AdminFP, good.Secret, -1),
		"expires past 9999": handCodeBody(1, good.Bootstrap, good.AdminFP, good.Secret,
			fmtMaxNotAfter+1),
	}
	// An unknown address family, and lengths that do not match the family.
	v4 := body(func(*Code) {})
	fam5 := bytes.Clone(v4)
	fam5[1] = 5
	cases["family 5"] = fam5
	fam6short := bytes.Clone(v4)
	fam6short[1] = 6
	cases["family 6 with 4 address bytes"] = fam6short
	cases["one byte short"] = v4[:len(v4)-1]
	cases["one byte over"] = append(bytes.Clone(v4), 0)
	v6 := handCodeBody(1, netip.MustParseAddrPort("[2001:db8::1]:7432"), good.AdminFP, good.Secret, good.Expires.Unix())
	cases["IPv6 one byte short"] = v6[:len(v6)-1]
	cases["IPv6 one byte over"] = append(bytes.Clone(v6), 0)
	cases["version only"] = v4[:1]

	for name, b := range cases {
		if _, err := ParseCode(handCodeText(b)); !errors.Is(err, ErrCodeInvalid) {
			t.Errorf("%s: err = %v, want ErrCodeInvalid", name, err)
		}
	}
	// The largest expiry is still valid.
	if _, err := ParseCode(handCodeText(handCodeBody(1, good.Bootstrap, good.AdminFP, good.Secret, fmtMaxNotAfter))); err != nil {
		t.Errorf("expiry 9999-12-31T23:59:59Z: %v", err)
	}

	// A Code that ParseCode would refuse has no text at all.
	for name, edit := range map[string]func(c *Code){
		"zero code":   func(c *Code) { *c = Code{} },
		"zero secret": func(c *Code) { c.Secret = [16]byte{} },
		"zone":        func(c *Code) { c.Bootstrap = netip.MustParseAddrPort("[fe80::1%br-lan]:7432") },
		"4in6":        func(c *Code) { c.Bootstrap = netip.MustParseAddrPort("[::ffff:192.168.1.1]:7432") },
		"no expiry":   func(c *Code) { c.Expires = time.Time{} },
	} {
		c := good
		edit(&c)
		if s := c.String(); s != "" {
			t.Errorf("String of an invalid code (%s) = %q, want empty", name, s)
		}
	}
}

func TestAdminFingerprint(t *testing.T) {
	f := newFixture(t)
	pub := pubOf(f.admin)
	if got, want := AdminFingerprint(pub), handFP(pub); got != want {
		t.Errorf("AdminFingerprint = %x, want first 16 bytes of SHA-256(label || key) %x", got, want)
	}
	plain := sha256.Sum256(pub)
	if got := AdminFingerprint(pub); bytes.Equal(got[:], plain[:16]) {
		t.Errorf("AdminFingerprint has no domain label")
	}
	if AdminFingerprint(pub) == AdminFingerprint(pubOf(f.backup)) {
		t.Errorf("two keys share a fingerprint")
	}
}

func TestInviterOpen(t *testing.T) {
	f := newFixture(t)
	inv := &Inviter{}
	ap := netip.MustParseAddrPort(fmtTestBootstrap)
	now := t0.Add(400 * time.Millisecond)
	c, err := inv.Open(now, ap, f.admin)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if c.Bootstrap != ap {
		t.Errorf("Bootstrap = %v, want %v", c.Bootstrap, ap)
	}
	if c.AdminFP != handFP(pubOf(f.admin)) {
		t.Errorf("AdminFP is not the admin's fingerprint")
	}
	if want := t0.Add(JoinWindow); !c.Expires.Equal(want) || c.Expires.Location() != time.UTC {
		t.Errorf("Expires = %v, want %v UTC (now + 10 min, whole seconds)", c.Expires, want)
	}
	if c.Secret == [16]byte{} {
		t.Errorf("Secret is zero")
	}
	if _, err := ParseCode(c.String()); err != nil {
		t.Errorf("the code Open made does not parse: %v", err)
	}
	c2, err := inv.Open(now, ap, f.admin)
	if err != nil || c2.Secret == c.Secret {
		t.Errorf("a second Open reused the secret (err %v)", err)
	}

	// IPv4 in IPv6 is shown as IPv4.
	c3, err := inv.Open(now, netip.MustParseAddrPort("[::ffff:192.168.1.1]:7432"), f.admin)
	if err != nil || c3.Bootstrap != ap {
		t.Errorf("4in6 bootstrap: %v, %v; want %v", c3.Bootstrap, err, ap)
	}

	for name, bad := range map[string]netip.AddrPort{
		"zero":        {},
		"port 0":      netip.MustParseAddrPort("192.168.1.1:0"),
		"unspecified": netip.MustParseAddrPort("0.0.0.0:7432"),
		"multicast":   netip.MustParseAddrPort("[ff02::114]:7432"),
		"zone":        netip.MustParseAddrPort("[fe80::1%br-lan]:7432"),
		"4in6 zone":   netip.MustParseAddrPort("[::ffff:192.168.1.1%br-lan]:7432"),
	} {
		if _, err := inv.Open(now, bad, f.admin); !errors.Is(err, ErrBootstrap) {
			t.Errorf("bootstrap %s: err = %v, want ErrBootstrap", name, err)
		}
	}

	badSign := *f.admin
	badSign.Sign = bytes.Clone(f.admin.Sign)
	badSign.Sign[40] ^= 1 // public half no longer matches the seed
	zeroID := *f.admin
	zeroID.ID = [16]byte{}
	short := *f.admin
	short.Sign = f.admin.Sign[:32]
	for name, admin := range map[string]*identity.Identity{
		"nil admin":          nil,
		"zero member ID":     &zeroID,
		"short signing key":  &short,
		"inconsistent key":   &badSign,
		"small-order public": smallOrderAdmin(f.admin),
	} {
		if _, err := inv.Open(now, ap, admin); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
	}
	for name, at := range map[string]time.Time{
		"zero time": {},
		"year 9999": time.Date(9999, 12, 31, 23, 55, 0, 0, time.UTC),
	} {
		if _, err := inv.Open(at, ap, f.admin); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
	}
}

// smallOrderAdmin returns a copy of id whose signing key's public half is a
// small-order point.
func smallOrderAdmin(id *identity.Identity) *identity.Identity {
	c := *id
	c.Sign = bytes.Clone(id.Sign)
	copy(c.Sign[ed25519.SeedSize:], make([]byte, 32)) // y = 0
	return &c
}

func TestCodeExpired(t *testing.T) {
	f := newFixture(t)
	opened := t0.Add(400 * time.Millisecond) // the code shows t0 + 10 min; the window ends 400 ms later
	open := func() (*Inviter, Code) {
		inv := &Inviter{}
		c, err := inv.Open(opened, netip.MustParseAddrPort(fmtTestBootstrap), f.admin)
		if err != nil {
			t.Fatal(err)
		}
		return inv, c
	}

	for name, d := range map[string]time.Duration{
		"at once":         0,
		"after 5 minutes": 5 * time.Minute,
		"1 ns before end": JoinWindow - 1,
		"past shown time": JoinWindow - time.Millisecond, // after c.Expires, inside the window
	} {
		inv, c := open()
		if err := inv.Consume(c, opened.Add(d)); err != nil {
			t.Errorf("Consume %s: %v", name, err)
		}
	}
	for name, d := range map[string]time.Duration{
		"exactly at the end": JoinWindow,
		"1 ns after":         JoinWindow + 1,
		"an hour later":      time.Hour,
		"a year later":       365 * 24 * time.Hour,
		"clock stepped back": -time.Second,
	} {
		inv, c := open()
		if err := inv.Consume(c, opened.Add(d)); !errors.Is(err, ErrCodeExpired) {
			t.Errorf("Consume %s: err = %v, want ErrCodeExpired", name, err)
		}
		// An expired code is closed for good, even if the clock comes back.
		if err := inv.Consume(c, opened.Add(time.Minute)); !errors.Is(err, ErrCodeClosed) {
			t.Errorf("Consume after expiry (%s), clock back in the window: err = %v, want ErrCodeClosed", name, err)
		}
	}

	// Accept refuses a valid request once the window is over.
	inv, c := open()
	blob, err := NewJoinRequest(c, f.joiner, "ap-garden")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inv.Accept(blob, opened.Add(JoinWindow)); !errors.Is(err, ErrCodeExpired) {
		t.Errorf("Accept at the end of the window: err = %v, want ErrCodeExpired", err)
	}
	if _, err := inv.Accept(blob, opened.Add(time.Minute)); !errors.Is(err, ErrCodeClosed) {
		t.Errorf("Accept after expiry: err = %v, want ErrCodeClosed", err)
	}

	// A monotonic clock reading measures the window when the caller has one.
	inv, c = &Inviter{}, Code{}
	now := time.Now()
	if c, err = inv.Open(now, netip.MustParseAddrPort(fmtTestBootstrap), f.admin); err != nil {
		t.Fatal(err)
	}
	if err := inv.Consume(c, now.Add(JoinWindow)); !errors.Is(err, ErrCodeExpired) {
		t.Errorf("monotonic: Consume at the end: err = %v, want ErrCodeExpired", err)
	}
}

func TestSecretBurned(t *testing.T) {
	f := newFixture(t)
	inv, c := f.open(t)
	blob, err := NewJoinRequest(c, f.joiner, "ap-garden")
	if err != nil {
		t.Fatal(err)
	}
	req, err := inv.Accept(blob, t0.Add(time.Minute))
	if err != nil {
		t.Fatalf("first Accept: %v", err)
	}
	if req.ID != f.joiner.ID || req.Name != "ap-garden" {
		t.Errorf("Accept returned member %v named %q", req.ID, req.Name)
	}
	if _, err := inv.Accept(blob, t0.Add(2*time.Minute)); !errors.Is(err, ErrCodeClosed) {
		t.Errorf("the same request again: err = %v, want ErrCodeClosed", err)
	}
	other, err := NewJoinRequest(c, f.stranger, "evil")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inv.Accept(other, t0.Add(2*time.Minute)); !errors.Is(err, ErrCodeClosed) {
		t.Errorf("a second router with the same code: err = %v, want ErrCodeClosed", err)
	}
	if err := inv.Consume(c, t0.Add(2*time.Minute)); !errors.Is(err, ErrCodeClosed) {
		t.Errorf("Consume after Accept: err = %v, want ErrCodeClosed", err)
	}

	// Consume burns the code as well.
	inv, c = f.open(t)
	if err := inv.Consume(c, t0.Add(time.Minute)); err != nil {
		t.Fatalf("first Consume: %v", err)
	}
	if err := inv.Consume(c, t0.Add(time.Minute)); !errors.Is(err, ErrCodeClosed) {
		t.Errorf("second Consume: err = %v, want ErrCodeClosed", err)
	}
	if _, err := inv.Accept(blob, t0.Add(time.Minute)); !errors.Is(err, ErrCodeClosed) {
		t.Errorf("Accept after Consume: err = %v, want ErrCodeClosed", err)
	}

	// An Inviter that never opened a code refuses everything.
	var none Inviter
	if err := none.Consume(c, t0); !errors.Is(err, ErrCodeClosed) {
		t.Errorf("Consume on a fresh Inviter: err = %v, want ErrCodeClosed", err)
	}
	if _, err := none.Accept(blob, t0); !errors.Is(err, ErrCodeClosed) {
		t.Errorf("Accept on a fresh Inviter: err = %v, want ErrCodeClosed", err)
	}
}

func TestInviterOneCodeAtATime(t *testing.T) {
	f := newFixture(t)
	inv, first := f.open(t)
	second, err := inv.Open(t0.Add(time.Minute), netip.MustParseAddrPort(fmtTestBootstrap), f.admin)
	if err != nil {
		t.Fatal(err)
	}
	if err := inv.Consume(first, t0.Add(2*time.Minute)); !errors.Is(err, ErrCodeClosed) {
		t.Errorf("the replaced code: err = %v, want ErrCodeClosed", err)
	}
	blob, err := NewJoinRequest(first, f.joiner, "ap-garden")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inv.Accept(blob, t0.Add(2*time.Minute)); !errors.Is(err, ErrRequestAuth) {
		t.Errorf("a request made with the replaced code: err = %v, want ErrRequestAuth", err)
	}
	if err := inv.Consume(second, t0.Add(2*time.Minute)); err != nil {
		t.Errorf("the open code: %v", err)
	}
}

func TestInviterConsumeWrongCode(t *testing.T) {
	f := newFixture(t)
	inv, c := f.open(t)
	for name, edit := range map[string]func(c *Code){
		"another secret":      func(c *Code) { c.Secret[15] ^= 1 },
		"another fingerprint": func(c *Code) { c.AdminFP[0] ^= 1 },
		"another expiry":      func(c *Code) { c.Expires = c.Expires.Add(time.Second) },
		"another address":     func(c *Code) { c.Bootstrap = netip.MustParseAddrPort("192.168.1.2:7432") },
		"another port":        func(c *Code) { c.Bootstrap = netip.MustParseAddrPort("192.168.1.1:7433") },
		"zero code":           func(c *Code) { *c = Code{} },
	} {
		w := c
		edit(&w)
		if err := inv.Consume(w, t0.Add(time.Minute)); !errors.Is(err, ErrCodeClosed) {
			t.Errorf("%s: err = %v, want ErrCodeClosed", name, err)
		}
	}
	if err := inv.Consume(c, t0.Add(time.Minute)); err != nil {
		t.Errorf("the right code after wrong ones: %v", err)
	}
}

func TestInviterFailedRequestKeepsCode(t *testing.T) {
	f := newFixture(t)
	inv, c := f.open(t)
	stranger := testCode(fmtTestBootstrap)
	forged, err := NewJoinRequest(stranger, f.stranger, "evil")
	if err != nil {
		t.Fatal(err)
	}
	for name, blob := range map[string][]byte{
		"empty":                  nil,
		"garbage":                bytes.Repeat([]byte{1}, 1320),
		"made with another code": forged,
	} {
		if _, err := inv.Accept(blob, t0.Add(time.Minute)); err == nil || errors.Is(err, ErrCodeClosed) {
			t.Errorf("%s: err = %v, want a refusal that leaves the code open", name, err)
		}
	}
	f.accepted(t, inv, c)
}

func TestInviterConcurrentAccept(t *testing.T) {
	f := newFixture(t)
	inv, c := f.open(t)
	const n = 8
	blobs := make([][]byte, n)
	for i := range blobs {
		b, err := NewJoinRequest(c, f.joiner, "ap-garden")
		if err != nil {
			t.Fatal(err)
		}
		blobs[i] = b
	}
	var (
		wg sync.WaitGroup
		mu sync.Mutex
		ok int
	)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := inv.Accept(blobs[i], t0.Add(time.Minute)); err == nil {
				mu.Lock()
				ok++
				mu.Unlock()
			} else if !errors.Is(err, ErrCodeClosed) {
				t.Errorf("Accept: %v", err)
			}
		}()
	}
	wg.Wait()
	if ok != 1 {
		t.Errorf("%d of %d concurrent requests accepted with one code, want exactly 1", ok, n)
	}
}

func TestFormatRedacts(t *testing.T) {
	f := newFixture(t)
	used, c0 := f.open(t)
	req := f.accepted(t, used, c0)
	inv, c := f.open(t) // still open while it is printed
	sec := Secrets{BotToken: canary, ChatID: 123456789}
	secrets := map[string][]byte{
		"join code":   []byte(c.String()),
		"join secret": c.Secret[:],
		"used secret": c0.Secret[:],
		"binding":     req.binding[:],
		"bot token":   []byte(canary),
	}
	for _, v := range []any{c, &c, sec, &sec, req, &req, inv} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%x", "%X", "%q", "%d"} {
			out := fmt.Sprintf(verb, v)
			if what, bad := leaks(out, secrets); bad {
				t.Errorf("fmt %s of %T prints the %s: %s", verb, v, what, out)
			}
		}
	}
	if got := fmt.Sprint(sec); strings.Contains(got, "123456789") {
		t.Errorf("Secrets print the chat ID: %s", got)
	}
}
