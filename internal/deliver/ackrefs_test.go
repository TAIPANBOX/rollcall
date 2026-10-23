package deliver

import (
	"slices"
	"strings"
	"testing"

	"github.com/TAIPANBOX/rollcall/internal/history"
	"github.com/TAIPANBOX/rollcall/internal/ids"
)

// TestAckRefsRoundTrip (Q4): an acknowledgement names the events the
// message told, sorted and once each; AckOf reads its ID and AckRefs its
// events, and one without events stays the short form.
func TestAckRefsRoundTrip(t *testing.T) {
	h1, h2 := ids.Hash{2}, ids.Hash{1}
	body, err := AckBodyRefs("0123456789abcdef", []ids.Hash{h1, h2, h1})
	if err != nil {
		t.Fatal(err)
	}
	e := history.Entry{Origin: a, Kind: history.KindEvent, Body: body}
	if id, by, ok := AckOf(e); !ok || id != "0123456789abcdef" || by != a {
		t.Fatalf("AckOf(%s) = %q, %v, %v", body, id, by, ok)
	}
	if got := AckRefs(e); !slices.Equal(got, []ids.Hash{h2, h1}) {
		t.Fatalf("AckRefs = %v, want the two events in order", got)
	}
	short, err := AckBodyRefs("0123456789abcdef", nil)
	if want, _ := AckBody("0123456789abcdef"); err != nil || string(short) != string(want) {
		t.Fatalf("AckBodyRefs without events = %s, %v; want %s", short, err, want)
	}
	if AckRefs(history.Entry{Origin: a, Kind: history.KindEvent, Body: short}) != nil {
		t.Fatal("AckRefs of the short form is not nil")
	}
	if AckRefs(history.Entry{Origin: a, Kind: history.KindWitness, Body: body}) != nil {
		t.Fatal("AckRefs of an entry that is not an event is not nil")
	}
	many := make([]ids.Hash, MaxAckRefs+1)
	for i := range many {
		many[i] = ids.Hash{byte(i + 1)}
	}
	if _, err := AckBodyRefs("0123456789abcdef", many); err == nil {
		t.Fatalf("AckBodyRefs accepted %d events", len(many))
	}
}

// TestAckRefsOnlyCanonical (Q4): any other form of an acknowledgement that
// names events is not one.
func TestAckRefsOnlyCanonical(t *testing.T) {
	h := func(b byte) string { return ids.Hash{b}.String() }
	for _, body := range []string{
		`{"ack":"0123456789abcdef","refs":[]}`,
		`{"ack":"0123456789abcdef","refs":["` + h(2) + `","` + h(1) + `"]}`,
		`{"ack":"0123456789abcdef","refs":["` + h(1) + `","` + h(1) + `"]}`,
		`{"ack":"0123456789abcdef","refs":["` + strings.ToUpper(h(0xab)) + `"]}`,
		`{"ack":"0123456789abcdef", "refs":["` + h(1) + `"]}`,
		`{"ack":"0123456789abcdef","refs":["` + h(1) + `"],"x":1}`,
		`{"refs":["` + h(1) + `"],"ack":"0123456789abcdef"}`,
		`{"ack":"0123456789ABCDEF","refs":["` + h(1) + `"]}`,
	} {
		if id, _, ok := AckOf(history.Entry{Origin: a, Kind: history.KindEvent, Body: []byte(body)}); ok {
			t.Errorf("AckOf(%s) = %q, true", body, id)
		}
	}
}
