package node

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/clock"
	"github.com/TAIPANBOX/rollcall/internal/deliver"
	"github.com/TAIPANBOX/rollcall/internal/events"
	"github.com/TAIPANBOX/rollcall/internal/history"
	"github.com/TAIPANBOX/rollcall/internal/ids"
)

// dnsBlip has n record a DNS loss dated 20 s back, and its return gap
// later.
func dnsBlip(g *group, n *Node, gap time.Duration) {
	n.LocalEvent(events.Event{Type: dnsLost, At: with(n, func() clock.Stamp {
		st := n.localStamp(n.stamp())
		st.Wall, st.Mono = st.Wall.Add(-20*sec), st.Mono-20*sec
		return st
	})})
	g.run(gap)
	n.LocalEvent(events.Event{Type: dnsRestored})
}

// olderIncidents returns, for n's own DNS events, the IDs of the incidents
// a router of an older version makes of them: one per event, a fact of its
// own, whose ID the event alone fixes; and the entries.
func olderIncidents(t *testing.T, n *Node) ([]string, []history.Entry) {
	t.Helper()
	var out []string
	var es []history.Entry
	for _, typ := range []events.Type{dnsLost, dnsRestored} {
		e := eventOfType(t, n, typ, n.id.ID)
		b, err := DecodeEvent(e)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, events.Coalesce([]events.Event{eventOf(e, b)}, events.DefaultWindow)[0].ID)
		es = append(es, e)
	}
	return out, es
}

// ackedBy returns the incident IDs n's own chain acknowledges.
func ackedBy(n *Node) []string {
	var out []string
	for _, e := range ownEntries(n, history.KindEvent) {
		if id, _, ok := deliver.AckOf(e); ok {
			out = append(out, id)
		}
	}
	return out
}

// TestOlderMemberDNSIncidentsAcknowledged: a router of an older version
// knows no DNS event and tells each one as a fact of its own ("event
// dns_lost at 09:01"), under the ID that event alone gives. A newer router
// tells a DNS loss and its return as one incident, under another ID: one
// chain when they lie within 30 s, a start merged with its end when they lie
// further apart. It acknowledges the older router's IDs too, so that router
// keeps nothing to send later. And when an older sender told the events one
// by one, the newer router counts its own incident told and sends nothing.
func TestOlderMemberDNSIncidentsAcknowledged(t *testing.T) {
	for _, c := range []struct {
		gap  time.Duration
		want string
	}{{5 * sec, "(25 s)"}, {15 * sec, "(35 s)"}} {
		t.Run("a newer sender told it "+c.want, func(t *testing.T) {
			g := newGroup(t, setup{n: 3, senders: map[int]int{0: 1}})
			g.run(90 * sec)
			a := g.nodes[0]
			dnsBlip(g, a, c.gap)
			g.run(2 * time.Minute)
			msgs := g.chat.all()
			t.Logf("chat:\n  %s", strings.Join(msgs, "\n  "))
			if len(msgs) != 1 || !strings.Contains(msgs[0], "DNS was down from 09:01 to 09:01 "+c.want) {
				t.Fatalf("chat %q; want the DNS loss and its return in one message", msgs)
			}
			older, _ := olderIncidents(t, a)
			acked := ackedBy(a)
			for _, id := range older {
				if !slices.Contains(acked, id) {
					t.Fatalf("r01 acknowledged %q, not %s, the incident an older router made of one DNS event", acked, id)
				}
			}
		})
	}
	t.Run("an older sender told it", func(t *testing.T) {
		g := newGroup(t, setup{n: 3, running: []bool{true, false, true}, senders: map[int]int{0: 1, 1: 2}})
		g.run(90 * sec)
		g.chat.setDown(true)
		a, c := g.nodes[0], g.nodes[2]
		dnsBlip(g, c, 5*sec)
		g.run(40 * sec)
		if st := a.Status(); st.Queued != 1 {
			t.Fatalf("r01 queues %d incidents, want its one of r03's DNS blip: the case did not happen", st.Queued)
		}
		// r02, a sender of an older version, told each event alone and
		// acknowledged what it told, as it does.
		older, es := olderIncidents(t, c)
		var acks []history.Entry
		head := history.Head{}
		for i, id := range older {
			body, err := deliver.AckBodyRefs(id, []ids.Hash{es[i].Hash()})
			if err != nil {
				t.Fatal(err)
			}
			e, err := history.NewEntry(g.ids[1], head, history.KindEvent, body)
			if err != nil {
				t.Fatal(err)
			}
			acks, head = append(acks, e), history.Head{Seq: e.Seq, Hash: e.Hash()}
		}
		inject(a, acks...)
		inject(c, acks...)
		g.chat.setDown(false)
		g.run(time.Minute)
		if msgs := g.chat.messages("DNS"); len(msgs) != 0 {
			t.Fatalf("r01 told the DNS blip again after an older sender had: %q", msgs)
		}
		for i, n := range []*Node{a, c} {
			if st := n.Status(); st.Queued != 0 {
				t.Fatalf("router %d still queues %d incidents", i, st.Queued)
			}
		}
	})
}

// TestOlderSenderToldTheOutageInPieces replays lab cell R1.4 while the
// sender is a router of an older version: its window is 10 s, so it told
// beryl2's outage in six messages, each acknowledged with the events it
// told (its start, its internet loss, three short WAN drops, the internet's
// return). The newer routers, whose chat was out meanwhile, made of the same
// events one incident, under another ID. Every event of it was named by one
// of those messages, so they count it told and keep nothing to send when they
// take over: whether the acknowledgements came after the newer incident was
// made, or, as an older sender's shorter window makes likely, before it.
func TestOlderSenderToldTheOutageInPieces(t *testing.T) {
	for _, early := range []bool{false, true} {
		t.Run(map[bool]string{false: "acks after the incident", true: "acks before the incident"}[early], func(t *testing.T) {
			g := newGroup(t, setup{n: 3, running: []bool{true, false, true}, senders: map[int]int{0: 1, 1: 2}})
			g.run(90 * sec)
			g.chat.setDown(true)
			D, U, L, R := events.WanDown, events.WanUp, events.InternetLost, events.InternetRestored
			c := g.nodes[2]
			now := 0
			for _, s := range []cellStep{{0, 0, 2, D}, {22, 20, 2, L}, {61, 0, 2, D}, {63, 0, 2, U}, {72, 0, 2, D},
				{74, 0, 2, U}, {83, 0, 2, D}, {85, 0, 2, U}, {109, 0, 2, R}} {
				g.run(time.Duration(s.at-now) * sec)
				now = s.at
				e := events.Event{Type: s.typ}
				if s.ago > 0 {
					ago := time.Duration(s.ago) * sec
					e.At = with(c, func() clock.Stamp {
						st := c.localStamp(c.stamp())
						st.Wall, st.Mono = st.Wall.Add(-ago), st.Mono-ago
						return st
					})
				}
				c.LocalEvent(e)
			}
			if !early {
				g.run(2 * time.Minute)
				// The chat was out: the start was merged into the end, one
				// message.
				if st := g.nodes[0].Status(); st.Queued != 1 {
					t.Fatalf("r01 queues %d incidents, want the outage in one: the case did not happen", st.Queued)
				}
			}
			var refs []ids.Hash
			for _, e := range ownEntries(c, history.KindEvent) {
				if b, err := DecodeEvent(e); err == nil && linkChange(b.Type) {
					refs = append(refs, e.Hash())
				}
			}
			if len(refs) != 9 {
				t.Fatalf("r03 recorded %d link changes, want 9", len(refs))
			}
			// The older sender's six messages, as a987992 makes them of these
			// records: the WAN loss; the internet loss; three WAN drops; the
			// internet's loss and return merged.
			pieces := [][]ids.Hash{refs[:1], refs[1:2], refs[2:4], refs[4:6], refs[6:8], {refs[1], refs[8]}}
			head := history.Head{}
			var acks []history.Entry
			for i, told := range pieces {
				body, err := deliver.AckBodyRefs(fmt.Sprintf("%016x", 0xa0+i), told)
				if err != nil {
					t.Fatal(err)
				}
				e, err := history.NewEntry(g.ids[1], head, history.KindEvent, body)
				if err != nil {
					t.Fatal(err)
				}
				acks, head = append(acks, e), history.Head{Seq: e.Seq, Hash: e.Hash()}
			}
			inject(g.nodes[0], acks...)
			inject(c, acks...)
			if early {
				g.run(2 * time.Minute) // the end is made now, after the acks
			}
			g.chat.setDown(false)
			g.run(time.Minute)
			// r02 runs no node here, so the newer routers tell its silence;
			// nothing else.
			for _, m := range g.chat.all() {
				if strings.Contains(m, "WAN") || strings.Contains(m, "internet") {
					t.Fatalf("the newer routers told the outage again after the older sender had: %q", m)
				}
			}
			for i, n := range []*Node{g.nodes[0], c} {
				if st := n.Status(); st.Queued != 0 {
					t.Fatalf("router %d still queues %d incidents", i, st.Queued)
				}
			}
		})
	}
}

// TestNamedFollowsTheKeptNotes: the events kept acknowledgements name are
// counted per note, and an event no kept note names any longer is
// forgotten, so the count stays bounded by keepAckNotes.
func TestNamedFollowsTheKeptNotes(t *testing.T) {
	var c incidents
	c.init()
	a, b := ids.Hash{1}, ids.Hash{2}
	c.name([]ids.Hash{a, b}, 1)
	c.name([]ids.Hash{a}, 1)
	c.name([]ids.Hash{a, b}, -1)
	if c.named[a] != 1 || c.named[b] != 0 || len(c.named) != 1 {
		t.Fatalf("named %v; want a once, b forgotten", c.named)
	}
	c.name([]ids.Hash{a}, -1)
	if len(c.named) != 0 {
		t.Fatalf("named %v after every note left", c.named)
	}
}
