package node

import (
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/deliver"
	"github.com/TAIPANBOX/rollcall/internal/events"
	"github.com/TAIPANBOX/rollcall/internal/history"
)

// TestTwoSendersRegainTelegramOnce (D2): both senders reach Telegram again
// in the same second after an outage. Each waits until its peers have heard
// that it can send again before it sends, so the one the shared view names
// sends the incident held during the outage, once.
func TestTwoSendersRegainTelegramOnce(t *testing.T) {
	g := newGroup(t, setup{n: 3, senders: map[int]int{0: 2, 1: 1}})
	g.run(40 * sec)
	g.chat.setDown(true)
	g.stop(2)
	g.run(2 * time.Minute)
	g.chat.setDown(false)
	g.run(2 * time.Minute)
	t.Logf("chat:\n%s", strings.Join(g.chat.all(), "\n"))
	g.chat.mu.Lock()
	defer g.chat.mu.Unlock()
	var by []string
	for _, m := range g.chat.msgs {
		if strings.Contains(m.text, "r03 stopped answering") {
			by = append(by, m.by)
		}
	}
	if len(by) != 1 || by[0] != "r01" {
		t.Fatalf("the held silence was sent by %v; want once, by r01", by)
	}
}

// TestMergedIncidentHonoursReturnAck (D2): a return merged with the silence
// it ends is not sent once other members acknowledged the silence and the
// return apart: the merged incident tells nothing the chat did not get.
// While the silence is untold, it is still sent.
func TestMergedIncidentHonoursReturnAck(t *testing.T) {
	// r02 holds the sender role too, below r01: only a sender's
	// acknowledgement counts (B3).
	g := newGroup(t, setup{n: 2, senders: map[int]int{0: 2, 1: 1}})
	g.run(10 * sec)
	g.chat.setDown(true)
	a := g.nodes[0]
	const silence, ret, merged = "1111111111111111", "2222222222222222", "3333333333333333"
	queued := func() int { return a.Status().Queued }
	with(a, func() any {
		now := a.stamp()
		a.queueLocked(events.Incident{ID: merged, Start: now, End: now}, nil, []string{silence, ret}, now)
		return nil
	})
	if queued() != 1 {
		t.Fatal("the merged incident was not queued")
	}
	b := g.ids[1]
	body, err := deliver.AckBody(ret)
	if err != nil {
		t.Fatal(err)
	}
	head := with(a, func() history.Head { return a.log.Head(b.ID) })
	ack, err := history.NewEntry(b, head, history.KindEvent, body)
	if err != nil {
		t.Fatal(err)
	}
	inject(a, ack)
	if q := queued(); q != 1 {
		t.Fatalf("%d incidents queued once only the return was acknowledged, want 1: the silence is untold", q)
	}
	body, _ = deliver.AckBody(silence)
	ack2, err := history.NewEntry(b, history.Head{Seq: ack.Seq, Hash: ack.Hash()}, history.KindEvent, body)
	if err != nil {
		t.Fatal(err)
	}
	inject(a, ack2)
	if q := queued(); q != 0 {
		t.Fatalf("%d incidents queued after the silence and the return were acknowledged, want 0", q)
	}
	with(a, func() any {
		now := a.stamp()
		a.queueLocked(events.Incident{ID: "4444444444444444", Start: now, End: now}, nil, []string{silence, ret}, now)
		return nil
	})
	if q := queued(); q != 0 {
		t.Fatalf("a merged incident whose parts were acknowledged was queued")
	}
}

// TestSenderWaitsForPeerHeardAgain (D2): when a partition heals, the sender
// of each side takes itself for the sender until it hears the other side.
// A sender that hears a member again waits for their views to meet before
// it sends, so the two sides' senders do not both send at once.
func TestSenderWaitsForPeerHeardAgain(t *testing.T) {
	// r02 has no sender role here, so no acknowledgement of its own holds
	// r01 back: only hearing r02 again does.
	g := newGroup(t, setup{n: 2, senders: map[int]int{0: 2}})
	g.run(40 * sec)
	g.split([]int{0}, []int{1}, true)
	g.run(time.Minute)
	// A fact of its own, which no return joins.
	g.nodes[0].LocalEvent(events.Event{Type: events.MemberLeft})
	g.run(settle - 2*sec) // the incident is ready two seconds after the heal
	g.split([]int{0}, []int{1}, false)
	healed := g.clk.Mono()
	// r02's next heartbeat goes out at once: r01 hears it again now.
	b := g.nodes[1]
	b.mu.Lock()
	b.beatLocked(b.stamp())
	out := b.takeOut()
	b.mu.Unlock()
	b.send(out)
	if st := stateOf(g.nodes[0].Status(), "r02"); st != "up" {
		t.Fatalf("r01 sees r02 %q after its heartbeat, want up", st)
	}
	g.run(time.Minute)
	t.Logf("chat:\n%s", strings.Join(g.chat.all(), "\n"))
	g.chat.mu.Lock()
	defer g.chat.mu.Unlock()
	for _, m := range g.chat.msgs {
		if strings.Contains(m.text, "left the group") {
			if d := m.at - healed; d < g.cfgs[0].Heartbeat {
				t.Fatalf("r01 sent %s after it heard r02 again, before their views could meet (a heartbeat, %s)", d, g.cfgs[0].Heartbeat)
			}
			return
		}
	}
	t.Fatal("the fact never reached the chat")
}

// TestMergedAckCoversItsStart (D5): once another member told a whole
// absence (the merged incident acknowledged), the silence that began it
// counts as told: the sender holds nothing of it.
func TestMergedAckCoversItsStart(t *testing.T) {
	// r02 holds the sender role too, below r01 (B3).
	g := newGroup(t, setup{n: 2, senders: map[int]int{0: 2, 1: 1}})
	g.run(10 * sec)
	g.chat.setDown(true)
	a := g.nodes[0]
	const silence, ret, merged = "1111111111111111", "2222222222222222", "3333333333333333"
	with(a, func() any {
		now := a.stamp()
		a.queueLocked(events.Incident{ID: silence, Start: now, End: now}, nil, nil, now)
		a.queueLocked(events.Incident{ID: merged, Start: now, End: now}, nil, []string{silence, ret}, now)
		return nil
	})
	body, err := deliver.AckBody(merged)
	if err != nil {
		t.Fatal(err)
	}
	b := g.ids[1]
	head := with(a, func() history.Head { return a.log.Head(b.ID) })
	ack, err := history.NewEntry(b, head, history.KindEvent, body)
	if err != nil {
		t.Fatal(err)
	}
	inject(a, ack)
	st := a.Status()
	if st.Queued != 0 {
		t.Fatalf("%d incidents queued after the whole absence was told, want 0", st.Queued)
	}
	for _, inc := range st.Incidents {
		if !inc.Delivered {
			t.Fatalf("incident %s %q not delivered after the whole absence was told", inc.ID, inc.Text)
		}
	}
}

// TestNoSendAfterGoingDown (D2): a router that announced its shutdown sends
// nothing more: its peers took it for gone and one of them sends now.
func TestNoSendAfterGoingDown(t *testing.T) {
	g := newGroup(t, setup{n: 2, senders: map[int]int{0: 1}})
	g.run(60 * sec)
	a := g.nodes[0]
	a.GoingDown()
	with(a, func() any {
		now := a.stamp()
		a.queueLocked(events.Incident{ID: "1111111111111111", Start: now, End: now}, nil, nil, now)
		return nil
	})
	g.run(time.Minute)
	if m := g.chat.messages("[11111111]"); len(m) != 0 {
		t.Fatalf("r01 sent after it announced its shutdown: %q", m)
	}
}

// TestTakeoverWaitsGrace (D2): the sender loses its internet; the member that
// takes over waits the delivery grace and 2 s after its announcing heartbeat,
// so a message the old sender sent just before is not followed by another
// sender's within the grace, and its acknowledgement can arrive.
func TestTakeoverWaitsGrace(t *testing.T) {
	g := newGroup(t, setup{n: 2, senders: map[int]int{0: 2, 1: 1}})
	g.run(60 * sec)
	a, b := g.nodes[0], g.nodes[1]
	a.LocalEvent(events.Event{Type: events.InternetLost})
	with(b, func() any {
		now := b.stamp()
		b.queueLocked(events.Incident{ID: "2222222222222222", Start: now, End: now}, nil, nil, now)
		return nil
	})
	var took time.Duration
	for range 60 {
		g.run(sec)
		if s := b.Status().Sender; took == 0 && s != nil && *s == "r02" {
			took = g.clk.Mono()
		}
	}
	g.chat.mu.Lock()
	defer g.chat.mu.Unlock()
	for _, m := range g.chat.msgs {
		if strings.Contains(m.text, "[22222222]") {
			if d := m.at - took; m.by != "r02" || d < handover {
				t.Fatalf("%s sent it %s after r02 took over, want r02 after %s", m.by, d, handover)
			}
			return
		}
	}
	t.Fatal("the incident never reached the chat")
}

// TestTakeoverWaitsForAcks (D2): the member that takes over sending does
// not send while it lacks entries the previous sender's heartbeat says that
// sender holds (its acknowledgements among them), up to twice the handover,
// so an incident the previous sender delivered is not sent again.
func TestTakeoverWaitsForAcks(t *testing.T) {
	g := newGroup(t, setup{n: 2, senders: map[int]int{0: 2, 1: 1}})
	g.run(60 * sec)
	a, b := g.nodes[0], g.nodes[1]
	a.LocalEvent(events.Event{Type: events.InternetLost})
	const id = "3333333333333333"
	for _, n := range []*Node{a, b} {
		with(n, func() any {
			now := n.stamp()
			n.queueLocked(events.Incident{ID: id, Start: now, End: now}, nil, nil, now)
			return nil
		})
	}
	block := func(d time.Duration) {
		with(a, func() any {
			a.peers[b.id.ID].nextSync = a.clk.Mono() + d
			return nil
		})
	}
	block(time.Hour) // r01 does not fetch r02's chain for now
	g.run(40 * sec)
	if n := len(g.chat.messages("[33333333]")); n != 1 {
		t.Fatalf("r02 did not send the incident (%d messages): the case did not happen", n)
	}
	a.LocalEvent(events.Event{Type: events.InternetRestored})
	g.run(25 * sec)
	block(0)
	g.run(time.Minute)
	t.Logf("chat:\n%s", strings.Join(g.chat.all(), "\n"))
	if n := len(g.chat.messages("[33333333]")); n != 1 {
		t.Fatalf("the incident was sent %d times: r01 took over before it held r02's acknowledgement", n)
	}
}

// TestForeignAckHoldsSender (D2): while another member still delivers (its
// acknowledgements keep arriving), this node, though it takes itself for the
// sender, waits the delivery grace after the last of them, so the two do not
// send at once while their views converge.
func TestForeignAckHoldsSender(t *testing.T) {
	g := newGroup(t, setup{n: 3, running: []bool{true, true, false}, senders: map[int]int{0: 2, 2: 1}})
	g.run(60 * sec)
	a := g.nodes[0]
	body, err := deliver.AckBody("4444444444444444")
	if err != nil {
		t.Fatal(err)
	}
	ack, err := history.NewEntry(g.ids[2], history.Head{}, history.KindEvent, body)
	if err != nil {
		t.Fatal(err)
	}
	inject(a, ack)
	acked := g.clk.Mono()
	with(a, func() any {
		now := a.stamp()
		a.queueLocked(events.Incident{ID: "5555555555555555", Start: now, End: now}, nil, nil, now)
		return nil
	})
	g.run(time.Minute)
	g.chat.mu.Lock()
	defer g.chat.mu.Unlock()
	for _, m := range g.chat.msgs {
		if strings.Contains(m.text, "[55555555]") {
			if d := m.at - acked; d < deliver.Grace {
				t.Fatalf("r01 sent %s after r03's acknowledgement arrived, want the grace (%s)", d, deliver.Grace)
			}
			return
		}
	}
	t.Fatal("the incident never reached the chat")
}
