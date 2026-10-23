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
	g := newGroup(t, setup{n: 2, senders: map[int]int{0: 1}})
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
	g := newGroup(t, setup{n: 2, senders: map[int]int{0: 2, 1: 1}})
	g.run(40 * sec)
	g.split([]int{0}, []int{1}, true)
	g.run(time.Minute)
	g.nodes[0].LocalEvent(events.Event{Type: events.WanDown})
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
		if strings.Contains(m.text, "WAN went down") {
			if d := m.at - healed; d < g.cfgs[0].Heartbeat {
				t.Fatalf("r01 sent %s after it heard r02 again, before their views could meet (a heartbeat, %s)", d, g.cfgs[0].Heartbeat)
			}
			return
		}
	}
	t.Fatal("the WAN loss never reached the chat")
}

// TestMergedAckCoversItsStart (D5): once another member told a whole
// absence (the merged incident acknowledged), the silence that began it
// counts as told: the sender holds nothing of it.
func TestMergedAckCoversItsStart(t *testing.T) {
	g := newGroup(t, setup{n: 2, senders: map[int]int{0: 1}})
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
