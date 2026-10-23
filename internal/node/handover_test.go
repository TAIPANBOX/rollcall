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
// it ends is not sent once another member acknowledged the return alone: the
// merged incident tells nothing the chat did not get.
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
	if q := queued(); q != 0 {
		t.Fatalf("%d incidents queued after the return was acknowledged, want 0", q)
	}
	with(a, func() any {
		now := a.stamp()
		a.queueLocked(events.Incident{ID: "4444444444444444", Start: now, End: now}, nil, []string{"5555555555555555", ret}, now)
		return nil
	})
	if q := queued(); q != 0 {
		t.Fatalf("a merged incident whose return was acknowledged was queued")
	}
}
