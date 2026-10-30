package node

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

type lines struct {
	mu sync.Mutex
	l  []string
}

func (l *lines) logf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.l = append(l.l, fmt.Sprintf(format, args...))
}

func (l *lines) with(sub string) []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []string
	for _, s := range l.l {
		if strings.Contains(s, sub) {
			out = append(out, s)
		}
	}
	return out
}

var chatTag = regexp.MustCompile(`\[([0-9a-f]{8})\]$`)

// TestChatSendsAreLogged: the sender logs one line for each message it puts in
// the chat, with the message's tag, and one line when sends start failing, not
// one per attempt; a later outage, after a send worked, gets its own line. Without it nothing on a router said what reached the chat:
// on 2026-10-30 a 7 s WAN loss on beryl2 showed two records, both marked
// delivered, and whether the chat got one message or two could not be told.
func TestChatSendsAreLogged(t *testing.T) {
	g := newGroup(t, setup{n: 3, senders: map[int]int{0: 1}})
	info, problems := &lines{}, &lines{}
	g.nodes[0].SetLogf(info.logf, problems.logf)
	g.run(90 * sec)
	// r03 stops; Telegram goes down 10 s later, after the sender's last good
	// call, so the sender still counts as able to send when the silence is
	// due and its sends fail until the 60 s window runs out.
	g.stop(2)
	g.run(10 * sec)
	g.chat.setDown(true)
	g.run(3 * time.Minute)
	g.chat.setDown(false)
	g.run(3 * time.Minute)
	g.reboot(2)
	g.run(2 * time.Minute)
	// A second outage after sends worked again is logged again.
	g.stop(1)
	g.run(10 * sec)
	g.chat.setDown(true)
	g.run(3 * time.Minute)
	g.chat.setDown(false)
	g.run(3 * time.Minute)

	msgs := g.chat.all()
	t.Logf("chat:\n%s\nsent:\n%s\nproblems:\n%s", strings.Join(msgs, "\n"),
		strings.Join(info.with(""), "\n"), strings.Join(problems.with(""), "\n"))
	if len(msgs) == 0 {
		t.Fatal("nothing reached the chat: the case did not happen")
	}
	sent := info.with("told the chat")
	if len(sent) != len(msgs) {
		t.Fatalf("%d sent lines for %d chat messages", len(sent), len(msgs))
	}
	for i, m := range msgs {
		tag := chatTag.FindStringSubmatch(m)
		if tag == nil || !strings.Contains(sent[i], tag[1]) {
			t.Errorf("message %q; sent line %q does not name its tag", m, sent[i])
		}
	}
	if fails := problems.with("could not tell the chat"); len(fails) != 2 {
		t.Errorf("%d lines about failed sends in two outages of Telegram, want 2: %q", len(fails), fails)
	}
}
