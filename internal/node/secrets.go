package node

import (
	"errors"
	"fmt"

	"github.com/TAIPANBOX/rollcall/internal/deliver"
	"github.com/TAIPANBOX/rollcall/internal/pairing"
	"github.com/TAIPANBOX/rollcall/internal/roster"
)

// # Secrets of a running sender
//
// rollcall set-token and a finished bind-telegram give a running node a new
// bot token, chat ID and channel. SetSecrets takes them under the node's lock
// and stores them as SaveSecrets does, so the node keeps its boot, its
// counters and what it has not flushed yet: no restart.

// ErrNotSender reports secrets given to a router without the sender role:
// only a sender holds the bot token (security spec 6).
var ErrNotSender = errors.New("node: this router does not have the sender role")

// SetSecrets makes s the bot token and chat ID this router holds, and ch the
// channel it sends through (nil for none, as New takes it). It stores s first
// and changes nothing if that fails. The new channel is pinged at the next
// Tick. A token is 1 to pairing.MaxTokenLen bytes from A-Z, a-z, 0-9, ':',
// '_' and '-'; the zero Secrets clears them.
func (n *Node) SetSecrets(s pairing.Secrets, ch deliver.Channel) error {
	if !validBotToken(s.BotToken) {
		return fmt.Errorf("%w: the bot token", ErrArgument)
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.running() {
		return n.why()
	}
	if s.BotToken != "" {
		if m, ok := memberOf(n.cur(), n.id.ID); !ok || !hasRole(m, roster.RoleSender) {
			return ErrNotSender
		}
	}
	if err := SaveSecrets(n.st, s.BotToken, s.ChatID); err != nil {
		return err
	}
	n.secrets = secretsFile{BotToken: s.BotToken, ChatID: s.ChatID}
	n.ch = ch
	n.telegram = ""
	n.nextPing = n.clk.Mono()
	return nil
}

// validBotToken accepts the empty token and the bot tokens a join response
// carries.
func validBotToken(t string) bool {
	if len(t) > pairing.MaxTokenLen {
		return false
	}
	for _, r := range t {
		ok := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == ':' || r == '_' || r == '-'
		if !ok {
			return false
		}
	}
	return true
}
