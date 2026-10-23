package channel

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/deliver"
	"github.com/TAIPANBOX/rollcall/internal/redact"
)

// TelegramBaseURL is the production API root. The Telegram host is fixed to it.
const TelegramBaseURL = "https://api.telegram.org"

const (
	// bindPause is the wait after a binding poll that bound nothing. Telegram
	// holds a long poll open itself; the pause only spaces out the polls that
	// return at once, such as failures.
	bindPause = time.Second
	// bindPollSeconds is the long-poll timeout of each binding poll.
	bindPollSeconds = 5
	// clearTimeout bounds the call that clears the update queue.
	clearTimeout = 10 * time.Second
)

var _ deliver.Channel = (*Telegram)(nil)

// Telegram is a deliver.Channel that sends plain text to one chat. Its token
// is never printed and never appears in its errors.
type Telegram struct {
	baseURL string
	token   string
	chatID  int64
	hc      *http.Client
	pause   time.Duration
}

// NewTelegram returns a client for chatID through the bot token, at baseURL
// (TelegramBaseURL outside tests). A nil hc uses GuardedClient for the host of
// baseURL. The token is not checked here: a wrong one shows up as the error of
// the first call.
func NewTelegram(baseURL, token string, chatID int64, hc *http.Client) *Telegram {
	if hc == nil {
		hc = GuardedClient([]string{hostOf(baseURL)})
	}
	return &Telegram{
		baseURL: strings.TrimSuffix(baseURL, "/"),
		token:   token,
		chatID:  chatID,
		hc:      hc,
		pause:   bindPause,
	}
}

// tgSend is the body of sendMessage. It has no parse_mode field on purpose:
// the message is plain text.
type tgSend struct {
	ChatID             int64         `json:"chat_id"`
	Text               string        `json:"text"`
	LinkPreviewOptions tgLinkPreview `json:"link_preview_options"`
}

type tgLinkPreview struct {
	IsDisabled bool `json:"is_disabled"`
}

// Send posts text to the chat as plain text, with link previews off.
func (t *Telegram) Send(ctx context.Context, text string) error {
	return t.call(ctx, "sendMessage", tgSend{
		ChatID:             t.chatID,
		Text:               text,
		LinkPreviewOptions: tgLinkPreview{IsDisabled: true},
	}, nil)
}

// Ping calls getMe, which sends nothing.
func (t *Telegram) Ping(ctx context.Context) error {
	return t.call(ctx, "getMe", struct{}{}, nil)
}

// tgPoll is the body of getUpdates.
type tgPoll struct {
	Offset         int64    `json:"offset"`
	Timeout        int      `json:"timeout"`
	AllowedUpdates []string `json:"allowed_updates"`
}

type tgUpdate struct {
	UpdateID int64      `json:"update_id"`
	Message  *tgMessage `json:"message"`
}

type tgMessage struct {
	Text string `json:"text"`
	Chat tgChat `json:"chat"`
}

type tgChat struct {
	ID   int64  `json:"id"`
	Type string `json:"type"`
}

// BindChat waits up to within for a private chat to send exactly code. It
// polls getUpdates and accepts a message only from a private chat whose text,
// without surrounding spaces, equals code. Messages from any other chat are
// ignored. The offset moves past every update seen. On a match it makes one
// more getUpdates call, with the offset past the last update, so the queue is
// cleared, and it returns the chat ID.
//
// The clearing call is best effort: its failure does not undo the binding, and
// it is harmless, since rollcall never polls again after binding. A TLS failure
// ends the wait at once with deliver.ErrTLS. Other failures are retried until
// the window ends.
func (t *Telegram) BindChat(ctx context.Context, code string, within time.Duration) (int64, error) {
	if code == "" {
		return 0, errors.New("telegram bind: the code is empty")
	}
	wait, cancel := context.WithTimeout(ctx, within)
	defer cancel()
	var offset int64
	var last error
	for {
		var answer struct {
			OK     bool       `json:"ok"`
			Result []tgUpdate `json:"result"`
		}
		err := t.call(wait, "getUpdates", tgPoll{
			Offset:         offset,
			Timeout:        bindPollSeconds,
			AllowedUpdates: []string{"message"},
		}, &answer)
		switch {
		case err == nil && !answer.OK:
			last = errors.New("telegram getUpdates: the answer is not ok")
		case err == nil:
			last = nil
			var found bool
			var chatID int64
			for _, u := range answer.Result {
				if u.UpdateID+1 > offset {
					offset = u.UpdateID + 1
				}
				if !found && isBindingMessage(u, code) {
					found, chatID = true, u.Message.Chat.ID
				}
			}
			if found {
				t.clear(ctx, offset)
				return chatID, nil
			}
		case errors.Is(err, deliver.ErrTLS):
			return 0, err
		default:
			last = err
		}
		if wait.Err() != nil {
			return 0, bindFailed(ctx, within, last)
		}
		timer := time.NewTimer(t.pause)
		select {
		case <-wait.Done():
			timer.Stop()
			return 0, bindFailed(ctx, within, last)
		case <-timer.C:
		}
	}
}

// isBindingMessage reports whether u is a private chat message whose text,
// without surrounding spaces, equals code. The comparison takes the same time
// for every guess of the same length.
func isBindingMessage(u tgUpdate, code string) bool {
	m := u.Message
	if m == nil || m.Chat.Type != "private" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(strings.TrimSpace(m.Text)), []byte(code)) == 1
}

// clear asks Telegram to drop the updates before offset. Its outcome changes
// nothing: rollcall never polls again after binding. Its error is ignored on
// purpose, and the call is not cut short by the binding window.
func (t *Telegram) clear(parent context.Context, offset int64) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), clearTimeout)
	defer cancel()
	_ = t.call(ctx, "getUpdates", tgPoll{
		Offset:         offset,
		Timeout:        0,
		AllowedUpdates: []string{"message"},
	}, nil)
}

// bindFailed is the error of a binding that found no code in time. last is the
// error of the final poll, if there was one.
func bindFailed(parent context.Context, within time.Duration, last error) error {
	if err := parent.Err(); err != nil {
		return fmt.Errorf("telegram bind: %w", err)
	}
	if last != nil {
		return fmt.Errorf("telegram bind: no private message with the code within %s (last error: %w)", within, last)
	}
	return fmt.Errorf("telegram bind: no private message with the code within %s", within)
}

// call posts body as JSON to method. On a 2xx answer it decodes the answer into
// out, when out is not nil. Every error it returns is free of the token.
func (t *Telegram) call(ctx context.Context, method string, body any, out any) error {
	op := "telegram " + method
	raw, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.endpoint(method), bytes.NewReader(raw))
	if err != nil {
		return transportError(op, err, t.secrets()...)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := t.hc.Do(req)
	if err != nil {
		return transportError(op, err, t.secrets()...)
	}
	defer resp.Body.Close()
	answer, err := readBody(resp.Body)
	if err != nil {
		return transportError(op, err, t.secrets()...)
	}
	if err := statusError(op, resp.StatusCode, telegramRetryAfter(answer)); err != nil {
		return err
	}
	if out != nil && json.Unmarshal(answer, out) != nil {
		return fmt.Errorf("%s: the answer is not the JSON expected", op)
	}
	return nil
}

// endpoint is the method's URL. The token is in the path, as the Bot API wants.
func (t *Telegram) endpoint(method string) string {
	return t.baseURL + "/bot" + url.PathEscape(t.token) + "/" + method
}

// secrets are the token and its escaped forms, for redaction.
func (t *Telegram) secrets() []string {
	return []string{t.token, url.PathEscape(t.token), url.QueryEscape(t.token)}
}

// telegramRetryAfter reads parameters.retry_after from an answer, or returns 0.
func telegramRetryAfter(answer []byte) time.Duration {
	var b struct {
		Parameters struct {
			RetryAfter int64 `json:"retry_after"`
		} `json:"parameters"`
	}
	if json.Unmarshal(answer, &b) != nil || b.Parameters.RetryAfter <= 0 {
		return 0
	}
	return time.Duration(min(b.Parameters.RetryAfter, maxRetryAfterSeconds)) * time.Second
}

// String names the chat and marks where the token goes. It never prints the
// token.
func (t Telegram) String() string {
	return fmt.Sprintf("channel.Telegram{chat: %d, token: %s}", t.chatID, redact.Marker)
}

// Format prints String for every verb, %#v included, so no verb reaches the
// token.
func (t Telegram) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, t.String())
}
