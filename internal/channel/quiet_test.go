package channel

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
)

// quietText is the message of the quiet hours tests.
const quietText = "Home: r02 silent [0123abcd]"

// dumpRequest writes a request as it reached the fake server: method, path and
// query, every header in name order, and the body.
func dumpRequest(r recorded) string {
	keys := make([]string, 0, len(r.header))
	for k := range r.header {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s?%s\n", r.method, r.path, r.query)
	for _, k := range keys {
		fmt.Fprintf(&b, "%s: %s\n", k, strings.Join(r.header[k], ","))
	}
	fmt.Fprintf(&b, "\n%s", r.body)
	return b.String()
}

// The requests a send outside the quiet hours makes, as the clients made them
// before quiet hours existed (dumped with dumpRequest at 543784a, 2026-10-30).
const (
	loudTelegramRequest = "POST /bot" + canary + "/sendMessage?\n" +
		"Accept-Encoding: gzip\nContent-Length: 95\nContent-Type: application/json\nUser-Agent: Go-http-client/1.1\n\n" +
		`{"chat_id":42,"text":"Home: r02 silent [0123abcd]","link_preview_options":{"is_disabled":true}}`
	loudNtfyRequest = "POST /alerts?\n" +
		"Accept-Encoding: gzip\nAuthorization: Bearer " + canary + "\nContent-Length: 27\nContent-Type: text/plain; charset=utf-8\nUser-Agent: Go-http-client/1.1\n\n" +
		quietText
)

// onlyRequest returns the one request the fake server got.
func onlyRequest(t *testing.T, reqs *reqLog) recorded {
	t.Helper()
	got := reqs.all()
	if len(got) != 1 {
		t.Fatalf("requests = %d, want 1", len(got))
	}
	return got[0]
}

// TestTelegramSilentSendDisablesNotification: a silent send asks Telegram for
// a message without a sound (disable_notification, Bot API sendMessage); the
// text, the chat, the plain text and the link previews off stay as they are.
func TestTelegramSilentSendDisablesNotification(t *testing.T) {
	srv, reqs := serve(t, okFn)
	if err := NewTelegram(srv.URL, canary, 42, srv.Client()).Send(context.Background(), quietText, true); err != nil {
		t.Fatalf("Send: %v", err)
	}
	r := onlyRequest(t, reqs)
	var body map[string]any
	if err := json.Unmarshal([]byte(r.body), &body); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	keys := make([]string, 0, len(body))
	for k := range body {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	if want := []string{"chat_id", "disable_notification", "link_preview_options", "text"}; !slices.Equal(keys, want) {
		t.Fatalf("body keys = %v, want exactly %v", keys, want)
	}
	if body["disable_notification"] != true {
		t.Errorf("disable_notification = %v, want true", body["disable_notification"])
	}
	if body["text"] != quietText || body["chat_id"] != float64(42) {
		t.Errorf("text %v to chat %v, want the same text to chat 42", body["text"], body["chat_id"])
	}
	if lpo, _ := body["link_preview_options"].(map[string]any); len(lpo) != 1 || lpo["is_disabled"] != true {
		t.Errorf("link_preview_options = %v, want exactly {is_disabled: true}", lpo)
	}
	loud := strings.Replace(loudTelegramRequest, "Content-Length: 95", "Content-Length: 123", 1)
	loud = strings.Replace(loud, `{"is_disabled":true}}`, `{"is_disabled":true},"disable_notification":true}`, 1)
	if got := dumpRequest(r); got != loud {
		t.Errorf("silent request:\n%s\nwant the loud one with only disable_notification added:\n%s", got, loud)
	}
}

// TestTelegramLoudSendUnchanged: outside the quiet hours the request is byte
// for byte the one Send made before quiet hours existed: no
// disable_notification field, not even false.
func TestTelegramLoudSendUnchanged(t *testing.T) {
	srv, reqs := serve(t, okFn)
	if err := NewTelegram(srv.URL, canary, 42, srv.Client()).Send(context.Background(), quietText, false); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if got := dumpRequest(onlyRequest(t, reqs)); got != loudTelegramRequest {
		t.Errorf("loud request:\n%s\nwant, as before quiet hours:\n%s", got, loudTelegramRequest)
	}
}

// TestNtfySilentSendIsLowPriority: a silent publish carries X-Priority 2
// (low), which ntfy documents as no vibration and no sound, while the message
// stays in the notification list (1, min, would fold it under "Other
// notifications"). Body and other headers stay as they are.
func TestNtfySilentSendIsLowPriority(t *testing.T) {
	srv, reqs := serve(t, okFn)
	n, err := NewNtfy(srv.URL+"/alerts", canary, true, srv.Client())
	if err != nil {
		t.Fatalf("NewNtfy: %v", err)
	}
	if err := n.Send(context.Background(), quietText, true); err != nil {
		t.Fatalf("Send: %v", err)
	}
	r := onlyRequest(t, reqs)
	if p := r.header.Values("X-Priority"); !slices.Equal(p, []string{"2"}) {
		t.Errorf("X-Priority = %q, want exactly [2] (low: no sound, no vibration)", p)
	}
	for _, alias := range []string{"Priority", "Prio", "P"} {
		if v := r.header.Values(alias); v != nil {
			t.Errorf("header %s = %q; one priority header only", alias, v)
		}
	}
	if got := dumpRequest(r); got != silentNtfyRequest() {
		t.Errorf("silent request:\n%s\nwant the loud one with only X-Priority added:\n%s", got, silentNtfyRequest())
	}
}

// silentNtfyRequest is loudNtfyRequest with X-Priority: 2 among the headers,
// in name order.
func silentNtfyRequest() string {
	return strings.Replace(loudNtfyRequest, "User-Agent: Go-http-client/1.1\n", "User-Agent: Go-http-client/1.1\nX-Priority: 2\n", 1)
}

// TestNtfyLoudSendUnchanged: outside the quiet hours the publish is byte for
// byte the one Send made before quiet hours existed, with no priority header,
// so ntfy uses its default priority, which rings.
func TestNtfyLoudSendUnchanged(t *testing.T) {
	srv, reqs := serve(t, okFn)
	n, err := NewNtfy(srv.URL+"/alerts", canary, true, srv.Client())
	if err != nil {
		t.Fatalf("NewNtfy: %v", err)
	}
	if err := n.Send(context.Background(), quietText, false); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if got := dumpRequest(onlyRequest(t, reqs)); got != loudNtfyRequest {
		t.Errorf("loud request:\n%s\nwant, as before quiet hours:\n%s", got, loudNtfyRequest)
	}
}
