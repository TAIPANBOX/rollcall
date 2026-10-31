package channel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/rollcall/internal/deliver"
)

const okAnswer = `{"ok":true,"result":{}}`

// okFn answers every request with okAnswer.
func okFn(_ int, w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, okAnswer) }

// fastBind returns a Telegram whose polls do not pause for long.
func fastBind(hostURL string, hc *http.Client) *Telegram {
	tg := NewTelegram(hostURL, canary, 0, hc)
	tg.pause = time.Millisecond
	return tg
}

// requestOffset reads the offset a getUpdates request carried.
func requestOffset(t *testing.T, body string) int64 {
	t.Helper()
	var b struct {
		Offset int64 `json:"offset"`
	}
	if err := json.Unmarshal([]byte(body), &b); err != nil {
		t.Fatalf("getUpdates body %q is not JSON: %v", body, err)
	}
	return b.Offset
}

func TestTelegramProductionBaseURL(t *testing.T) {
	if TelegramBaseURL != "https://api.telegram.org" {
		t.Fatalf("TelegramBaseURL = %q", TelegramBaseURL)
	}
}

func TestTelegramSendHasNoParseMode(t *testing.T) {
	srv, reqs := serve(t, okFn)
	tg := NewTelegram(srv.URL, canary, 42, srv.Client())
	if err := tg.Send(context.Background(), "hello <b>there</b>", false); err != nil {
		t.Fatalf("Send: %v", err)
	}
	got := reqs.all()
	if len(got) != 1 {
		t.Fatalf("requests = %d, want 1", len(got))
	}
	r := got[0]
	if r.method != http.MethodPost || r.path != "/bot"+canary+"/sendMessage" {
		t.Fatalf("request = %s %s, want POST /bot<token>/sendMessage", r.method, r.path)
	}
	var body map[string]any
	if err := json.Unmarshal([]byte(r.body), &body); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	keys := make([]string, 0, len(body))
	for k := range body {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	if want := []string{"chat_id", "link_preview_options", "text"}; !slices.Equal(keys, want) {
		t.Fatalf("body keys = %v, want exactly %v (no parse_mode)", keys, want)
	}
	if body["chat_id"] != float64(42) {
		t.Errorf("chat_id = %v, want 42", body["chat_id"])
	}
	if body["text"] != "hello <b>there</b>" {
		t.Errorf("text = %v, want the message unchanged", body["text"])
	}
	lpo, _ := body["link_preview_options"].(map[string]any)
	if len(lpo) != 1 || lpo["is_disabled"] != true {
		t.Errorf("link_preview_options = %v, want exactly {is_disabled: true}", lpo)
	}
}

func TestTelegramPingCallsGetMe(t *testing.T) {
	srv, reqs := serve(t, okFn)
	if err := NewTelegram(srv.URL, canary, 42, srv.Client()).Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	got := reqs.all()
	if len(got) != 1 || got[0].path != "/bot"+canary+"/getMe" {
		t.Fatalf("requests = %+v, want one call to /bot<token>/getMe", got)
	}
}

func TestTelegramBlockedIsErrBlocked(t *testing.T) {
	srv, _ := serve(t, status(403, `{"ok":false,"error_code":403,"description":"Forbidden: bot was blocked by the user"}`))
	err := NewTelegram(srv.URL, canary, 42, srv.Client()).Send(context.Background(), "x", false)
	if !errors.Is(err, deliver.ErrBlocked) {
		t.Fatalf("err = %v, want deliver.ErrBlocked", err)
	}
	noCanary(t, err)
}

func TestTelegramRateLimitCarriesRetryAfter(t *testing.T) {
	body := `{"ok":false,"error_code":429,"description":"Too Many Requests: retry after 7","parameters":{"retry_after":7}}`
	srv, _ := serve(t, status(429, body))
	err := NewTelegram(srv.URL, canary, 42, srv.Client()).Send(context.Background(), "x", false)
	var rl *deliver.RateLimitError
	if !errors.As(err, &rl) {
		t.Fatalf("err = %v, want a *deliver.RateLimitError", err)
	}
	if rl.RetryAfter != 7*time.Second {
		t.Fatalf("RetryAfter = %v, want 7s from parameters.retry_after", rl.RetryAfter)
	}
	if !errors.Is(err, deliver.ErrRateLimited) {
		t.Fatalf("err = %v, want it to match deliver.ErrRateLimited", err)
	}
	noCanary(t, err)
}

func TestTelegramOtherStatusIsPlain(t *testing.T) {
	srv, _ := serve(t, status(500, "internal"))
	err := NewTelegram(srv.URL, canary, 42, srv.Client()).Send(context.Background(), "x", false)
	if err == nil {
		t.Fatal("err = nil, want an error for HTTP 500")
	}
	if errors.Is(err, deliver.ErrBlocked) || errors.Is(err, deliver.ErrRateLimited) || errors.Is(err, deliver.ErrTLS) {
		t.Fatalf("err = %v, want a plain error that matches no deliver sentinel", err)
	}
	if !strings.Contains(err.Error(), "500") {
		t.Fatalf("err = %q, want the status code in it", err.Error())
	}
	noCanary(t, err)
}

func TestTelegramTLSFailureIsErrTLS(t *testing.T) {
	srv, _ := serveTLS(t, okFn)
	// nil client: the default guarded client verifies certificates, and the
	// test server's certificate is not trusted.
	err := NewTelegram(srv.URL, canary, 42, nil).Send(context.Background(), "x", false)
	if !errors.Is(err, deliver.ErrTLS) {
		t.Fatalf("err = %v, want deliver.ErrTLS", err)
	}
	noCanary(t, err)
}

func TestCanaryNeverInTelegramErrors(t *testing.T) {
	closed := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	refusedURL := closed.URL
	closed.Close()

	tlsSrv, _ := serveTLS(t, okFn)
	s500, _ := serve(t, status(500, "internal"))
	s403, _ := serve(t, status(403, "forbidden"))
	s429, _ := serve(t, status(429, `{"parameters":{"retry_after":3}}`))

	cases := []struct {
		name string
		tg   *Telegram
	}{
		{"connection refused", NewTelegram(refusedURL, canary, 42, nil)},
		{"untrusted certificate", NewTelegram(tlsSrv.URL, canary, 42, nil)},
		{"unparsable base URL", NewTelegram("http://bad host\x7f", canary, 42, http.DefaultClient)},
		{"HTTP 500", NewTelegram(s500.URL, canary, 42, s500.Client())},
		{"HTTP 403", NewTelegram(s403.URL, canary, 42, s403.Client())},
		{"HTTP 429", NewTelegram(s429.URL, canary, 42, s429.Client())},
	}
	ctx := context.Background()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sendErr := c.tg.Send(ctx, "x", false)
			pingErr := c.tg.Ping(ctx)
			if sendErr == nil || pingErr == nil {
				t.Fatalf("Send err = %v, Ping err = %v; want both to fail", sendErr, pingErr)
			}
			noCanary(t, sendErr)
			noCanary(t, pingErr)
			fast := fastBind(c.tg.baseURL, c.tg.hc)
			_, bindErr := fast.BindChat(ctx, "123456", 30*time.Millisecond)
			if bindErr == nil {
				t.Fatal("BindChat err = nil, want an error")
			}
			noCanary(t, bindErr)
		})
	}
}

func TestTelegramNeverPrintsToken(t *testing.T) {
	tg := NewTelegram(TelegramBaseURL, canary, 42, nil)
	forms := []struct {
		name string
		text string
	}{
		{"%v", fmt.Sprintf("%v", tg)},
		{"%+v", fmt.Sprintf("%+v", tg)},
		{"%#v", fmt.Sprintf("%#v", tg)},
		{"%s on the value", fmt.Sprintf("%s", *tg)},
		{"String", tg.String()},
	}
	for _, f := range forms {
		if strings.Contains(f.text, canary) {
			t.Errorf("%s shows the token: %q", f.name, f.text)
		}
	}
	if !strings.Contains(tg.String(), "[redacted]") {
		t.Errorf("String() = %q, want the token slot marked [redacted]", tg.String())
	}
}

func TestBindChatAcceptsOnlyTheCodeFromAPrivateChat(t *testing.T) {
	const code = "741852"
	srv, reqs := serve(t, func(n int, w http.ResponseWriter, _ *http.Request) {
		if n == 1 {
			fmt.Fprint(w, `{"ok":true,"result":[`+
				`{"update_id":10,"message":{"message_id":1,"chat":{"id":-100,"type":"group"},"text":"741852"}},`+
				`{"update_id":11,"message":{"message_id":2,"chat":{"id":7,"type":"private"},"text":"wrong"}},`+
				`{"update_id":12,"message":{"message_id":3,"chat":{"id":9,"type":"private"},"text":"  741852  "}}`+
				`]}`)
			return
		}
		fmt.Fprint(w, `{"ok":true,"result":[]}`)
	})
	chat, err := fastBind(srv.URL, srv.Client()).BindChat(context.Background(), code, 5*time.Second)
	if err != nil {
		t.Fatalf("BindChat: %v", err)
	}
	if chat != 9 {
		t.Fatalf("chat = %d, want 9 (the private chat that sent the code)", chat)
	}
	got := reqs.all()
	if len(got) != 2 {
		t.Fatalf("requests = %d, want the poll and one clearing call", len(got))
	}
	if off := requestOffset(t, got[0].body); off != 0 {
		t.Errorf("first poll offset = %d, want 0", off)
	}
	if off := requestOffset(t, got[1].body); off != 13 {
		t.Errorf("clearing call offset = %d, want 13 (past update 12)", off)
	}
	if !strings.Contains(got[1].body, `"timeout":0`) {
		t.Errorf("clearing call body = %s, want timeout 0", got[1].body)
	}
}

func TestBindChatIgnoresGroupAndWrongText(t *testing.T) {
	srv, reqs := serve(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"ok":true,"result":[`+
			`{"update_id":1,"message":{"message_id":1,"chat":{"id":-100,"type":"group"},"text":"741852"}},`+
			`{"update_id":2,"message":{"message_id":2,"chat":{"id":7,"type":"private"},"text":"741853"}}`+
			`]}`)
	})
	chat, err := fastBind(srv.URL, srv.Client()).BindChat(context.Background(), "741852", 40*time.Millisecond)
	if err == nil {
		t.Fatalf("BindChat = %d, nil; want no binding from a group or a wrong text", chat)
	}
	if chat != 0 {
		t.Fatalf("chat = %d, want 0 without a binding", chat)
	}
	if n := len(reqs.all()); n < 2 {
		t.Fatalf("requests = %d, want polling to continue until the window ends", n)
	}
}

func TestBindChatPollsUntilTheCodeArrives(t *testing.T) {
	srv, reqs := serve(t, func(n int, w http.ResponseWriter, _ *http.Request) {
		if n == 2 {
			fmt.Fprint(w, `{"ok":true,"result":[{"update_id":20,"message":{"message_id":5,"chat":{"id":5,"type":"private"},"text":"741852"}}]}`)
			return
		}
		fmt.Fprint(w, `{"ok":true,"result":[]}`)
	})
	chat, err := fastBind(srv.URL, srv.Client()).BindChat(context.Background(), "741852", 5*time.Second)
	if err != nil {
		t.Fatalf("BindChat: %v", err)
	}
	if chat != 5 {
		t.Fatalf("chat = %d, want 5", chat)
	}
	got := reqs.all()
	if len(got) != 3 {
		t.Fatalf("requests = %d, want empty poll, code poll, clearing call", len(got))
	}
	if off := requestOffset(t, got[2].body); off != 21 {
		t.Fatalf("clearing call offset = %d, want 21", off)
	}
}

func TestBindChatRetriesAfterServerError(t *testing.T) {
	srv, _ := serve(t, func(n int, w http.ResponseWriter, _ *http.Request) {
		switch n {
		case 1:
			w.WriteHeader(500)
		case 2:
			fmt.Fprint(w, `{"ok":true,"result":[{"update_id":1,"message":{"message_id":1,"chat":{"id":8,"type":"private"},"text":"741852"}}]}`)
		default:
			fmt.Fprint(w, `{"ok":true,"result":[]}`)
		}
	})
	chat, err := fastBind(srv.URL, srv.Client()).BindChat(context.Background(), "741852", 5*time.Second)
	if err != nil || chat != 8 {
		t.Fatalf("BindChat = %d, %v; want 8 after a transient 500", chat, err)
	}
}

func TestBindChatStopsOnTLSFailure(t *testing.T) {
	srv, _ := serveTLS(t, okFn)
	start := time.Now()
	_, err := NewTelegram(srv.URL, canary, 0, nil).BindChat(context.Background(), "741852", 5*time.Second)
	if !errors.Is(err, deliver.ErrTLS) {
		t.Fatalf("err = %v, want deliver.ErrTLS", err)
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("binding kept polling for %v after a TLS failure; it must stop at once", took)
	}
	noCanary(t, err)
}

func TestBindChatTimesOut(t *testing.T) {
	srv, _ := serve(t, okFn)
	chat, err := fastBind(srv.URL, srv.Client()).BindChat(context.Background(), "741852", 30*time.Millisecond)
	if err == nil || chat != 0 {
		t.Fatalf("BindChat = %d, %v; want no chat and an error when the window ends", chat, err)
	}
	noCanary(t, err)
}

func TestBindChatRejectsEmptyCode(t *testing.T) {
	srv, reqs := serve(t, okFn)
	if _, err := fastBind(srv.URL, srv.Client()).BindChat(context.Background(), "", time.Second); err == nil {
		t.Fatal("BindChat with an empty code returned no error")
	}
	if n := len(reqs.all()); n != 0 {
		t.Fatalf("requests = %d, want none for an empty code", n)
	}
}

func TestBindChatHonoursCancelledContext(t *testing.T) {
	srv, _ := serve(t, okFn)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := fastBind(srv.URL, srv.Client()).BindChat(ctx, "741852", time.Minute); err == nil {
		t.Fatal("BindChat with a cancelled context returned no error")
	}
}

func TestTelegramRefusesOversizedAnswer(t *testing.T) {
	srv, _ := serve(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, strings.Repeat("x", maxResponse+10))
	})
	if err := NewTelegram(srv.URL, canary, 42, srv.Client()).Send(context.Background(), "x", false); err == nil {
		t.Fatal("an answer over the size limit was accepted")
	}
}
