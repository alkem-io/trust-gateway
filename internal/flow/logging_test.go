package flow

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/alkem-io/trust-gateway/internal/session"
)

func TestEffectLoggingRedactsSecrets(t *testing.T) {
	const oauthState = "DO-NOT-LOG-OAUTH-STATE"
	var buf bytes.Buffer
	e := &Engine{
		SDK: &scriptedSDK{steps: []Result{
			redirect("https://cb/oauth2/authorize", oauthState),
			performHTTP("https://cb/oauth2/token?hash=TOPSECRET&code=ABC"),
			done([]byte("%PDF")),
		}},
		Up:    &fakeEffector{},
		Store: session.NewMemory(),
		Log:   slog.New(slog.NewTextHandler(&buf, nil)),
		TTL:   time.Minute,
	}
	_, _ = e.Begin("c", []byte("%PDF"), "B-B", "", nil)
	s, _ := e.Store.GetByState(oauthState)
	if _, _, _, err := e.Complete(context.Background(), s, "code", oauthState); err != nil {
		t.Fatalf("complete: %v", err)
	}

	out := buf.String()
	// The effect loop logs each request/result and each transition.
	for _, want := range []string{"effect.perform_http", "effect.http_result", "transition.done", "/oauth2/token"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing log line %q in:\n%s", want, out)
		}
	}
	// But never the query string, which can carry the document hash / OAuth code.
	for _, leak := range []string{"TOPSECRET", "hash=", "code=ABC", oauthState} {
		if strings.Contains(out, leak) {
			t.Fatalf("log leaked %q:\n%s", leak, out)
		}
	}
}
