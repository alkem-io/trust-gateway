package upstream

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRewrite(t *testing.T) {
	c := New("http://mock:9000")
	if got := c.Rewrite("https://connect.acc.cleverbase.com/oauth2/token?x=1"); got != "http://mock:9000/oauth2/token?x=1" {
		t.Fatalf("rewrite = %q", got)
	}
	// No rewrite target → identity.
	if got := New("").Rewrite("https://x/y"); got != "https://x/y" {
		t.Fatalf("identity rewrite = %q", got)
	}
	// Unparseable base → identity (no panic).
	if got := New("://bad").Rewrite("https://x/y"); got != "https://x/y" {
		t.Fatalf("bad-base rewrite = %q", got)
	}
	// Unparseable input → returned unchanged.
	if got := c.Rewrite("://nope"); got != "://nope" {
		t.Fatalf("bad-input rewrite = %q", got)
	}
}

func TestDo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("K") != "V" {
			http.Error(w, "missing header", http.StatusBadRequest)
			return
		}
		b, _ := io.ReadAll(r.Body)
		_, _ = w.Write(append([]byte("ok:"), b...))
	}))
	defer srv.Close()

	// Direct (no rewrite), with header + body.
	status, body, err := New("").Do(context.Background(), "POST", srv.URL+"/x", [][2]string{{"K", "V"}}, []byte("hi"))
	if err != nil || status != 200 || string(body) != "ok:hi" {
		t.Fatalf("Do: status=%d body=%q err=%v", status, body, err)
	}

	// Rewritten host → still reaches srv.
	status, _, err = New(srv.URL).Do(context.Background(), "POST", "https://other.example/x", [][2]string{{"K", "V"}}, nil)
	if err != nil || status != 200 {
		t.Fatalf("rewritten Do: status=%d err=%v", status, err)
	}

	// Transport error surfaces. Start a server, capture its URL, then Close() it so the address is
	// guaranteed-closed (deterministic, no reliance on an environment-specific port being shut).
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	dead.Close()
	if _, _, err := New("").Do(context.Background(), "GET", deadURL+"/x", nil, nil); err == nil {
		t.Fatal("expected a transport error")
	}
	// Bad method → request build error.
	if _, _, err := New("").Do(context.Background(), "bad method", srv.URL, nil, nil); err == nil {
		t.Fatal("expected a request-construction error")
	}
}
