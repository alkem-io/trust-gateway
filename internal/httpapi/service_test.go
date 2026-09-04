package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alkem-io/trust-gateway/internal/config"
	"github.com/alkem-io/trust-gateway/internal/flow"
	"github.com/alkem-io/trust-gateway/internal/session"
)

// --- test doubles (implement flow.SDK / flow.Effector, cgo-free) ---

type scriptSDK struct {
	steps []flow.Result
	i     int
}

func (s *scriptSDK) next() (flow.Result, error) {
	if s.i >= len(s.steps) {
		return flow.Result{}, io.EOF
	}
	r := s.steps[s.i]
	s.i++
	return r, nil
}
func (s *scriptSDK) Begin([]byte, string, *flow.Options) (flow.Result, error)        { return s.next() }
func (s *scriptSDK) ResumeRedirect([]byte, string, string) (flow.Result, error)      { return s.next() }
func (s *scriptSDK) ResumeRedirectError([]byte, string, string) (flow.Result, error) { return s.next() }
func (s *scriptSDK) ResumeHTTP([]byte, int, []byte) (flow.Result, error)             { return s.next() }

type nopEffector struct{}

func (nopEffector) Do(context.Context, string, string, [][2]string, []byte) (int, []byte, error) {
	return 200, []byte("{}"), nil
}
func (nopEffector) Rewrite(u string) string { return u }

func redirect(url, state string) flow.Result {
	return flow.Result{Handle: []byte("HANDLE-SECRET"), Step: map[string]any{"kind": "redirect", "url": url, "state": state}}
}
func performHTTP(url string) flow.Result {
	return flow.Result{Handle: []byte("HANDLE-SECRET"), Step: map[string]any{"kind": "perform_http", "method": "POST", "url": url, "headers": []any{}, "body": []byte("{}")}}
}
func done(pdf []byte) flow.Result {
	return flow.Result{Handle: []byte("HANDLE-SECRET"), Step: map[string]any{"kind": "done",
		"signed": map[string]any{"pdf": pdf},
		"evidence": map[string]any{
			"outcome": "signed", "request_digest": "abcd",
			"signer": map[string]any{
				"serial_number": "CERT-123", "common_name": "Ada Signer",
				"given_name": "Ada", "surname": "Signer",
				"raw_subject": "CN=Ada Signer,serialNumber=PNONL-123",
			},
		}}}
}

func happySteps() []flow.Result {
	return []flow.Result{
		redirect("https://cb/oauth2/authorize?scope=service", "s1"),
		performHTTP("https://cb/oauth2/token"),
		performHTTP("https://cb/csc/v1/credentials/list"),
		performHTTP("https://cb/csc/v1/credentials/info"),
		redirect("https://cb/oauth2/authorize?scope=credential", "s2"),
		performHTTP("https://cb/oauth2/token"),
		performHTTP("https://cb/csc/v1/signatures/signHash"),
		done([]byte("%PDF-signed")),
	}
}

func newService(steps []flow.Result, auth bool) *Service {
	store := session.NewMemory()
	eng := &flow.Engine{
		SDK:   &scriptSDK{steps: steps},
		Up:    nopEffector{},
		Store: store,
		Log:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		TTL:   time.Minute,
	}
	return &Service{
		Engine:  eng,
		Store:   store,
		Profile: &config.Profile{AuthEnabled: auth, APIKey: "test-key", DefaultConformance: "B-B"},
		Sample:  []byte("%PDF-sample"),
	}
}

func mustParseURL(t *testing.T, rawURL string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse URL %q: %v", rawURL, err)
	}
	return parsed
}

func do(t *testing.T, h http.Handler, method, target, body, key string) *httptest.ResponseRecorder {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, target, r)
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestAuthRequiredAndHealthOpen(t *testing.T) {
	h := newService(happySteps(), true).Handler()
	if rec := do(t, h, "POST", "/v1/sign/start", "{}", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing key should 401, got %d", rec.Code)
	}
	if rec := do(t, h, "POST", "/v1/sign/start", "{}", "wrong"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong key should 401, got %d", rec.Code)
	}
	if rec := do(t, h, "GET", "/healthz", "", ""); rec.Code != http.StatusOK {
		t.Fatalf("health should be open, got %d", rec.Code)
	}
}

func TestGatewayCallbackIsPublicAndRequiresState(t *testing.T) {
	h := newService(happySteps(), true).Handler()
	rec := do(t, h, http.MethodGet, "/oauth/cleverbase/callback?code=c", "", "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("public callback with missing state should 400 without an API key, got %d", rec.Code)
	}
}

func TestStartRejectsOversizeClientState(t *testing.T) {
	h := newService(happySteps(), false).Handler()
	body := `{"clientState":"` + strings.Repeat("x", 1025) + `"}`
	if rec := do(t, h, http.MethodPost, "/v1/sign/start", body, ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("oversize clientState should 400, got %d", rec.Code)
	}
}

func TestFullFlowOverHTTP(t *testing.T) {
	svc := newService(happySteps(), true)
	h := svc.Handler()

	rec := do(t, h, "POST", "/v1/sign/start", `{"conformanceLevel":"B-B"}`, "test-key")
	if rec.Code != http.StatusOK {
		t.Fatalf("start: %d %s", rec.Code, rec.Body)
	}
	var sr map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &sr); err != nil || sr["redirectUrl"] == "" || sr["correlationId"] == "" {
		t.Fatalf("start response: %s (%v)", rec.Body, err)
	}
	corr := sr["correlationId"]
	// First redirect return → drives token/list/info → second redirect.
	rec = do(t, h, "POST", "/v1/sign/complete", `{"code":"c1","state":"s1"}`, "test-key")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"authorizing"`) || !strings.Contains(rec.Body.String(), `"redirectUrl"`) {
		t.Fatalf("first complete: %d %s", rec.Code, rec.Body)
	}
	// Second redirect return → SAD + signHash → completed.
	rec = do(t, h, "POST", "/v1/sign/complete", `{"code":"c2","state":"s2"}`, "test-key")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"completed"`) {
		t.Fatalf("second complete: %d %s", rec.Code, rec.Body)
	}
	// Result fetch returns the signed PDF + evidence header.
	rec = do(t, h, "GET", "/v1/sign/result?correlationId="+corr, "", "test-key")
	if rec.Code != http.StatusOK || rec.Body.String() != "%PDF-signed" {
		t.Fatalf("result: %d %q", rec.Code, rec.Body)
	}
	if rec.Header().Get("X-Signature-Evidence") == "" {
		t.Fatal("missing evidence header")
	}
	// Status reports completed.
	rec = do(t, h, "GET", "/v1/sign/status?correlationId="+corr, "", "test-key")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"completed"`) {
		t.Fatalf("status: %d %s", rec.Code, rec.Body)
	}
}

func TestGatewayCallbackOwnsBothOAuthLegsAndReturnsOpaqueState(t *testing.T) { //nolint:gocyclo // The assertions pin one end-to-end callback contract.
	const (
		returnURL   = "https://alkemio.example/api/public/rest/content-signing/complete"
		clientState = "opaque continuation + / ? & ="
	)
	svc := newService(happySteps(), true)
	svc.Profile.ReturnURL = mustParseURL(t, returnURL)
	h := svc.Handler()

	startBody, err := json.Marshal(map[string]string{"clientState": clientState})
	if err != nil {
		t.Fatal(err)
	}
	start := do(t, h, http.MethodPost, "/v1/sign/start", string(startBody), "test-key")
	if start.Code != http.StatusOK {
		t.Fatalf("start: %d %s", start.Code, start.Body)
	}
	var sr map[string]string
	if err := json.Unmarshal(start.Body.Bytes(), &sr); err != nil || sr["correlationId"] == "" {
		t.Fatalf("start response: %s (%v)", start.Body, err)
	}

	// The gateway consumes the first callback itself and sends the browser directly to CB's second
	// authorization leg. The callback is public: neither request carries the private API key.
	first := do(t, h, http.MethodGet, "/oauth/cleverbase/callback?code=c1&state=s1", "", "")
	if first.Code != http.StatusFound || first.Header().Get("Location") != "https://cb/oauth2/authorize?scope=credential" {
		t.Fatalf("first callback = %d Location %q", first.Code, first.Header().Get("Location"))
	}
	if first.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("first callback Cache-Control = %q", first.Header().Get("Cache-Control"))
	}

	terminal := do(t, h, http.MethodGet, "/oauth/cleverbase/callback?code=c2&state=s2", "", "")
	if terminal.Code != http.StatusFound {
		t.Fatalf("terminal callback = %d body %s", terminal.Code, terminal.Body)
	}
	if terminal.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("terminal callback Cache-Control = %q", terminal.Header().Get("Cache-Control"))
	}
	location, err := url.Parse(terminal.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse terminal Location: %v", err)
	}
	if location.Scheme+"://"+location.Host+location.Path != returnURL {
		t.Fatalf("terminal return base = %q, want %q", location.Scheme+"://"+location.Host+location.Path, returnURL)
	}
	query := location.Query()
	if len(query) != 2 || query.Get("correlationId") != sr["correlationId"] || query.Get("clientState") != clientState {
		t.Fatalf("terminal query = %v", query)
	}
	for _, forbidden := range []string{"code", "state", "status", "error"} {
		if query.Has(forbidden) {
			t.Fatalf("terminal redirect must not expose %q: %v", forbidden, query)
		}
	}

	// Result retrieval remains private and idempotent.
	if rec := do(t, h, http.MethodGet, "/v1/sign/result?correlationId="+url.QueryEscape(sr["correlationId"]), "", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("result without API key should 401, got %d", rec.Code)
	}
	var firstPDF, firstEvidence string
	for i := 0; i < 2; i++ {
		result := do(t, h, http.MethodGet, "/v1/sign/result?correlationId="+url.QueryEscape(sr["correlationId"]), "", "test-key")
		if result.Code != http.StatusOK {
			t.Fatalf("result fetch %d: %d %s", i+1, result.Code, result.Body)
		}
		if i == 0 {
			firstPDF, firstEvidence = result.Body.String(), result.Header().Get("X-Signature-Evidence")
		} else if result.Body.String() != firstPDF || result.Header().Get("X-Signature-Evidence") != firstEvidence {
			t.Fatal("repeated result fetch must return the same PDF and evidence")
		}
	}
	evidenceJSON, err := base64.StdEncoding.DecodeString(firstEvidence)
	if err != nil {
		t.Fatalf("decode evidence: %v", err)
	}
	var evidence map[string]any
	if err := json.Unmarshal(evidenceJSON, &evidence); err != nil {
		t.Fatalf("parse evidence: %v", err)
	}
	signer, _ := evidence["signer"].(map[string]any)
	if signer["serial_number"] != "CERT-123" || signer["raw_subject"] != "CN=Ada Signer,serialNumber=PNONL-123" {
		t.Fatalf("signer identity missing from evidence: %v", signer)
	}
	if _, duplicated := evidence["cert_chain"]; duplicated {
		t.Fatal("certificate chain must not be duplicated into the evidence header")
	}
}

func TestGatewayCallbackReturnsForDeclinedAndFailed(t *testing.T) {
	cases := []struct {
		name     string
		steps    []flow.Result
		callback string
	}{
		{"declined", []flow.Result{redirect("https://cb/a", "s1"), {Handle: []byte("h"), Step: map[string]any{"kind": "failed", "evidence": map[string]any{"outcome": "declined"}}}}, "/oauth/cleverbase/callback?error=access_denied&state=s1"},
		{"failed", []flow.Result{redirect("https://cb/a", "s1"), {Handle: []byte("h"), Step: map[string]any{"kind": "failed", "evidence": map[string]any{"outcome": "invalid_document"}}}}, "/oauth/cleverbase/callback?code=c1&state=s1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := newService(tc.steps, true)
			svc.Profile.ReturnURL = mustParseURL(t, "https://alkemio.example/complete")
			h := svc.Handler()
			start := do(t, h, http.MethodPost, "/v1/sign/start", `{"clientState":"opaque-attempt"}`, "test-key")
			var sr map[string]string
			if err := json.Unmarshal(start.Body.Bytes(), &sr); err != nil || sr["correlationId"] == "" {
				t.Fatalf("start: %d %s (%v)", start.Code, start.Body, err)
			}
			callback := do(t, h, http.MethodGet, tc.callback, "", "")
			if callback.Code != http.StatusFound {
				t.Fatalf("callback = %d body %s", callback.Code, callback.Body)
			}
			location, err := url.Parse(callback.Header().Get("Location"))
			if err != nil {
				t.Fatal(err)
			}
			query := location.Query()
			if len(query) != 2 || query.Get("correlationId") != sr["correlationId"] || query.Get("clientState") != "opaque-attempt" {
				t.Fatalf("terminal query = %v", query)
			}
		})
	}
}

func TestGatewayCallbackValidationAndExactPublicRoute(t *testing.T) {
	svc := newService(happySteps(), true)
	svc.Profile.ReturnURL = mustParseURL(t, "https://alkemio.example/complete")
	h := svc.Handler()
	for _, target := range []string{
		"/oauth/cleverbase/callback",
		"/oauth/cleverbase/callback?code=c",
		"/oauth/cleverbase/callback?state=s1",
	} {
		if rec := do(t, h, http.MethodGet, target, "", ""); rec.Code != http.StatusBadRequest {
			t.Fatalf("invalid public callback %q should 400, got %d", target, rec.Code)
		}
	}
	if rec := do(t, h, http.MethodGet, "/oauth/cleverbase/callback/extra?code=c&state=s", "", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("only the exact callback route is public, sibling path got %d", rec.Code)
	}
	if rec := do(t, h, http.MethodPost, "/oauth/cleverbase/callback", "", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("only GET on the exact callback route is public, POST got %d", rec.Code)
	}
	if rec := do(t, h, http.MethodHead, "/oauth/cleverbase/callback", "", ""); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("HEAD on the public callback must be rejected with 405, got %d", rec.Code)
	}
}

func TestGatewayCallbackRejectsConsumedStateOnRefresh(t *testing.T) {
	svc := newService(happySteps(), true)
	svc.Profile.ReturnURL = mustParseURL(t, "https://alkemio.example/complete")
	handler := svc.Handler()
	start := do(t, handler, http.MethodPost, "/v1/sign/start", `{"clientState":"attempt"}`, "test-key")
	if start.Code != http.StatusOK {
		t.Fatalf("start = %d %s", start.Code, start.Body)
	}
	first := do(t, handler, http.MethodGet, "/oauth/cleverbase/callback?code=c1&state=s1", "", "")
	if first.Code != http.StatusFound {
		t.Fatalf("first callback = %d %s", first.Code, first.Body)
	}
	replay := do(t, handler, http.MethodGet, "/oauth/cleverbase/callback?code=c1&state=s1", "", "")
	if replay.Code != http.StatusBadRequest || !strings.Contains(replay.Body.String(), `"error":"unknown_state"`) {
		t.Fatalf("replayed callback = %d %s", replay.Code, replay.Body)
	}
}

func TestGatewayCallbackReturnsAfterInternalResumeFailure(t *testing.T) {
	svc := newService([]flow.Result{redirect("https://cb/a", "s1")}, true) // resume exhausts the SDK script
	svc.Profile.ReturnURL = mustParseURL(t, "https://alkemio.example/complete")
	h := svc.Handler()
	start := do(t, h, http.MethodPost, "/v1/sign/start", `{"clientState":"opaque-attempt"}`, "test-key")
	var sr map[string]string
	if err := json.Unmarshal(start.Body.Bytes(), &sr); err != nil || sr["correlationId"] == "" {
		t.Fatalf("start: %d %s (%v)", start.Code, start.Body, err)
	}
	callback := do(t, h, http.MethodGet, "/oauth/cleverbase/callback?code=c1&state=s1", "", "")
	if callback.Code != http.StatusFound {
		t.Fatalf("terminal internal failure must return the browser, got %d %s", callback.Code, callback.Body)
	}
	location, err := url.Parse(callback.Header().Get("Location"))
	if err != nil || location.Query().Get("correlationId") != sr["correlationId"] || location.Query().Get("clientState") != "opaque-attempt" {
		t.Fatalf("terminal failure Location = %q (%v)", callback.Header().Get("Location"), err)
	}
	status := do(t, h, http.MethodGet, "/v1/sign/status?correlationId="+url.QueryEscape(sr["correlationId"]), "", "test-key")
	if status.Code != http.StatusOK || !strings.Contains(status.Body.String(), `"status":"failed"`) || !strings.Contains(status.Body.String(), `"reason":"resume_error"`) {
		t.Fatalf("server-to-server status must carry the failure: %d %s", status.Code, status.Body)
	}
}

func TestGatewayCallbackFailsClosedWithoutConfiguredReturn(t *testing.T) {
	svc := newService(happySteps(), false)
	h := svc.Handler()
	_ = do(t, h, http.MethodPost, "/v1/sign/start", `{}`, "")
	_ = do(t, h, http.MethodGet, "/oauth/cleverbase/callback?code=c1&state=s1", "", "")
	terminal := do(t, h, http.MethodGet, "/oauth/cleverbase/callback?code=c2&state=s2", "", "")
	if terminal.Code != http.StatusInternalServerError {
		t.Fatalf("terminal callback without TRUST_GATEWAY_RETURN_URL should 500, got %d", terminal.Code)
	}
}

func TestWriteCompleteErrorLogsConflictAsClientCondition(t *testing.T) {
	svc := newService(happySteps(), false)
	var logs strings.Builder
	svc.Log = slog.New(slog.NewTextHandler(&logs, nil))
	rec := httptest.NewRecorder()
	svc.writeCompleteError(rec, session.ErrResuming)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), errCodeAlreadyProcessing) {
		t.Fatalf("duplicate completion = %d %s", rec.Code, rec.Body)
	}
	if !strings.Contains(logs.String(), "level=INFO") || strings.Contains(logs.String(), "level=ERROR") {
		t.Fatalf("duplicate completion log = %q, want INFO and no ERROR", logs.String())
	}
}

func TestConfiguredReturnRequiresClientState(t *testing.T) {
	svc := newService(happySteps(), false)
	svc.Profile.ReturnURL = mustParseURL(t, "https://alkemio.example/complete")
	rec := do(t, svc.Handler(), http.MethodPost, "/v1/sign/start", `{"document":"not-base64"}`, "")
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "clientState is required") {
		t.Fatalf("start must reject clientState before document decoding: %d %s", rec.Code, rec.Body)
	}
}

func TestTerminalCompleteResultUsesEntireTerminalStatusSet(t *testing.T) {
	for _, status := range []session.Status{session.StatusCompleted, session.StatusDeclined, session.StatusFailed} {
		if !returnsToApplication(completeResult{Status: status, CorrelationID: "corr"}, errors.New("duplicate")) {
			t.Fatalf("terminal status %q did not return to the application", status)
		}
	}
	if returnsToApplication(completeResult{Status: session.StatusAuthorizing, CorrelationID: "corr"}, errors.New("resume")) {
		t.Fatal("non-terminal status returned to the application")
	}
	if returnsToApplication(completeResult{Status: session.StatusFailed}, errors.New("resume")) {
		t.Fatal("terminal result without a correlation ID returned to the application")
	}
}

func TestClientStateSizeBoundary(t *testing.T) {
	h := newService(happySteps(), false).Handler()
	body := `{"clientState":"` + strings.Repeat("x", maxClientStateBytes) + `"}`
	if rec := do(t, h, http.MethodPost, "/v1/sign/start", body, ""); rec.Code != http.StatusOK {
		t.Fatalf("clientState at the size limit should be accepted, got %d", rec.Code)
	}
}

func TestClientStateNeverLogged(t *testing.T) {
	const opaque = "DO-NOT-LOG-client-state"
	svc := newService(happySteps(), false)
	svc.Profile.ReturnURL = mustParseURL(t, "https://alkemio.example/complete")
	var logs strings.Builder
	svc.Log = slog.New(slog.NewTextHandler(&logs, nil))
	h := svc.Handler()
	_ = do(t, h, http.MethodPost, "/v1/sign/start", `{"clientState":"`+opaque+`"}`, "")
	_ = do(t, h, http.MethodGet, "/oauth/cleverbase/callback?code=c1&state=s1", "", "")
	_ = do(t, h, http.MethodGet, "/oauth/cleverbase/callback?code=c2&state=s2", "", "")
	if strings.Contains(logs.String(), opaque) {
		t.Fatalf("clientState leaked to logs: %s", logs.String())
	}
}

func TestStartErrors(t *testing.T) {
	h := newService(happySteps(), false).Handler()
	if rec := do(t, h, "POST", "/v1/sign/start", "{not json", ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad json should 400, got %d", rec.Code)
	}
	if rec := do(t, h, "POST", "/v1/sign/start", `{"document":"!!!notb64"}`, ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad base64 should 400, got %d", rec.Code)
	}
	// No document and no bundled sample.
	svc := newService(happySteps(), false)
	svc.Sample = nil
	if rec := do(t, svc.Handler(), "POST", "/v1/sign/start", `{}`, ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("empty doc+sample should 400, got %d", rec.Code)
	}
}

func TestStartRejectsOversizeBody(t *testing.T) {
	h := newService(happySteps(), false).Handler()

	// 1) A raw JSON body above the MaxBytesReader cap → 413 (trips during decode, before any
	//    document allocation).
	bigBody := `{"document":"` + strings.Repeat("A", maxStartBodyBytes+1) + `"}`
	if rec := do(t, h, "POST", "/v1/sign/start", bigBody, ""); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize body should 413, got %d", rec.Code)
	}

	// 2) A body within the raw cap but whose decoded document exceeds maxPDFBytes → 413. Use valid
	//    base64 (a repeated 'A' is base64 for 0x00 triples) just over the decoded limit.
	overB64Len := base64.StdEncoding.EncodedLen(maxPDFBytes + 3)
	if overB64Len >= maxStartBodyBytes {
		t.Fatalf("test invariant: oversized-document base64 (%d) must fit under the raw body cap (%d)", overB64Len, maxStartBodyBytes)
	}
	overDoc := `{"document":"` + strings.Repeat("A", overB64Len) + `"}`
	if rec := do(t, h, "POST", "/v1/sign/start", overDoc, ""); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize decoded document should 413, got %d", rec.Code)
	}
}

func TestCompleteRejectsOversizeBody(t *testing.T) {
	h := newService(happySteps(), false).Handler()
	bigBody := `{"state":"` + strings.Repeat("A", maxCompleteBodyBytes+1) + `"}`
	if rec := do(t, h, "POST", "/v1/sign/complete", bigBody, ""); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize complete body should 413, got %d", rec.Code)
	}
}

func TestCompleteRejectsMalformedJSON(t *testing.T) {
	h := newService(happySteps(), false).Handler()
	if rec := do(t, h, http.MethodPost, "/v1/sign/complete", "{not-json", ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed complete JSON should 400, got %d", rec.Code)
	}
}

func TestStartDefaultsAndExpectedSigner(t *testing.T) {
	h := newService(happySteps(), false).Handler()
	// Omitted conformanceLevel → profile default; explicit document (base64 of "%PDF").
	body := `{"document":"JVBERg==","expectedSigner":{"matchOn":"certificate_serial_number","value":"PNONL-1"}}`
	if rec := do(t, h, "POST", "/v1/sign/start", body, ""); rec.Code != http.StatusOK {
		t.Fatalf("start with options: %d %s", rec.Code, rec.Body)
	}
}

func TestCompleteErrorDeclinedHTTP(t *testing.T) {
	steps := make([]flow.Result, 0, 2)
	steps = append(steps, redirect("https://cb/a", "s1"))
	steps = append(steps, flow.Result{Handle: []byte("h"), Step: map[string]any{"kind": "failed",
		"evidence": map[string]any{"outcome": "declined"}}})
	h := newService(steps, false).Handler()
	_ = do(t, h, "POST", "/v1/sign/start", `{}`, "")
	rec := do(t, h, "POST", "/v1/sign/complete", `{"error":"access_denied","state":"s1"}`, "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"declined"`) {
		t.Fatalf("decline: %d %s", rec.Code, rec.Body)
	}
	// Per the contract, a non-failed status (declined) carries no `reason`.
	if strings.Contains(rec.Body.String(), `"reason"`) {
		t.Fatalf("declined response must not include a reason: %s", rec.Body)
	}
	// A complete with neither code nor error is a 400.
	if rec := do(t, h, "POST", "/v1/sign/complete", `{"state":"s1"}`, ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("empty complete should 400, got %d", rec.Code)
	}
}

func TestResultNotCompleted(t *testing.T) {
	svc := newService([]flow.Result{redirect("https://cb/a", "s1")}, false) // stays authorizing
	h := svc.Handler()
	rec := do(t, h, "POST", "/v1/sign/start", `{}`, "")
	var sr map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &sr)
	if rec := do(t, h, "GET", "/v1/sign/result?correlationId="+sr["correlationId"], "", ""); rec.Code != http.StatusConflict {
		t.Fatalf("result of a non-completed session should 409, got %d", rec.Code)
	}
	if rec := do(t, h, "GET", "/v1/sign/result?correlationId=nope", "", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("result of unknown id should 404, got %d", rec.Code)
	}
}

func TestStartBeginAndResumeErrors(t *testing.T) {
	// Begin error → 500 (empty script).
	if rec := do(t, newService(nil, false).Handler(), "POST", "/v1/sign/start", `{}`, ""); rec.Code != http.StatusInternalServerError {
		t.Fatalf("begin error should 500, got %d", rec.Code)
	}
	// Resume error → 500 (begin redirect, then exhausted script).
	h := newService([]flow.Result{redirect("https://cb/a", "s1")}, false).Handler()
	_ = do(t, h, "POST", "/v1/sign/start", `{}`, "")
	if rec := do(t, h, "POST", "/v1/sign/complete", `{"code":"c","state":"s1"}`, ""); rec.Code != http.StatusInternalServerError {
		t.Fatalf("resume error should 500, got %d", rec.Code)
	}
}

func TestStatusReportsReason(t *testing.T) {
	steps := []flow.Result{redirect("https://cb/a", "s1"),
		{Handle: []byte("h"), Step: map[string]any{"kind": "failed", "evidence": map[string]any{"outcome": "invalid_document"}}}}
	h := newService(steps, false).Handler()
	rec := do(t, h, "POST", "/v1/sign/start", `{}`, "")
	var sr map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &sr)
	cr := do(t, h, "POST", "/v1/sign/complete", `{"code":"c","state":"s1"}`, "")
	if !strings.Contains(cr.Body.String(), `"reason":"invalid_document"`) {
		t.Fatalf("complete should include reason: %s", cr.Body)
	}
	st := do(t, h, "GET", "/v1/sign/status?correlationId="+sr["correlationId"], "", "")
	if !strings.Contains(st.Body.String(), `"invalid_document"`) {
		t.Fatalf("status should include reason: %s", st.Body)
	}
}

func TestStatusAndResultErrors(t *testing.T) {
	h := newService(happySteps(), false).Handler() // auth disabled
	if rec := do(t, h, "GET", "/v1/sign/status?correlationId=nope", "", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown status should 404, got %d", rec.Code)
	}
	if rec := do(t, h, "POST", "/v1/sign/complete", `{"code":"c","state":"nope"}`, ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown state should 400, got %d", rec.Code)
	}
}

func TestLogReturnsConfiguredLoggerElseDiscard(t *testing.T) {
	l := slog.New(slog.NewTextHandler(io.Discard, nil))
	if (&Service{Log: l}).log() != l {
		t.Fatal("log() must return the configured logger when Log is set")
	}
	if (&Service{}).log() == nil {
		t.Fatal("log() must return a non-nil discard logger when Log is unset")
	}
}

func TestStartRNGFailureReturns500(t *testing.T) {
	orig := randRead
	randRead = func([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
	t.Cleanup(func() { randRead = orig })
	h := newService(happySteps(), false).Handler()
	rec := do(t, h, "POST", "/v1/sign/start", `{"conformanceLevel":"B-B"}`, "")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("a failed RNG must fail the start request (500), got %d %s", rec.Code, rec.Body)
	}
}

func TestCompleteMissingStateAndNeitherCodeNorError(t *testing.T) {
	h := newService(happySteps(), false).Handler()
	// Missing state → 400.
	if rec := do(t, h, "POST", "/v1/sign/complete", `{"code":"c"}`, ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("missing state should 400, got %d", rec.Code)
	}
	// A pending session exists at state "s1" (happySteps' first redirect); a body with the state but
	// neither code nor error hits the "neither code nor error" branch → 400.
	do(t, h, "POST", "/v1/sign/start", `{"conformanceLevel":"B-B"}`, "")
	if rec := do(t, h, "POST", "/v1/sign/complete", `{"state":"s1"}`, ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("neither code nor error should 400, got %d", rec.Code)
	}
}

// TestClassifyCompleteError pins the handleComplete error mapping deterministically: a raced
// duplicate callback (rejected by flow.consume() with flow.ErrTerminal when the winner already
// finished, or session.ErrResuming when the winner is still in-flight) is a CLIENT condition that
// MUST map to 409 already_processing (conflict) — never the SDK/upstream-error 500 reserved for a
// genuine internal resume failure. The two duplicate-conflict errors are wrapped to prove the mapping
// uses errors.Is (not ==), since flow.consume()/Engine.Complete may return a wrapped error.
func TestClassifyCompleteError(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		wantCode   int
		wantErrStr string
		wantConfl  bool
	}{
		{"in-flight duplicate (ErrResuming)", session.ErrResuming, http.StatusConflict, errCodeAlreadyProcessing, true},
		{"already terminal (flow.ErrTerminal)", flow.ErrTerminal, http.StatusConflict, errCodeAlreadyProcessing, true},
		{"wrapped ErrResuming", fmt.Errorf("resume: %w", session.ErrResuming), http.StatusConflict, errCodeAlreadyProcessing, true},
		{"wrapped flow.ErrTerminal", fmt.Errorf("advance: %w", flow.ErrTerminal), http.StatusConflict, errCodeAlreadyProcessing, true},
		{"internal failure", errors.New("upstream 502"), http.StatusInternalServerError, "resume_failed", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, errCode, msg, conflict := classifyCompleteError(c.err)
			if code != c.wantCode || errCode != c.wantErrStr || conflict != c.wantConfl {
				t.Fatalf("classify(%v) = (%d, %q, conflict=%v), want (%d, %q, conflict=%v)",
					c.err, code, errCode, conflict, c.wantCode, c.wantErrStr, c.wantConfl)
			}
			if msg == "" {
				t.Fatal("classify must return a non-empty generic client message (no leaked internal text)")
			}
			if strings.Contains(msg, c.err.Error()) {
				t.Fatalf("client message %q must not leak the internal error text %q", msg, c.err.Error())
			}
		})
	}
}

// TestCompleteConcurrentDuplicateNeverFivehundred drives many concurrent duplicate callbacks for the
// SAME pending state through the real HTTP handler and asserts the regression the 409 mapping fixed:
// a raced/duplicate callback is NEVER answered with a 500. Exactly one callback wins the resume
// (drives the non-idempotent effects once); every loser is a 4xx client condition — a 409
// already_processing if it raced past GetByState and lost the consume, or a 400 unknown_state if it
// arrived after the winner de-indexed the state. (Run under `go test -race`, this also proves the
// concurrent callbacks do not corrupt shared store state.)
func TestCompleteConcurrentDuplicateNeverFivehundred(t *testing.T) {
	svc := newService([]flow.Result{
		redirect("https://cb/a", "s1"),
		performHTTP("https://cb/token"),
		done([]byte("%PDF-signed")),
	}, false)
	h := svc.Handler()
	if rec := do(t, h, "POST", "/v1/sign/start", `{}`, ""); rec.Code != http.StatusOK {
		t.Fatalf("start: %d %s", rec.Code, rec.Body)
	}

	const callers = 8
	start := make(chan struct{})
	codes := make([]int, callers)
	var wg sync.WaitGroup
	for i := range codes {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start
			codes[idx] = do(t, h, "POST", "/v1/sign/complete", `{"code":"c1","state":"s1"}`, "").Code
		}(i)
	}
	close(start)
	wg.Wait()

	winners := 0
	for _, c := range codes {
		switch c {
		case http.StatusOK:
			winners++
		case http.StatusConflict, http.StatusBadRequest: // 4xx client conditions are fine
		default:
			t.Fatalf("a raced duplicate callback must never be a 5xx, got %d (codes=%v)", c, codes)
		}
	}
	if winners != 1 {
		t.Fatalf("exactly one callback should win the resume, got %d (codes=%v)", winners, codes)
	}
}
