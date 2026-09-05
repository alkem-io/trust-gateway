package flow

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alkem-io/trust-gateway/internal/session"
)

// scriptedSDK returns a fixed sequence of Results, one per SDK call.
type scriptedSDK struct {
	steps []Result
	i     int
}

func (s *scriptedSDK) next() (Result, error) {
	if s.i >= len(s.steps) {
		return Result{}, io.EOF
	}
	r := s.steps[s.i]
	s.i++
	return r, nil
}
func (s *scriptedSDK) Begin([]byte, string, *Options) (Result, error)        { return s.next() }
func (s *scriptedSDK) ResumeRedirect([]byte, string, string) (Result, error) { return s.next() }
func (s *scriptedSDK) ResumeRedirectError([]byte, string, string) (Result, error) {
	return s.next()
}
func (s *scriptedSDK) ResumeHTTP([]byte, int, []byte) (Result, error) { return s.next() }
func (*scriptedSDK) VerifyPDF([]byte) (PDFVerification, error)        { return PDFVerification{}, nil }

type fakeEffector struct {
	rewritePrefix string
	calls         []string
}

func (f *fakeEffector) Do(_ context.Context, _, rawURL string, _ [][2]string, _ []byte) (int, []byte, error) {
	f.calls = append(f.calls, rawURL)
	return 200, []byte("{}"), nil
}
func (f *fakeEffector) Rewrite(u string) string {
	if f.rewritePrefix == "" {
		return u
	}
	return f.rewritePrefix + u
}

func redirect(url, state string) Result {
	return Result{Handle: []byte("h"), Step: map[string]any{"kind": "redirect", "url": url, "state": state}}
}
func performHTTP(url string) Result {
	return Result{Handle: []byte("h"), Step: map[string]any{"kind": "perform_http", "method": "POST", "url": url, "headers": []any{}, "body": []byte("{}")}}
}
func done(pdf []byte) Result {
	return Result{Handle: []byte("h"), Step: map[string]any{"kind": "done",
		"signed":   map[string]any{"pdf": pdf},
		"evidence": map[string]any{"outcome": "signed", "request_digest": "abcd"}}}
}
func failed(outcome string) Result {
	return Result{Handle: []byte("h"), Step: map[string]any{"kind": "failed",
		"evidence": map[string]any{"outcome": outcome, "failure_reason": "x"}}}
}

func newEngine(steps []Result) (*Engine, *fakeEffector) {
	up := &fakeEffector{}
	return &Engine{
		SDK:   &scriptedSDK{steps: steps},
		Up:    up,
		Store: session.NewMemory(),
		Log:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		TTL:   time.Minute,
	}, up
}

func TestFullHappyFlow(t *testing.T) {
	e, up := newEngine([]Result{
		redirect("https://cb/oauth2/authorize?scope=service", "s1"), // begin
		performHTTP("https://cb/oauth2/token"),                      // resume(code,s1)
		performHTTP("https://cb/csc/v1/credentials/list"),
		performHTTP("https://cb/csc/v1/credentials/info"),
		redirect("https://cb/oauth2/authorize?scope=credential&hash=SECRET", "s2"),
		performHTTP("https://cb/oauth2/token"), // resume(code,s2)
		performHTTP("https://cb/csc/v1/signatures/signHash"),
		done([]byte("%PDF-signed")),
	})

	url, _, err := e.Begin("corr-1", []byte("%PDF"), "B-B", "opaque-client-state", nil)
	if err != nil || url == "" {
		t.Fatalf("begin: %v url=%q", err, url)
	}
	s, _ := e.Store.GetByState("s1")
	if s == nil || s.Status != session.StatusAuthorizing || s.ClientState != "opaque-client-state" {
		t.Fatal("session not stored at s1")
	}

	st, url2, _, err := e.Complete(context.Background(), s, "code1", "s1")
	if err != nil || st != session.StatusAuthorizing || url2 == "" {
		t.Fatalf("first complete: st=%s url=%q err=%v", st, url2, err)
	}
	if s.OAuthState != "s2" {
		t.Fatalf("state should be re-indexed to s2, got %q", s.OAuthState)
	}

	st, _, _, err = e.Complete(context.Background(), s, "code2", "s2")
	if err != nil || st != session.StatusCompleted {
		t.Fatalf("second complete: st=%s err=%v", st, err)
	}
	if string(s.ResultPDF) != "%PDF-signed" {
		t.Fatalf("result pdf missing: %q", s.ResultPDF)
	}
	if s.Handle != nil {
		t.Fatal("handle should be scrubbed on completion")
	}
	if len(up.calls) != 5 { // token, list, info, sad, signHash
		t.Fatalf("expected 5 upstream calls, got %d", len(up.calls))
	}
}

func TestBeginReturnsTheStoreExpiry(t *testing.T) {
	e, _ := newEngine([]Result{redirect("https://cb/oauth2/authorize", "state")})
	_, expiresAt, err := e.Begin("corr", []byte("%PDF"), "B-B", "", nil)
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}
	session, err := e.Store.GetByState("state")
	if err != nil {
		t.Fatalf("GetByState() error = %v", err)
	}
	if !expiresAt.Equal(session.ExpiresAt) {
		t.Fatalf("Begin() expiry = %s, store expiry = %s", expiresAt, session.ExpiresAt)
	}
}

func TestOutcomeMappingAllDistinct(t *testing.T) {
	cases := map[string]struct {
		status session.Status
		reason string
	}{
		"declined":                   {session.StatusDeclined, "declined"},
		"authorization_expired":      {session.StatusFailed, "authorization_expired"},
		"credential_unavailable":     {session.StatusFailed, "credential_unavailable"},
		"identity_mismatch":          {session.StatusFailed, "identity_mismatch"},
		"invalid_document":           {session.StatusFailed, "invalid_document"},
		"timestamp_failed":           {session.StatusFailed, "timestamp_failed"},
		"appearance_placement_error": {session.StatusFailed, "appearance_placement_error"},
		"signature_invalid":          {session.StatusFailed, "signature_invalid"},
	}
	seen := map[string]bool{}
	for outcome, want := range cases {
		e, _ := newEngine([]Result{
			redirect("https://cb/oauth2/authorize", "s1"),
			failed(outcome),
		})
		_, _, _ = e.Begin("c", []byte("%PDF"), "B-B", "", nil)
		s, _ := e.Store.GetByState("s1")
		st, _, reason, err := e.Complete(context.Background(), s, "code", "s1")
		if err != nil {
			t.Fatalf("%s: %v", outcome, err)
		}
		if st != want.status || reason != want.reason {
			t.Fatalf("%s → %s/%s, want %s/%s", outcome, st, reason, want.status, want.reason)
		}
		key := string(st) + "/" + reason
		if seen[key] {
			t.Fatalf("outcome %s collapses to a non-distinct %s", outcome, key)
		}
		seen[key] = true
	}
}

type errEffector struct{}

func (errEffector) Do(context.Context, string, string, [][2]string, []byte) (int, []byte, error) {
	return 0, nil, io.ErrUnexpectedEOF
}
func (errEffector) Rewrite(u string) string { return u }

func TestCompleteErrorDeclined(t *testing.T) {
	e, _ := newEngine([]Result{redirect("https://cb/a", "s1"), failed("declined")})
	_, _, _ = e.Begin("c", []byte("%PDF"), "B-B", "", nil)
	s, _ := e.Store.GetByState("s1")
	st, _, reason, err := e.CompleteError(context.Background(), s, "access_denied", "s1")
	if err != nil || st != session.StatusDeclined || reason != "declined" {
		t.Fatalf("decline: st=%s reason=%s err=%v", st, reason, err)
	}
	if _, _, _, err := e.CompleteError(context.Background(), s, "x", "s1"); !errors.Is(err, ErrTerminal) {
		t.Fatal("expected ErrTerminal on terminal CompleteError")
	}
}

func TestUpstreamErrorBecomesFailed(t *testing.T) {
	e := &Engine{
		SDK:   &scriptedSDK{steps: []Result{redirect("https://cb/a", "s1"), performHTTP("https://cb/token")}},
		Up:    errEffector{},
		Store: session.NewMemory(),
		Log:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		TTL:   time.Minute,
	}
	_, _, _ = e.Begin("c", []byte("%PDF"), "B-B", "", nil)
	s, _ := e.Store.GetByState("s1")
	st, _, reason, err := e.Complete(context.Background(), s, "code", "s1")
	if err != nil || st != session.StatusFailed || reason != "upstream_error" {
		t.Fatalf("upstream error: st=%s reason=%s err=%v", st, reason, err)
	}
}

func TestBeginUnexpectedStepIsError(t *testing.T) {
	e, _ := newEngine([]Result{performHTTP("https://cb/x")})
	if _, _, err := e.Begin("c", []byte("%PDF"), "B-B", "", nil); err == nil {
		t.Fatal("begin with a non-redirect first step should error")
	}
}

func TestBeginWithExpectedSignerOption(t *testing.T) {
	e, _ := newEngine([]Result{redirect("https://cb/a", "s1")})
	opts := &Options{ExpectedSignerMatchOn: "certificate_serial_number", ExpectedSignerValue: "PNONL-123"}
	if _, _, err := e.Begin("c", []byte("%PDF"), "B-B", "client-state", opts); err != nil {
		t.Fatalf("begin with opts: %v", err)
	}
}

func TestConsumeDeterministicallyMapsBusyAndTerminal(t *testing.T) {
	e, _ := newEngine(nil)
	sess := e.Store.New("corr", "state", "client", "B-B", time.Minute)
	e.Store.Update(sess, func() { sess.Handle = []byte("handle") })
	if handle, err := e.consume(sess); err != nil || string(handle) != "handle" {
		t.Fatalf("first consume = %q, %v", handle, err)
	}
	if _, err := e.consume(sess); !errors.Is(err, session.ErrResuming) {
		t.Fatalf("second consume error = %v, want ErrResuming", err)
	}
	e.Store.Update(sess, func() { sess.Status = session.StatusCompleted })
	e.Store.Finalize(sess)
	if _, err := e.consume(sess); !errors.Is(err, ErrTerminal) {
		t.Fatalf("terminal consume error = %v, want ErrTerminal", err)
	}
}

func TestEvidenceMarshalFailureFailsSession(t *testing.T) {
	e, _ := newEngine([]Result{
		redirect("https://cb/a", "state"),
		{Handle: []byte("h"), Step: map[string]any{
			"kind": "done", "signed": map[string]any{"pdf": []byte("%PDF")},
			"evidence": make(chan int),
		}},
	})
	_, _, _ = e.Begin("corr", []byte("%PDF"), "B-B", "", nil)
	sess, _ := e.Store.GetByState("state")
	if _, _, _, err := e.Complete(context.Background(), sess, "code", "state"); err == nil {
		t.Fatal("Complete() silently accepted evidence that cannot be serialized")
	}
	view, err := e.Store.ViewByID("corr")
	if err != nil || view.Status != session.StatusFailed || view.Reason != reasonResumeError || len(view.Evidence) != 0 {
		t.Fatalf("failed session = %+v, %v", view, err)
	}
}

func TestFailedEvidenceMarshalFailureFailsSession(t *testing.T) {
	e, _ := newEngine([]Result{
		redirect("https://cb/a", "state"),
		{Handle: []byte("h"), Step: map[string]any{
			"kind": "failed", "evidence": make(chan int),
		}},
	})
	_, _, _ = e.Begin("corr", []byte("%PDF"), "B-B", "", nil)
	sess, _ := e.Store.GetByState("state")
	if _, _, _, err := e.Complete(context.Background(), sess, "code", "state"); err == nil {
		t.Fatal("Complete() silently accepted failed evidence that cannot be serialized")
	}
	view, err := e.Store.ViewByID("corr")
	if err != nil || view.Status != session.StatusFailed || view.Reason != reasonResumeError || len(view.Evidence) != 0 {
		t.Fatalf("failed session = %+v, %v", view, err)
	}
}

func TestOptionsValidateRequiresCompleteExpectedSigner(t *testing.T) {
	for _, options := range []*Options{
		{ExpectedSignerMatchOn: "certificate_serial_number"},
		{ExpectedSignerValue: "PNONL-123"},
	} {
		if err := options.Validate(); err == nil {
			t.Fatalf("Validate() accepted incomplete expected signer: %+v", options)
		}
	}
	for _, options := range []*Options{
		nil,
		{},
		{ExpectedSignerMatchOn: "certificate_serial_number", ExpectedSignerValue: "PNONL-123"},
	} {
		if err := options.Validate(); err != nil {
			t.Fatalf("Validate() rejected complete options %+v: %v", options, err)
		}
	}
}

func TestRedactHandlesBadURL(t *testing.T) {
	if got := redact("://bad url"); got == "" {
		t.Fatalf("redact should not return empty, got %q", got)
	}
}

func TestStepHelpers(t *testing.T) {
	ef, err := stepHTTP(map[string]any{
		"method": "POST", "url": "u",
		"headers": []any{[]any{"K", "V"}, "bad", []any{"only-one"}},
		"body":    []byte("b"),
	})
	if err != nil || ef.method != "POST" || ef.rawURL != "u" || len(ef.headers) != 1 || ef.headers[0] != [2]string{"K", "V"} || string(ef.body) != "b" {
		t.Fatalf("stepHTTP: %v / %s %s %v %q", err, ef.method, ef.rawURL, ef.headers, ef.body)
	}
	// Fail-fast: a perform_http/redirect/done step missing required fields is an error, not a coerced
	// zero value that would flow downstream as an empty URL/state/PDF.
	if _, err := stepHTTP(map[string]any{"url": "u"}); err == nil {
		t.Fatal("perform_http missing method should error")
	}
	if _, _, err := stepRedirect(map[string]any{"url": "u"}); err == nil {
		t.Fatal("redirect missing state should error")
	}
	if _, _, err := stepDone(map[string]any{}); err == nil {
		t.Fatal("done missing signed pdf should error")
	}
	if evidence, err := stepEvidence(map[string]any{}); err != nil || evidence != nil {
		t.Fatal("missing evidence should be nil")
	}
	st, reason := mapFailed(map[string]any{"evidence": map[string]any{}})
	if st != session.StatusFailed || reason != "unknown" {
		t.Fatalf("empty outcome → %s/%s, want failed/unknown", st, reason)
	}
}

func TestResumeErrorsPropagate(t *testing.T) {
	// Begin SDK error (empty script → io.EOF).
	e, _ := newEngine(nil)
	if _, _, err := e.Begin("c", []byte("%PDF"), "B-B", "", nil); err == nil {
		t.Fatal("begin SDK error should propagate")
	}
	// Complete resume error (begin redirect, then exhausted).
	e2, _ := newEngine([]Result{redirect("https://cb/a", "s1")})
	_, _, _ = e2.Begin("c", []byte("%PDF"), "B-B", "", nil)
	s2, _ := e2.Store.GetByState("s1")
	if _, _, _, err := e2.Complete(context.Background(), s2, "code", "s1"); err == nil {
		t.Fatal("complete resume error should propagate")
	}
	// ResumeHTTP error inside drive (begin redirect, one perform_http, then exhausted).
	e3, _ := newEngine([]Result{redirect("https://cb/a", "s1"), performHTTP("https://cb/t")})
	_, _, _ = e3.Begin("c", []byte("%PDF"), "B-B", "", nil)
	s3, _ := e3.Store.GetByState("s1")
	if _, _, _, err := e3.Complete(context.Background(), s3, "code", "s1"); err == nil {
		t.Fatal("resume-http error should propagate")
	}
	// CompleteError resume error.
	e4, _ := newEngine([]Result{redirect("https://cb/a", "s1")})
	_, _, _ = e4.Begin("c", []byte("%PDF"), "B-B", "", nil)
	s4, _ := e4.Store.GetByState("s1")
	if _, _, _, err := e4.CompleteError(context.Background(), s4, "x", "s1"); err == nil {
		t.Fatal("complete-error resume error should propagate")
	}
}

// countingSDK is a thread-safe SDK double that counts how many times each resume entry point is
// invoked, so a test can assert the non-idempotent resume ran at most once.
type countingSDK struct {
	mu          sync.Mutex
	resumeStep  Result
	resumeCalls atomic.Int64
}

func (*countingSDK) Begin([]byte, string, *Options) (Result, error) {
	return redirect("https://cb/oauth2/authorize?scope=service", "s1"), nil
}
func (c *countingSDK) ResumeRedirect([]byte, string, string) (Result, error) {
	c.resumeCalls.Add(1)
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.resumeStep, nil
}
func (c *countingSDK) ResumeRedirectError([]byte, string, string) (Result, error) {
	c.resumeCalls.Add(1)
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.resumeStep, nil
}
func (c *countingSDK) ResumeHTTP([]byte, int, []byte) (Result, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return done([]byte("%PDF-signed")), nil
}
func (*countingSDK) VerifyPDF([]byte) (PDFVerification, error) { return PDFVerification{}, nil }

// TestConcurrentDuplicateCallbackDoesNotDoubleResume proves (under `go test -race`) that two
// concurrent /complete callbacks for the SAME pending state advance the SDK resume exactly once: the
// store's atomic consume lets one win and rejects the other cleanly, so the non-idempotent
// upstream/signing effects never run twice. Without the atomic consume, both callbacks would snapshot
// the same handle and both call ResumeRedirect.
func TestConcurrentDuplicateCallbackDoesNotDoubleResume(t *testing.T) {
	sdk := &countingSDK{resumeStep: performHTTP("https://cb/oauth2/token")} // resume → token → done
	e := &Engine{
		SDK:   sdk,
		Up:    &fakeEffector{},
		Store: session.NewMemory(),
		Log:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		TTL:   time.Minute,
	}
	if _, _, err := e.Begin("c", []byte("%PDF"), "B-B", "", nil); err != nil {
		t.Fatalf("begin: %v", err)
	}
	s, _ := e.Store.GetByState("s1")

	const callers = 2
	start := make(chan struct{})
	var wg sync.WaitGroup
	var ok, rejected atomic.Int64
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, _, _, err := e.Complete(context.Background(), s, "code", "s1")
			switch {
			case err == nil:
				ok.Add(1)
			case errors.Is(err, ErrTerminal) || errors.Is(err, session.ErrResuming):
				rejected.Add(1)
			default:
				t.Errorf("unexpected error from a duplicate callback: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()

	if got := sdk.resumeCalls.Load(); got != 1 {
		t.Fatalf("resume must be driven exactly once, got %d (double-resume of non-idempotent effects)", got)
	}
	if ok.Load() != 1 || rejected.Load() != callers-1 {
		t.Fatalf("expected 1 winner + %d clean rejections, got ok=%d rejected=%d", callers-1, ok.Load(), rejected.Load())
	}
	if v, err := e.Store.ViewByID("c"); err != nil || v.Status != session.StatusCompleted {
		t.Fatalf("session should complete once: %v status=%s", err, v.Status)
	}
}

func TestCompleteOnTerminalRejected(t *testing.T) {
	e, _ := newEngine([]Result{redirect("https://cb/a", "s1"), failed("invalid_document")})
	_, _, _ = e.Begin("c", []byte("%PDF"), "B-B", "", nil)
	s, _ := e.Store.GetByState("s1")
	_, _, _, _ = e.Complete(context.Background(), s, "code", "s1") // → terminal failed
	if _, _, _, err := e.Complete(context.Background(), s, "code", "s1"); !errors.Is(err, ErrTerminal) {
		t.Fatalf("expected ErrTerminal, got %v", err)
	}
}

// TestDriveFailsFastOnMalformedSteps proves a malformed SDK step surfaced mid-drive becomes a failed
// session + error, instead of being coerced into an empty redirect URL/state or empty PDF downstream.
func TestDriveFailsFastOnMalformedSteps(t *testing.T) {
	for _, tc := range []struct {
		name string
		step map[string]any
	}{
		{"perform_http missing url", map[string]any{"kind": "perform_http", "method": "POST"}},
		{"redirect missing state", map[string]any{"kind": "redirect", "url": "u"}},
		{"done missing pdf", map[string]any{"kind": "done", "signed": map[string]any{}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, _ := newEngine([]Result{
				redirect("https://cb/oauth2/authorize?scope=service", "s1"),
				{Handle: []byte("h"), Step: tc.step},
			})
			if _, _, err := e.Begin("corr-1", []byte("%PDF"), "B-B", "", nil); err != nil {
				t.Fatalf("begin: %v", err)
			}
			s, _ := e.Store.GetByState("s1")
			if _, _, _, err := e.Complete(context.Background(), s, "code", "s1"); err == nil {
				t.Fatal("expected a fail-fast error for the malformed step")
			}
			if s.Status != session.StatusFailed {
				t.Fatalf("session should be failed after a malformed step, got %s", s.Status)
			}
		})
	}
}

// TestBeginFailsFastOnMalformedRedirect proves begin rejects a redirect step missing its state.
func TestBeginFailsFastOnMalformedRedirect(t *testing.T) {
	e, _ := newEngine([]Result{{Handle: []byte("h"), Step: map[string]any{"kind": "redirect", "url": "u"}}})
	if _, _, err := e.Begin("corr-1", []byte("%PDF"), "B-B", "", nil); err == nil {
		t.Fatal("begin with a malformed redirect (no state) should error")
	}
}
