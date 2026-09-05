// Package httpapi exposes the signing gateway's REST API (docs/trust-gateway-api.md):
// start/complete/status/result + health, behind an optional API-key gate. It holds all secrets and
// the SDK session handle server-side.
package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/alkem-io/trust-gateway/internal/config"
	"github.com/alkem-io/trust-gateway/internal/flow"
	"github.com/alkem-io/trust-gateway/internal/session"
)

// keyStatus is the JSON field name carrying a session's status in API responses.
const keyStatus = "status"

// errCodeAlreadyProcessing is the machine-readable error code returned when a duplicate/in-flight
// callback for a session is rejected (HTTP 409). Defined once so the handler and its tests agree.
const errCodeAlreadyProcessing = "already_processing"

// Request/document size caps for /v1/sign/start. The endpoint accepts a base64-encoded PDF inside a
// JSON envelope; without a bound, a client could force huge allocations decoding the body.
const (
	// maxPDFBytes caps the decoded document. 20 MiB comfortably covers realistic signable PDFs while
	// bounding per-request memory.
	maxPDFBytes = 20 << 20 // 20 MiB
	// maxStartBodyBytes caps the raw JSON request body read before decoding. The document travels
	// base64-encoded (~4/3 expansion) inside JSON, so the body cap is maxPDFBytes*4/3 plus a small
	// slack for the surrounding JSON fields.
	maxStartBodyBytes = maxPDFBytes*4/3 + (1 << 16) // base64 expansion + 64 KiB JSON slack
	// maxCompleteBodyBytes caps /v1/sign/complete bodies, which carry only short OAuth code/state/error
	// fields — no document — so a small cap suffices and bounds the decode allocation.
	maxCompleteBodyBytes = 1 << 16 // 64 KiB
	// maxClientStateBytes is ample for an opaque one-time continuation token while preventing the
	// gateway from becoming an arbitrary browser-reflected storage channel.
	maxClientStateBytes = 1024
)

// Service holds the engine + store + profile and serves the REST API.
type Service struct {
	Engine  *flow.Engine
	Store   *session.Memory
	Profile *config.Profile
	// Sample is the bundled PDF used when a start request omits a document.
	Sample []byte
	// Log records server-side errors whose details must not reach the client. Defaults to a
	// discard logger when nil so handlers never panic on a partially-wired Service (tests).
	Log *slog.Logger
}

// log returns the configured logger, or a no-op discard logger when none was wired.
func (s *Service) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// Handler returns the routed, auth-wrapped HTTP handler.
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	if s.Profile.ReturnURL != nil {
		mux.HandleFunc("GET "+config.OAuthCallbackPath, s.handleOAuthCallback)
	}
	mux.HandleFunc("POST /v1/sign/start", s.handleStart)
	mux.HandleFunc("POST /v1/sign/complete", s.handleComplete)
	mux.HandleFunc("GET /v1/sign/status", s.handleStatus)
	mux.HandleFunc("GET /v1/sign/result", s.handleResult)
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /readyz", s.handleHealth)
	return s.authMiddleware(mux)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	// Keep ampersands literal in redirect URLs (the default JSON HTML-escaping would mangle them).
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func writeErr(w http.ResponseWriter, code int, errCode, msg string) {
	writeJSON(w, code, map[string]string{"error": errCode, "message": msg})
}

// randRead is crypto/rand.Read, indirected so tests can exercise the RNG-failure path.
var randRead = rand.Read

// newCorrelationID returns a 128-bit random correlation ID. It propagates a failed RNG read
// instead of silently returning a predictable/zero ID (a degraded RNG must fail the request,
// not hand out a guessable correlation handle).
func newCorrelationID() (string, error) {
	b := make([]byte, 16)
	if _, err := randRead(b); err != nil {
		return "", fmt.Errorf("generate correlation id: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// expectedSignerInput binds the request to a signer identity (FR-014).
type expectedSignerInput struct {
	MatchOn string `json:"matchOn"`
	Value   string `json:"value"`
}

type startRequest struct {
	Document         string               `json:"document"` // base64 PDF; omit to use the bundled sample
	ConformanceLevel string               `json:"conformanceLevel"`
	ExpectedSigner   *expectedSignerInput `json:"expectedSigner"`
	ClientState      string               `json:"clientState"`
}

func (s *Service) handleStart(w http.ResponseWriter, r *http.Request) {
	// Bound the body before reading it so a client cannot force a huge allocation decoding the JSON
	// (which carries the base64 document). MaxBytesReader trips the decode with an *http.MaxBytesError
	// once the cap is exceeded.
	r.Body = http.MaxBytesReader(w, r.Body, maxStartBodyBytes)
	var req startRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeErr(w, http.StatusRequestEntityTooLarge, "payload_too_large", "request body too large")
			return
		}
		writeErr(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
		return
	}
	// Validate the small opaque continuation before decoding a document that may be up to 20 MiB.
	if len(req.ClientState) > maxClientStateBytes {
		writeErr(w, http.StatusBadRequest, "bad_request", "clientState exceeds the size limit")
		return
	}
	if s.Profile.ReturnURL != nil && req.ClientState == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "clientState is required")
		return
	}
	var opts *flow.Options
	if req.ExpectedSigner != nil {
		opts = &flow.Options{
			ExpectedSignerMatchOn: req.ExpectedSigner.MatchOn,
			ExpectedSignerValue:   req.ExpectedSigner.Value,
		}
	}
	if err := opts.Validate(); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	doc := s.Sample
	if req.Document != "" {
		// The request body is already bounded by MaxBytesReader (maxStartBodyBytes) above, so decoding
		// allocates at most that many bytes — bounded. Decode, then enforce the EXACT decoded-PDF cap
		// (a pre-decode base64 DecodedLen check over-rejects by up to 2 bytes at the boundary).
		b, err := base64.StdEncoding.DecodeString(req.Document)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", "document is not valid base64")
			return
		}
		if len(b) > maxPDFBytes {
			writeErr(w, http.StatusRequestEntityTooLarge, "payload_too_large", "document exceeds the size limit")
			return
		}
		doc = b
	}
	if len(doc) == 0 {
		writeErr(w, http.StatusBadRequest, "bad_request", "no document and no bundled sample")
		return
	}
	conformance := req.ConformanceLevel
	if conformance == "" {
		conformance = s.Profile.DefaultConformance
	}
	corr, err := newCorrelationID()
	if err != nil {
		s.log().Error("correlation id generation failed", "err", err.Error())
		writeErr(w, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	redirectURL, expiresAt, err := s.Engine.Begin(corr, doc, conformance, req.ClientState, opts)
	if err != nil {
		// Do not surface the upstream/SDK error text to the client (it can leak internal/session
		// detail); log it server-side and return a stable generic message with the same status.
		s.log().Error("begin failed", "correlation_id", corr, "err", err.Error())
		writeErr(w, http.StatusInternalServerError, "begin_failed", "could not start signing session")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"redirectUrl":   redirectURL,
		"correlationId": corr,
		"expiresAt":     expiresAt.UTC().Format(time.RFC3339),
	})
}

type completeRequest struct {
	Code  string `json:"code"`
	Error string `json:"error"`
	State string `json:"state"`
}

type completeResult struct {
	Status        session.Status
	RedirectURL   string
	Reason        string
	CorrelationID string
	ClientState   string
}

var (
	errInvalidComplete = errors.New("invalid completion input")
	errUnknownState    = errors.New("unknown OAuth state")
)

func (s *Service) handleComplete(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxCompleteBodyBytes)
	var req completeRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	var maxErr *http.MaxBytesError
	if errors.As(err, &maxErr) {
		writeErr(w, http.StatusRequestEntityTooLarge, "payload_too_large", "request body too large")
		return
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "invalid body or missing state")
		return
	}
	result, err := s.complete(r.Context(), req)
	if err != nil {
		s.writeCompleteError(w, err, result.CorrelationID)
		return
	}
	resp := map[string]any{keyStatus: string(result.Status)}
	if result.RedirectURL != "" {
		resp["redirectUrl"] = result.RedirectURL
	}
	// Per the API contract, `reason` is present only for a failed status.
	if result.Status == session.StatusFailed && result.Reason != "" {
		resp["reason"] = result.Reason
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleOAuthCallback is the one public browser endpoint registered with Cleverbase. It owns both
// OAuth legs: an intermediate result redirects back to Cleverbase; a terminal result redirects to
// the configured application return URL with only opaque gateway/application references.
func (s *Service) handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodHead {
		w.Header().Set("Allow", http.MethodGet)
		writeErr(w, http.StatusMethodNotAllowed, "method_not_allowed", "HEAD is not supported")
		return
	}
	query := r.URL.Query()
	result, err := s.complete(r.Context(), completeRequest{
		Code: query.Get("code"), Error: query.Get("error"), State: query.Get("state"),
	})
	if !returnsToApplication(result, err) {
		s.writeCompleteError(w, err, result.CorrelationID)
		return
	}
	if err != nil {
		// The session itself is terminal and Alkemio obtains the authoritative failure via the private
		// status endpoint. Return the browser without reflecting any error or status in its URL.
		_, _, _, conflict := classifyCompleteError(err)
		s.logCompleteError(err, result.CorrelationID, conflict)
	}
	if result.RedirectURL != "" {
		http.Redirect(w, r, result.RedirectURL, http.StatusFound)
		return
	}
	http.Redirect(w, r, s.applicationReturnURL(result), http.StatusFound)
}

func returnsToApplication(result completeResult, err error) bool {
	return err == nil || (result.Status.Terminal() && result.CorrelationID != "")
}

// complete is the single completion path shared by the JSON API and browser callback.
func (s *Service) complete(ctx context.Context, req completeRequest) (completeResult, error) {
	if req.State == "" || (req.Code == "" && req.Error == "") {
		return completeResult{}, errInvalidComplete
	}
	sess, err := s.Store.GetByState(req.State)
	if err != nil {
		return completeResult{}, errUnknownState
	}
	var result completeResult
	if req.Error != "" {
		result.Status, result.RedirectURL, result.Reason, err = s.Engine.CompleteError(ctx, sess, req.Error, req.State)
	} else {
		result.Status, result.RedirectURL, result.Reason, err = s.Engine.Complete(ctx, sess, req.Code, req.State)
	}
	completeErr := err
	view, err := s.Store.ViewByID(sess.CorrelationID)
	if err != nil {
		if completeErr != nil {
			return completeResult{}, completeErr
		}
		return completeResult{}, fmt.Errorf("view completed session: %w", err)
	}
	if result.Status == "" {
		result.Status = view.Status
	}
	if result.Reason == "" {
		result.Reason = view.Reason
	}
	result.CorrelationID = view.CorrelationID
	result.ClientState = view.ClientState
	return result, completeErr
}

func (s *Service) writeCompleteError(w http.ResponseWriter, err error, correlationID string) {
	switch {
	case errors.Is(err, errInvalidComplete):
		writeErr(w, http.StatusBadRequest, "bad_request", "missing state, code, or error")
		return
	case errors.Is(err, errUnknownState):
		writeErr(w, http.StatusBadRequest, "unknown_state", "no pending session for that state")
		return
	}
	code, errCode, msg, conflict := classifyCompleteError(err)
	s.logCompleteError(err, correlationID, conflict)
	writeErr(w, code, errCode, msg)
}

func (s *Service) logCompleteError(err error, correlationID string, conflict bool) {
	if conflict {
		s.log().Info("duplicate or in-flight complete rejected", "correlation_id", correlationID)
		return
	}
	s.log().Error("resume failed", "correlation_id", correlationID, "err", err.Error())
}

func (s *Service) applicationReturnURL(result completeResult) string {
	parsed := *s.Profile.ReturnURL
	parsed.RawQuery = url.Values{
		"clientState":   {result.ClientState},
		"correlationId": {result.CorrelationID},
	}.Encode()
	return parsed.String()
}

// classifyCompleteError maps an Engine.Complete/CompleteError failure to its HTTP response. A
// sequential re-complete is already screened out by GetByState (a terminal session is de-indexed by
// its state → "unknown_state"), but two callbacks for the same state can race past GetByState before
// either consumes the session: flow.consume() then lets exactly one win and rejects the loser with
// flow.ErrTerminal (the winner already finished) or session.ErrResuming (the winner is still
// in-flight). Both are CLIENT conditions (a duplicate/in-flight callback), so they map to 409
// already_processing (conflict == true) — never the SDK/upstream-error 500 reserved for a genuine
// internal resume failure.
func classifyCompleteError(err error) (code int, errCode, msg string, conflict bool) {
	if errors.Is(err, flow.ErrTerminal) || errors.Is(err, session.ErrResuming) {
		return http.StatusConflict, errCodeAlreadyProcessing, "session is already being completed", true
	}
	return http.StatusInternalServerError, "resume_failed", "could not complete signing session", false
}

func (s *Service) handleStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	corr := r.URL.Query().Get("correlationId")
	v, err := s.Store.ViewByID(corr) // race-free snapshot (the flow engine may be writing concurrently)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "unknown correlation id")
		return
	}
	resp := map[string]any{keyStatus: string(v.Status)}
	// Per the API contract, `reason` is present only for a failed status.
	if v.Status == session.StatusFailed && v.Reason != "" {
		resp["reason"] = v.Reason
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Service) handleResult(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	corr := r.URL.Query().Get("correlationId")
	v, err := s.Store.ViewByID(corr)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "unknown correlation id")
		return
	}
	if v.Status != session.StatusCompleted {
		writeErr(w, http.StatusConflict, "not_completed", "session is not completed")
		return
	}
	if len(v.Evidence) > 0 {
		w.Header().Set("X-Signature-Evidence", base64.StdEncoding.EncodeToString(v.Evidence))
	}
	w.Header().Set("content-type", "application/pdf")
	w.WriteHeader(http.StatusOK)
	// The body is the SDK-produced signed PDF served as application/pdf (not HTML); no XSS surface.
	_, _ = w.Write(v.ResultPDF)
}

func (*Service) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{keyStatus: "ok"})
}
