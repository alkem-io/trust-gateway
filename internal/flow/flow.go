// Package flow drives the SDK's sans-IO begin/resume state machine: it performs the emitted HTTP
// effects, advances across the two authorization redirects, maps terminal SDK outcomes to a
// frontend-facing status, and emits structured, secret-redacted logs of every effect and transition.
//
// The SDK and the HTTP effector are injected as interfaces so this package's unit tests run without
// cgo; the real adapters live in internal/cleverbase and internal/upstream.
package flow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"time"

	"github.com/alkem-io/trust-gateway/internal/session"
)

// Options carries the optional request inputs (the expected-signer binding, FR-014).
type Options struct {
	ExpectedSignerMatchOn string
	ExpectedSignerValue   string
}

// Validate rejects a partially specified signer identity while accepting either a complete pair or
// no expected signer. Keeping the pair rule here gives HTTP and binding callers one source of truth.
func (options *Options) Validate() error {
	if options == nil {
		return nil
	}
	if (options.ExpectedSignerMatchOn == "") != (options.ExpectedSignerValue == "") {
		return errors.New("expectedSigner requires both matchOn and value")
	}
	return nil
}

// Result is one SDK step: the updated opaque handle and the decoded Step map.
type Result struct {
	Handle []byte
	Step   map[string]any
}

// SDK is the subset of the binding the flow drives.
type SDK interface {
	// Begin starts the SDK state machine for a document.
	Begin(document []byte, conformance string, opts *Options) (Result, error)
	// ResumeRedirect advances a successful OAuth redirect.
	ResumeRedirect(handle []byte, code, state string) (Result, error)
	// ResumeRedirectError advances a failed or declined OAuth redirect.
	ResumeRedirectError(handle []byte, oauthError, state string) (Result, error)
	// ResumeHTTP advances an SDK-emitted HTTP effect.
	ResumeHTTP(handle []byte, status int, body []byte) (Result, error)
}

// Effector performs a single HTTP effect (the upstream client rewrites the host internally in
// fixtures mode). The request context is threaded through so a client disconnect or server shutdown
// cancels in-flight upstream calls rather than letting them run to the per-call timeout.
type Effector interface {
	// Do executes one SDK-emitted HTTP request.
	Do(ctx context.Context, method, rawURL string, headers [][2]string, body []byte) (int, []byte, error)
}

// ErrTerminal is returned when an already-terminal session is advanced again.
var ErrTerminal = errors.New("session already terminal")

// SDK step kinds emitted across the begin/resume state machine.
const (
	stepKindPerformHTTP = "perform_http"
	stepKindRedirect    = "redirect"
	stepKindDone        = "done"
	stepKindFailed      = "failed"
)

// outcomeDeclined is the terminal evidence outcome for a signer-declined flow.
const outcomeDeclined = "declined"

// Service-operational failure reasons this engine emits on a `failed` status, alongside the SDK's
// SigningOutcome failure codes (passed through verbatim from the evidence `outcome`). These are the
// single authoritative spelling for the snake_case wire codes; they MUST stay in sync with the
// `failed` reason set in docs/trust-gateway-api.md. The session store emits one further code,
// "session_expired", on TTL expiry (see internal/session/store.go).
const (
	reasonUpstreamError = "upstream_error" // an upstream HTTP call failed
	reasonResumeError   = "resume_error"   // the SDK could not advance the state machine
	reasonUnknown       = "unknown"        // defensive catch-all for an unmapped/future SDK outcome
)

// Engine ties the SDK, effector, and session store together.
type Engine struct {
	SDK   SDK
	Up    Effector
	Store *session.Memory
	Log   *slog.Logger
	TTL   time.Duration
	// RedirectRewrite rewrites the authorization redirect URLs handed to the frontend to a
	// browser-reachable host (fixtures mode). Nil = identity (live mode / tests).
	RedirectRewrite func(string) string
}

func (e *Engine) rewriteRedirect(u string) string {
	if e.RedirectRewrite != nil {
		return e.RedirectRewrite(u)
	}
	return u
}

// drive runs the perform-http loop until the next redirect or a terminal step.
func (e *Engine) drive(ctx context.Context, s *session.Session, res Result) (status session.Status, redirectURL, reason string, err error) {
	for {
		handle := res.Handle
		e.Store.Update(s, func() { s.Handle = handle })
		switch stepKind(res.Step) {
		case stepKindPerformHTTP:
			ef, perr := stepHTTP(res.Step)
			if perr != nil {
				e.fail(s, session.StatusFailed, reasonResumeError, nil)
				return "", "", "", fmt.Errorf("malformed perform_http step: %w", perr)
			}
			e.Log.Info("effect.perform_http", "method", ef.method, "url", redact(ef.rawURL))
			httpStatus, respBody, doErr := e.Up.Do(ctx, ef.method, ef.rawURL, ef.headers, ef.body)
			if doErr != nil {
				e.fail(s, session.StatusFailed, reasonUpstreamError, nil)
				e.Log.Error("effect.http_error", "url", redact(ef.rawURL), "err", doErr.Error())
				return session.StatusFailed, "", reasonUpstreamError, nil
			}
			e.Log.Info("effect.http_result", "status", httpStatus)
			next, resumeErr := e.SDK.ResumeHTTP(handle, httpStatus, respBody)
			if resumeErr != nil {
				// Scrub + de-index now rather than letting the handle linger until the TTL.
				e.fail(s, session.StatusFailed, reasonResumeError, nil)
				return "", "", "", fmt.Errorf("resume http: %w", resumeErr)
			}
			res = next
		case stepKindRedirect:
			rawURL, state, perr := stepRedirect(res.Step)
			if perr != nil {
				e.fail(s, session.StatusFailed, reasonResumeError, nil)
				return "", "", "", fmt.Errorf("malformed redirect step: %w", perr)
			}
			e.Store.SetState(s, state)
			e.Store.Update(s, func() { s.Status = session.StatusAuthorizing })
			e.Log.Info("transition.redirect", "correlation_id", s.CorrelationID)
			return session.StatusAuthorizing, e.rewriteRedirect(rawURL), "", nil
		case stepKindDone:
			pdf, evidence, perr := stepDone(res.Step)
			if perr != nil {
				e.fail(s, session.StatusFailed, reasonResumeError, nil)
				e.Log.Error("transition.done_invalid", "correlation_id", s.CorrelationID)
				return session.StatusFailed, "", reasonResumeError, fmt.Errorf("malformed done step: %w", perr)
			}
			e.Store.Update(s, func() {
				s.Status = session.StatusCompleted
				s.ResultPDF = pdf
				s.Evidence = evidence
			})
			e.Store.Finalize(s)
			e.Log.Info("transition.done", "pdf_bytes", len(pdf))
			return session.StatusCompleted, "", "", nil
		case stepKindFailed:
			failStatus, failReason := mapFailed(res.Step)
			evidence, evidenceErr := stepEvidence(res.Step)
			if evidenceErr != nil {
				e.fail(s, session.StatusFailed, reasonResumeError, nil)
				e.Log.Error("transition.failed_invalid", "correlation_id", s.CorrelationID)
				return session.StatusFailed, "", reasonResumeError, fmt.Errorf("malformed failed step: %w", evidenceErr)
			}
			e.fail(s, failStatus, failReason, evidence)
			e.Log.Info("transition.failed", "reason", failReason)
			return failStatus, "", failReason, nil
		default:
			e.fail(s, session.StatusFailed, reasonResumeError, nil)
			return "", "", "", fmt.Errorf("unexpected step kind %q", stepKind(res.Step))
		}
	}
}

func (e *Engine) fail(s *session.Session, status session.Status, reason string, evidence []byte) {
	e.Store.Update(s, func() {
		s.Status = status
		s.Reason = reason
		if evidence != nil {
			s.Evidence = evidence
		}
	})
	e.Store.Finalize(s)
}

// Begin starts a session, stores the handle, and returns the (rewritten) service-auth redirect URL
// together with the exact expiry the store assigned to that session. Returning it from the same
// creation operation keeps callers from recomputing TTLs or rereading mutable session state.
func (e *Engine) Begin(corr string, document []byte, conformance, clientState string, opts *Options) (string, time.Time, error) {
	res, err := e.SDK.Begin(document, conformance, opts)
	if err != nil {
		return "", time.Time{}, err
	}
	if kind := stepKind(res.Step); kind != stepKindRedirect {
		// begin always emits the service-scope redirect; anything else is a hard error.
		return "", time.Time{}, fmt.Errorf("begin produced unexpected step %q", kind)
	}
	rawURL, state, perr := stepRedirect(res.Step)
	if perr != nil {
		return "", time.Time{}, fmt.Errorf("begin produced malformed redirect: %w", perr)
	}
	s := e.Store.New(corr, state, clientState, conformance, e.TTL)
	e.Store.Update(s, func() {
		s.Handle = res.Handle
		s.Status = session.StatusAuthorizing
	})
	e.Log.Info("begin", "correlation_id", corr)
	return e.rewriteRedirect(rawURL), s.ExpiresAt, nil
}

// Complete advances a session after a redirect return with code+state. ctx is the request context,
// threaded to the upstream effector so a client disconnect cancels in-flight calls.
func (e *Engine) Complete(ctx context.Context, s *session.Session, code, state string) (status session.Status, redirectURL, reason string, err error) {
	handle, err := e.consume(s)
	if err != nil {
		return "", "", "", err
	}
	res, err := e.SDK.ResumeRedirect(handle, code, state)
	if err != nil {
		e.fail(s, session.StatusFailed, reasonResumeError, nil)
		return "", "", "", err
	}
	return e.drive(ctx, s, res)
}

// CompleteError advances a session after a redirect return carrying an OAuth error. ctx is the
// request context, threaded to the upstream effector (see Complete).
func (e *Engine) CompleteError(ctx context.Context, s *session.Session, oauthError, state string) (status session.Status, redirectURL, reason string, err error) {
	handle, err := e.consume(s)
	if err != nil {
		return "", "", "", err
	}
	res, err := e.SDK.ResumeRedirectError(handle, oauthError, state)
	if err != nil {
		e.fail(s, session.StatusFailed, reasonResumeError, nil)
		return "", "", "", err
	}
	return e.drive(ctx, s, res)
}

// consume atomically claims the session for this resume and returns its handle. It is the single
// guard against a concurrent duplicate redirect callback for the same state: the store de-indexes the
// pending state and marks the session resuming under its lock, so the second concurrent caller is
// rejected here (with ErrTerminal for an already-finished session, mapped from the store) and never
// reaches the SDK — the non-idempotent upstream/signing effects run at most once.
func (e *Engine) consume(s *session.Session) ([]byte, error) {
	handle, err := e.Store.ConsumeForResume(s)
	if err != nil {
		// An already-terminal session keeps the existing ErrTerminal contract; a concurrent
		// in-flight resume surfaces as the store's ErrResuming. Both are clean rejections that do not
		// re-finalize or double-resume.
		if errors.Is(err, session.ErrTerminal) {
			return nil, ErrTerminal
		}
		return nil, err
	}
	return handle, nil
}

// --- Step parsing helpers ---

// mapString reads a string-typed field from a decoded step/evidence map, returning "" when the key
// is absent or holds a non-string. Centralizing the checked assertion keeps the per-field extraction
// uniform (and avoids scattering bare `v, _ := m[k].(string)` casts across the package).
func mapString(m map[string]any, key string) string {
	if s, ok := m[key].(string); ok {
		return s
	}
	return ""
}

// stepKind returns the step's "kind" discriminator (or "" if absent/wrong-typed).
func stepKind(step map[string]any) string { return mapString(step, "kind") }

// stepRedirect extracts a redirect step's url+state, failing fast on a malformed step rather than
// coercing a schema violation into an empty redirect URL/state that would flow to the frontend.
func stepRedirect(step map[string]any) (rawURL, state string, err error) {
	rawURL, state = mapString(step, "url"), mapString(step, "state")
	if rawURL == "" || state == "" {
		return "", "", errors.New("redirect step missing url or state")
	}
	return rawURL, state, nil
}

// httpEffect is the decoded shape of a perform_http step.
type httpEffect struct {
	method  string
	rawURL  string
	headers [][2]string
	body    []byte
}

func stepHTTP(step map[string]any) (httpEffect, error) {
	ef := httpEffect{method: mapString(step, "method"), rawURL: mapString(step, "url")}
	if ef.method == "" || ef.rawURL == "" {
		return httpEffect{}, errors.New("perform_http step missing method or url")
	}
	if hs, ok := step["headers"].([]any); ok {
		ef.headers = make([][2]string, 0, len(hs))
		for _, h := range hs {
			pair, ok := h.([]any)
			if !ok || len(pair) != 2 {
				continue
			}
			k, kok := pair[0].(string)
			v, vok := pair[1].(string)
			if kok && vok {
				ef.headers = append(ef.headers, [2]string{k, v})
			}
		}
	}
	if b, ok := step["body"].([]byte); ok {
		ef.body = b
	}
	return ef, nil
}

func stepDone(step map[string]any) (pdf, evidence []byte, err error) {
	if signed, ok := step["signed"].(map[string]any); ok {
		if p, ok := signed["pdf"].([]byte); ok {
			pdf = p
		}
	}
	if len(pdf) == 0 {
		return nil, nil, errors.New("done step missing signed pdf")
	}
	evidence, err = stepEvidence(step)
	if err != nil {
		return nil, nil, fmt.Errorf("serialize evidence: %w", err)
	}
	return pdf, evidence, nil
}

func stepEvidence(step map[string]any) ([]byte, error) {
	ev, ok := step["evidence"]
	if !ok {
		return nil, nil
	}
	b, err := json.Marshal(ev)
	if err != nil {
		return nil, fmt.Errorf("serialize evidence: %w", err)
	}
	return b, nil
}

func mapFailed(step map[string]any) (session.Status, string) {
	outcome := ""
	if ev, ok := step["evidence"].(map[string]any); ok {
		outcome = mapString(ev, "outcome")
	}
	if outcome == outcomeDeclined {
		return session.StatusDeclined, outcomeDeclined
	}
	if outcome == "" {
		outcome = reasonUnknown
	}
	return session.StatusFailed, outcome
}

// redact returns scheme://host/path of a URL, dropping the query (which can carry the document hash
// or an OAuth code) so logs never leak sensitive material.
func redact(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "(unparseable)"
	}
	return u.Scheme + "://" + u.Host + u.Path
}
