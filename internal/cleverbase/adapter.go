// Package cleverbase adapts the cgo Go binding to the flow.SDK interface (so the flow package stays
// cgo-free and unit-testable). It re-implements no protocol/crypto — all of that lives in the Rust
// core (Constitution III).
package cleverbase

import (
	"crypto/rand"
	"fmt"
	"time"

	bindings "github.com/alkem-io/cleverbase-sdk/bindings/go"
	"github.com/fxamacker/cbor/v2"

	"github.com/alkem-io/trust-gateway/internal/config"
	"github.com/alkem-io/trust-gateway/internal/flow"
)

// Adapter wraps the binding with a fixed trust-service config.
type Adapter struct {
	cfg bindings.Config
}

// New builds an adapter from the run profile.
func New(p *config.Profile) *Adapter {
	return &Adapter{cfg: bindings.Config{
		Environment:  p.Environment,
		CscAPI:       p.CSCAPI,
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
		RedirectURI:  p.RedirectURI,
		TsaURL:       p.TSAURL,
		TsaAuth:      p.TSAAuth,
		TsaPolicy:    p.TSAPolicy,
	}}
}

func now() int64 { return time.Now().Unix() }

// randRead is the entropy source, indirected so tests can exercise the RNG-failure path. It defaults
// to crypto/rand.Reader.
var randRead = rand.Read

// entropy draws 16 bytes of per-call randomness for the signing flow. A failed RNG read MUST fail
// the request: returning zeroed "entropy" would feed predictable bytes into BeginSigning/Resume* (a
// degraded RNG must never silently produce signatures with guessable nonces).
func entropy() ([]byte, error) {
	b := make([]byte, 16)
	if _, err := randRead(b); err != nil {
		return nil, fmt.Errorf("generate signing entropy: %w", err)
	}
	return b, nil
}

func toResult(s *bindings.Session) flow.Result {
	return flow.Result{Handle: []byte(s.Handle), Step: s.Step}
}

// Begin starts a signing session.
func (a *Adapter) Begin(document []byte, conformance string, opts *flow.Options) (flow.Result, error) {
	var bopts *bindings.RequestOptions
	if opts != nil && opts.ExpectedSignerValue != "" {
		bopts = &bindings.RequestOptions{ExpectedSigner: &bindings.ExpectedSigner{
			MatchOn: opts.ExpectedSignerMatchOn,
			Value:   opts.ExpectedSignerValue,
		}}
	}
	ent, err := entropy()
	if err != nil {
		return flow.Result{}, err
	}
	s, err := bindings.BeginSigning(document, a.cfg, conformance, bopts, now(), ent)
	if err != nil {
		return flow.Result{}, err
	}
	return toResult(s), nil
}

// ResumeRedirect advances after a redirect return with code+state.
func (*Adapter) ResumeRedirect(handle []byte, code, state string) (flow.Result, error) {
	ent, err := entropy()
	if err != nil {
		return flow.Result{}, err
	}
	s, err := bindings.ResumeRedirect(cbor.RawMessage(handle), code, state, now(), ent)
	if err != nil {
		return flow.Result{}, err
	}
	return toResult(s), nil
}

// ResumeRedirectError advances after a redirect return carrying an OAuth error.
func (*Adapter) ResumeRedirectError(handle []byte, oauthError, state string) (flow.Result, error) {
	ent, err := entropy()
	if err != nil {
		return flow.Result{}, err
	}
	s, err := bindings.ResumeRedirectError(cbor.RawMessage(handle), oauthError, state, now(), ent)
	if err != nil {
		return flow.Result{}, err
	}
	return toResult(s), nil
}

// ResumeHTTP advances after performing an HTTP effect.
func (*Adapter) ResumeHTTP(handle []byte, status int, body []byte) (flow.Result, error) {
	ent, err := entropy()
	if err != nil {
		return flow.Result{}, err
	}
	s, err := bindings.ResumeHTTP(cbor.RawMessage(handle), status, body, now(), ent)
	if err != nil {
		return flow.Result{}, err
	}
	return toResult(s), nil
}
