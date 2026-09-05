// Package config loads and validates the signing gateway's environment contract.
package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"
)

// Mode selects credential-free fixtures or the live Cleverbase service.
type Mode string

const (
	// ModeFixtures drives the SDK against the published Cleverbase mock.
	ModeFixtures Mode = "fixtures"
	// ModeLive drives the SDK against Cleverbase.
	ModeLive Mode = "live"

	// ConformanceBB produces a PAdES baseline signature.
	ConformanceBB = "B-B"
	// ConformanceBT adds an RFC 3161 timestamp to the baseline signature.
	ConformanceBT = "B-T"

	// OAuthCallbackPath is the single public route registered with Cleverbase.
	OAuthCallbackPath = "/oauth/cleverbase/callback"
)

const (
	envAPIKey             = "TRUST_GATEWAY_API_KEY"
	envAuthDisabled       = "TRUST_GATEWAY_AUTH_DISABLED"
	envBaseURL            = "TRUST_GATEWAY_BASE_URL"
	envClientID           = "TRUST_GATEWAY_CLIENT_ID"
	envClientSecret       = "TRUST_GATEWAY_CLIENT_SECRET"
	envCSCAPI             = "TRUST_GATEWAY_CSC_API"
	envDefaultConformance = "TRUST_GATEWAY_DEFAULT_CONFORMANCE"
	envEnvironment        = "TRUST_GATEWAY_ENV"
	envListen             = "TRUST_GATEWAY_LISTEN"
	envMode               = "TRUST_GATEWAY_MODE"
	envPublicBaseURL      = "TRUST_GATEWAY_PUBLIC_BASE_URL"
	envRedirectURI        = "TRUST_GATEWAY_REDIRECT_URI"
	envReturnURL          = "TRUST_GATEWAY_RETURN_URL"
	envSessionTTL         = "TRUST_GATEWAY_SESSION_TTL"
	envTSAAuth            = "TRUST_GATEWAY_TSA_AUTH"
	envTSAPolicy          = "TRUST_GATEWAY_TSA_POLICY"
	envTSAURL             = "TRUST_GATEWAY_TSA_URL"
	// envSDKUpstreamBaseURL deliberately differs from envBaseURL: this is the SDK's authoritative
	// Cleverbase endpoint selection, while BASE_URL only rewrites fixture HTTP effects.
	envSDKUpstreamBaseURL = "TRUST_GATEWAY_UPSTREAM_BASE_URL"
)

const (
	fixturesClientID    = "trust-gateway-fixtures"
	fixturesSecret      = "fixtures"
	fixturesRedirectURI = "http://localhost:8080/return"
)

// Profile is a complete, validated runtime configuration.
type Profile struct {
	Mode         Mode
	Environment  string
	CSCAPI       string
	ClientID     string
	ClientSecret string
	RedirectURI  string
	ReturnURL    *url.URL
	TSAURL       string
	TSAAuth      string
	TSAPolicy    string

	UpstreamBaseURL       string
	PublicUpstreamBaseURL string
	// SDKUpstreamBaseURL optionally replaces the selected Cleverbase origin inside the SDK, for a
	// documented developer/stub service. The SDK owns URL syntax/security validation; this profile
	// only applies the gateway's production-policy restriction before any signing session starts.
	SDKUpstreamBaseURL string

	APIKey      string
	AuthEnabled bool

	DefaultConformance string
	SessionTTL         time.Duration
	Listen             string
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

// Load reads TRUST_GATEWAY_* variables and fails before startup on an incomplete profile.
func Load() (*Profile, error) {
	profile := &Profile{
		Mode:                  Mode(env(envMode, string(ModeFixtures))),
		Environment:           env(envEnvironment, "acceptance"),
		CSCAPI:                env(envCSCAPI, "v1_rsa"),
		ClientID:              os.Getenv(envClientID),
		ClientSecret:          os.Getenv(envClientSecret),
		RedirectURI:           os.Getenv(envRedirectURI),
		TSAURL:                os.Getenv(envTSAURL),
		TSAAuth:               os.Getenv(envTSAAuth),
		TSAPolicy:             os.Getenv(envTSAPolicy),
		UpstreamBaseURL:       os.Getenv(envBaseURL),
		PublicUpstreamBaseURL: os.Getenv(envPublicBaseURL),
		SDKUpstreamBaseURL:    os.Getenv(envSDKUpstreamBaseURL),
		APIKey:                os.Getenv(envAPIKey),
		DefaultConformance:    env(envDefaultConformance, ConformanceBB),
		Listen:                env(envListen, ":8080"),
	}

	ttlText := env(envSessionTTL, "15m")
	ttl, err := parseSessionTTL(ttlText)
	if err != nil {
		return nil, err
	}
	profile.SessionTTL = ttl

	if err := profile.resolveAuth(); err != nil {
		return nil, err
	}
	if err := profile.validateStaticFields(); err != nil {
		return nil, err
	}

	switch profile.Mode {
	case ModeFixtures:
		if err := profile.applyFixturesDefaults(); err != nil {
			return nil, err
		}
	case ModeLive:
		if err := profile.validateLive(); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("invalid %s %q (%s|%s)", envMode, profile.Mode, ModeFixtures, ModeLive)
	}

	redirectURL, err := profile.validateURLs()
	if err != nil {
		return nil, err
	}
	if err := profile.validateBrowserFlow(redirectURL); err != nil {
		return nil, err
	}
	return profile, nil
}

func (profile *Profile) validateStaticFields() error {
	if profile.DefaultConformance != ConformanceBB && profile.DefaultConformance != ConformanceBT {
		return fmt.Errorf("invalid %s %q (%s|%s)", envDefaultConformance, profile.DefaultConformance, ConformanceBB, ConformanceBT)
	}
	if profile.Environment != "acceptance" && profile.Environment != "production" {
		return fmt.Errorf("invalid %s %q (acceptance|production)", envEnvironment, profile.Environment)
	}
	if profile.CSCAPI != "v1_rsa" && profile.CSCAPI != "v2_ecdsa" {
		return fmt.Errorf("invalid %s %q (v1_rsa|v2_ecdsa)", envCSCAPI, profile.CSCAPI)
	}
	return profile.validateSDKUpstreamPolicy()
}

func parseSessionTTL(value string) (time.Duration, error) {
	ttl, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("invalid %s %q: %w", envSessionTTL, value, err)
	}
	if ttl <= 0 {
		return 0, fmt.Errorf("invalid %s %q: must be positive", envSessionTTL, value)
	}
	return ttl, nil
}

func (profile *Profile) resolveAuth() error {
	authDisabled := strings.EqualFold(os.Getenv(envAuthDisabled), "true")
	if authDisabled && profile.APIKey != "" {
		return fmt.Errorf("%s and %s cannot both be set", envAPIKey, envAuthDisabled)
	}
	switch {
	case profile.APIKey != "":
		profile.AuthEnabled = true
	case authDisabled:
		profile.AuthEnabled = false
	default:
		return fmt.Errorf("API auth is on by default: set %s, or explicitly set %s=true for network-isolated runs", envAPIKey, envAuthDisabled)
	}
	return nil
}

func (profile *Profile) validateSDKUpstreamPolicy() error {
	if profile.SDKUpstreamBaseURL != "" && profile.Environment == "production" {
		return fmt.Errorf("%s is not allowed when %s=production", envSDKUpstreamBaseURL, envEnvironment)
	}
	return nil
}

func (profile *Profile) applyFixturesDefaults() error {
	if profile.UpstreamBaseURL == "" {
		return fmt.Errorf("fixtures mode requires %s", envBaseURL)
	}
	if profile.ClientID == "" {
		profile.ClientID = fixturesClientID
	}
	if profile.ClientSecret == "" {
		profile.ClientSecret = fixturesSecret
	}
	if profile.RedirectURI == "" {
		profile.RedirectURI = fixturesRedirectURI
	}
	if profile.TSAURL == "" {
		profile.TSAURL = strings.TrimRight(profile.UpstreamBaseURL, "/") + "/tsr"
	}
	if profile.PublicUpstreamBaseURL == "" {
		profile.PublicUpstreamBaseURL = profile.UpstreamBaseURL
	}
	return nil
}

func (profile *Profile) validateLive() error {
	values := []struct {
		name  string
		value string
	}{
		{envClientID, profile.ClientID},
		{envClientSecret, profile.ClientSecret},
		{envRedirectURI, profile.RedirectURI},
		{envReturnURL, os.Getenv(envReturnURL)},
		{envTSAURL, profile.TSAURL},
	}
	missing := make([]string, 0, len(values))
	for _, item := range values {
		if item.value == "" {
			missing = append(missing, item.name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("live mode requires: %s", strings.Join(missing, ", "))
	}
	return nil
}

func parseAbsoluteURL(name, value string) (*url.URL, error) {
	if value == "" {
		return nil, nil
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return nil, fmt.Errorf("invalid %s %q: %w", name, value, err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("invalid %s %q: must be an absolute URL with a scheme and host", name, value)
	}
	return parsed, nil
}

func (profile *Profile) validateURLs() (*url.URL, error) {
	values := []struct {
		name  string
		value string
	}{
		{envBaseURL, profile.UpstreamBaseURL},
		{envPublicBaseURL, profile.PublicUpstreamBaseURL},
		{envTSAURL, profile.TSAURL},
	}
	for _, item := range values {
		if _, err := parseAbsoluteURL(item.name, item.value); err != nil {
			return nil, err
		}
	}
	redirectURL, err := parseAbsoluteURL(envRedirectURI, profile.RedirectURI)
	if err != nil {
		return nil, err
	}
	returnURL, err := parseAbsoluteURL(envReturnURL, os.Getenv(envReturnURL))
	if err != nil {
		return nil, err
	}
	profile.ReturnURL = returnURL
	return redirectURL, nil
}

func (profile *Profile) validateBrowserFlow(redirectURL *url.URL) error {
	if redirectURL != nil && redirectURL.Path == OAuthCallbackPath && profile.ReturnURL == nil {
		return fmt.Errorf("%s is required when %s uses %s", envReturnURL, envRedirectURI, OAuthCallbackPath)
	}
	if profile.ReturnURL != nil {
		if err := validateBrowserURL(envReturnURL, profile.ReturnURL, profile.Mode == ModeLive); err != nil {
			return err
		}
	}
	if profile.Mode != ModeLive {
		return nil
	}
	if err := validateBrowserURL(envRedirectURI, redirectURL, true); err != nil {
		return err
	}
	if redirectURL.Path != OAuthCallbackPath {
		return fmt.Errorf("invalid %s %q: path must be %s", envRedirectURI, profile.RedirectURI, OAuthCallbackPath)
	}
	return nil
}

func validateBrowserURL(name string, parsed *url.URL, requireHTTPS bool) error {
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("invalid %s %q: scheme must be http or https", name, parsed.String())
	}
	if requireHTTPS && parsed.Scheme != "https" && !isLoopbackHost(parsed.Hostname()) {
		return fmt.Errorf("invalid %s %q: live mode requires https", name, parsed.String())
	}
	if parsed.RawQuery != "" {
		return fmt.Errorf("invalid %s %q: URL must not contain a query", name, parsed.String())
	}
	if parsed.Fragment != "" {
		return fmt.Errorf("invalid %s %q: URL must not contain a fragment", name, parsed.String())
	}
	return nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
