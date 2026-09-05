package config

import (
	"net/url"
	"strings"
	"testing"
	"time"
)

var knownEnvKeys = []string{
	"TRUST_GATEWAY_API_KEY", "TRUST_GATEWAY_AUTH_DISABLED", "TRUST_GATEWAY_BASE_URL",
	"TRUST_GATEWAY_CLIENT_ID", "TRUST_GATEWAY_CLIENT_SECRET", "TRUST_GATEWAY_CSC_API",
	"TRUST_GATEWAY_DEFAULT_CONFORMANCE", "TRUST_GATEWAY_ENV", "TRUST_GATEWAY_LISTEN",
	"TRUST_GATEWAY_MODE", "TRUST_GATEWAY_PUBLIC_BASE_URL", "TRUST_GATEWAY_REDIRECT_URI",
	"TRUST_GATEWAY_RETURN_URL", "TRUST_GATEWAY_SESSION_TTL", "TRUST_GATEWAY_TSA_AUTH",
	"TRUST_GATEWAY_TSA_POLICY", "TRUST_GATEWAY_TSA_URL", "TRUST_GATEWAY_UPSTREAM_BASE_URL",
}

func setEnv(t *testing.T, values map[string]string) {
	t.Helper()
	for _, key := range knownEnvKeys {
		t.Setenv(key, "")
	}
	for key, value := range values {
		t.Setenv(key, value)
	}
}

func fixturesEnv() map[string]string {
	return map[string]string{
		"TRUST_GATEWAY_API_KEY":  "test-key",
		"TRUST_GATEWAY_BASE_URL": "http://mock:9000",
		"TRUST_GATEWAY_MODE":     "fixtures",
	}
}

func validLiveEnv() map[string]string {
	return map[string]string{
		"TRUST_GATEWAY_API_KEY":       "key",
		"TRUST_GATEWAY_CLIENT_ID":     "client",
		"TRUST_GATEWAY_CLIENT_SECRET": "secret",
		"TRUST_GATEWAY_MODE":          "live",
		"TRUST_GATEWAY_REDIRECT_URI":  "https://gateway.example" + OAuthCallbackPath,
		"TRUST_GATEWAY_RETURN_URL":    "https://app.example/signing/complete",
		"TRUST_GATEWAY_TSA_URL":       "https://tsa.example/tsr",
	}
}

func clone(values map[string]string) map[string]string {
	result := make(map[string]string, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}

func TestLoadFixturesDefaults(t *testing.T) { //nolint:gocyclo // The assertions pin one cohesive default profile.
	setEnv(t, fixturesEnv())

	profile, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if profile.Mode != ModeFixtures || profile.UpstreamBaseURL != "http://mock:9000" {
		t.Fatalf("unexpected profile: %+v", profile)
	}
	if profile.Environment != "acceptance" || profile.CSCAPI != "v1_rsa" || profile.DefaultConformance != ConformanceBB {
		t.Fatalf("unexpected defaults: %+v", profile)
	}
	if profile.ClientID != "trust-gateway-fixtures" || profile.ClientSecret != "fixtures" {
		t.Fatalf("unexpected fixture credentials: %+v", profile)
	}
	if profile.RedirectURI != "http://localhost:8080/return" || profile.TSAURL != "http://mock:9000/tsr" {
		t.Fatalf("unexpected fixture URLs: %+v", profile)
	}
	if profile.PublicUpstreamBaseURL != profile.UpstreamBaseURL || profile.ReturnURL != nil {
		t.Fatalf("unexpected public URLs: %+v", profile)
	}
	if profile.SessionTTL != 15*time.Minute || profile.Listen != ":8080" || !profile.AuthEnabled {
		t.Fatalf("unexpected operational defaults: %+v", profile)
	}
}

func TestLoadRejectsInvalidModeAndRequestDefaults(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]string)
		want   string
	}{
		{"mode", func(env map[string]string) { env["TRUST_GATEWAY_MODE"] = "unknown" }, "TRUST_GATEWAY_MODE"},
		{"environment", func(env map[string]string) { env["TRUST_GATEWAY_ENV"] = "sandbox" }, "TRUST_GATEWAY_ENV"},
		{"CSC API", func(env map[string]string) { env["TRUST_GATEWAY_CSC_API"] = "v3" }, "TRUST_GATEWAY_CSC_API"},
		{"ttl", func(env map[string]string) { env["TRUST_GATEWAY_SESSION_TTL"] = "soon" }, "TRUST_GATEWAY_SESSION_TTL"},
		{"zero ttl", func(env map[string]string) { env["TRUST_GATEWAY_SESSION_TTL"] = "0s" }, "TRUST_GATEWAY_SESSION_TTL"},
		{"negative ttl", func(env map[string]string) { env["TRUST_GATEWAY_SESSION_TTL"] = "-1s" }, "TRUST_GATEWAY_SESSION_TTL"},
		{"conformance", func(env map[string]string) { env["TRUST_GATEWAY_DEFAULT_CONFORMANCE"] = "B-X" }, "TRUST_GATEWAY_DEFAULT_CONFORMANCE"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			env := fixturesEnv()
			test.mutate(env)
			setEnv(t, env)
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Load() error = %v, want text %q", err, test.want)
			}
		})
	}
}

func TestAuthenticationRequiresAnExplicitPolicy(t *testing.T) {
	setEnv(t, map[string]string{
		"TRUST_GATEWAY_BASE_URL": "http://mock:9000",
		"TRUST_GATEWAY_MODE":     "fixtures",
	})
	if _, err := Load(); err == nil {
		t.Fatal("Load() accepted a profile without an API key or explicit fixtures opt-out")
	}

	setEnv(t, map[string]string{
		"TRUST_GATEWAY_AUTH_DISABLED": "true",
		"TRUST_GATEWAY_BASE_URL":      "http://mock:9000",
		"TRUST_GATEWAY_MODE":          "fixtures",
	})
	profile, err := Load()
	if err != nil {
		t.Fatalf("Load() fixtures opt-out error = %v", err)
	}
	if profile.AuthEnabled {
		t.Fatal("AuthEnabled = true after the explicit fixtures opt-out")
	}

	t.Run("live explicit network isolation", func(t *testing.T) {
		env := validLiveEnv()
		delete(env, "TRUST_GATEWAY_API_KEY")
		env["TRUST_GATEWAY_AUTH_DISABLED"] = "true"
		setEnv(t, env)
		profile, err := Load()
		if err != nil {
			t.Fatalf("Load() live network-isolation profile error = %v", err)
		}
		if profile.AuthEnabled {
			t.Fatal("AuthEnabled = true with explicit network isolation")
		}
	})

	t.Run("key and network isolation conflict", func(t *testing.T) {
		env := validLiveEnv()
		env["TRUST_GATEWAY_AUTH_DISABLED"] = "true"
		setEnv(t, env)
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "both") {
			t.Fatalf("Load() conflicting auth profile error = %v", err)
		}
	})
}

func TestLiveUpstreamOverrideIsNonProductionOnly(t *testing.T) {
	const stubURL = "https://trust-driver-stub-hash-signing.cleverbase.com"

	t.Run("acceptance", func(t *testing.T) {
		env := validLiveEnv()
		env["TRUST_GATEWAY_UPSTREAM_BASE_URL"] = stubURL
		setEnv(t, env)
		profile, err := Load()
		if err != nil {
			t.Fatalf("Load() override error = %v", err)
		}
		if profile.SDKUpstreamBaseURL != stubURL {
			t.Fatalf("SDKUpstreamBaseURL = %q, want %q", profile.SDKUpstreamBaseURL, stubURL)
		}
	})

	t.Run("production", func(t *testing.T) {
		env := validLiveEnv()
		env["TRUST_GATEWAY_ENV"] = "production"
		env["TRUST_GATEWAY_UPSTREAM_BASE_URL"] = stubURL
		setEnv(t, env)
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "production") {
			t.Fatalf("Load() production override error = %v", err)
		}
	})
}

func TestFixturesRequiresBaseURL(t *testing.T) {
	setEnv(t, map[string]string{
		"TRUST_GATEWAY_API_KEY": "key",
		"TRUST_GATEWAY_MODE":    "fixtures",
	})
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "TRUST_GATEWAY_BASE_URL") {
		t.Fatalf("Load() error = %v", err)
	}
}

func TestLiveRequiresCompleteCredentials(t *testing.T) {
	for _, missing := range []string{
		"TRUST_GATEWAY_API_KEY",
		"TRUST_GATEWAY_CLIENT_ID",
		"TRUST_GATEWAY_CLIENT_SECRET",
		"TRUST_GATEWAY_REDIRECT_URI",
		"TRUST_GATEWAY_RETURN_URL",
		"TRUST_GATEWAY_TSA_URL",
	} {
		t.Run(missing, func(t *testing.T) {
			env := validLiveEnv()
			delete(env, missing)
			setEnv(t, env)
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), missing) {
				t.Fatalf("Load() error = %v, want missing %s", err, missing)
			}
		})
	}
}

func TestCallbackRedirectRequiresReturnURLInFixturesMode(t *testing.T) {
	env := fixturesEnv()
	env["TRUST_GATEWAY_REDIRECT_URI"] = "http://localhost:8080" + OAuthCallbackPath
	setEnv(t, env)

	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "TRUST_GATEWAY_RETURN_URL") {
		t.Fatalf("Load() error = %v, want callback return URL requirement", err)
	}
}

func TestGatewayURLContract(t *testing.T) {
	setEnv(t, validLiveEnv())
	profile, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if profile.RedirectURI != "https://gateway.example"+OAuthCallbackPath {
		t.Fatalf("RedirectURI = %q", profile.RedirectURI)
	}
	wantReturn, _ := url.Parse("https://app.example/signing/complete")
	if profile.ReturnURL == nil || profile.ReturnURL.String() != wantReturn.String() {
		t.Fatalf("ReturnURL = %v, want %v", profile.ReturnURL, wantReturn)
	}

	tests := []struct {
		name   string
		mutate func(map[string]string)
		want   string
	}{
		{"callback scheme", func(env map[string]string) {
			env["TRUST_GATEWAY_REDIRECT_URI"] = "ftp://gateway.example" + OAuthCallbackPath
		}, "http"},
		{"callback https", func(env map[string]string) {
			env["TRUST_GATEWAY_REDIRECT_URI"] = "http://gateway.example" + OAuthCallbackPath
		}, "https"},
		{"callback path", func(env map[string]string) { env["TRUST_GATEWAY_REDIRECT_URI"] = "https://gateway.example/return" }, OAuthCallbackPath},
		{"callback query", func(env map[string]string) { env["TRUST_GATEWAY_REDIRECT_URI"] += "?x=1" }, "query"},
		{"callback fragment", func(env map[string]string) { env["TRUST_GATEWAY_REDIRECT_URI"] += "#x" }, "fragment"},
		{"return scheme", func(env map[string]string) { env["TRUST_GATEWAY_RETURN_URL"] = "ftp://app.example/complete" }, "http"},
		{"return https", func(env map[string]string) { env["TRUST_GATEWAY_RETURN_URL"] = "http://app.example/complete" }, "https"},
		{"return query", func(env map[string]string) { env["TRUST_GATEWAY_RETURN_URL"] += "?x=1" }, "query"},
		{"return fragment", func(env map[string]string) { env["TRUST_GATEWAY_RETURN_URL"] += "#x" }, "fragment"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			env := clone(validLiveEnv())
			test.mutate(env)
			setEnv(t, env)
			if _, err := Load(); err == nil || !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(test.want)) {
				t.Fatalf("Load() error = %v, want text %q", err, test.want)
			}
		})
	}
}

func TestLiveAllowsLoopbackHTTP(t *testing.T) {
	for _, host := range []string{"localhost", "127.0.0.1", "[::1]"} {
		t.Run(host, func(t *testing.T) {
			env := validLiveEnv()
			env["TRUST_GATEWAY_REDIRECT_URI"] = "http://" + host + ":3000" + OAuthCallbackPath
			env["TRUST_GATEWAY_RETURN_URL"] = "http://" + host + ":3000/signing/complete"
			setEnv(t, env)
			if _, err := Load(); err != nil {
				t.Fatalf("Load() loopback error = %v", err)
			}
		})
	}
}

func TestMalformedURLsFailFast(t *testing.T) {
	for _, variable := range []string{
		"TRUST_GATEWAY_BASE_URL",
		"TRUST_GATEWAY_PUBLIC_BASE_URL",
		"TRUST_GATEWAY_REDIRECT_URI",
		"TRUST_GATEWAY_RETURN_URL",
		"TRUST_GATEWAY_TSA_URL",
	} {
		t.Run(variable, func(t *testing.T) {
			env := fixturesEnv()
			env[variable] = "missing-scheme.example/path"
			setEnv(t, env)
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), variable) {
				t.Fatalf("Load() error = %v, want malformed %s", err, variable)
			}
		})
	}

	env := fixturesEnv()
	env["TRUST_GATEWAY_BASE_URL"] = "http://[broken"
	setEnv(t, env)
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "missing ']' in host") {
		t.Fatalf("Load() syntax error = %v", err)
	}
}
