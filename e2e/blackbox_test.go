// Package e2e_test exercises a running trust-gateway only through its HTTP contract. It deliberately
// imports no gateway or Cleverbase binding package, so the test compiles with CGO_ENABLED=0.
package e2e_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	maxJSONBytes   = 1 << 20
	maxResultBytes = 21 << 20
	clientState    = "blackbox-e2e-continuation"
)

var byteRangePattern = regexp.MustCompile(`/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]`)

type testConfig struct {
	baseURL  string
	apiKey   string
	mode     string
	caBundle string
	timeout  time.Duration
}

func loadConfig(t *testing.T) testConfig {
	t.Helper()
	cfg := testConfig{
		baseURL:  strings.TrimRight(os.Getenv("TRUST_GATEWAY_E2E_URL"), "/"),
		apiKey:   os.Getenv("TRUST_GATEWAY_E2E_API_KEY"),
		mode:     os.Getenv("TRUST_GATEWAY_E2E_MODE"),
		caBundle: os.Getenv("TRUST_GATEWAY_E2E_CA_BUNDLE"),
		timeout:  45 * time.Second,
	}
	if cfg.baseURL == "" || cfg.apiKey == "" {
		t.Skip("black-box E2E requires TRUST_GATEWAY_E2E_URL and TRUST_GATEWAY_E2E_API_KEY")
	}
	if cfg.mode == "" {
		cfg.mode = "mock"
	}
	if cfg.mode != "mock" && cfg.mode != "live" {
		t.Fatalf("TRUST_GATEWAY_E2E_MODE must be mock or live, got %q", cfg.mode)
	}
	if raw := os.Getenv("TRUST_GATEWAY_E2E_TIMEOUT"); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil || d <= 0 {
			t.Fatalf("TRUST_GATEWAY_E2E_TIMEOUT must be a positive duration, got %q", raw)
		}
		cfg.timeout = d
	} else if cfg.mode == "live" {
		cfg.timeout = 5 * time.Minute
	}
	if cfg.mode == "live" && cfg.caBundle == "" {
		t.Skip("live black-box E2E requires TRUST_GATEWAY_E2E_CA_BUNDLE")
	}
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl is required for independent CMS validation")
	}
	return cfg
}

type redirectOpener interface {
	Open(context.Context, string, string) error
}

type liveOpener struct{}

func (liveOpener) Open(_ context.Context, authorizeURL, _ string) error {
	fmt.Fprintf(os.Stderr, "\nOpen this URL and complete both Cleverbase authorization steps:\n%s\n\n", authorizeURL)
	return nil
}

type mockOpener struct {
	client *http.Client
}

func (m mockOpener) Open(ctx context.Context, authorizeURL, correlationID string) error {
	current := authorizeURL
	callbackCount := 0
	for range 6 {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, current, nil)
		if err != nil {
			return fmt.Errorf("build browser request: %w", err)
		}
		resp, err := m.client.Do(req)
		if err != nil {
			return fmt.Errorf("open authorization redirect: %w", err)
		}
		_, readErr := io.Copy(io.Discard, io.LimitReader(resp.Body, maxJSONBytes))
		closeErr := resp.Body.Close()
		if readErr != nil {
			return fmt.Errorf("read browser response: %w", readErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close browser response: %w", closeErr)
		}
		if resp.StatusCode < http.StatusMultipleChoices || resp.StatusCode >= http.StatusBadRequest {
			return fmt.Errorf("browser navigation %s returned %d, want redirect", current, resp.StatusCode)
		}
		location, err := resp.Location()
		if err != nil {
			return fmt.Errorf("browser redirect has no valid Location: %w", err)
		}
		if location.Path == "/oauth/cleverbase/callback" {
			callbackCount++
		}
		if isTerminalReturn(location) {
			return validateTerminalReturn(location, correlationID, callbackCount)
		}
		current = location.String()
	}
	return errors.New("browser redirect chain did not reach the application return")
}

func isTerminalReturn(location *url.URL) bool {
	query := location.Query()
	return query.Get("correlationId") != "" || query.Get("clientState") != ""
}

func validateTerminalReturn(location *url.URL, correlationID string, callbackCount int) error {
	query := location.Query()
	if len(query) != 2 || query.Get("correlationId") != correlationID || query.Get("clientState") != clientState {
		return fmt.Errorf("terminal return query does not match the opaque contract: %s", location.Redacted())
	}
	if callbackCount != 2 {
		return fmt.Errorf("browser traversed %d gateway callbacks, want 2", callbackCount)
	}
	return nil
}

type startResponse struct {
	RedirectURL   string `json:"redirectUrl"`
	CorrelationID string `json:"correlationId"`
}

type statusResponse struct {
	Status string `json:"status"`
	Reason string `json:"reason"`
}

func TestBlackboxSigning(t *testing.T) {
	cfg := loadConfig(t)
	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), cfg.timeout)
	defer cancel()

	document, err := os.ReadFile(filepath.Join("testdata", "sample.pdf"))
	if err != nil {
		t.Fatalf("read sample PDF: %v", err)
	}
	body, err := json.Marshal(map[string]string{
		"document":         base64.StdEncoding.EncodeToString(document),
		"conformanceLevel": "B-B",
		"clientState":      clientState,
	})
	if err != nil {
		t.Fatalf("encode start request: %v", err)
	}
	var started startResponse
	doJSON(t, ctx, client, cfg, http.MethodPost, "/v1/sign/start", body, http.StatusOK, &started)
	if started.RedirectURL == "" || started.CorrelationID == "" {
		t.Fatalf("start response lacks redirectUrl or correlationId: %+v", started)
	}

	var opener redirectOpener = mockOpener{client: client}
	if cfg.mode == "live" {
		opener = liveOpener{}
	}
	if err := opener.Open(ctx, started.RedirectURL, started.CorrelationID); err != nil {
		t.Fatalf("authorize signing: %v", err)
	}
	waitCompleted(t, ctx, client, cfg, started.CorrelationID)

	req, err := authorizedRequest(ctx, cfg, http.MethodGet,
		"/v1/sign/result?correlationId="+url.QueryEscape(started.CorrelationID), nil)
	if err != nil {
		t.Fatalf("build result request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("fetch signed result: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	result, err := io.ReadAll(io.LimitReader(resp.Body, maxResultBytes+1))
	if err != nil {
		t.Fatalf("read signed result: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("result returned %d: %s", resp.StatusCode, result)
	}
	if len(result) > maxResultBytes || !bytes.HasPrefix(result, []byte("%PDF-")) {
		t.Fatalf("result is not a bounded PDF: %d bytes", len(result))
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("result Cache-Control = %q, want no-store", resp.Header.Get("Cache-Control"))
	}
	assertEvidence(t, resp.Header.Get("X-Signature-Evidence"))
	verifyCMS(t, result, cfg)
}

func doJSON(t *testing.T, ctx context.Context, client *http.Client, cfg testConfig, method, path string, body []byte, wantStatus int, out any) {
	t.Helper()
	req, err := authorizedRequest(ctx, cfg, method, path, body)
	if err != nil {
		t.Fatalf("build %s request: %v", path, err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	limited := io.LimitReader(resp.Body, maxJSONBytes+1)
	payload, err := io.ReadAll(limited)
	if err != nil {
		t.Fatalf("read %s response: %v", path, err)
	}
	if len(payload) > maxJSONBytes {
		t.Fatalf("%s response exceeds %d bytes", path, maxJSONBytes)
	}
	if resp.StatusCode != wantStatus {
		t.Fatalf("%s returned %d, want %d: %s", path, resp.StatusCode, wantStatus, payload)
	}
	if err := json.Unmarshal(payload, out); err != nil {
		t.Fatalf("decode %s response: %v: %s", path, err, payload)
	}
}

func authorizedRequest(ctx context.Context, cfg testConfig, method, path string, body []byte) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, cfg.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.apiKey)
	return req, nil
}

func waitCompleted(t *testing.T, ctx context.Context, client *http.Client, cfg testConfig, correlationID string) {
	t.Helper()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		var status statusResponse
		doJSON(t, ctx, client, cfg, http.MethodGet,
			"/v1/sign/status?correlationId="+url.QueryEscape(correlationID), nil, http.StatusOK, &status)
		switch status.Status {
		case "completed":
			return
		case "failed", "declined":
			t.Fatalf("signing ended with %s: %s", status.Status, status.Reason)
		case "pending", "authorizing":
			// Continue until the browser completes both authorization legs or the context expires.
		default:
			t.Fatalf("unknown signing status %q", status.Status)
		}
		select {
		case <-ctx.Done():
			t.Fatalf("signing did not complete within %s: %v", cfg.timeout, ctx.Err())
		case <-ticker.C:
		}
	}
}

func assertEvidence(t *testing.T, encoded string) {
	t.Helper()
	if encoded == "" {
		t.Fatal("result lacks X-Signature-Evidence")
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("evidence is not base64: %v", err)
	}
	var evidence map[string]any
	if err := json.Unmarshal(raw, &evidence); err != nil {
		t.Fatalf("evidence is not JSON: %v", err)
	}
	if evidence["outcome"] != "signed" || evidence["signer"] == nil {
		t.Fatalf("evidence lacks signed outcome or signer identity: %v", evidence)
	}
}

func verifyCMS(t *testing.T, pdf []byte, cfg testConfig) {
	t.Helper()
	matches := byteRangePattern.FindSubmatch(pdf)
	if matches == nil {
		t.Fatal("signed PDF lacks /ByteRange")
	}
	parts := make([]int, 4)
	for i := range parts {
		value, err := strconv.Atoi(string(matches[i+1]))
		if err != nil {
			t.Fatalf("invalid ByteRange component: %v", err)
		}
		parts[i] = value
	}
	a, b, c, d := parts[0], parts[1], parts[2], parts[3]
	if a != 0 || b < 0 || c < 0 || d < 0 || a+b > c || c+d > len(pdf) {
		t.Fatalf("ByteRange out of bounds: %v for %d-byte PDF", parts, len(pdf))
	}
	signed := append(append([]byte(nil), pdf[a:a+b]...), pdf[c:c+d]...)
	cms := extractContents(t, pdf)

	work := t.TempDir()
	cmsPath := filepath.Join(work, "signature.der")
	contentPath := filepath.Join(work, "signed-content.bin")
	outPath := filepath.Join(work, "verified-content.bin")
	if err := os.WriteFile(cmsPath, cms, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(contentPath, signed, 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"cms", "-verify", "-binary", "-inform", "DER", "-in", cmsPath, "-content", contentPath, "-out", outPath}
	if cfg.mode == "mock" {
		args = append(args, "-noverify")
	} else {
		args = append(args, "-CAfile", cfg.caBundle, "-purpose", "any", "-no_check_time")
	}
	//nolint:gosec // G204: executable and flags are fixed; the optional CA path is explicit operator input.
	if output, err := exec.Command("openssl", args...).CombinedOutput(); err != nil {
		t.Fatalf("OpenSSL rejected the detached CMS: %v\n%s", err, output)
	}
}

func extractContents(t *testing.T, pdf []byte) []byte {
	t.Helper()
	contentsAt := bytes.Index(pdf, []byte("/Contents"))
	if contentsAt < 0 {
		t.Fatal("signed PDF lacks /Contents")
	}
	start := bytes.IndexByte(pdf[contentsAt:], '<')
	if start < 0 {
		t.Fatal("signed PDF /Contents lacks opening delimiter")
	}
	start += contentsAt + 1
	end := bytes.IndexByte(pdf[start:], '>')
	if end < 0 {
		t.Fatal("signed PDF /Contents lacks closing delimiter")
	}
	hexText := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\n' || r == '\r' || r == '\t' {
			return -1
		}
		return r
	}, string(pdf[start:start+end]))
	raw, err := hex.DecodeString(hexText)
	if err != nil {
		t.Fatalf("decode CMS hex: %v", err)
	}
	total, err := derLength(raw)
	if err != nil {
		t.Fatalf("decode CMS DER length: %v", err)
	}
	return raw[:total]
}

func derLength(der []byte) (int, error) {
	if len(der) < 2 {
		return 0, errors.New("truncated DER header")
	}
	lengthByte := der[1]
	if lengthByte < 0x80 {
		total := 2 + int(lengthByte)
		if total > len(der) {
			return 0, errors.New("truncated DER value")
		}
		return total, nil
	}
	lengthBytes := int(lengthByte & 0x7f)
	if lengthBytes == 0 || lengthBytes > 4 || len(der) < 2+lengthBytes {
		return 0, errors.New("invalid DER length")
	}
	contentLength := 0
	for _, value := range der[2 : 2+lengthBytes] {
		contentLength = contentLength<<8 | int(value)
	}
	total := 2 + lengthBytes + contentLength
	if total > len(der) {
		return 0, errors.New("truncated DER value")
	}
	return total, nil
}
