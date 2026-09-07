// Package e2e_test exercises a running trust-gateway only through its HTTP contract. It deliberately
// imports no gateway or Cleverbase binding package, so the test compiles with CGO_ENABLED=0.
package e2e_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
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
	maxJSONBytes     = 1 << 20
	maxResultBytes   = 21 << 20
	clientState      = "blackbox-e2e-continuation"
	mockSignerCN     = "Jane Doe"
	mockSignerSerial = "07FB0DA8384404C33517B852CFE79F04C5006AC1"
)

var byteRangePattern = regexp.MustCompile(`/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]`)

type testConfig struct {
	baseURL     string
	apiKey      string
	mode        string
	caBundle    string
	artifactDir string
	timeout     time.Duration
}

func loadConfig(t *testing.T) testConfig {
	t.Helper()
	required := os.Getenv("TRUST_GATEWAY_E2E_REQUIRED") == "1"
	cfg := testConfig{
		baseURL:     strings.TrimRight(os.Getenv("TRUST_GATEWAY_E2E_URL"), "/"),
		apiKey:      os.Getenv("TRUST_GATEWAY_E2E_API_KEY"),
		mode:        os.Getenv("TRUST_GATEWAY_E2E_MODE"),
		caBundle:    os.Getenv("TRUST_GATEWAY_E2E_CA_BUNDLE"),
		artifactDir: os.Getenv("TRUST_GATEWAY_E2E_ARTIFACT_DIR"),
		timeout:     45 * time.Second,
	}
	if cfg.baseURL == "" || cfg.apiKey == "" {
		unavailable(t, required, "black-box E2E requires TRUST_GATEWAY_E2E_URL and TRUST_GATEWAY_E2E_API_KEY")
	}
	if cfg.mode == "" {
		cfg.mode = "mock"
	}
	if cfg.mode != "mock" && cfg.mode != "stub" && cfg.mode != "live" {
		t.Fatalf("TRUST_GATEWAY_E2E_MODE must be mock, stub, or live, got %q", cfg.mode)
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
		unavailable(t, required, "live black-box E2E requires TRUST_GATEWAY_E2E_CA_BUNDLE")
	}
	if cfg.mode != "stub" {
		if _, err := exec.LookPath("openssl"); err != nil {
			unavailable(t, required, "openssl is required for independent CMS validation")
		}
	}
	return cfg
}

func unavailable(t *testing.T, required bool, message string) {
	t.Helper()
	if required {
		t.Fatal(message)
	}
	t.Skip(message)
}

type redirectOpener interface {
	Open(context.Context, string, string) error
}

type liveOpener struct{}

func (liveOpener) Open(_ context.Context, authorizeURL, _ string) error {
	fmt.Fprintf(os.Stderr, "\nOpen this URL and complete both Cleverbase authorization steps:\n%s\n\n", authorizeURL)
	return nil
}

// automatedOpener follows the documented immediate browser redirects used by both the local mock
// and Cleverbase's public hash-signing stub. The interactive live service keeps the human opener.
type automatedOpener struct {
	client *http.Client
}

func (m automatedOpener) Open(ctx context.Context, authorizeURL, correlationID string) error {
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
	ExpiresAt     string `json:"expiresAt"`
}

type statusResponse struct {
	Status string `json:"status"`
	Reason string `json:"reason"`
}

type verifyResponse struct {
	Integrity bool    `json:"integrity"`
	Profile   *string `json:"profile"`
	Signer    *struct {
		Serial string `json:"serial"`
		CN     string `json:"cn"`
	} `json:"signer"`
	Reasons []string `json:"reasons"`
}

type signedResult struct {
	PDF      []byte
	Evidence json.RawMessage
}

type acceptanceArtifacts struct {
	CorrelationID string
	ExpiresAt     string
	SignedPDF     []byte
	Evidence      json.RawMessage
	Verification  verifyResponse
}

type artifactMetadata struct {
	CorrelationID   string `json:"correlationId"`
	ExpiresAt       string `json:"expiresAt"`
	SignedPDFSHA256 string `json:"signedPdfSha256"`
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

	started := startSigning(t, ctx, client, cfg)
	if err := openerFor(cfg, client).Open(ctx, started.RedirectURL, started.CorrelationID); err != nil {
		t.Fatalf("authorize signing: %v", err)
	}
	status := waitTerminal(t, ctx, client, cfg, started.CorrelationID)
	result := assertTerminalResult(t, ctx, client, cfg, started.CorrelationID, status)
	if cfg.mode != "stub" {
		verification := assertGatewayVerification(t, ctx, client, cfg, result.PDF)
		if cfg.artifactDir != "" {
			if err := writeArtifacts(cfg.artifactDir, acceptanceArtifacts{
				CorrelationID: started.CorrelationID,
				ExpiresAt:     started.ExpiresAt,
				SignedPDF:     result.PDF,
				Evidence:      result.Evidence,
				Verification:  verification,
			}); err != nil {
				t.Fatalf("write acceptance artifacts: %v", err)
			}
			t.Logf("acceptance evidence written to %s", cfg.artifactDir)
		}
	}
}

func startSigning(t *testing.T, ctx context.Context, client *http.Client, cfg testConfig) startResponse {
	t.Helper()
	document, err := os.ReadFile(filepath.Join("testdata", "sample.pdf"))
	if err != nil {
		t.Fatalf("read sample PDF: %v", err)
	}
	body, err := json.Marshal(map[string]string{
		"document":    base64.StdEncoding.EncodeToString(document),
		"clientState": clientState,
	})
	if err != nil {
		t.Fatalf("encode start request: %v", err)
	}
	var started startResponse
	doJSON(t, ctx, client, cfg, http.MethodPost, "/v1/sign/start", body, http.StatusOK, &started)
	if started.RedirectURL == "" || started.CorrelationID == "" || started.ExpiresAt == "" {
		t.Fatalf("start response lacks redirectUrl, correlationId, or expiresAt: %+v", started)
	}
	if _, err := time.Parse(time.RFC3339, started.ExpiresAt); err != nil {
		t.Fatalf("start expiresAt = %q, want RFC 3339: %v", started.ExpiresAt, err)
	}
	return started
}

func openerFor(cfg testConfig, client *http.Client) redirectOpener {
	if cfg.mode == "live" {
		return liveOpener{}
	}
	return automatedOpener{client: client}
}

func assertTerminalResult(t *testing.T, ctx context.Context, client *http.Client, cfg testConfig, correlationID string, status statusResponse) signedResult {
	t.Helper()
	if cfg.mode == "stub" {
		assertStubFailure(t, ctx, client, cfg, correlationID, status)
		return signedResult{}
	}
	if status.Status != "completed" {
		t.Fatalf("signing ended with %s: %s", status.Status, status.Reason)
	}

	req, err := authorizedRequest(ctx, cfg, http.MethodGet,
		"/v1/sign/result?correlationId="+url.QueryEscape(correlationID), nil)
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
	evidence := assertEvidence(t, resp.Header.Get("X-Signature-Evidence"))
	verifyCMS(t, result, cfg)
	return signedResult{PDF: result, Evidence: evidence}
}

func assertGatewayVerification(t *testing.T, ctx context.Context, client *http.Client, cfg testConfig, signedPDF []byte) verifyResponse {
	t.Helper()
	valid := verifyThroughGateway(t, ctx, client, cfg, signedPDF)
	assertValidGatewayVerification(t, cfg, valid)

	tampered := tamperSignedWhitespace(t, signedPDF)
	invalid := verifyThroughGateway(t, ctx, client, cfg, tampered)
	if invalid.Integrity || invalid.Profile != nil || invalid.Signer != nil ||
		len(invalid.Reasons) != 1 || invalid.Reasons[0] != "message_digest_mismatch" {
		t.Fatalf("gateway tamper verdict = %+v, want message_digest_mismatch", invalid)
	}
	return valid
}

func assertValidGatewayVerification(t *testing.T, cfg testConfig, valid verifyResponse) {
	t.Helper()
	if !valid.Integrity || valid.Profile == nil || valid.Signer == nil || len(valid.Reasons) != 0 {
		t.Fatalf("gateway rejected its signed PDF: %+v", valid)
	}
	if *valid.Profile != "B-B" && *valid.Profile != "B-T" {
		t.Fatalf("gateway returned unsupported profile: %+v", valid)
	}
	if cfg.mode == "mock" && (*valid.Profile != "B-B" || valid.Signer.Serial != mockSignerSerial || valid.Signer.CN != mockSignerCN) {
		t.Fatalf("gateway mock verification = %+v, want B-B signer %s / %s", valid, mockSignerSerial, mockSignerCN)
	}
	if cfg.mode == "live" && (valid.Signer.Serial == "" || valid.Signer.CN == "") {
		t.Fatalf("gateway live verification lacks signer identity: %+v", valid)
	}
}

func verifyThroughGateway(t *testing.T, ctx context.Context, client *http.Client, cfg testConfig, pdf []byte) verifyResponse {
	t.Helper()
	body, err := json.Marshal(map[string]string{"document": base64.StdEncoding.EncodeToString(pdf)})
	if err != nil {
		t.Fatalf("encode verify request: %v", err)
	}
	var verdict verifyResponse
	doJSON(t, ctx, client, cfg, http.MethodPost, "/v1/verify", body, http.StatusOK, &verdict)
	return verdict
}

func tamperSignedWhitespace(t *testing.T, pdf []byte) []byte {
	t.Helper()
	parts, err := parseByteRange(pdf)
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), pdf...)
	for _, span := range [][2]int{{parts[0], parts[0] + parts[1]}, {parts[2], parts[2] + parts[3]}} {
		for i := span[0]; i < span[1]; i++ {
			if tampered[i] == ' ' {
				tampered[i] = '\n' // Equal-length PDF whitespace keeps structure/offsets valid.
				return tampered
			}
		}
	}
	t.Fatal("signed PDF ranges contain no whitespace byte to tamper")
	return nil
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

func waitTerminal(t *testing.T, ctx context.Context, client *http.Client, cfg testConfig, correlationID string) statusResponse {
	t.Helper()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		var status statusResponse
		doJSON(t, ctx, client, cfg, http.MethodGet,
			"/v1/sign/status?correlationId="+url.QueryEscape(correlationID), nil, http.StatusOK, &status)
		switch status.Status {
		case "completed":
			return status
		case "failed", "declined":
			return status
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

func assertStubFailure(t *testing.T, ctx context.Context, client *http.Client, cfg testConfig, correlationID string, status statusResponse) {
	t.Helper()
	if status.Status != "failed" || status.Reason != "signature_invalid" {
		t.Fatalf("stub terminal status = %+v, want failed/signature_invalid", status)
	}
	req, err := authorizedRequest(ctx, cfg, http.MethodGet,
		"/v1/sign/result?correlationId="+url.QueryEscape(correlationID), nil)
	if err != nil {
		t.Fatalf("build failed-result request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("fetch failed result: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJSONBytes+1))
	if err != nil {
		t.Fatalf("read failed result: %v", err)
	}
	if resp.StatusCode != http.StatusConflict || len(body) == 0 || resp.Header.Get("X-Signature-Evidence") != "" {
		t.Fatalf("stub result = status %d, body %q, evidence %q; want 409 JSON with no result evidence", resp.StatusCode, body, resp.Header.Get("X-Signature-Evidence"))
	}
}

func assertEvidence(t *testing.T, encoded string) json.RawMessage {
	t.Helper()
	raw, err := validateEvidence(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func validateEvidence(encoded string) (json.RawMessage, error) {
	if encoded == "" {
		return nil, errors.New("result lacks X-Signature-Evidence")
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("evidence is not base64: %w", err)
	}
	var evidence map[string]any
	if err := json.Unmarshal(raw, &evidence); err != nil {
		return nil, fmt.Errorf("evidence is not JSON: %w", err)
	}
	if evidence["outcome"] != "signed" {
		return nil, errors.New("evidence outcome is not signed")
	}
	signer, ok := evidence["signer"].(map[string]any)
	if !ok {
		return nil, errors.New("evidence lacks signer identity")
	}
	serialNumber, serialOK := signer["serial_number"].(string)
	rawSubject, subjectOK := signer["raw_subject"].(string)
	if !serialOK || strings.TrimSpace(serialNumber) == "" || !subjectOK || strings.TrimSpace(rawSubject) == "" {
		return nil, errors.New("evidence signer identity lacks serial_number or raw_subject")
	}
	return json.RawMessage(raw), nil
}

func writeArtifacts(directory string, artifacts acceptanceArtifacts) error {
	directory, err := prepareArtifactDirectory(directory)
	if err != nil {
		return err
	}
	metadata := artifactMetadata{
		CorrelationID:   artifacts.CorrelationID,
		ExpiresAt:       artifacts.ExpiresAt,
		SignedPDFSHA256: fmt.Sprintf("%x", sha256.Sum256(artifacts.SignedPDF)),
	}
	files := []struct {
		name  string
		value any
		raw   []byte
	}{
		{name: "signed.pdf", raw: artifacts.SignedPDF},
		{name: "evidence.json", raw: artifacts.Evidence},
		{name: "verify.json", value: artifacts.Verification},
		{name: "metadata.json", value: metadata},
	}
	for _, file := range files {
		content := file.raw
		if file.value != nil {
			content, err = json.MarshalIndent(file.value, "", "  ")
			if err != nil {
				return fmt.Errorf("encode %s: %w", file.name, err)
			}
			content = append(content, '\n')
		}
		path := filepath.Join(directory, file.name)
		if err := os.WriteFile(path, content, 0o600); err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}
		if err := os.Chmod(path, 0o600); err != nil {
			return fmt.Errorf("secure %s: %w", path, err)
		}
	}
	return nil
}

func prepareArtifactDirectory(directory string) (string, error) {
	if !filepath.IsAbs(directory) {
		return "", errors.New("TRUST_GATEWAY_E2E_ARTIFACT_DIR must be an absolute path outside the repository")
	}
	info, err := os.Stat(directory)
	if err != nil {
		return "", fmt.Errorf("inspect artifact directory: %w", err)
	}
	if !info.IsDir() {
		return "", errors.New("TRUST_GATEWAY_E2E_ARTIFACT_DIR must name an existing directory")
	}
	resolvedDirectory, err := filepath.EvalSymlinks(directory)
	if err != nil {
		return "", fmt.Errorf("resolve artifact directory: %w", err)
	}
	repositoryRoot, err := findRepositoryRoot()
	if err != nil {
		return "", err
	}
	resolvedRoot, err := filepath.EvalSymlinks(repositoryRoot)
	if err != nil {
		return "", fmt.Errorf("resolve repository root: %w", err)
	}
	relative, err := filepath.Rel(resolvedRoot, resolvedDirectory)
	if err != nil {
		return "", fmt.Errorf("compare artifact directory with repository: %w", err)
	}
	if relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))) {
		return "", errors.New("TRUST_GATEWAY_E2E_ARTIFACT_DIR must be outside the repository")
	}
	// The operator owns this directory. Reject unsafe permissions instead of changing them.
	if info.Mode().Perm() != 0o700 {
		return "", errors.New("TRUST_GATEWAY_E2E_ARTIFACT_DIR must already have mode 0700")
	}
	return resolvedDirectory, nil
}

func findRepositoryRoot() (string, error) {
	directory, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("get working directory: %w", err)
	}
	for {
		if info, statErr := os.Stat(filepath.Join(directory, "go.mod")); statErr == nil && !info.IsDir() {
			return directory, nil
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			return "", errors.New("cannot locate repository root containing go.mod")
		}
		directory = parent
	}
}

func verifyCMS(t *testing.T, pdf []byte, cfg testConfig) {
	t.Helper()
	parts, err := parseByteRange(pdf)
	if err != nil {
		t.Fatal(err)
	}
	a, b, c, d := parts[0], parts[1], parts[2], parts[3]
	signed := append(append([]byte(nil), pdf[a:a+b]...), pdf[c:c+d]...)
	cms := extractSignatureContents(t, pdf, a+b, c)

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
		args = append(args, "-CAfile", cfg.caBundle, "-purpose", "any")
	}
	//nolint:gosec // G204: executable and flags are fixed; the optional CA path is explicit operator input.
	if output, err := exec.Command("openssl", args...).CombinedOutput(); err != nil {
		t.Fatalf("OpenSSL rejected the detached CMS: %v\n%s", err, output)
	}
}

func parseByteRange(pdf []byte) ([4]int, error) {
	matches := byteRangePattern.FindSubmatch(pdf)
	if matches == nil {
		return [4]int{}, errors.New("signed PDF lacks /ByteRange")
	}
	var parts [4]int
	for i := range parts {
		value, err := strconv.Atoi(string(matches[i+1]))
		if err != nil {
			return [4]int{}, fmt.Errorf("invalid ByteRange component: %w", err)
		}
		parts[i] = value
	}
	a, b, c, d := parts[0], parts[1], parts[2], parts[3]
	if a != 0 || b < 0 || c < 0 || d < 0 || a+b > c || c > len(pdf) || d != len(pdf)-c {
		return [4]int{}, fmt.Errorf("ByteRange does not cover the full PDF: %v for %d-byte PDF", parts, len(pdf))
	}
	return parts, nil
}

func extractSignatureContents(t *testing.T, pdf []byte, gapStart, gapEnd int) []byte {
	t.Helper()
	gap := pdf[gapStart:gapEnd]
	hexText := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\n' || r == '\r' || r == '\t' {
			return -1
		}
		return r
	}, string(gap))
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

func TestExtractSignatureContentsUsesByteRangeGap(t *testing.T) {
	t.Parallel()
	pageContents := []byte("/Contents 1 0 R\n")
	signatureGap := []byte("30 00")
	pdf := append(append([]byte(nil), pageContents...), signatureGap...)

	got := extractSignatureContents(t, pdf, len(pageContents), len(pdf))
	if !bytes.Equal(got, []byte{0x30, 0x00}) {
		t.Fatalf("signature contents = %x, want 3000", got)
	}
}

func TestParseByteRangeRejectsUnsignedSuffix(t *testing.T) {
	t.Parallel()
	declaredLength := 0
	var pdf []byte
	for {
		pdf = fmt.Appendf(nil, "/ByteRange [0 0 0 %d]", declaredLength)
		if len(pdf) == declaredLength {
			break
		}
		declaredLength = len(pdf)
	}
	if _, err := parseByteRange(pdf); err != nil {
		t.Fatalf("valid full-document ByteRange rejected: %v", err)
	}
	if _, err := parseByteRange(append(pdf, 'x')); err == nil {
		t.Fatal("ByteRange with unsigned suffix accepted")
	}
}

func TestValidateEvidenceRequiresSignerIdentity(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"missing serial number": `{"outcome":"signed","signer":{"raw_subject":"CN=Ada"}}`,
		"missing raw subject":   `{"outcome":"signed","signer":{"serial_number":"CERT-123"}}`,
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			encoded := base64.StdEncoding.EncodeToString([]byte(raw))
			if _, err := validateEvidence(encoded); err == nil {
				t.Fatal("validateEvidence accepted incomplete signer identity")
			}
		})
	}
}

func TestStartSigningUsesGatewayDefaultConformance(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request map[string]any
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode start request: %v", err)
		}
		if _, exists := request["conformanceLevel"]; exists {
			t.Errorf("start request overrides the gateway's configured conformance: %v", request)
		}
		writeTestJSON(t, w, startResponse{
			RedirectURL:   "https://example.invalid/authorize",
			CorrelationID: "correlation-id",
			ExpiresAt:     "2026-09-07T12:00:00Z",
		})
	}))
	defer server.Close()

	startSigning(t, context.Background(), server.Client(), testConfig{
		baseURL: server.URL,
		apiKey:  "test-key",
	})
}

func TestWriteArtifactsPersistsValidatedEvidenceOutsideRepository(t *testing.T) {
	t.Parallel()
	artifactDir := t.TempDir()
	//nolint:gosec // This is a directory; owner read/write/traverse is intentionally 0700.
	if err := os.Chmod(artifactDir, 0o700); err != nil {
		t.Fatal(err)
	}
	profile := "B-T"
	artifacts := acceptanceArtifacts{
		CorrelationID: "correlation-id",
		ExpiresAt:     "2026-09-07T12:00:00Z",
		SignedPDF:     []byte("%PDF-signed"),
		Evidence:      json.RawMessage(`{"outcome":"signed"}`),
		Verification:  verifyResponse{Integrity: true, Profile: &profile, Reasons: []string{}},
	}
	if err := writeArtifacts(artifactDir, artifacts); err != nil {
		t.Fatalf("writeArtifacts() error = %v", err)
	}

	assertArtifactFile(t, artifactDir, "signed.pdf", artifacts.SignedPDF)
	assertArtifactFile(t, artifactDir, "evidence.json", artifacts.Evidence)

	var verification verifyResponse
	verificationBytes := readArtifactFile(t, artifactDir, "verify.json")
	if err := json.Unmarshal(verificationBytes, &verification); err != nil {
		t.Fatal(err)
	}
	if !verification.Integrity || verification.Profile == nil || *verification.Profile != "B-T" {
		t.Fatalf("verify.json = %+v", verification)
	}

	var metadata artifactMetadata
	metadataBytes := readArtifactFile(t, artifactDir, "metadata.json")
	if err := json.Unmarshal(metadataBytes, &metadata); err != nil {
		t.Fatal(err)
	}
	wantDigest := fmt.Sprintf("%x", sha256.Sum256(artifacts.SignedPDF))
	if metadata.CorrelationID != artifacts.CorrelationID || metadata.ExpiresAt != artifacts.ExpiresAt || metadata.SignedPDFSHA256 != wantDigest {
		t.Fatalf("metadata.json = %+v", metadata)
	}
}

func assertArtifactFile(t *testing.T, directory, name string, want []byte) {
	t.Helper()
	got := readArtifactFile(t, directory, name)
	if !bytes.Equal(bytes.TrimSpace(got), want) {
		t.Fatalf("%s = %q, want %q", name, bytes.TrimSpace(got), want)
	}
	info, err := os.Stat(filepath.Join(directory, name))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("%s mode = %o, want 600", name, info.Mode().Perm())
	}
}

func readArtifactFile(t *testing.T, directory, name string) []byte {
	t.Helper()
	//nolint:gosec // G304: both directory and fixed filenames are controlled by this test.
	content, err := os.ReadFile(filepath.Join(directory, name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return content
}

func TestArtifactDirectoryMustBeOutsideRepository(t *testing.T) {
	t.Parallel()
	repoRoot, err := findRepositoryRoot()
	if err != nil {
		t.Fatal(err)
	}
	rootInfo, err := os.Stat(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	insidePath := filepath.Join(repoRoot, "e2e", "artifacts-must-not-be-created")
	for _, path := range []string{"relative", repoRoot, insidePath} {
		if _, err := prepareArtifactDirectory(path); err == nil {
			t.Errorf("prepareArtifactDirectory(%q) succeeded", path)
		}
	}
	afterInfo, err := os.Stat(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	if afterInfo.Mode().Perm() != rootInfo.Mode().Perm() {
		t.Fatalf("rejected repository directory mode changed from %o to %o", rootInfo.Mode().Perm(), afterInfo.Mode().Perm())
	}
	if _, err := os.Stat(insidePath); !os.IsNotExist(err) {
		t.Fatalf("rejected in-repository artifact path was created: %v", err)
	}
	outsidePath := t.TempDir()
	//nolint:gosec // This is a directory; owner read/write/traverse is intentionally 0700.
	if err := os.Chmod(outsidePath, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareArtifactDirectory(outsidePath); err != nil {
		t.Fatalf("outside artifact directory rejected: %v", err)
	}
}

func TestArtifactDirectoryMustAlreadyBePrivate(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	//nolint:gosec // The insecure mode is deliberate test input and must remain unchanged.
	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatal(err)
	}

	if _, err := prepareArtifactDirectory(directory); err == nil {
		t.Fatal("prepareArtifactDirectory accepted a non-private operator directory")
	}
	info, err := os.Stat(directory)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("rejected operator directory mode changed to %o", info.Mode().Perm())
	}
}

func writeTestJSON(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Errorf("encode test response: %v", err)
	}
}
