package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestNoSecretInFrontendBoundResponses scans every client-bound response (start/complete/status/result
// bodies + headers) for any secret, token, or SDK handle (SC-004) — distinct from the upstream
// hash-only check in the E2E.
func TestNoSecretInFrontendBoundResponses(t *testing.T) {
	svc := newService(happySteps(), true)
	h := svc.Handler()

	var sink strings.Builder
	record := func(rec *httptest.ResponseRecorder) {
		sink.WriteString(rec.Body.String())
		for k, vs := range rec.Header() {
			sink.WriteString(k)
			for _, v := range vs {
				sink.WriteString(v)
				// X-Signature-Evidence is base64-encoded JSON; decode it so a secret leaked INSIDE the
				// evidence is scanned in plaintext rather than hidden behind the base64 encoding.
				if dec, err := base64.StdEncoding.DecodeString(v); err == nil {
					_, _ = sink.Write(dec) // strings.Builder.Write never errors; []byte avoids a string alloc
				}
			}
		}
	}

	rec := do(t, h, "POST", "/v1/sign/start", `{"conformanceLevel":"B-B"}`, "test-key")
	record(rec)
	var sr map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &sr); err != nil {
		t.Fatalf("start response is not JSON: %v (body %q)", err, rec.Body)
	}
	corr := sr["correlationId"]
	if corr == "" {
		t.Fatalf("start did not return a correlationId, so /status and /result are never exercised: %s", rec.Body)
	}

	record(do(t, h, "POST", "/v1/sign/complete", `{"code":"c1","state":"s1"}`, "test-key"))
	record(do(t, h, "POST", "/v1/sign/complete", `{"code":"c2","state":"s2"}`, "test-key"))
	record(do(t, h, "GET", "/v1/sign/status?correlationId="+corr, "", "test-key"))
	record(do(t, h, "GET", "/v1/sign/result?correlationId="+corr, "", "test-key"))

	out := sink.String()
	for _, secret := range []string{"HANDLE-SECRET", "client_secret", "test-key", "access_token", "SAD"} {
		if strings.Contains(out, secret) {
			t.Fatalf("frontend-bound response leaked %q", secret)
		}
	}
}
