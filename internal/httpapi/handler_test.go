package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthEndpoints(t *testing.T) {
	t.Parallel()

	handler := NewHandler()
	for _, path := range []string{"/healthz", "/readyz"} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()

			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
			if recorder.Code != http.StatusOK {
				t.Fatalf("GET %s status = %d, want %d", path, recorder.Code, http.StatusOK)
			}
			if got, want := recorder.Header().Get("Content-Type"), "application/json"; got != want {
				t.Fatalf("GET %s Content-Type = %q, want %q", path, got, want)
			}
			if got, want := recorder.Body.String(), "{\"status\":\"ok\"}\n"; got != want {
				t.Fatalf("GET %s body = %q, want %q", path, got, want)
			}
		})
	}
}
