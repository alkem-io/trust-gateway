// Package httpapi exposes the signing gateway HTTP interface.
package httpapi

import (
	"io"
	"net/http"
)

// NewHandler builds the service router. Signing routes are added as their packages are ported.
func NewHandler() http.Handler {
	mux := http.NewServeMux()
	for _, path := range []string{"/healthz", "/readyz"} {
		mux.HandleFunc("GET "+path, handleHealth)
	}
	return mux
}

func handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "{\"status\":\"ok\"}\n")
}
