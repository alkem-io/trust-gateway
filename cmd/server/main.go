// Command server runs the Alkemio signing gateway.
package main

import (
	"errors"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/alkem-io/trust-gateway/internal/httpapi"
)

func main() {
	server := &http.Server{
		Addr:              ":8080",
		Handler:           httpapi.NewHandler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("signing gateway stopped", "error", err)
		os.Exit(1)
	}
}
