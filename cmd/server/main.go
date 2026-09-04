// Command server runs the signing gateway: it embeds the Cleverbase SDK (via the Go binding)
// and serves the REST API that the no-crypto web frontend drives. See specs/002-reference-integration.
package main

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/alkem-io/trust-gateway/internal/cleverbase"
	"github.com/alkem-io/trust-gateway/internal/config"
	"github.com/alkem-io/trust-gateway/internal/flow"
	"github.com/alkem-io/trust-gateway/internal/httpapi"
	"github.com/alkem-io/trust-gateway/internal/session"
	"github.com/alkem-io/trust-gateway/internal/upstream"
)

//go:embed sample.pdf
var samplePDF []byte

// requestBudget bounds the worst-case duration of a single in-flight request. /v1/sign/complete
// synchronously drives up to ~3 sequential upstream calls (each capped at 30s by the upstream
// client) plus a TSA round-trip for B-T, so it must comfortably exceed that aggregate. It is the
// single source of truth for both the server WriteTimeout (which aborts a stuck write) and the
// graceful-shutdown deadline (which must be at least as long, or a SIGTERM would cut off a
// legitimate in-flight signing request the WriteTimeout would have allowed to finish).
const requestBudget = 150 * time.Second

var (
	listenTCP    = net.Listen
	serveHTTP    = (*http.Server).Serve
	shutdownHTTP = (*http.Server).Shutdown
)

func main() {
	os.Exit(runMain())
}

func runMain() int {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, logger); err != nil {
		logger.Error("gateway stopped", "err", err.Error())
		return 1
	}
	logger.Info("stopped")
	return 0
}

func run(ctx context.Context, logger *slog.Logger) error {
	p, err := config.Load()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	store := session.NewMemory()
	var internalRewrite, publicRewrite string
	if p.Mode == config.ModeFixtures {
		internalRewrite = p.UpstreamBaseURL     // server-side effects → internal mock host
		publicRewrite = p.PublicUpstreamBaseURL // browser redirects → reachable mock host
	}
	engine := &flow.Engine{
		SDK:             cleverbase.New(p),
		Up:              upstream.New(internalRewrite),
		Store:           store,
		Log:             logger,
		TTL:             p.SessionTTL,
		RedirectRewrite: upstream.New(publicRewrite).Rewrite,
	}
	svc := &httpapi.Service{Engine: engine, Store: store, Profile: p, Sample: samplePDF, Log: logger}

	srv := &http.Server{
		Addr:    p.Listen,
		Handler: svc.Handler(),
		// Bound every phase of a connection so a slow/stalled client cannot tie up a goroutine
		// indefinitely. ReadHeaderTimeout guards the request line+headers; ReadTimeout bounds the
		// full request body (the base64 PDF on /start); IdleTimeout reaps idle keep-alive connections.
		// WriteTimeout bounds the whole handler+response: a /v1/sign/complete drives the multi-call
		// signing round-trip, so it is set to requestBudget (see its doc) — comfortably exceeding that
		// aggregate while still bounding a genuinely stuck write.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      requestBudget,
		IdleTimeout:       120 * time.Second,
	}

	listener, err := listenTCP("tcp", p.Listen)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	if ctx.Err() != nil {
		if err := listener.Close(); err != nil {
			return fmt.Errorf("close canceled listener: %w", err)
		}
		return nil
	}
	serveErrors := make(chan error, 1)
	go func() { serveErrors <- serveHTTP(srv, listener) }()
	logger.Info("listening", "addr", listener.Addr().String(), "mode", string(p.Mode), "auth", p.AuthEnabled)

	select {
	case err := <-serveErrors:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve: %w", err)
	case <-ctx.Done():
	}

	// Give graceful shutdown the same budget as a single request (requestBudget) so a SIGTERM
	// during a legitimate in-flight signing round-trip lets it finish, rather than cutting it off
	// short of what WriteTimeout would have allowed. The deadline still bounds the wait so a wedged
	// connection cannot block shutdown forever.
	shutdownContext, cancel := context.WithTimeout(context.Background(), requestBudget)
	err = shutdownHTTP(srv, shutdownContext)
	cancel()
	// A failed/timed-out Shutdown means in-flight requests were dropped; surface it (error level +
	// non-zero exit) rather than masking it behind an unconditional "stopped".
	if err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	if err := <-serveErrors; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve during shutdown: %w", err)
	}
	return nil
}
