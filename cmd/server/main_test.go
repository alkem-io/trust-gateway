package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

type stubListener struct {
	closeErr error
}

func (*stubListener) Accept() (net.Conn, error) { return nil, errors.New("accept failed") }
func (listener *stubListener) Close() error     { return listener.closeErr }
func (*stubListener) Addr() net.Addr            { return &net.TCPAddr{} }

func resetRuntimeHooks(t *testing.T) {
	t.Helper()
	originalListen, originalServe, originalShutdown := listenTCP, serveHTTP, shutdownHTTP
	t.Cleanup(func() {
		listenTCP, serveHTTP, shutdownHTTP = originalListen, originalServe, originalShutdown
	})
}

func cleanGatewayEnv(t *testing.T) {
	t.Helper()
	for _, assignment := range os.Environ() {
		key, _, _ := strings.Cut(assignment, "=")
		if strings.HasPrefix(key, "TRUST_GATEWAY_") {
			t.Setenv(key, "")
		}
	}
}

func fixtureRuntime(t *testing.T) {
	t.Helper()
	cleanGatewayEnv(t)
	t.Setenv("TRUST_GATEWAY_MODE", "fixtures")
	t.Setenv("TRUST_GATEWAY_BASE_URL", "http://mock:9000")
	t.Setenv("TRUST_GATEWAY_AUTH_DISABLED", "true")
	t.Setenv("TRUST_GATEWAY_LISTEN", "127.0.0.1:0")
}

func liveNetworkIsolatedRuntime(t *testing.T) {
	t.Helper()
	cleanGatewayEnv(t)
	t.Setenv("TRUST_GATEWAY_MODE", "live")
	t.Setenv("TRUST_GATEWAY_CLIENT_ID", "client")
	t.Setenv("TRUST_GATEWAY_CLIENT_SECRET", "secret")
	t.Setenv("TRUST_GATEWAY_REDIRECT_URI", "http://localhost:3000/oauth/cleverbase/callback")
	t.Setenv("TRUST_GATEWAY_RETURN_URL", "http://localhost:3000/api/public/rest/content-signing/complete")
	t.Setenv("TRUST_GATEWAY_TSA_URL", "https://tsa.example/tsr")
	t.Setenv("TRUST_GATEWAY_AUTH_DISABLED", "true")
	t.Setenv("TRUST_GATEWAY_LISTEN", "127.0.0.1:0")
}

func captureListenAddress(t *testing.T) <-chan string {
	t.Helper()
	resetRuntimeHooks(t)
	address := make(chan string, 1)
	listenTCP = func(network, listenAddress string) (net.Listener, error) {
		listener, err := net.Listen(network, listenAddress)
		if err == nil {
			address <- listener.Addr().String()
		}
		return listener, err
	}
	return address
}

func waitListenAddress(t *testing.T, address <-chan string) string {
	t.Helper()
	select {
	case actual := <-address:
		return actual
	case <-time.After(5 * time.Second):
		t.Fatal("gateway did not bind a listener")
		return ""
	}
}

func waitReady(t *testing.T, address string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		response, err := http.Get("http://" + address + "/readyz") //nolint:gosec // loopback test server
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode != http.StatusOK {
				t.Fatalf("ready status = %d", response.StatusCode)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("gateway did not become ready: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestRunRejectsInvalidConfiguration(t *testing.T) {
	cleanGatewayEnv(t)
	t.Setenv("TRUST_GATEWAY_MODE", "invalid")
	t.Setenv("TRUST_GATEWAY_API_KEY", "key")

	err := run(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err == nil || !strings.Contains(err.Error(), "config") {
		t.Fatalf("run() error = %v", err)
	}
}

func TestRunRejectsInvalidListenAddress(t *testing.T) {
	fixtureRuntime(t)
	t.Setenv("TRUST_GATEWAY_LISTEN", "127.0.0.1:-1")

	err := run(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err == nil || !strings.Contains(err.Error(), "listen") {
		t.Fatalf("run() error = %v", err)
	}
}

func TestRunShutsDownWhenContextIsCanceled(t *testing.T) {
	fixtureRuntime(t)
	address := captureListenAddress(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, slog.New(slog.NewTextHandler(io.Discard, nil))) }()
	waitReady(t, waitListenAddress(t, address))
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run() error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run() did not stop after cancellation")
	}
}

func TestRunWithAlreadyCanceledContext(t *testing.T) {
	fixtureRuntime(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := run(ctx, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatalf("run() error = %v", err)
	}
}

func TestRunWarnsWhenLiveAPIRoutesAreNetworkIsolated(t *testing.T) {
	liveNetworkIsolatedRuntime(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	if err := run(ctx, logger); err != nil {
		t.Fatalf("run() error = %v", err)
	}
	if !strings.Contains(logs.String(), "API authentication is disabled") {
		t.Fatalf("startup warning missing from logs: %s", logs.String())
	}
}

func TestRunWarnsWhenCleverbaseUpstreamIsOverridden(t *testing.T) {
	liveNetworkIsolatedRuntime(t)
	t.Setenv("TRUST_GATEWAY_UPSTREAM_BASE_URL", "https://trust-driver-stub-hash-signing.cleverbase.com")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	if err := run(ctx, logger); err != nil {
		t.Fatalf("run() error = %v", err)
	}
	if !strings.Contains(logs.String(), "Cleverbase upstream endpoint is overridden") {
		t.Fatalf("upstream override warning missing from logs: %s", logs.String())
	}
}

func TestRunMainRunsUntilSignal(t *testing.T) {
	fixtureRuntime(t)
	address := captureListenAddress(t)
	done := make(chan int, 1)
	go func() {
		done <- runMain()
	}()
	waitReady(t, waitListenAddress(t, address))
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("send SIGTERM: %v", err)
	}
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("runMain() = %d", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("runMain() did not stop after SIGTERM")
	}
}

func TestRunMainReportsConfigurationFailure(t *testing.T) {
	cleanGatewayEnv(t)
	t.Setenv("TRUST_GATEWAY_MODE", "invalid")
	t.Setenv("TRUST_GATEWAY_API_KEY", "key")
	if code := runMain(); code != 1 {
		t.Fatalf("runMain() = %d, want 1", code)
	}
}

func TestRunReportsCanceledListenerCloseFailure(t *testing.T) {
	fixtureRuntime(t)
	resetRuntimeHooks(t)
	closeErr := errors.New("close failed")
	listenTCP = func(string, string) (net.Listener, error) {
		return &stubListener{closeErr: closeErr}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := run(ctx, slog.New(slog.NewTextHandler(io.Discard, nil))); !errors.Is(err, closeErr) {
		t.Fatalf("run() error = %v", err)
	}
}

func TestRunReportsServeFailure(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		want bool
	}{
		{"closed", http.ErrServerClosed, false},
		{"failed", errors.New("serve failed"), true},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixtureRuntime(t)
			resetRuntimeHooks(t)
			listenTCP = func(string, string) (net.Listener, error) { return &stubListener{}, nil }
			serveHTTP = func(*http.Server, net.Listener) error { return test.err }
			err := run(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)))
			if (err != nil) != test.want {
				t.Fatalf("run() error = %v, want error %v", err, test.want)
			}
		})
	}
}

func TestRunReportsShutdownAndLateServeFailures(t *testing.T) {
	for _, test := range []struct {
		name        string
		shutdownErr error
		serveErr    error
		wantText    string
	}{
		{"shutdown", errors.New("shutdown failed"), http.ErrServerClosed, "shutdown failed"},
		{"late serve", nil, errors.New("late serve failed"), "late serve failed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixtureRuntime(t)
			resetRuntimeHooks(t)
			listenTCP = func(string, string) (net.Listener, error) { return &stubListener{}, nil }
			started := make(chan struct{})
			release := make(chan struct{})
			serveHTTP = func(*http.Server, net.Listener) error {
				close(started)
				<-release
				return test.serveErr
			}
			shutdownHTTP = func(*http.Server, context.Context) error {
				close(release)
				return test.shutdownErr
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- run(ctx, slog.New(slog.NewTextHandler(io.Discard, nil))) }()
			<-started
			cancel()
			err := <-done
			if err == nil || !strings.Contains(err.Error(), test.wantText) {
				t.Fatalf("run() error = %v, want text %q", err, test.wantText)
			}
		})
	}
}
