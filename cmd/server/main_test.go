package main

import (
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

func reserveAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve address: %v", err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("release address: %v", err)
	}
	return address
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
	address := reserveAddress(t)
	t.Setenv("TRUST_GATEWAY_LISTEN", address)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, slog.New(slog.NewTextHandler(io.Discard, nil))) }()
	waitReady(t, address)
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

func TestRunMainRunsUntilSignal(t *testing.T) {
	fixtureRuntime(t)
	address := reserveAddress(t)
	t.Setenv("TRUST_GATEWAY_LISTEN", address)
	done := make(chan int, 1)
	go func() {
		done <- runMain()
	}()
	waitReady(t, address)
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
