# Alkemio Trust Gateway

Security-sensitive signing gateway for Alkemio. The service owns the Cleverbase authorization and
PDF-signing protocol boundary; Alkemio server owns domain authorization, durable signing attempts,
and signed-document attachment.

This initial scaffold exposes only orchestration probes on port 8080:

- `GET /healthz`
- `GET /readyz`

Signing packages and routes are added tests-first after the versioned Cleverbase SDK dependency is
available.

## Development

```bash
make test
make lint
make build
make docker
```

Unit coverage is gated at 95%. The runtime image is non-root and has no shell or package manager.

The Go binding is pinned to `bindings/go/v0.1.0`. `make setup-native` downloads the matching
Cleverbase FFI archive for the current Go platform and verifies its pinned SHA-256 digest. Build,
test, lint, run, and container targets all use that same setup script; the service repository does
not require a Rust toolchain.
