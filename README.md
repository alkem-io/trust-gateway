# Alkemio Trust Gateway

The signing gateway is Alkemio's server-side boundary for Cleverbase qualified electronic signing.
It owns OAuth state, the two Cleverbase authorization legs, CSC hash signing, PAdES assembly, TSA
requests, and temporary signed-document evidence. The Alkemio server remains authoritative for
domain authorization, durable signing attempts, immutable source documents, audit, and attachment.

The HTTP contract is documented in [docs/trust-gateway-api.md](docs/trust-gateway-api.md). The only
public signing route is `GET /oauth/cleverbase/callback`; `/v1/sign/*` stays private and API-key
protected.

## Configuration

The gateway reads only `TRUST_GATEWAY_*` variables and fails startup on an invalid or incomplete
profile.

| Variable | Default | Required / meaning |
| --- | --- | --- |
| `TRUST_GATEWAY_MODE` | `fixtures` | `fixtures` for the published Cleverbase mock; `live` for Cleverbase. |
| `TRUST_GATEWAY_ENV` | `acceptance` | Cleverbase environment: `acceptance` or `production`. |
| `TRUST_GATEWAY_CSC_API` | `v1_rsa` | `v1_rsa` or `v2_ecdsa`. |
| `TRUST_GATEWAY_CLIENT_ID` | fixture placeholder | OAuth client ID; required in live mode. |
| `TRUST_GATEWAY_CLIENT_SECRET` | fixture placeholder | OAuth client secret; required in live mode. |
| `TRUST_GATEWAY_REDIRECT_URI` | `http://localhost:8080/return` in fixtures | Registered Cleverbase redirect URI. Live mode requires the exact path `/oauth/cleverbase/callback`; non-loopback live URLs require HTTPS. |
| `TRUST_GATEWAY_RETURN_URL` | unset | Fixed application return URL. Required in live mode and whenever the redirect URI uses the public callback path. It must have no query or fragment; the gateway adds `correlationId` and `clientState`. |
| `TRUST_GATEWAY_TSA_URL` | `<BASE_URL>/tsr` in fixtures | RFC 3161 TSA URL. Required in live mode because requests may select B-T. |
| `TRUST_GATEWAY_TSA_AUTH` | unset | Optional TSA `Authorization` header value. |
| `TRUST_GATEWAY_TSA_POLICY` | unset | Optional TSA policy OID. |
| `TRUST_GATEWAY_BASE_URL` | unset | Internal mock base URL; required in fixtures mode. Live mode does not rewrite SDK URLs. |
| `TRUST_GATEWAY_PUBLIC_BASE_URL` | `TRUST_GATEWAY_BASE_URL` | Browser-reachable mock base used only to rewrite fixture authorization redirects. |
| `TRUST_GATEWAY_API_KEY` | unset | Bearer key protecting `/v1/sign/*`; required unless fixtures explicitly disable auth. Mandatory in live mode. |
| `TRUST_GATEWAY_AUTH_DISABLED` | `false` | May be `true` only for local fixtures. Rejected in live mode. |
| `TRUST_GATEWAY_DEFAULT_CONFORMANCE` | `B-B` | Default PAdES level: `B-B` or `B-T`. Requests may override it. |
| `TRUST_GATEWAY_SESSION_TTL` | `15m` | Lifetime of an in-progress in-memory signing session. |
| `TRUST_GATEWAY_LISTEN` | `:8080` | HTTP listen address inside the workload. |

### Alkemio-to-Cleverbase environment mapping

| Alkemio environment | `TRUST_GATEWAY_ENV` | Cleverbase host (CSC v1) |
| --- | --- | --- |
| PROD (`alkem.io`) | `production` | `connect.cleverbase.com` |
| ACC (`acc-alkem.io`) | `acceptance` | `connect.acc.cleverbase.com` |
| DEV (`dev-alkem.io`) | `acceptance` | `connect.acc.cleverbase.com` |
| TEST (`test-alkem.io`) | `acceptance` | `connect.acc.cleverbase.com` |
| SANDBOX (`sandbox-alkem.io`) | `acceptance` | `connect.acc.cleverbase.com` |
| local | `acceptance` | `connect.acc.cleverbase.com` |

Never derive `TRUST_GATEWAY_ENV` from the Alkemio overlay name: the Alkemio SANDBOX overlay still
uses Cleverbase pre-production (`acceptance`). Each Alkemio environment receives its own Cleverbase
client ID and secret even when several environments use the same Cleverbase tier. CSC v2 remains on
Cleverbase's single lab host as defined by the SDK.

## Development

```bash
make setup-native
make test
make lint
make build
make docker
```

The Go binding is pinned to `bindings/go/v0.1.0`. `make setup-native` downloads the matching
Cleverbase FFI archive for the current Go platform and verifies its pinned SHA-256 digest. Build,
test, lint, run, and container targets all invoke the same setup script; this repository requires no
Rust toolchain. Unit coverage is gated at 95% for every Go package.

The runtime image is non-root and has no shell or package manager. The current store is deliberately
single-replica and in-memory: sessions and results survive only for their TTL and are lost on restart.
The pilot deployment must use one replica and retry a signing journey from the start after a restart.

## Kubernetes base

`deploy/k8s/base` is a kustomize-consumable Deployment and ClusterIP Service. It intentionally
contains no Ingress, ConfigMap, Secret, or environment-specific value. Applying the base directly
cannot accidentally deploy a mutable image: its image tag is the non-resolving
`overlay-must-set-digest` sentinel.

Every dev-orchestration overlay must:

1. replace the image through the kustomize `images` transformer with an immutable
   `ghcr.io/alkem-io/trust-gateway@sha256:…` digest;
2. provide `trust-gateway-config` and `trust-gateway-secrets` for the `envFrom` references;
3. keep `/v1/sign/*` private and reachable only by `alkemio-server`; and
4. add one public, unauthenticated, exact-path route for `GET /oauth/cleverbase/callback`, with no
   prefix stripping and priority above the web-client catch-all.

The base deliberately uses one replica and a `Recreate` strategy while session storage is in-memory.
It runs as UID/GID 65532 with a read-only root filesystem, RuntimeDefault seccomp, and all Linux
capabilities dropped. Validate it locally with:

```bash
kubectl kustomize deploy/k8s/base >/dev/null
```

## Black-box signing test

The black-box test imports no gateway or SDK package. It drives a running image only through HTTP,
traverses both public callback legs, retrieves the signed PDF, and independently verifies its
detached CMS with OpenSSL. The credential-free path uses the published Cleverbase mock image pinned
by digest and compiles with `CGO_ENABLED=0`.

```bash
make e2e
```

`make e2e` builds the local gateway image, starts the gateway and pinned mock on an isolated Docker
network, polls their health endpoints, runs one B-B/RSA signing journey, and always removes the
containers and network. Override `TRUST_GATEWAY_E2E_GATEWAY_PORT` or
`TRUST_GATEWAY_E2E_MOCK_PORT` if ports 18080 or 19000 are occupied.

The same driver can validate a deployed gateway against real Cleverbase. It prints the first
authorization URL; a human completes both steps in the Cleverbase app while the test polls the
authoritative gateway status. Run it from a location that can reach the private `/v1/sign/*`
endpoints:

| E2E variable | Default | Required / meaning |
| --- | --- | --- |
| `TRUST_GATEWAY_E2E_URL` | unset | Private base URL of the deployed gateway. |
| `TRUST_GATEWAY_E2E_API_KEY` | unset | Bearer key for the private signing routes. |
| `TRUST_GATEWAY_E2E_MODE` | `mock` | `mock` for automated fixture authorization; `live` for human Cleverbase authorization. |
| `TRUST_GATEWAY_E2E_CA_BUNDLE` | unset | CA bundle for live CMS trust validation; required in live mode. |
| `TRUST_GATEWAY_E2E_TIMEOUT` | `45s` (`5m` live) | Bounded journey timeout. |
| `TRUST_GATEWAY_E2E_REQUIRED` | unset | Set to `1` in CI/deployment gates so missing prerequisites fail instead of skipping. |

```bash
export TRUST_GATEWAY_E2E_URL=https://<private-gateway-address>
export TRUST_GATEWAY_E2E_API_KEY=<gateway-api-key>
export TRUST_GATEWAY_E2E_CA_BUNDLE=/path/to/cleverbase-acceptance-ca.pem
export TRUST_GATEWAY_E2E_TIMEOUT=5m # optional
make e2e-live
```

The real-Cleverbase acceptance run is manual because the signer must authorize in the app. SANDBOX
and DEV are the first deployment targets; TEST is reserved for the later automated nightly run.
