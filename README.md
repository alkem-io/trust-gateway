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
uses Cleverbase pre-production (`acceptance`). Non-production environments, including local, share
Alkemio's existing acceptance client; production has its own client. CSC v2 remains on Cleverbase's
single lab host as defined by the SDK.

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

### First manual acceptance run

This is a gateway-only, local Docker smoke test against Cleverbase acceptance. It signs the bundled
sample PDF as PAdES B-B/RSA, validates the returned CMS with OpenSSL, and never writes credentials
or the signed PDF to the repository. It is not the Alkemio-integrated local route: that route stays
on `localhost:3000` behind the local Traefik stack.

Before starting, obtain out of band: the existing Alkemio acceptance client ID and secret (with the
signing service credential), a user-approved qualified TSA URL, an acceptance signer enrolled in the
Cleverbase Wallet app, and the Cleverbase acceptance issuer/CA bundle in PEM form. The CA bundle is
mandatory: live E2E intentionally has no `-noverify` or other trust bypass.

Create an env file **outside this repository**, set its permissions to `0600`, and do not commit or
paste its contents into chat. Replace every angle-bracket value locally. Generate a random API key
locally, for example with `openssl rand -hex 32`.

```dotenv
# /absolute/secure/directory/trust-gateway.acceptance.env
TRUST_GATEWAY_MODE=live
TRUST_GATEWAY_ENV=acceptance
TRUST_GATEWAY_CSC_API=v1_rsa
TRUST_GATEWAY_CLIENT_ID=<provided-out-of-band>
TRUST_GATEWAY_CLIENT_SECRET=<provided-out-of-band>
TRUST_GATEWAY_REDIRECT_URI=http://localhost:8080/oauth/cleverbase/callback
TRUST_GATEWAY_RETURN_URL=http://localhost:8080/acceptance-complete
TRUST_GATEWAY_TSA_URL=https://<user-approved-qualified-tsa>/...
TRUST_GATEWAY_API_KEY=<locally-generated-random-bearer-key>
TRUST_GATEWAY_DEFAULT_CONFORMANCE=B-B
TRUST_GATEWAY_SESSION_TTL=15m
TRUST_GATEWAY_LISTEN=:8080
```

Build the image and start the gateway in one terminal. This direct local mode uses port 8080 because
it does not start Alkemio's Traefik stack; the acceptance client's unrestricted localhost redirect
allows the callback URL above.

```bash
make docker
docker run --rm --name trust-gateway-acceptance \
  --publish 127.0.0.1:8080:8080 \
  --read-only \
  --security-opt no-new-privileges \
  --cap-drop ALL \
  --env-file /absolute/secure/directory/trust-gateway.acceptance.env \
  alkemio/trust-gateway:latest
```

Wait for a healthy configuration before starting the browser journey:

```bash
curl --fail http://127.0.0.1:8080/readyz
```

In a second terminal, source the protected env file only into the current shell, then run the same
black-box driver used for deployed live runs:

```bash
set -a
. /absolute/secure/directory/trust-gateway.acceptance.env
set +a
export TRUST_GATEWAY_E2E_URL=http://127.0.0.1:8080
export TRUST_GATEWAY_E2E_API_KEY="$TRUST_GATEWAY_API_KEY"
export TRUST_GATEWAY_E2E_CA_BUNDLE=/absolute/secure/directory/cleverbase-acceptance-ca.pem
export TRUST_GATEWAY_E2E_TIMEOUT=10m
export TRUST_GATEWAY_E2E_REQUIRED=1
make e2e-live
```

The test prints the first Cleverbase authorization URL. Open it in a browser on this machine and
complete both Cleverbase steps with the enrolled Wallet signer. The expected path is:

1. Cleverbase redirects the browser to `http://localhost:8080/oauth/cleverbase/callback` after the
   first authorization.
2. The gateway validates that state and responds with a redirect to Cleverbase's second
   authorization/signing step.
3. Cleverbase redirects to the same gateway callback again after Wallet approval. The gateway marks
   the session complete, then redirects to `/acceptance-complete` with only `correlationId` and
   `clientState`.

In this gateway-only smoke run, the final local return URL has no Alkemio handler, so the browser may
show `404` after completion. That is expected; the E2E driver polls the private status endpoint,
retrieves the result, verifies the CMS against the supplied acceptance CA bundle, and finishes with
`PASS`. Stop the container with `docker stop trust-gateway-acceptance` when finished.
