# Trust Gateway HTTP API

All response bodies are JSON unless noted. Requests to `/v1/sign/*` require
`Authorization: Bearer <TRUST_GATEWAY_API_KEY>`. The only public signing route is the exact
`GET /oauth/cleverbase/callback` path. Health probes are also public.

Errors have the shape `{ "error": "<code>", "message": "<safe text>" }`. A `correlationId` is an
opaque gateway identifier; SDK handles, access tokens, authorization codes, and OAuth state never
leave the gateway.

## `POST /v1/sign/start`

Starts a signing journey.

```json
{
  "document": "<base64 PDF>",
  "conformanceLevel": "B-B",
  "expectedSigner": {
    "matchOn": "certificate_serial_number",
    "value": "PNONL-…"
  },
  "clientState": "<opaque application continuation>"
}
```

- `document` may be omitted only when the deployed binary carries a sample PDF.
- `conformanceLevel` is `B-B` or `B-T`; omission uses `TRUST_GATEWAY_DEFAULT_CONFORMANCE`.
- `expectedSigner` is optional.
- `clientState` is opaque, is never interpreted or logged, and is limited to 1024 bytes. It is
  required whenever `TRUST_GATEWAY_RETURN_URL` is configured.
- The decoded PDF is limited to 20 MiB.

Success is `200`:

```json
{
  "redirectUrl": "https://…/oauth2/authorize?…",
  "correlationId": "…"
}
```

The PDF remains inside the gateway; only its digest is sent to Cleverbase.

## `GET /oauth/cleverbase/callback?code=…&state=…`

Cleverbase redirects the browser to this public route. Provider failures use `error=…&state=…`.
The gateway validates and consumes state itself.

- An intermediate authorization result responds `302` to Cleverbase's second authorization URL.
- A terminal success, decline, or failure responds `302` to the fixed `TRUST_GATEWAY_RETURN_URL`
  with exactly two URL-encoded query parameters: `correlationId` and the original `clientState`.
- The return URL never carries status, error, Cleverbase code, or OAuth state. The application must
  fetch authoritative status and result server-to-server.
- Redirect responses include `Cache-Control: no-store`.
- `HEAD` returns `405`.

The pending OAuth state is one-shot. Refreshing or navigating back to a consumed callback URL
returns `400 unknown_state`; no session can be safely resolved from consumed state alone. Other
malformed, unknown, or expired states also return `400`. A callback racing an in-flight completion
may return `409 already_processing`. Internal details are never reflected to the browser.

## `POST /v1/sign/complete`

Protected completion endpoint for non-browser drivers. It shares the same completion function as
the public callback.

```json
{ "code": "<oauth code>", "state": "<oauth state>" }
```

or:

```json
{ "error": "access_denied", "state": "<oauth state>" }
```

An intermediate `200` response has status `authorizing` and another `redirectUrl`; a terminal
response has `completed`, `declined`, or `failed`. Only `failed` carries a `reason`.

## `GET /v1/sign/status?correlationId=…`

Returns `pending`, `authorizing`, `completed`, `declined`, or `failed`. Only `failed` includes one
of these reason codes:

- SDK outcomes: `authorization_expired`, `credential_unavailable`, `identity_mismatch`,
  `invalid_document`, `timestamp_failed`, `appearance_placement_error`, `signature_invalid`;
- gateway failures: `upstream_error`, `resume_error`, `session_expired`;
- defensive fallback: `unknown`.

Unknown identifiers return `404`.

## `GET /v1/sign/result?correlationId=…`

A completed result is returned as `application/pdf`. `X-Signature-Evidence` contains the SDK's
base64-encoded JSON evidence record. Its `signer` object is the authoritative signer-identity
contract and contains `serial_number`, `common_name`, optional `given_name` and `surname`, and the
RFC 4514 `raw_subject`. The certificate chain is not duplicated into the header; it is embedded in
the PDF's CMS. Repeated authenticated reads return the same PDF and evidence until session eviction;
result retrieval is not consuming. Unknown identifiers return `404`, and a known non-completed
journey returns `409`.

## `GET /healthz` and `GET /readyz`

Both return `200` with `{ "status": "ok" }` after startup configuration and SDK loading succeeded.
