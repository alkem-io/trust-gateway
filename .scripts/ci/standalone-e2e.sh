#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
readonly repo_root
cd "${repo_root}"

readonly gateway_image="${TRUST_GATEWAY_IMAGE:-alkemio/trust-gateway:latest}"
readonly mock_image="ghcr.io/alkem-io/cleverbase-refmock@sha256:271f70ee82e8114c0fc03f45788512d5d8f54a9a4fb3c3d7b33057781233fee2"
readonly gateway_port="${TRUST_GATEWAY_E2E_GATEWAY_PORT:-18080}"
readonly mock_port="${TRUST_GATEWAY_E2E_MOCK_PORT:-19000}"
readonly api_key="trust-gateway-blackbox-e2e"
readonly suffix="$$"
readonly network="trust-gateway-e2e-${suffix}"
readonly mock_name="trust-gateway-e2e-mock-${suffix}"
readonly gateway_name="trust-gateway-e2e-gateway-${suffix}"

cleanup() {
  local status=$?
  if [[ ${status} -ne 0 ]]; then
    docker logs --tail 200 "${mock_name}" 2>/dev/null || true
    docker logs --tail 200 "${gateway_name}" 2>/dev/null || true
  fi
  docker rm --force "${gateway_name}" "${mock_name}" >/dev/null 2>&1 || true
  docker network rm "${network}" >/dev/null 2>&1 || true
  exit "${status}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

wait_ready() {
  local name="$1"
  local url="$2"
  for _ in {1..60}; do
    if curl --fail --silent --show-error --connect-timeout 1 --max-time 2 "${url}" >/dev/null 2>&1; then
      return 0
    fi
    if [[ "$(docker inspect --format '{{.State.Running}}' "${name}" 2>/dev/null || true)" != "true" ]]; then
      printf '%s exited before becoming ready\n' "${name}" >&2
      return 1
    fi
    sleep 1
  done
  printf '%s did not become ready at %s within 60 seconds\n' "${name}" "${url}" >&2
  return 1
}

docker pull "${mock_image}" >/dev/null
if ! docker image inspect "${gateway_image}" >/dev/null 2>&1; then
  docker pull "${gateway_image}" >/dev/null
fi
docker network create "${network}" >/dev/null

docker run --detach \
  --name "${mock_name}" \
  --network "${network}" \
  --publish "127.0.0.1:${mock_port}:9000" \
  "${mock_image}" >/dev/null
wait_ready "${mock_name}" "http://127.0.0.1:${mock_port}/healthz"

docker run --detach \
  --name "${gateway_name}" \
  --network "${network}" \
  --publish "127.0.0.1:${gateway_port}:8080" \
  --read-only \
  --security-opt no-new-privileges \
  --cap-drop ALL \
  --env TRUST_GATEWAY_MODE=fixtures \
  --env TRUST_GATEWAY_ENV=acceptance \
  --env TRUST_GATEWAY_CSC_API=v1_rsa \
  --env TRUST_GATEWAY_CLIENT_ID=trust-gateway-e2e \
  --env TRUST_GATEWAY_CLIENT_SECRET=fixtures \
  --env "TRUST_GATEWAY_BASE_URL=http://${mock_name}:9000" \
  --env "TRUST_GATEWAY_PUBLIC_BASE_URL=http://127.0.0.1:${mock_port}" \
  --env "TRUST_GATEWAY_REDIRECT_URI=http://127.0.0.1:${gateway_port}/oauth/cleverbase/callback" \
  --env "TRUST_GATEWAY_RETURN_URL=http://127.0.0.1:${gateway_port}/e2e-complete" \
  --env "TRUST_GATEWAY_TSA_URL=http://${mock_name}:9000/tsr" \
  --env "TRUST_GATEWAY_API_KEY=${api_key}" \
  --env TRUST_GATEWAY_DEFAULT_CONFORMANCE=B-B \
  --env TRUST_GATEWAY_SESSION_TTL=2m \
  --env TRUST_GATEWAY_LISTEN=:8080 \
  "${gateway_image}" >/dev/null
wait_ready "${gateway_name}" "http://127.0.0.1:${gateway_port}/readyz"

TRUST_GATEWAY_E2E_URL="http://127.0.0.1:${gateway_port}" \
TRUST_GATEWAY_E2E_API_KEY="${api_key}" \
TRUST_GATEWAY_E2E_MODE=mock \
TRUST_GATEWAY_E2E_REQUIRED=1 \
CGO_ENABLED=0 \
go test -v -count=1 ./e2e
