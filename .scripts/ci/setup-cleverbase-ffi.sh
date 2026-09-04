#!/usr/bin/env bash

set -euo pipefail

readonly ffi_version="v0.1.0"
readonly release_tag="bindings/go/${ffi_version}"
readonly release_base="https://github.com/alkem-io/cleverbase-sdk/releases/download/${release_tag}"

goos="${GOOS:-$(go env GOOS)}"
goarch="${GOARCH:-$(go env GOARCH)}"

case "${goos}/${goarch}" in
  darwin/amd64)
    readonly expected_sha256="4aa1644ded30033611a0d84bde61da9c4c26b093ca7425dd87c0add3d33296cf"
    ;;
  darwin/arm64)
    readonly expected_sha256="f89c0d69bd941f78a2a84b5302ffc0f3c3f066a9e6969b5929a68a0d1ce51710"
    ;;
  linux/amd64)
    readonly expected_sha256="927ed002a122ba3dd4c691ebf70769669c96cb6c733f5dde806b588b38e03c67"
    ;;
  linux/arm64)
    readonly expected_sha256="1763a6187f021637a0cbbda5c0bf2c318f89475b83cddd21d591541b2610c168"
    ;;
  *)
    printf 'unsupported Cleverbase FFI platform: %s/%s\n' "${goos}" "${goarch}" >&2
    exit 1
    ;;
esac

readonly asset="cleverbase-ffi-${ffi_version}-${goos}-${goarch}.tar.gz"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
readonly repo_root
readonly download_dir="${repo_root}/.native/downloads"
readonly archive="${download_dir}/${asset}"
readonly install_dir="${repo_root}/.native/cleverbase-ffi/${ffi_version}/${goos}-${goarch}"
download=""
work_dir=""

cleanup() {
  if [[ -n "${work_dir}" ]]; then
    rm -rf -- "${work_dir}"
  fi
  if [[ -n "${download}" ]]; then
    rm -f -- "${download}"
  fi
}
trap cleanup EXIT

verify_sha256() {
  local archive_path="$1"
  local actual
  if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "${archive_path}" | awk '{print $1}')"
  else
    actual="$(shasum -a 256 "${archive_path}" | awk '{print $1}')"
  fi
  if [[ "${actual}" != "${expected_sha256}" ]]; then
    printf 'SHA-256 mismatch for %s: got %s, want %s\n' \
      "${asset}" "${actual}" "${expected_sha256}" >&2
    return 1
  fi
}

mkdir -p "${download_dir}"
if [[ ! -f "${archive}" ]]; then
  download="${archive}.tmp.$$"
  curl --fail --location --silent --show-error --proto '=https' --retry 3 \
    --output "${download}" "${release_base}/${asset}"
  mv "${download}" "${archive}"
  download=""
fi
verify_sha256 "${archive}"

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/trust-gateway-ffi.XXXXXX")"
tar -xzf "${archive}" -C "${work_dir}"
if [[ ! -f "${work_dir}/lib/libcleverbase_ffi.a" ]]; then
  printf 'release archive %s does not contain lib/libcleverbase_ffi.a\n' "${asset}" >&2
  exit 1
fi
mkdir -p "$(dirname "${install_dir}")"
rm -rf -- "${install_dir}"
mv "${work_dir}" "${install_dir}"
work_dir=""

if [[ -n "${GITHUB_ENV:-}" ]]; then
  printf 'CGO_LDFLAGS=%s-L%s\n' "${CGO_LDFLAGS:+${CGO_LDFLAGS} }" "${install_dir}/lib" >>"${GITHUB_ENV}"
fi

printf '%s\n' "${install_dir}/lib"
