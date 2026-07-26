#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPOSITORY_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd -P)"
DOCKER_BIN="${ARIAVA_DOCKER_BIN:-docker}"
BASE_IMAGE="docker.io/library/node:24.18.0-bookworm-slim@sha256:6f7b03f7c2c8e2e784dcf9295400527b9b1270fd37b7e9a7285cf83b6951452d"
NODE_VERSION="24.18.0"
NPM_VERSION="11.18.0"
BUN_VERSION="1.3.14"

if ! command -v "${DOCKER_BIN}" >/dev/null 2>&1; then
  printf '%s\n' "Docker CLI not found: ${DOCKER_BIN}" >&2
  exit 127
fi

host_arch="$(uname -m)"
case "${host_arch}" in
  arm64|aarch64) default_platform="linux/arm64" ;;
  x86_64|amd64) default_platform="linux/amd64" ;;
  *)
    printf '%s\n' "Unsupported host architecture for Docker Linux verification: ${host_arch}" >&2
    exit 64
    ;;
esac

platform="${ARIAVA_DOCKER_PLATFORM:-${default_platform}}"
case "${platform}" in
  linux/arm64|linux/amd64) ;;
  *)
    printf '%s\n' "ARIAVA_DOCKER_PLATFORM must be linux/arm64 or linux/amd64, got: ${platform}" >&2
    exit 64
    ;;
esac

platform_arch="${platform#linux/}"
mode="native-architecture default"
if [[ "${platform}" != "${default_platform}" ]]; then
  mode="explicit emulated-platform request"
fi

image="ariava-verify-linux:node-${NODE_VERSION}-bun-${BUN_VERSION}-${platform_arch}-$$"
image_built=0
status_logged=0
cleanup() {
  local status=$?
  if [[ "${image_built}" -eq 1 && "${ARIAVA_DOCKER_KEEP_IMAGE:-0}" != "1" ]]; then
    "${DOCKER_BIN}" image rm --force "${image}" >/dev/null 2>&1 || true
  fi
  if [[ "${status_logged}" -eq 0 ]]; then
    printf '%s\n' "[ariava verify:linux:docker] exit status: ${status}"
  fi
}
trap cleanup EXIT

printf '%s\n' "[ariava verify:linux:docker] base image: ${BASE_IMAGE}"
printf '%s\n' "[ariava verify:linux:docker] host architecture: ${host_arch}"
printf '%s\n' "[ariava verify:linux:docker] evidence: Docker Linux ${platform_arch} (${mode})"
printf '%s\n' "[ariava verify:linux:docker] toolchain: Node ${NODE_VERSION}, npm ${NPM_VERSION}, Bun ${BUN_VERSION}"

"${DOCKER_BIN}" build \
  --pull \
  --platform "${platform}" \
  --file "${REPOSITORY_ROOT}/scripts/docker/Dockerfile.verify-linux" \
  --tag "${image}" \
  "${REPOSITORY_ROOT}"
image_built=1

set +e
"${DOCKER_BIN}" run \
  --rm \
  --read-only \
  --platform "${platform}" \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --pids-limit 512 \
  --tmpfs /workspace:rw,exec,nosuid,nodev,size=4g,uid=1000,gid=1000,mode=0700 \
  --tmpfs /tmp:rw,exec,nosuid,nodev,size=2g,mode=1777 \
  --env "ARIAVA_VERIFY_REQUESTED_PLATFORM=${platform}" \
  "${image}" \
  bun run verify:linux
status=$?
set -e

printf '%s\n' "[ariava verify:linux:docker] exit status: ${status}"
status_logged=1
exit "${status}"
