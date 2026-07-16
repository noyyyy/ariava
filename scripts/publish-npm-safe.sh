#!/usr/bin/env bash
set -euo pipefail

PUBLISH=0
OTP=""
SKIP_INSTALL=0
SKIP_VERIFY=0
INCLUDE_PI_EXTENSION=0

usage() {
  cat <<'EOF'
Usage: ./scripts/publish-npm-safe.sh [options]

Runs Ariava's safe npm release checklist:
  1. Check npm/bun/node and npm login
  2. Install dependencies with bun install
  3. Run bun run verify:public
  4. Run npm pack --dry-run for the public ariava package
  5. Create a tarball with npm pack
  6. Install the tarball globally and smoke-test ariava help/status/doctor
  7. Optionally pack/publish the generated @ariava/pi-extension package
  8. Publish only when --publish is explicitly provided

Options:
  --publish       Actually run npm publish --access public after checks pass
  --otp <code>    Pass a 2FA OTP to npm publish
  --skip-install  Skip bun install
  --skip-verify   Skip bun run verify:public
  --include-pi-extension
                   Also pack/publish extensions/pi/bundle as @ariava/pi-extension
  -h, --help      Show this help

Examples:
  ./scripts/publish-npm-safe.sh
  ./scripts/publish-npm-safe.sh --publish --otp 123456
  ./scripts/publish-npm-safe.sh --publish
  ./scripts/publish-npm-safe.sh --include-pi-extension
  ./scripts/publish-npm-safe.sh --include-pi-extension --publish --otp 123456
EOF
}

log() {
  printf '\n\033[1;34m==> %s\033[0m\n' "$*"
}

fail() {
  printf '\n\033[1;31merror:\033[0m %s\n' "$*" >&2
  exit 1
}

run() {
  printf '+ %q' "$1"
  for arg in "${@:2}"; do
    printf ' %q' "$arg"
  done
  printf '\n'
  "$@"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --publish)
      PUBLISH=1
      shift
      ;;
    --otp)
      [[ $# -ge 2 ]] || fail "--otp requires a value"
      OTP="$2"
      shift 2
      ;;
    --skip-install)
      SKIP_INSTALL=1
      shift
      ;;
    --skip-verify)
      SKIP_VERIFY=1
      shift
      ;;
    --include-pi-extension)
      INCLUDE_PI_EXTENSION=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "unknown option: $1"
      ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

PACKAGE_NAME="$(node -e "const p=require('./package.json'); console.log(p.name)")"
PACKAGE_VERSION="$(node -e "const p=require('./package.json'); console.log(p.version)")"
TARBALL="${PACKAGE_NAME}-${PACKAGE_VERSION}.tgz"
PI_EXTENSION_BUNDLE_DIR="${REPO_ROOT}/extensions/pi/bundle"
PI_EXTENSION_PACKAGE_NAME="@ariava/pi-extension"
SMOKE_TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/ariava-publish.XXXXXX")"
SMOKE_STATUS_JSON="${SMOKE_TMP_DIR}/status.json"
SMOKE_DOCTOR_JSON="${SMOKE_TMP_DIR}/doctor.json"
PACK_DRY_RUN_JSON="${SMOKE_TMP_DIR}/pack.json"

cleanup() {
  rm -rf "${SMOKE_TMP_DIR}"
  if npm list -g "${PACKAGE_NAME}" >/dev/null 2>&1; then
    log "Cleaning up global smoke-test install"
    npm uninstall -g "${PACKAGE_NAME}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

log "Checking required tools"
command -v npm >/dev/null 2>&1 || fail "npm is required"
command -v node >/dev/null 2>&1 || fail "node is required"
command -v bun >/dev/null 2>&1 || fail "bun is required"
printf 'npm:  %s\n' "$(npm --version)"
printf 'node: %s\n' "$(node --version)"
printf 'bun:  %s\n' "$(bun --version)"

log "Checking npm registry and login"
REGISTRY="$(npm config get registry)"
printf 'registry: %s\n' "${REGISTRY}"
[[ "${REGISTRY}" == "https://registry.npmjs.org/" ]] || fail "npm registry must be https://registry.npmjs.org/ for public publish"
npm whoami >/dev/null || fail "npm login required; run npm login first"
printf 'npm user: %s\n' "$(npm whoami)"

if [[ ${SKIP_INSTALL} -eq 0 ]]; then
  log "Installing dependencies"
  bun install
else
  log "Skipping bun install"
fi

if [[ ${SKIP_VERIFY} -eq 0 ]]; then
  log "Running Public Core verification"
  bun run verify:public
else
  log "Skipping bun run verify:public"
fi

if [[ ${INCLUDE_PI_EXTENSION} -eq 1 ]]; then
  log "Building pi extension npm package bundle"
  bun run build:pi-bundle
fi

log "Checking that the generated Public Core README is publishable"
node "${SCRIPT_DIR}/assert-publication-readme.mjs" --root "${REPO_ROOT}"

log "Checking package contents with npm pack --dry-run"
npm pack --dry-run --json >"${PACK_DRY_RUN_JSON}"
node "${SCRIPT_DIR}/assert-npm-package.mjs" "${PACK_DRY_RUN_JSON}"

log "Creating npm tarball"
rm -f "${TARBALL}"
npm pack
[[ -f "${TARBALL}" ]] || fail "expected tarball was not created: ${TARBALL}"
node "${SCRIPT_DIR}/assert-npm-package.mjs" "${TARBALL}"

log "Installing tarball globally for smoke test"
npm install -g "./${TARBALL}"

log "Smoke-testing ariava CLI without installing or starting a service"
command -v ariava >/dev/null 2>&1 || fail "ariava command was not installed globally"
ariava help
set +e
ariava status --json >"${SMOKE_STATUS_JSON}"
STATUS_EXIT=$?
set -e
node "${SCRIPT_DIR}/assert-cli-envelope.mjs" "${SMOKE_STATUS_JSON}" status "${STATUS_EXIT}"

set +e
ariava doctor --json >"${SMOKE_DOCTOR_JSON}"
DOCTOR_EXIT=$?
set -e
node "${SCRIPT_DIR}/assert-cli-envelope.mjs" "${SMOKE_DOCTOR_JSON}" doctor "${DOCTOR_EXIT}"

log "Removing global smoke-test install"
npm uninstall -g "${PACKAGE_NAME}"

if [[ ${INCLUDE_PI_EXTENSION} -eq 1 ]]; then
  log "Checking ${PI_EXTENSION_PACKAGE_NAME} package contents with npm pack --dry-run"
  (cd "${PI_EXTENSION_BUNDLE_DIR}" && npm pack --dry-run)

  log "Creating ${PI_EXTENSION_PACKAGE_NAME} tarball"
  (cd "${PI_EXTENSION_BUNDLE_DIR}" && npm pack)
fi

if [[ ${PUBLISH} -eq 1 ]]; then
  log "Publishing ${PACKAGE_NAME}@${PACKAGE_VERSION} to npm"
  if [[ -n "${OTP}" ]]; then
    npm publish --access public --otp "${OTP}"
  else
    npm publish --access public
  fi
  if [[ ${INCLUDE_PI_EXTENSION} -eq 1 ]]; then
    log "Publishing ${PI_EXTENSION_PACKAGE_NAME} to npm"
    if [[ -n "${OTP}" ]]; then
      (cd "${PI_EXTENSION_BUNDLE_DIR}" && npm publish --access public --otp "${OTP}")
    else
      (cd "${PI_EXTENSION_BUNDLE_DIR}" && npm publish --access public)
    fi
    log "Published ${PI_EXTENSION_PACKAGE_NAME}"
  fi
  log "Published ${PACKAGE_NAME}@${PACKAGE_VERSION}"
else
  log "Dry run complete; package was NOT published"
  printf 'To publish, run:\n'
  printf '  ./scripts/publish-npm-safe.sh --publish --otp <6-digit-code>\n'
  if [[ ${INCLUDE_PI_EXTENSION} -eq 1 ]]; then
    printf '  ./scripts/publish-npm-safe.sh --include-pi-extension --publish --otp <6-digit-code>\n'
  fi
fi
