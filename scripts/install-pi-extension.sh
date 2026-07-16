#!/usr/bin/env bash
set -euo pipefail

# Repository helper for installing the Ariava Pi extension through Pi's package installer.
#
# Preferred local dev path: install the generated local bundle as a pi package.
# Cloud/npm path: ./scripts/install-pi-extension.sh --source npm:@ariava/pi-extension
# Legacy copy fallback: ./scripts/install-pi-extension.sh --legacy-copy
#
# Usage: ./scripts/install-pi-extension.sh [--source <pi-package-source>] [--legacy-copy]

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEFAULT_SOURCE="${REPO_ROOT}/extensions/pi/bundle"
SOURCE="${ARIAVA_PI_EXTENSION_SOURCE:-${DEFAULT_SOURCE}}"
EXT_DIR="${HOME}/.pi/agent/extensions/ariava-pi"
LEGACY_COPY=0

usage() {
  sed -n '4,10p' "$0" | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --source)
      SOURCE="${2:-}"
      if [[ -z "${SOURCE}" ]]; then
        echo "Missing value for --source" >&2
        exit 2
      fi
      shift 2
      ;;
    --legacy-copy)
      LEGACY_COPY=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

legacy_copy_install() {
  echo "[legacy copy] Installing Ariava Pi extension to ${EXT_DIR}"
  mkdir -p "${EXT_DIR}"
  rm -rf "${EXT_DIR:?}/"*
  rsync -a --delete --exclude='.DS_Store' \
    "${DEFAULT_SOURCE}/" "${EXT_DIR}/"
  echo "Ariava Pi extension copied to ${EXT_DIR}"
}

if [[ "${LEGACY_COPY}" == "1" ]]; then
  legacy_copy_install
else
  if command -v pi >/dev/null 2>&1; then
    echo "Installing Ariava Pi extension package: ${SOURCE}"
    pi install "${SOURCE}"
  elif [[ "${SOURCE}" == "${DEFAULT_SOURCE}" ]]; then
    echo "[warn] pi CLI not found; falling back to legacy copy install for local bundle." >&2
    legacy_copy_install
  else
    echo "pi CLI is required to install non-local package source: ${SOURCE}" >&2
    exit 1
  fi
fi

echo "Reload pi or run /reload to load the extension."
