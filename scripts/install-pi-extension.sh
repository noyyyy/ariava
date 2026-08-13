#!/usr/bin/env bash
set -euo pipefail

# Repository helper for installing the generated Ariava Pi package through Pi's
# official package installer.
#
# Usage: ./scripts/install-pi-extension.sh [--source <pi-package-source>]

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEFAULT_SOURCE="${REPO_ROOT}/extensions/pi/bundle"
SOURCE="${ARIAVA_PI_EXTENSION_SOURCE:-${DEFAULT_SOURCE}}"

usage() {
  sed -n '4,7p' "$0" | sed 's/^# \{0,1\}//'
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

if ! command -v pi >/dev/null 2>&1; then
  echo "pi CLI is required to install Ariava Pi package source: ${SOURCE}" >&2
  exit 1
fi

echo "Installing Ariava Pi extension package: ${SOURCE}"
pi install "${SOURCE}"
echo "Reload pi or run /reload to load the extension."
