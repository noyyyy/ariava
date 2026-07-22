#!/usr/bin/env bash
set -euo pipefail

SOURCE="${BASH_SOURCE[0]}"
while [[ -L "${SOURCE}" ]]; do
  SOURCE_DIR="$(cd -P "$(dirname "${SOURCE}")" && pwd)"
  SOURCE_TARGET="$(readlink "${SOURCE}")"
  if [[ "${SOURCE_TARGET}" == /* ]]; then
    SOURCE="${SOURCE_TARGET}"
  else
    SOURCE="${SOURCE_DIR}/${SOURCE_TARGET}"
  fi
done

SCRIPT_DIR="$(cd -P "$(dirname "${SOURCE}")" && pwd)"
exec node "${SCRIPT_DIR}/npm-release.mjs" "$@"
