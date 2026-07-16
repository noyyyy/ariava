#!/usr/bin/env bash
set -euo pipefail
[[ "$(id -u)" != "0" ]] || { echo 'real self-upgrade phase must run as ordinary user' >&2; exit 1; }
before="$(ariava --version 2>/dev/null || npm list -g ariava --depth=0)"
env -u ARIAVA_UPGRADE_SELF_DONE ARIAVA_UPGRADE_PACKAGE_MANAGER=npm ariava upgrade --json >/tmp/ariava-real-upgrade.json
after="$(ariava --version 2>/dev/null || npm list -g ariava --depth=0)"
[[ "$before" != "$after" ]] || { echo 'real self-upgrade did not change installed version' >&2; exit 1; }
echo 'REAL_NPM_SELF_UPGRADE_PHASE=PASS'
