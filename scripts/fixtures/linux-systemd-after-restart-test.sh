#!/usr/bin/env bash
set -euo pipefail

[[ "$(id -u)" != "0" ]] || { echo "Ariava integration phases must run as an ordinary user" >&2; exit 1; }

export HOME="${HOME:-/home/ariava-test}"
export PATH="$HOME/.npm-global/bin:/usr/local/bin:/usr/bin:/bin"
export npm_config_prefix="$HOME/.npm-global"
TEST_TMPDIR="${ARIAVA_SYSTEMD_TEST_TMPDIR:-/tmp}"
mkdir -p "$TEST_TMPDIR"

record_json() {
  local name="$1" expected="$2"; shift 2
  set +e
  "$@" > "$TEST_TMPDIR/$name.json" 2> "$TEST_TMPDIR/$name.err"
  local exit_code=$?
  set -e
  cat "$TEST_TMPDIR/$name.json"
  cat "$TEST_TMPDIR/$name.err" >&2
  [[ "$exit_code" == "$expected" ]] || {
    echo "$name exited $exit_code, expected $expected" >&2
    exit 1
  }
}

systemctl --user show-environment >/dev/null
[[ "$(systemctl --user is-enabled ariava.service)" == "enabled" ]]
[[ "$(systemctl --user is-active ariava.service)" == "active" ]]

npm install -g "$HOME/ariava-under-test.tgz"
record_json upgrade 0 env -u ARIAVA_UPGRADE_SELF_DONE ariava upgrade --json
record_json post-upgrade-status 0 ariava service status --json

node <<'NODE'
const fs = require('fs');
const status = JSON.parse(fs.readFileSync(process.env.ARIAVA_SYSTEMD_TEST_TMPDIR + '/post-upgrade-status.json', 'utf8'));
const before = JSON.parse(fs.readFileSync(process.env.ARIAVA_SYSTEMD_TEST_TMPDIR + '/ariava-identity-before.json', 'utf8'));
const config = JSON.parse(fs.readFileSync(process.env.HOME + '/.config/ariava/config.json', 'utf8'));
if (config.identity?.hostId !== before.hostId || config.identity?.keyId !== before.keyId) {
  throw new Error('hostId/keyId changed across restart or reconciliation-only upgrade');
}
if (!status.ok || status.data.backend !== 'systemd-user' || !status.data.installed) {
  throw new Error('service was not installed after upgrade reconciliation');
}
if (status.data.runtimePathMatchesCurrent !== true || status.data.ariavaBinPathMatchesCurrent !== true) {
  throw new Error('runtimePathMatchesCurrent or ariavaBinPathMatchesCurrent is false');
}
if (!status.data.processRunning) throw new Error('service did not restart during upgrade reconciliation');
NODE

record_json service-uninstall 0 ariava service uninstall --json
[[ ! -e "$HOME/.config/systemd/user/ariava.service" ]]
record_json final-status 0 ariava service status --json

node <<'NODE'
const fs = require('fs');
const status = JSON.parse(fs.readFileSync(process.env.ARIAVA_SYSTEMD_TEST_TMPDIR + '/final-status.json', 'utf8'));
if (status.data.installed !== false) throw new Error('final installed !== false');
const metadataPath = process.env.HOME + '/.config/ariava/install.json';
if (fs.existsSync(metadataPath)) {
  const metadata = JSON.parse(fs.readFileSync(metadataPath, 'utf8'));
  if (metadata.service !== undefined) throw new Error('metadata.service remains after uninstall');
}
NODE

echo "AFTER_RESTART_SYSTEMD_PHASE=PASS"
