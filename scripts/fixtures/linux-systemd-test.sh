#!/usr/bin/env bash
set -euo pipefail

[[ "$(id -u)" != "0" ]] || { echo "Ariava integration phases must run as an ordinary user" >&2; exit 1; }

export HOME="${HOME:-/home/ariava-test}"
export PATH="$HOME/.npm-global/bin:/usr/local/bin:/usr/bin:/bin"
export npm_config_prefix="$HOME/.npm-global"
export ARIAVA_RELAY_BASE_URL=http://127.0.0.1:9
export ARIAVA_HOST_NAME='Linux systemd integration test'

record_json() {
  local name="$1" expected="$2"; shift 2
  set +e
  "$@" > "/tmp/$name.json" 2> "/tmp/$name.err"
  local exit_code=$?
  set -e
  cat "/tmp/$name.json"
  cat "/tmp/$name.err" >&2
  [[ "$exit_code" == "$expected" ]] || {
    echo "$name exited $exit_code, expected $expected" >&2
    exit 1
  }
}

mkdir -p "$npm_config_prefix"
npm install -g "$HOME/ariava-under-test.tgz"

systemctl --user show-environment >/dev/null
record_json status-before 0 ariava status --json
record_json doctor-before 0 ariava doctor --json
record_json init 0 ariava init --json
record_json service-install 0 ariava service install --json
node - <<'NODE'
const fs = require('fs');
const config = JSON.parse(fs.readFileSync(process.env.HOME + '/.config/ariava/config.json', 'utf8'));
if (!config.identity?.hostId || !config.identity?.keyId) throw new Error('persisted identity missing');
fs.writeFileSync('/tmp/ariava-identity-before.json', JSON.stringify({ hostId: config.identity.hostId, keyId: config.identity.keyId }));
NODE

UNIT="$HOME/.config/systemd/user/ariava.service"
[[ -f "$UNIT" ]] || { echo "Missing systemd user unit: $UNIT" >&2; exit 1; }
systemd-analyze --user verify "$UNIT"
grep -F 'WantedBy=default.target' "$UNIT" >/dev/null
if grep -Eq '^(User=|Group=)' "$UNIT"; then
  echo "User unit must not declare User= or Group=" >&2
  exit 1
fi
if grep -Eqi 'sudo|loginctl|nohup|linger|PIDFile|Task Scheduler' "$UNIT"; then
  echo "User unit contains a forbidden privileged or fallback directive" >&2
  exit 1
fi

[[ "$(systemctl --user is-enabled ariava.service)" == "enabled" ]]
[[ "$(systemctl --user is-active ariava.service)" == "active" ]]
record_json service-status 0 ariava service status --json
record_json service-stop 0 ariava service stop --json
[[ "$(systemctl --user is-active ariava.service || true)" == "inactive" ]]
record_json service-start 0 ariava service start --json
[[ "$(systemctl --user is-active ariava.service)" == "active" ]]
record_json service-restart 0 ariava service restart --json
record_json logs 0 ariava logs --json

node <<'NODE'
const fs = require('fs');
const status = JSON.parse(fs.readFileSync('/tmp/service-status.json', 'utf8'));
if (!status.ok || status.data.backend !== 'systemd-user') throw new Error('unexpected service backend');
if (!status.data.installed || !status.data.enabled || !status.data.loaded || !status.data.processRunning) {
  throw new Error('installed service state is incomplete');
}
const logs = JSON.parse(fs.readFileSync('/tmp/logs.json', 'utf8'));
if (!logs.ok || logs.data.backend !== 'systemd-user') throw new Error('journald logs were not returned');
NODE

echo "CAPABLE_SYSTEMD_PHASE=PASS"
