#!/usr/bin/env bash
set -euo pipefail

[[ "$(id -u)" != "0" ]] || { echo "Ariava integration phases must run as an ordinary user" >&2; exit 1; }

export HOME="${HOME:-/home/ariava-test}"
export PATH="$HOME/.npm-global/bin:/usr/local/bin:/usr/bin:/bin"
export npm_config_prefix="$HOME/.npm-global"
systemctl --user disable --now ariava.service >/dev/null 2>&1 || true
rm -rf "$HOME/.config/ariava" "$HOME/.config/systemd/user/ariava.service"
systemctl --user daemon-reload

export XDG_RUNTIME_DIR=/tmp/ariava-systemd-test-no-user-bus
export DBUS_SESSION_BUS_ADDRESS=unix:path:/tmp/ariava-systemd-test-no-user-bus/bus
mkdir -p "$XDG_RUNTIME_DIR"

run_json() {
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

run_json unavailable-status 0 ariava status --json
run_json unavailable-doctor 1 ariava doctor --json
run_json unavailable-init 1 ariava init --json
run_json unavailable-install 1 ariava service install --json
run_json unavailable-reinstall 1 ariava service reinstall --json
run_json unavailable-start 1 ariava service start --json

node <<'NODE'
const fs = require('fs');
for (const [name, expected] of [
  ['unavailable-doctor', 'ERR_DOCTOR'],
  ['unavailable-init', 'ERR_SYSTEMD_USER_UNAVAILABLE'],
  ['unavailable-install', 'ERR_SYSTEMD_USER_UNAVAILABLE'],
  ['unavailable-reinstall', 'ERR_SYSTEMD_USER_UNAVAILABLE'],
  ['unavailable-start', 'ERR_SYSTEMD_USER_UNAVAILABLE'],
]) {
  const output = fs.readFileSync(`/tmp/${name}.json`, 'utf8') || fs.readFileSync(`/tmp/${name}.err`, 'utf8');
  const body = JSON.parse(output);
  if (body.code !== expected) throw new Error(`${name}: expected ${expected}, got ${body.code}`);
  if (/wsl\.exe|systemd=true|\[boot\]/i.test(output)) throw new Error(`${name}: included WSL-specific guidance`);
}
const status = JSON.parse(fs.readFileSync('/tmp/unavailable-status.json', 'utf8'));
if (!status.ok || status.data.service.supportReason !== 'systemd-user-manager-unavailable') {
  throw new Error('status did not report the unavailable user manager');
}
for (const path of [
  process.env.HOME + '/.config/ariava/config.json',
  process.env.HOME + '/.config/systemd/user/ariava.service',
  process.env.HOME + '/.config/ariava/install.json',
]) {
  if (fs.existsSync(path)) throw new Error(`partial state written: ${path}`);
}
NODE

echo "UNAVAILABLE_USER_BUS_PHASE=PASS"
