#!/usr/bin/env bash
set -euo pipefail

if [[ "${ARIAVA_RUN_REAL_MACOS_KEYCHAIN_LAUNCHD_TEST:-}" != "1" ]]; then
  echo "SKIP: set ARIAVA_RUN_REAL_MACOS_KEYCHAIN_LAUNCHD_TEST=1 to run the real macOS Keychain/launchd integration test."
  exit 0
fi

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "ERROR: real Keychain/launchd integration requires macOS." >&2
  exit 1
fi

# This opt-in test intentionally uses the current user's real login Keychain and launchd domain.
# The hermetic adapter tests remain the normal gate; this verifies that a user launchd process can
# read a generic-password item written through security -i without placing the secret in argv.
service="io.noyx.ariava.host-identity.integration.$UID.$PPID"
account="launchd-probe"
label="io.noyx.ariava.keychain-probe.$UID.$PPID"
root="$(mktemp -d "${TMPDIR:-/tmp}/ariava-keychain-launchd.XXXXXX")"
plist="$HOME/Library/LaunchAgents/$label.plist"
output="$root/output"
secret="$(openssl rand -hex 32)"
cleanup() {
  launchctl bootout "gui/$UID/$label" >/dev/null 2>&1 || true
  /usr/bin/security delete-generic-password -s "$service" -a "$account" >/dev/null 2>&1 || true
  rm -f "$plist"
  rm -rf "$root"
}
trap cleanup EXIT

printf 'add-generic-password -U -s "%s" -a "%s" -w "%s"\n' "$service" "$account" "$secret" | /usr/bin/security -i
mkdir -p "$HOME/Library/LaunchAgents"
cat >"$plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>$label</string>
<key>ProgramArguments</key><array>
<string>/bin/sh</string><string>-c</string>
<string>/usr/bin/security find-generic-password -s '$service' -a '$account' -w &gt; '$output'</string>
</array>
<key>RunAtLoad</key><true/>
</dict></plist>
EOF
chmod 600 "$plist"
launchctl bootstrap "gui/$UID" "$plist"
for _ in {1..50}; do [[ -s "$output" ]] && break; sleep 0.1; done
[[ -s "$output" ]] || { echo "ERROR: launchd probe produced no Keychain output" >&2; exit 1; }
[[ "$(cat "$output")" == "$secret" ]] || { echo "ERROR: launchd Keychain readback mismatch" >&2; exit 1; }
echo "PASS: current-user launchd read the stdin-written Keychain item."
