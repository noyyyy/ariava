#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIXTURES_DIR="$ROOT/scripts/fixtures"
VM_NAME="ariava-systemd-test-$(date +%Y%m%d%H%M%S)-$$"
VM_USER="ariava-test"
TARBALL=""
KEEP_VM=0
OUTPUT_DIR="$ROOT/tmp/linux-systemd-test/$(date +%Y%m%d-%H%M%S)"
VM_CREATED=0
RESULT="FAIL"
TARBALL_SHA256="unavailable"
HOST_OS_VERSION="$(uname -sr)"
HOST_BUN_VERSION="$(bun --version 2>/dev/null || echo unavailable)"
HOST_NODE_VERSION="$(node --version 2>/dev/null || echo unavailable)"
HOST_NPM_VERSION="$(npm --version 2>/dev/null || echo unavailable)"
HOST_ARIAVA_VERSION="$(node -p "require('./package.json').version" 2>/dev/null || echo unavailable)"
REAL_SELF_UPGRADE=0

usage() {
  cat <<'USAGE'
Run the optional Linux systemd integration test in an isolated OrbStack VM.

Usage:
  ./scripts/test-linux-systemd.sh [options]

Options:
  --tarball <path>    Test an existing Ariava npm tarball instead of building one.
  --keep-vm           Preserve the VM after the test for diagnosis.
  --output-dir <path> Write logs and summary to this directory.
  --real-self-upgrade Run a separately labeled real npm self-upgrade phase.
  -h, --help          Show this help.

This test is optional, is not part of `bun run verify`, and does not test WSL.
USAGE
}

fail_usage() {
  echo "$1" >&2
  usage >&2
  exit 2
}

while (($#)); do
  case "$1" in
    --tarball)
      (($# >= 2)) || fail_usage "Missing value for --tarball"
      TARBALL="$2"
      shift 2
      ;;
    --keep-vm)
      KEEP_VM=1
      shift
      ;;
    --output-dir)
      (($# >= 2)) || fail_usage "Missing value for --output-dir"
      OUTPUT_DIR="$2"
      shift 2
      ;;
    --real-self-upgrade)
      REAL_SELF_UPGRADE=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail_usage "Unknown option: $1"
      ;;
  esac
done

if [[ -n "$TARBALL" && ! -f "$TARBALL" ]]; then
  fail_usage "Tarball not found: $TARBALL"
fi

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required command: $1" >&2
    exit 1
  }
}

absolute_path() {
  local path="$1"
  local directory
  directory="$(cd "$(dirname "$path")" && pwd)"
  printf '%s/%s\n' "$directory" "$(basename "$path")"
}

write_summary() {
  mkdir -p "$OUTPUT_DIR"
  cat > "$OUTPUT_DIR/summary.txt" <<EOF
scope=optional-linux-systemd-integration-test
result=$RESULT
vm_name=$VM_NAME
wsl_tested=false
macos_launchd_tested=false
physical_linux_logout_login_tested=false
tarball_sha256=$TARBALL_SHA256
real_self_upgrade=$REAL_SELF_UPGRADE
reconciliation_phase=reconciliation-only
host_os=$HOST_OS_VERSION
host_bun=$HOST_BUN_VERSION
host_node=$HOST_NODE_VERSION
host_npm=$HOST_NPM_VERSION
ariava_version=$HOST_ARIAVA_VERSION
EOF
}

cleanup() {
  local exit_code=$?
  write_summary
  if [[ "$VM_CREATED" == "1" ]]; then
    if [[ "$KEEP_VM" == "1" ]]; then
      echo "VM preserved: $VM_NAME"
    else
      echo "Cleaning VM: $VM_NAME"
      orbctl delete -f "$VM_NAME" >> "$OUTPUT_DIR/cleanup.log" 2>&1 || true
    fi
  fi
  if [[ "$exit_code" != "0" ]]; then
    echo "Linux systemd integration test failed. Logs: $OUTPUT_DIR" >&2
  fi
}
trap cleanup EXIT

need_cmd orbctl
mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(absolute_path "$OUTPUT_DIR")"

if [[ -z "$TARBALL" ]]; then
  need_cmd bun
  need_cmd npm
  PACK_DIR="$OUTPUT_DIR/artifact"
  mkdir -p "$PACK_DIR"
  echo "Building Ariava Bridge..."
  bun run build:bridge 2>&1 | tee "$OUTPUT_DIR/build.log"
  echo "Packing Ariava npm artifact..."
  npm pack --pack-destination "$PACK_DIR" 2>&1 | tee "$OUTPUT_DIR/pack.log"
  TARBALL="$(find "$PACK_DIR" -maxdepth 1 -type f -name '*.tgz' -print -quit)"
  [[ -n "$TARBALL" ]] || {
    echo "Expected one npm tarball under $PACK_DIR" >&2
    exit 1
  }
  [[ "$(find "$PACK_DIR" -maxdepth 1 -type f -name '*.tgz' -print | wc -l | tr -d '[:space:]')" == "1" ]] || {
    echo "Expected exactly one npm tarball under $PACK_DIR" >&2
    exit 1
  }
else
  TARBALL="$(absolute_path "$TARBALL")"
fi

TARBALL_SHA256="$(shasum -a 256 "$TARBALL" | awk '{print $1}')"
printf 'Testing tarball: %s\nSHA-256: %s\n' "$TARBALL" "$TARBALL_SHA256"

create_vm() {
  local attempt
  for attempt in 1 2; do
    echo "Creating isolated Ubuntu VM (attempt $attempt/2): $VM_NAME"
    if orbctl create \
      --isolated \
      --cpus 2 \
      --memory 2G \
      --disk 12G \
      --user "$VM_USER" \
      ubuntu:24.04 \
      "$VM_NAME" 2>&1 | tee -a "$OUTPUT_DIR/vm-create.log"; then
      VM_CREATED=1
      return 0
    fi

    echo "VM creation attempt $attempt failed; removing any partial VM before retry." >&2
    orbctl delete -f "$VM_NAME" >> "$OUTPUT_DIR/vm-create-cleanup.log" 2>&1 || true
  done

  echo "Unable to create the OrbStack test VM after two attempts." >&2
  return 1
}

create_vm

echo "Installing VM test prerequisites..."
orbctl run -m "$VM_NAME" -u root sh -lc \
  'apt-get update >/tmp/ariava-apt-update.log && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends nodejs npm ca-certificates curl unzip >/tmp/ariava-apt-install.log' \
  2>&1 | tee "$OUTPUT_DIR/vm-prerequisites.log"

transfer_file() {
  local source="$1"
  local destination="$2"
  cat "$source" | orbctl run -m "$VM_NAME" sh -c \
    "cat > '$destination' && chmod 0755 '$destination'"
}

cat "$TARBALL" | orbctl run -m "$VM_NAME" sh -c \
  "cat > '/home/$VM_USER/ariava-under-test.tgz'"
transfer_file "$FIXTURES_DIR/linux-systemd-test.sh" "/home/$VM_USER/linux-systemd-test.sh"
transfer_file "$FIXTURES_DIR/linux-systemd-after-restart-test.sh" "/home/$VM_USER/linux-systemd-after-restart-test.sh"
transfer_file "$FIXTURES_DIR/linux-systemd-unavailable-test.sh" "/home/$VM_USER/linux-systemd-unavailable-test.sh"
transfer_file "$FIXTURES_DIR/linux-systemd-real-upgrade-test.sh" "/home/$VM_USER/linux-systemd-real-upgrade-test.sh"

wait_for_user_manager() {
  local attempt
  for attempt in $(seq 1 90); do
    if orbctl run -m "$VM_NAME" systemctl --user show-environment >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  echo "Timed out waiting for the VM systemd user manager" >&2
  return 1
}

wait_for_user_manager

echo "Recording VM platform/tool versions..."
orbctl run -m "$VM_NAME" sh -lc 'printf "os="; . /etc/os-release; echo "$PRETTY_NAME"; systemd --version | head -1; node --version; npm --version' \
  2>&1 | tee "$OUTPUT_DIR/versions.log"

echo "Running capable systemd lifecycle..."
orbctl run -m "$VM_NAME" "/home/$VM_USER/linux-systemd-test.sh" \
  2>&1 | tee "$OUTPUT_DIR/capable.log"

echo "Restarting the VM to verify enabled service startup..."
orbctl restart "$VM_NAME" 2>&1 | tee "$OUTPUT_DIR/vm-restart.log"
wait_for_user_manager
orbctl run -m "$VM_NAME" "/home/$VM_USER/linux-systemd-after-restart-test.sh" \
  2>&1 | tee "$OUTPUT_DIR/after-restart.log"


if [[ "$REAL_SELF_UPGRADE" == "1" ]]; then
  echo "Running optional real npm self-upgrade phase (not reconciliation-only)..."
  orbctl run -m "$VM_NAME" "/home/$VM_USER/linux-systemd-real-upgrade-test.sh" \
    2>&1 | tee "$OUTPUT_DIR/real-self-upgrade.log"
fi

echo "Running non-WSL unavailable-user-bus diagnostics..."
orbctl run -m "$VM_NAME" "/home/$VM_USER/linux-systemd-unavailable-test.sh" \
  2>&1 | tee "$OUTPUT_DIR/user-bus-unavailable.log"

RESULT="PASS"
write_summary
echo "Optional Linux systemd integration test passed. Logs: $OUTPUT_DIR"
