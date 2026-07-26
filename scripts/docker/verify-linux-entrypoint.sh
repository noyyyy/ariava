#!/bin/sh
set -eu

if [ "$#" -ne 3 ] || [ "$1" != "bun" ] || [ "$2" != "run" ] || [ "$3" != "verify:linux" ]; then
  printf '%s\n' 'Docker Linux verification only permits: bun run verify:linux' >&2
  exit 64
fi

umask 077
mkdir -p \
  "$HOME" \
  "$XDG_CONFIG_HOME" \
  "$XDG_CACHE_HOME" \
  "$XDG_DATA_HOME" \
  "$NPM_CONFIG_PREFIX" \
  "$BUN_INSTALL_CACHE_DIR" \
  /workspace
: > "$NPM_CONFIG_USERCONFIG"
: > "$NPM_CONFIG_GLOBALCONFIG"
umask 022

cp -a /opt/ariava-source/. /workspace/
cd /workspace

printf '%s\n' "[ariava verify:linux:docker] base image: $ARIAVA_VERIFY_BASE_IMAGE"
printf '%s\n' "[ariava verify:linux:docker] requested platform: ${ARIAVA_VERIFY_REQUESTED_PLATFORM:-not-recorded}"
printf '%s\n' "[ariava verify:linux:docker] container architecture: $(uname -m)"
printf '%s\n' "[ariava verify:linux:docker] uname: $(uname -a)"
printf '%s\n' "[ariava verify:linux:docker] user: $(id -u):$(id -g) ($(id -un))"
printf '%s\n' "[ariava verify:linux:docker] node: $(node --version)"
printf '%s\n' "[ariava verify:linux:docker] npm: $(npm --version)"
printf '%s\n' "[ariava verify:linux:docker] bun: $(bun --version)"

bun install --frozen-lockfile
exec "$@"
