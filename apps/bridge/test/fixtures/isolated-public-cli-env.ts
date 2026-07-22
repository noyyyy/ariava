import { chmodSync, mkdirSync, writeFileSync } from 'node:fs';
import { delimiter, join } from 'node:path';

export interface IsolatedPublicCliEnvironment {
  env: Record<string, string | undefined>;
  launchctlPath: string;
  launchctlLogPath: string;
  piLogPath: string;
}


export function createIsolatedPublicCliEnvironment(
  home: string,
  overrides: Record<string, string | undefined> = {},
): IsolatedPublicCliEnvironment {
  const binDir = join(home, '.ariava-test-bin');
  const launchctlPath = join(binDir, 'launchctl');
  const launchctlLogPath = join(home, 'launchctl-calls.log');
  const piPath = join(binDir, 'pi');
  const piLogPath = join(home, 'pi-calls.log');
  mkdirSync(binDir, { recursive: true });
  writeFileSync(
    launchctlPath,
    `#!/bin/sh\nprintf '%s\\n' "$*" >> "$ARIAVA_TEST_LAUNCHCTL_LOG"\ncase "$1" in\n  print) exit 1 ;;\n  *) exit 0 ;;\nesac\n`,
  );
  chmodSync(launchctlPath, 0o755);
  writeFileSync(
    piPath,
    `#!/bin/sh
set -eu
printf '%s\\n' "$*" >> "$ARIAVA_TEST_PI_LOG"
agent_dir="\${PI_CODING_AGENT_DIR:-$HOME/.pi/agent}"
settings="$agent_dir/settings.json"
pkg="$agent_dir/npm/node_modules/@ariava/pi-extension"
case "$1" in
  install)
    source="$2"
    version="\${source##*@}"
    mkdir -p "$pkg" "$agent_dir"
    printf '{"name":"@ariava/pi-extension","version":"%s"}\\n' "$version" > "$pkg/package.json"
    ARIAVA_TEST_PI_SOURCE="$source" SETTINGS_PATH="$settings" bun -e '
      import { existsSync, readFileSync, writeFileSync } from "node:fs";
      const path = process.env.SETTINGS_PATH;
      const settings = existsSync(path) ? JSON.parse(readFileSync(path, "utf8")) : {};
      const packages = Array.isArray(settings.packages) ? settings.packages : [];
      settings.packages = [...packages.filter((entry) => {
        const source = typeof entry === "string" ? entry : entry?.source;
        return source !== "npm:@ariava/pi-extension" && !source?.startsWith("npm:@ariava/pi-extension@");
      }), process.env.ARIAVA_TEST_PI_SOURCE];
      writeFileSync(path, JSON.stringify(settings) + "\\n");
    '
    ;;
  remove)
    rm -rf "$pkg"
    ;;
esac
`,
  );
  chmodSync(piPath, 0o755);
  return {
    env: {
      ...process.env,
      ...overrides,
      HOME: home,
      XDG_CONFIG_HOME: join(home, '.config'),
      XDG_RUNTIME_DIR: join(home, '.runtime'),
      BUN_RUNTIME_TRANSPILER_CACHE_PATH: '',
      PI_CODING_AGENT_DIR: join(home, '.pi', 'agent'),
      PATH: `${binDir}${delimiter}${process.env.PATH ?? '/usr/bin:/bin:/usr/sbin:/sbin'}`,
      ARIAVA_TEST_LAUNCHCTL_LOG: launchctlLogPath,
      ARIAVA_TEST_PI_LOG: piLogPath,
    },
    launchctlPath,
    launchctlLogPath,
    piLogPath,
  };
}
