import { chmodSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { delimiter, join } from 'node:path';

export interface IsolatedPublicCliEnvironment {
  env: Record<string, string | undefined>;
  launchctlPath: string;
  launchctlLogPath: string;
  piLogPath: string;
}

const publicPackageVersion = (JSON.parse(readFileSync(join(process.cwd(), 'package.json'), 'utf8')) as { version: string }).version;

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
    `#!/bin/sh\nset -eu\nprintf '%s\\n' "$*" >> "$ARIAVA_TEST_PI_LOG"\nagent_dir="\${PI_CODING_AGENT_DIR:-$HOME/.pi/agent}"\nsettings="$agent_dir/settings.json"\npkg="$agent_dir/npm/node_modules/@ariava/pi-extension"\ncase "$1" in\n  install)\n    mkdir -p "$pkg"\n    printf '{"name":"@ariava/pi-extension","version":"%s"}\\n' "$ARIAVA_TEST_PACKAGE_VERSION" > "$pkg/package.json"\n    mkdir -p "$agent_dir"\n    printf '{"packages":["npm:@ariava/pi-extension"]}\\n' > "$settings"\n    ;;\n  update)\n    mkdir -p "$pkg"\n    printf '{"name":"@ariava/pi-extension","version":"%s"}\\n' "$ARIAVA_TEST_PACKAGE_VERSION" > "$pkg/package.json"\n    ;;\n  remove)\n    rm -rf "$pkg"\n    printf '{"packages":[]}\\n' > "$settings"\n    ;;\nesac\n`,
  );
  chmodSync(piPath, 0o755);
  return {
    env: {
      ...process.env,
      ...overrides,
      HOME: home,
      PATH: `${binDir}${delimiter}${process.env.PATH ?? '/usr/bin:/bin:/usr/sbin:/sbin'}`,
      ARIAVA_TEST_LAUNCHCTL_LOG: launchctlLogPath,
      ARIAVA_TEST_PI_LOG: piLogPath,
      ARIAVA_TEST_PACKAGE_VERSION: publicPackageVersion,
    },
    launchctlPath,
    launchctlLogPath,
    piLogPath,
  };
}
