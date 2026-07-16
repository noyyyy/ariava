import { chmodSync, mkdirSync, writeFileSync } from 'node:fs';
import { delimiter, join } from 'node:path';

export interface IsolatedPublicCliEnvironment {
  env: Record<string, string | undefined>;
  launchctlPath: string;
  launchctlLogPath: string;
}

export function createIsolatedPublicCliEnvironment(
  home: string,
  overrides: Record<string, string | undefined> = {},
): IsolatedPublicCliEnvironment {
  const binDir = join(home, '.ariava-test-bin');
  const launchctlPath = join(binDir, 'launchctl');
  const launchctlLogPath = join(home, 'launchctl-calls.log');
  mkdirSync(binDir, { recursive: true });
  writeFileSync(
    launchctlPath,
    `#!/bin/sh\nprintf '%s\\n' "$*" >> "$ARIAVA_TEST_LAUNCHCTL_LOG"\ncase "$1" in\n  print) exit 1 ;;\n  *) exit 0 ;;\nesac\n`,
  );
  chmodSync(launchctlPath, 0o755);
  return {
    env: {
      ...process.env,
      ...overrides,
      HOME: home,
      PATH: `${binDir}${delimiter}${process.env.PATH ?? '/usr/bin:/bin:/usr/sbin:/sbin'}`,
      ARIAVA_TEST_LAUNCHCTL_LOG: launchctlLogPath,
    },
    launchctlPath,
    launchctlLogPath,
  };
}
