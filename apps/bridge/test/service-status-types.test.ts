import { describe, expect, test } from 'bun:test';

const BOUNDARY_DIAGNOSTICS = [
  /apps\/bridge\/src\/host-manager\/status\.ts\(\d+,\d+\): error TS(?!2307|2591)\d+:/,
  /apps\/bridge\/test\/fixtures\/host-service-status-types\.ts\(\d+,\d+\): error TS\d+:/,
  /error TS2741: Property '[^']+' is missing in type 'ServiceStatus'/,
  /error TS2307: Cannot find module '..\/..\/src\/host-manager\/service'/,
  ];

describe('host service status semantic types', () => {
  test('keeps neutral service status assignable to the portable host status input', () => {
    const result = Bun.spawnSync({
      cmd: ['bunx', 'tsc', '--noEmit', '-p', 'apps/bridge/tsconfig.json', '--pretty', 'false'],
      cwd: process.cwd(),
      env: process.env,
      stdout: 'pipe',
      stderr: 'pipe',
    });
    const diagnostics = `${result.stdout.toString()}\n${result.stderr.toString()}`;

    // The Bridge tsconfig has known unrelated diagnostics because its base config omits
    // Node/Bun types. We intentionally permit that nonzero exit and fail only on the
    // neutral service-to-host-status compatibility boundary.
    const boundaryDiagnostics = diagnostics
      .split('\n')
      .filter((line) => BOUNDARY_DIAGNOSTICS.some((pattern) => pattern.test(line)));

    expect(boundaryDiagnostics).toEqual([]);
    expect(diagnostics).toContain('error TS');
  }, 30_000);
});
