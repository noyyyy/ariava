import { afterEach, describe, expect, test } from 'bun:test';
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const repositoryRoot = resolve(import.meta.dir, '..');
const temporaryRoots: string[] = [];

afterEach(() => {
  for (const root of temporaryRoots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function runTypecheck(config: string) {
  return Bun.spawnSync({
    cmd: ['bunx', 'tsc', '-p', config, '--pretty', 'false'],
    cwd: repositoryRoot,
    stdout: 'pipe',
    stderr: 'pipe',
  });
}

describe('protocol declaration contract typecheck', () => {
  test('passes the targeted public contract and fails if a removed type returns', () => {
    const contractConfig = join(repositoryRoot, 'packages/protocol/tsconfig.contract.json');
    const baseline = runTypecheck(contractConfig);
    expect(baseline.exitCode, baseline.stderr.toString()).toBe(0);

    const root = mkdtempSync(join(tmpdir(), 'ariava-protocol-contract-mutation-'));
    temporaryRoots.push(root);
    const packageRoot = join(root, 'packages/protocol');
    cpSync(join(repositoryRoot, 'packages/protocol/src'), join(packageRoot, 'src'), { recursive: true });
    cpSync(
      join(repositoryRoot, 'packages/protocol/test/public-contract-types.test.ts'),
      join(packageRoot, 'test/public-contract-types.test.ts'),
    );
    cpSync(join(repositoryRoot, 'tsconfig.base.json'), join(root, 'tsconfig.base.json'));
    for (const config of ['tsconfig.json', 'tsconfig.contract.json']) {
      cpSync(join(repositoryRoot, 'packages/protocol', config), join(packageRoot, config));
    }

    const identityPath = join(packageRoot, 'src/identity.ts');
    writeFileSync(identityPath, `${readFileSync(identityPath, 'utf8')}\nexport interface RotationPayload { keyId: string; }\n`);
    const mutated = runTypecheck(join(packageRoot, 'tsconfig.contract.json'));
    const diagnostics = `${mutated.stdout}\n${mutated.stderr}`;
    expect(mutated.exitCode).not.toBe(0);
    expect(diagnostics).toContain("Unused '@ts-expect-error' directive");
    expect(diagnostics).toContain('public-contract-types.test.ts');
  });
});
