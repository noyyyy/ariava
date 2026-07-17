import { describe, expect, test } from 'bun:test';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');

function run(command: string, args: string[], cwd: string) {
  return spawnSync(command, args, { cwd, encoding: 'utf8', shell: false });
}

function requireSuccess(result: ReturnType<typeof run>, label: string) {
  expect(result.status, `${label}\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`).toBe(0);
}

function pack(packagePath: string, destination: string): string {
  const result = run('npm', ['pack', packagePath, '--json', '--pack-destination', destination], repositoryRoot);
  requireSuccess(result, `npm pack ${packagePath}`);
  const metadata = JSON.parse(result.stdout) as Array<{ filename: string; files: Array<{ path: string }> }>;
  expect(metadata).toHaveLength(1);
  expect(metadata[0]!.files.some(({ path }) => path.startsWith('src/'))).toBeFalse();
  return join(destination, metadata[0]!.filename);
}

describe('packed public package consumers', () => {
  test('Bun runtime and strict NodeNext TypeScript resolve only packaged dist files', () => {
    const root = mkdtempSync(join(tmpdir(), 'ariava-public-packages-'));
    const tarballs = join(root, 'tarballs');
    const consumer = join(root, 'consumer');
    mkdirSync(tarballs);
    mkdirSync(consumer);

    try {
      requireSuccess(run('bun', ['run', 'build:protocol'], repositoryRoot), 'build protocol');
      requireSuccess(run('bun', ['run', 'build:shared-utils'], repositoryRoot), 'build shared utils');

      const protocolTarball = pack(join(repositoryRoot, 'packages', 'protocol'), tarballs);
      const sharedUtilsTarball = pack(join(repositoryRoot, 'packages', 'shared-utils'), tarballs);

      writeFileSync(join(consumer, 'package.json'), JSON.stringify({ private: true, type: 'module' }, null, 2));
      requireSuccess(
        run('npm', ['install', '--ignore-scripts', '--no-audit', '--no-fund', protocolTarball, sharedUtilsTarball], consumer),
        'install packed packages',
      );

      writeFileSync(join(consumer, 'runtime.ts'), `
import { COMMAND_TYPES } from '@ariava/protocol';
import { validateCommandType } from '@ariava/protocol/commands';
import { SESSION_STATUSES } from '@ariava/protocol/events';
import { HOST_PLATFORMS } from '@ariava/protocol/hosts';
import { ENTITY_TYPES } from '@ariava/protocol/identity';
import { formatPairingCode } from '@ariava/protocol/pairing';
import { REQUEST_SIGNATURE_DOMAIN } from '@ariava/protocol/request-signing';
import * as sessions from '@ariava/protocol/sessions';
import { validateSignedRequestHeaders } from '@ariava/protocol/validation';
import vectors from '@ariava/protocol/fixtures/ed25519-request-vectors' with { type: 'json' };
import { createId } from '@ariava/shared-utils';

if (COMMAND_TYPES.join(',') !== 'reply,interrupt') throw new Error('root export failed');
if (!validateCommandType('reply')) throw new Error('commands export failed');
if (!SESSION_STATUSES.includes('working')) throw new Error('events export failed');
if (!HOST_PLATFORMS.includes('linux')) throw new Error('hosts export failed');
if (!ENTITY_TYPES.includes('host')) throw new Error('identity export failed');
if (formatPairingCode('012345') !== '012345') throw new Error('pairing export failed');
if (REQUEST_SIGNATURE_DOMAIN !== 'ariava-request-v1') throw new Error('request-signing export failed');
if (typeof sessions !== 'object') throw new Error('sessions export failed');
if (typeof validateSignedRequestHeaders !== 'function') throw new Error('validation export failed');
if (!vectors || !Array.isArray(vectors.vectors) || vectors.vectors.length === 0) throw new Error('fixture export failed');
if (!createId('test', 1, 0).startsWith('test_')) throw new Error('shared-utils export failed');
`);
      requireSuccess(run('bun', ['run', 'runtime.ts'], consumer), 'Bun packed-package imports');

      writeFileSync(join(consumer, 'types.ts'), `
import { COMMAND_TYPES, type CommandEnvelope } from '@ariava/protocol';
import { validateCommandType, type CommandType } from '@ariava/protocol/commands';
import { SESSION_STATUSES, type CanonicalEvent } from '@ariava/protocol/events';
import { HOST_PLATFORMS, type HostProjection } from '@ariava/protocol/hosts';
import { ENTITY_TYPES, type EntityType } from '@ariava/protocol/identity';
import { formatPairingCode, type BridgePairWatchRequest } from '@ariava/protocol/pairing';
import { REQUEST_SIGNATURE_DOMAIN, type SignedRequestHeaders } from '@ariava/protocol/request-signing';
import type { CanonicalSessionState } from '@ariava/protocol/sessions';
import { validateSignedRequestHeaders, type ValidationResult } from '@ariava/protocol/validation';
import vectors from '@ariava/protocol/fixtures/ed25519-request-vectors' with { type: 'json' };
import { createId } from '@ariava/shared-utils';

const commandType: CommandType = COMMAND_TYPES[0];
const entityType: EntityType = ENTITY_TYPES[0];
const status = SESSION_STATUSES[0];
const platform = HOST_PLATFORMS[0];
const request: BridgePairWatchRequest = { pairingCode: formatPairingCode('012345') };
const validator: (value: string) => boolean = validateCommandType;
const validate: (headers: Record<string, string | undefined>) => ValidationResult<SignedRequestHeaders> = validateSignedRequestHeaders;
const fixtureCount: number = vectors.vectors.length;
const id: string = createId('typecheck');
void [commandType, entityType, status, platform, request, validator, validate, fixtureCount, id, REQUEST_SIGNATURE_DOMAIN];
void (null as unknown as CommandEnvelope | CanonicalEvent | HostProjection | CanonicalSessionState);
`);
      writeFileSync(join(consumer, 'tsconfig.json'), JSON.stringify({
        compilerOptions: {
          target: 'ES2022',
          module: 'NodeNext',
          moduleResolution: 'NodeNext',
          strict: true,
          noEmit: true,
          resolveJsonModule: true,
          skipLibCheck: false,
        },
        include: ['types.ts'],
      }, null, 2));

      requireSuccess(run('bunx', ['tsc', '-p', 'tsconfig.json'], consumer), 'strict NodeNext packed-package typecheck');
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  }, 120_000);
});
