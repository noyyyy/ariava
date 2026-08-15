import { describe, expect, test } from 'bun:test';
import { existsSync, mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';

import { fileURLToPath } from 'node:url';

const helper = fileURLToPath(new URL('assert-npm-package.mjs', import.meta.url));
const required = [
  'package.json', 'apps/bridge/dist/cli.js', 'apps/bridge/dist/public-cli.js',
  'apps/bridge/dist/ui/assets/ariava-success-wide.txt',
  'apps/bridge/dist/ui/assets/ariava-success-compact.txt',
  'apps/bridge/dist/e2e/node-crypto.js', 'apps/bridge/dist/e2e/node-crypto-self-test.js',
  'packages/protocol/dist/index.js', 'packages/protocol/dist/index.d.ts',
  'packages/protocol/dist/commands.js', 'packages/protocol/dist/commands.d.ts',
  'packages/protocol/dist/identity.js', 'packages/protocol/dist/identity.d.ts',
  'packages/protocol/dist/events.js', 'packages/protocol/dist/events.d.ts',
  'packages/protocol/dist/encryption.js', 'packages/protocol/dist/encryption.d.ts',
  'packages/protocol/dist/fixtures/command-e2e-v1-vectors.json',
  'packages/protocol/dist/fixtures/ed25519-request-vectors.json',
  'packages/protocol/dist/fixtures/e2e-v2-vectors.json',
  'packages/protocol/dist/fixtures/e2e-v3-vectors.json',
  'packages/protocol/dist/fixtures/notification-preview-v2-vector.json',
  'packages/protocol/dist/fixtures/need-human-error-validation-v2.json',
  'packages/shared-utils/dist/index.js', 'packages/shared-utils/dist/index.d.ts',
  'extensions/pi/bundle/index.js', 'extensions/pi/bundle/package.json',
  'extensions/pi/bundle/.ariava-release-bundle.json',
];

const validRootManifest = JSON.stringify({ name: 'ariava', version: '1.2.3' });
const validCommandDeclarations = `
interface CommandResultBase { commandId: string; hostId: string; sessionId: string; updatedAt: string; }
export type CommandResult = CommandResultBase & ({
  accepted: true;
  status: 'executed';
} | {
  accepted: false;
  status: 'expired' | 'rejected' | 'failed';
});
export interface CommandSubmissionAckV1 { commandId: string; receivedAt: string; }
`;
const validDeclarationContents: Record<string, string> = {
  'packages/protocol/dist/index.d.ts': "export * from './commands.js'; export * from './identity.js';",
  'packages/protocol/dist/commands.d.ts': validCommandDeclarations,
  'packages/protocol/dist/identity.d.ts': 'export interface PublicIdentity { entityId: string; }',
};
const validRuntimeFixtures: Record<string, string> = {
  'packages/protocol/dist/fixtures/command-e2e-v1-vectors.json': JSON.stringify({
    version: 1, suite: 'x25519-hkdf-sha256-chachapoly-v1',
    interrupt: { commandDigest: 'digest', envelope: { type: 'interrupt', payload: { content: { payloadKind: 'interrupt-content-v1' } } } },
    receiptPlaintexts: ['executed', 'expired', 'rejected', 'failed'].map((status) => ({ plaintext: status })),
    receipt: { receiptDigest: 'digest', envelope: { content: { payloadKind: 'command-receipt-content-v1' } } },
  }),
  'packages/protocol/dist/fixtures/e2e-v2-vectors.json': JSON.stringify({
    version: 2, event: { contentId: 'event', contentAAD: 'aad' }, session: { contentId: 'session', contentAAD: 'aad' },
  }),
  'packages/protocol/dist/fixtures/e2e-v3-vectors.json': JSON.stringify({
    version: 3,
    event: { contentId: 'event-v3', contentAAD: 'event-aad-v3', plaintext: 'event-plaintext-v3' },
    session: { contentId: 'session-v3', contentAAD: 'session-aad-v3', plaintext: 'session-plaintext-v3' },
  }),
  'packages/protocol/dist/fixtures/notification-preview-v2-vector.json': JSON.stringify({
    version: 2, preview: { contentId: 'preview', contentAAD: 'aad' },
  }),
  'packages/protocol/dist/fixtures/need-human-error-validation-v2.json': JSON.stringify({
    version: 2, cases: [{ name: 'valid', expected: true }],
  }),
};

const PROCESS_TIMEOUT_MS = 10_000;
const PROCESS_TERMINATION_GRACE_MS = 100;
const PROCESS_TABLE_TIMEOUT_MS = 1_000;
const PROCESS_OUTPUT_LIMIT_BYTES = 1024 * 1024;
const SUBPROCESS_WRAPPER = String.raw`
const { spawn } = require('node:child_process');
const [token, command, ...args] = process.argv.slice(1);
process.title = 'ariava-test-process-leader ' + token;
process.on('SIGTERM', () => {});
const child = spawn(command, args, {
  env: { ...process.env, ARIAVA_TEST_PROCESS_TOKEN: token },
  stdio: 'inherit',
});
if (process.send) process.send({ type: 'launched', token });
const finish = (exitCode, signalCode) => {
  if (signalCode) {
    process.removeAllListeners(signalCode);
    setImmediate(() => process.kill(process.pid, signalCode));
    return;
  }
  process.exit(exitCode ?? 1);
};
child.once('error', (error) => console.error(error.message));
child.once('close', (exitCode, signalCode) => {
  if (!process.send) {
    finish(exitCode, signalCode);
    return;
  }
  process.send({ type: 'settled', token, exitCode, signalCode });
  process.once('message', (message) => {
    if (message?.type === 'release' && message.token === token) finish(exitCode, signalCode);
  });
});
`;

interface ProcessResult {
  exitCode: number | null;
  signalCode: NodeJS.Signals | null;
  stdout: Buffer;
  stderr: Buffer;
  timedOut: boolean;
  processToken: string;
  processGroupId: number;
  processGroupSignals: NodeJS.Signals[];
}

interface ProcessTableEntry {
  pid: number;
  processGroupId: number;
  command: string;
}

async function withTempRoot<T>(prefix: string, action: (root: string) => Promise<T>): Promise<T> {
  const root = mkdtempSync(join(tmpdir(), prefix));
  try {
    return await action(root);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

function readProcessTable(): ProcessTableEntry[] {
  const result = spawnSync('/bin/ps', ['-axww', '-o', 'pid=,pgid=,command='], {
    encoding: 'utf8',
    maxBuffer: PROCESS_OUTPUT_LIMIT_BYTES,
    timeout: PROCESS_TABLE_TIMEOUT_MS,
  });
  if (result.status !== 0 || result.error) {
    throw result.error ?? new Error(`/bin/ps exited with status ${String(result.status)}: ${result.stderr}`);
  }
  return result.stdout.split('\n').flatMap((line) => {
    const match = /^\s*(\d+)\s+(\d+)\s+(.*)$/.exec(line);
    if (!match) return [];
    return [{ pid: Number(match[1]), processGroupId: Number(match[2]), command: match[3] }];
  });
}

function commandHasExactArgument(command: string, argument: string): boolean {
  return command.split(/\s+/u).includes(argument);
}

function tokenOwnedProcessGroup(processGroupId: number, token: string): boolean {
  return readProcessTable().some((entry) =>
    entry.pid === processGroupId
    && entry.processGroupId === processGroupId
    && commandHasExactArgument(entry.command, token)
  );
}

function exactProcessIdentityEntries(result: ProcessResult): ProcessTableEntry[] {
  return readProcessTable().filter((entry) =>
    entry.pid === result.processGroupId
    || entry.processGroupId === result.processGroupId
    || commandHasExactArgument(entry.command, result.processToken),
  );
}

function signalTokenOwnedProcessGroup(
  processGroupId: number,
  token: string,
  signal: NodeJS.Signals,
  signalsSent: NodeJS.Signals[],
): boolean {
  if (!tokenOwnedProcessGroup(processGroupId, token)) return false;
  try {
    process.kill(-processGroupId, signal);
    signalsSent.push(signal);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ESRCH') return false;
    throw error;
  }
}

function appendBounded(chunks: Buffer[], chunk: Buffer, capturedBytes: number): number {
  const remainingBytes = PROCESS_OUTPUT_LIMIT_BYTES - capturedBytes;
  if (remainingBytes > 0) chunks.push(Buffer.from(chunk.subarray(0, remainingBytes)));
  return Math.min(PROCESS_OUTPUT_LIMIT_BYTES, capturedBytes + chunk.length);
}

function runSubprocess(command: string, args: string[], timeoutMs = PROCESS_TIMEOUT_MS): Promise<ProcessResult> {
  return new Promise((resolve) => {
    const processToken = randomBytes(32).toString('hex');
    const child = spawn(process.execPath, ['-e', SUBPROCESS_WRAPPER, processToken, command, ...args], {
      detached: true,
      stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
    });
    if (!child.pid) throw new Error('spawned subprocess wrapper has no pid');
    const processGroupId = child.pid;
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    const processGroupSignals: NodeJS.Signals[] = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let timedOut = false;
    let targetSettlement: { exitCode: number | null; signalCode: NodeJS.Signals | null } | undefined;
    let escalationTimer: ReturnType<typeof setTimeout> | undefined;

    child.stdout?.on('data', (chunk: Buffer) => {
      stdoutBytes = appendBounded(stdout, chunk, stdoutBytes);
    });
    child.stderr?.on('data', (chunk: Buffer) => {
      stderrBytes = appendBounded(stderr, chunk, stderrBytes);
    });
    child.once('error', (error) => {
      stderrBytes = appendBounded(stderr, Buffer.from(error.message), stderrBytes);
    });

    const timeout = setTimeout(() => {
      if (targetSettlement) return;
      timedOut = true;
      signalTokenOwnedProcessGroup(processGroupId, processToken, 'SIGTERM', processGroupSignals);
      escalationTimer = setTimeout(() => {
        if (targetSettlement) return;
        signalTokenOwnedProcessGroup(processGroupId, processToken, 'SIGKILL', processGroupSignals);
      }, PROCESS_TERMINATION_GRACE_MS);
    }, timeoutMs);

    child.on('message', (message) => {
      const notification = message as {
        type?: unknown;
        token?: unknown;
        exitCode?: unknown;
        signalCode?: unknown;
      };
      if (notification.type === 'launched' && notification.token === processToken) {
        expect(tokenOwnedProcessGroup(processGroupId, processToken)).toBe(true);
        return;
      }
      if (
        notification.type !== 'settled'
        || notification.token !== processToken
        || (typeof notification.exitCode !== 'number' && notification.exitCode !== null)
        || (typeof notification.signalCode !== 'string' && notification.signalCode !== null)
      ) return;
      targetSettlement = {
        exitCode: notification.exitCode,
        signalCode: notification.signalCode as NodeJS.Signals | null,
      };
      clearTimeout(timeout);
      if (escalationTimer) clearTimeout(escalationTimer);
      child.send({ type: 'release', token: processToken });
    });

    child.once('close', (exitCode, signalCode) => {
      clearTimeout(timeout);
      if (escalationTimer) clearTimeout(escalationTimer);
      resolve({
        exitCode: targetSettlement?.exitCode ?? exitCode,
        signalCode: targetSettlement?.signalCode ?? signalCode,
        stdout: Buffer.concat(stdout),
        stderr: Buffer.concat(stderr),
        timedOut,
        processToken,
        processGroupId,
        processGroupSignals,
      });
    });
  });
}

function run(paths: string[], version: string | null = '1.2.3'): Promise<ProcessResult> {
  return withTempRoot('ariava-package-assert-', async (root) => {
    const input = join(root, 'pack.json');
    const entry: { files: Array<{ path: string }>; version?: string } = {
      files: paths.map((path) => ({ path })),
    };
    // null means omit version field entirely; string (including empty) is written as-is.
    if (version !== null) entry.version = version;
    writeFileSync(input, JSON.stringify([entry]));
    return runSubprocess(process.execPath, [helper, input]);
  });
}

function runTarball(
  paths: string[],
  kind: 'root' | 'pi' = 'root',
  contents: Record<string, string> = {},
): Promise<ProcessResult> {
  return withTempRoot('ariava-package-tarball-', async (root) => {
    const packageRoot = join(root, 'package');
    for (const path of paths) {
      const target = join(packageRoot, path);
      mkdirSync(join(target, '..'), { recursive: true });
      const defaultContent = path === 'package.json' && kind === 'root'
        ? validRootManifest
        : validDeclarationContents[path] ?? validRuntimeFixtures[path] ?? 'fixture';
      writeFileSync(target, contents[path] ?? defaultContent);
    }
    const tarball = join(root, 'fixture.tgz');
    const packed = await runSubprocess('/usr/bin/tar', ['-czf', tarball, '-C', root, 'package']);
    if (packed.timedOut) throw new Error('tar timed out');
    if (packed.exitCode !== 0) throw new Error(packed.stderr.toString());
    return runSubprocess(process.execPath, [helper, '--kind', kind, tarball]);
  });
}

describe('npm package artifact assertion', () => {
  test('accepts the required Bridge, protocol, shared utils, and pi bundle artifacts', async () => {
    const result = await run(required);
    expect(result.exitCode).toBe(0);
    expect(result.stdout.toString()).toContain(`${required.length} required artifacts`);
  });

  test('rejects missing, source, sensitive, and otherwise unexpected artifacts', async () => {
    expect((await run(required.filter((path) => path !== 'apps/bridge/dist/ui/assets/ariava-success-wide.txt'))).exitCode).toBe(1);
    for (const forbidden of [
      'helpers/Identity.swift',
      'unexpected/runtime.js',
      'apps/relay/dist/worker.js',
      'apps/watchos/Ariava/App/AriavaApp.swift',
      'docs/release.md',
      'screenshots/watch.png',
      'scripts/deploy.sh',
      'packages/protocol/src/index.ts',
      'packages/protocol/dist/index.js.map',
      'apps/bridge/dist/ui/assets/ariava.png',
      'apps/bridge/dist/ui/assets/unreviewed.txt',
      'Users/example/private.txt',
      'ariava-private/README.md',
      'packages/protocol/dist/fixtures/e2e-v1-vectors.json',
      'packages/protocol/dist/fixtures/notification-preview-v1-vector.json',
    ]) {
      const result = await run([...required, forbidden]);
      expect(result.exitCode, `${forbidden}: ${result.stderr.toString()}`).toBe(1);
    }
  });

  test('asserts actual tarball contents and rejects unexpected files', async () => {
    expect((await runTarball(required)).exitCode).toBe(0);
    expect((await runTarball(required.slice(1))).exitCode).toBe(1);
    expect((await runTarball([...required, 'unexpected/runtime.js'])).exitCode).toBe(1);
  });

  test.each(['RotationPayload', 'KeyRotationRequest', 'KeyRotationResponse'])(
    'rejects removed %s declaration from packed tarballs',
    async (removed) => {
      const result = await runTarball(required, 'root', {
        'packages/protocol/dist/identity.d.ts': `export interface ${removed} { value: string; }`,
      });
      expect(result.exitCode, removed).toBe(1);
      expect(result.stderr.toString()).toContain(`removed ${removed}`);
    },
  );

  test.each([
    'message?: string;',
    'readonly reason ?: string;',
    "readonly 'detail' ? : string;",
    '"error"\n  ?\n  : string;',
    'correlationId?: string;',
  ])('rejects an inexact command result declaration %#', async (property) => {
    const declaration = validCommandDeclarations.replace('updatedAt: string;', `updatedAt: string; ${property}`);
    const result = await runTarball(required, 'root', { 'packages/protocol/dist/commands.d.ts': declaration });
    expect(result.exitCode, `${property}: ${result.stderr.toString()}`).toBe(1);
    expect(result.stderr.toString()).toContain('CommandResultBase declaration is not exact');
  });

  test.each([
    validCommandDeclarations.replace("accepted: true;\n  status: 'executed';", 'accepted: boolean;\n  status: CommandResultStatus;'),
    validCommandDeclarations.replace('receivedAt: string;', 'receivedAt: string; accepted: boolean;'),
    validCommandDeclarations.replace('receivedAt: string;', 'receivedAt: string; result: CommandResult;'),
  ])('rejects widened command declaration %#', async (declaration) => {
    const result = await runTarball(required, 'root', { 'packages/protocol/dist/commands.d.ts': declaration });
    expect(result.exitCode, result.stderr.toString()).toBe(1);
  });

  test('allows an unrelated diagnostic declaration outside command result and acknowledgment', async () => {
    const result = await runTarball(required, 'root', {
      'packages/protocol/dist/commands.d.ts': `${validCommandDeclarations}\nexport interface TransportError { error?: string; }`,
    });
    expect(result.exitCode, result.stderr.toString()).toBe(0);
  });

  test('validates packaged command E2E v1, runtime v2/v3, and parity fixture contents', async () => {
    const invalidCommand = await runTarball(required, 'root', {
      'packages/protocol/dist/fixtures/command-e2e-v1-vectors.json': JSON.stringify({
        version: 1, suite: 'x25519-hkdf-sha256-chachapoly-v1', interrupt: { envelope: { type: 'interrupt' } },
      }),
    });
    expect(invalidCommand.exitCode).toBe(1);
    expect(invalidCommand.stderr.toString()).toContain('command E2E v1');

    const wrongVersion = await runTarball(required, 'root', {
      'packages/protocol/dist/fixtures/e2e-v2-vectors.json': JSON.stringify({
        version: 1, event: { contentId: 'event', contentAAD: 'aad' },
        session: { contentId: 'session', contentAAD: 'aad' },
      }),
    });
    expect(wrongVersion.exitCode).toBe(1);
    expect(wrongVersion.stderr.toString()).toContain('runtime v2 interoperability fixture');

    const wrongCurrentVersion = await runTarball(required, 'root', {
      'packages/protocol/dist/fixtures/e2e-v3-vectors.json': JSON.stringify({
        version: 2,
        event: { contentId: 'event-v3', contentAAD: 'event-aad-v3', plaintext: 'event-plaintext-v3' },
        session: { contentId: 'session-v3', contentAAD: 'session-aad-v3', plaintext: 'session-plaintext-v3' },
      }),
    });
    expect(wrongCurrentVersion.exitCode).toBe(1);
    expect(wrongCurrentVersion.stderr.toString()).toContain('runtime v3 interoperability fixture');

    const emptyParity = await runTarball(required, 'root', {
      'packages/protocol/dist/fixtures/need-human-error-validation-v2.json': JSON.stringify({ version: 2, cases: [] }),
    });
    expect(emptyParity.exitCode).toBe(1);
    expect(emptyParity.stderr.toString()).toContain('parity fixture');
  });


  test('accepts only the generated scoped package public files and validates its metadata', async () => {
    const piFiles = ['package.json', 'index.js', '.ariava-release-bundle.json'];
    const valid = {
      'package.json': JSON.stringify({
        name: '@ariava/pi-extension', version: '1.2.3', type: 'module', main: './index.js',
        files: ['index.js', '.ariava-release-bundle.json'], keywords: ['pi-package'],
        pi: { extensions: ['./index.js'] },
      }),
      '.ariava-release-bundle.json': JSON.stringify({
        bundleVersion: '1.2.3', createdAt: '2026-07-22T00:00:00.000Z', entry: 'index.js', source: 'extensions/pi/dist/index.js',
      }),
    };
    expect((await runTarball(piFiles, 'pi', valid)).exitCode).toBe(0);
    expect((await runTarball([...piFiles, 'src/private.ts'], 'pi', valid)).exitCode).toBe(1);
    expect((await runTarball(piFiles, 'pi', {
      ...valid,
      'package.json': JSON.stringify({ name: '@ariava/pi-extension', version: '1.2.3', private: true }),
    })).exitCode).toBe(1);
  });

  test('rejects missing, invalid, and placeholder package versions', async () => {
    expect((await run(required, null)).exitCode).toBe(1);
    expect((await run(required, '')).exitCode).toBe(1);
    expect((await run(required, 'not-a-version')).exitCode).toBe(1);
    expect((await run(required, '0.0.0')).exitCode).toBe(1);

    const missingVersion = await runTarball(required, 'root', {
      'package.json': JSON.stringify({ name: 'ariava' }),
    });
    expect(missingVersion.exitCode).toBe(1);
    expect(missingVersion.stderr.toString()).toContain('non-placeholder SemVer');

    const placeholder = await runTarball(required, 'root', {
      'package.json': JSON.stringify({ name: 'ariava', version: '0.0.0' }),
    });
    expect(placeholder.exitCode).toBe(1);
    expect(placeholder.stderr.toString()).toContain('0.0.0');

    const invalid = await runTarball(required, 'root', {
      'package.json': JSON.stringify({ name: 'ariava', version: 'v1.2.3' }),
    });
    expect(invalid.exitCode).toBe(1);

    const piFiles = ['package.json', 'index.js', '.ariava-release-bundle.json'];
    const piPlaceholder = {
      'package.json': JSON.stringify({
        name: '@ariava/pi-extension', version: '0.0.0', type: 'module', main: './index.js',
        files: ['index.js', '.ariava-release-bundle.json'], keywords: ['pi-package'],
        pi: { extensions: ['./index.js'] },
      }),
      '.ariava-release-bundle.json': JSON.stringify({
        bundleVersion: '0.0.0', createdAt: '2026-07-22T00:00:00.000Z', entry: 'index.js', source: 'extensions/pi/dist/index.js',
      }),
    };
    expect((await runTarball(piFiles, 'pi', piPlaceholder)).exitCode).toBe(1);
  });

  test('requires a real tarball for protocol declaration-only validation', async () => {
    const result = await withTempRoot('ariava-package-declaration-assert-', async (root) => {
      const input = join(root, 'pack.json');
      writeFileSync(input, JSON.stringify([{ files: required.map((path) => ({ path })), version: '1.2.3' }]));
      return runSubprocess(process.execPath, [helper, '--protocol-declarations-only', input]);
    });
    expect(result.exitCode).toBe(1);
    expect(result.stderr.toString()).toContain('requires a packed tarball');
  });

  test('cancels SIGKILL escalation when the timed-out child settles on SIGTERM', async () => {
    let rootPath = '';
    const result = await withTempRoot('ariava-package-timeout-', async (root) => {
      rootPath = root;
      return runSubprocess(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], 50);
    });

    expect(result.timedOut).toBe(true);
    expect(result.exitCode).toBeNull();
    expect(result.signalCode).toBe('SIGTERM');
    expect(result.processGroupSignals).toEqual(['SIGTERM']);
    expect(exactProcessIdentityEntries(result)).toEqual([]);
    expect(existsSync(rootPath)).toBe(false);
  });

  test('SIGKILLs a token-owned group with a resistant descendant and removes its temp root', async () => {
    let rootPath = '';
    const result = await withTempRoot('ariava-package-timeout-', async (root) => {
      rootPath = root;
      return runSubprocess(process.execPath, ['-e', `
        const { spawn } = require('node:child_process');
        process.on('SIGTERM', () => {});
        spawn(process.execPath, ['-e', \`
          process.on('SIGTERM', () => {});
          console.log('resistant descendant ready');
          setInterval(() => {}, 1000);
        \`, process.env.ARIAVA_TEST_PROCESS_TOKEN], { env: process.env, stdio: 'inherit' });
        setInterval(() => {}, 1000);
      `], 250);
    });

    expect(result.timedOut).toBe(true);
    expect(result.exitCode).toBeNull();
    expect(result.signalCode).toBe('SIGKILL');
    expect(result.processGroupSignals).toEqual(['SIGTERM', 'SIGKILL']);
    expect(result.stdout.toString()).toContain('resistant descendant ready');
    expect(exactProcessIdentityEntries(result)).toEqual([]);
    expect(existsSync(rootPath)).toBe(false);
  });
});
