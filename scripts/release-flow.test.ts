import { describe, expect, test } from 'bun:test';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  RELEASE_CHANGED_FILES,
  parseArgs,
  pushRelease,
  tagRelease,
  validateCommonReleaseVersion,
  validateReleaseChanges,
  validateReleaseContent,
} from './release-flow-lib.mjs';

const VERSION = '1.2.3';
const TAG = `v${VERSION}`;
const BASE_SHA = 'a'.repeat(40);
const SHA = 'c'.repeat(40);
const WORKFLOW_ID = 12345;
const releasePackageFiles = [
  'package.json',
  'apps/bridge/package.json',
  'extensions/pi/package.json',
  'extensions/pi/bundle/package.json',
  'packages/protocol/package.json',
  'packages/shared-utils/package.json',
];

type Invocation = { command: string; args: string[]; options?: Record<string, unknown> };

function fixture(version = VERSION) {
  const root = mkdtempSync(join(tmpdir(), 'ariava-release-flow-'));
  for (const file of releasePackageFiles) {
    mkdirSync(join(root, file, '..'), { recursive: true });
    writeFileSync(join(root, file), `${JSON.stringify({ name: file, version }, null, 2)}\n`);
  }
  writeFileSync(join(root, 'bun.lock'), `{
  // Bun lockfiles are JSONC.
  "workspaces": {
    "apps/bridge": { "version": "${version}", },
    "extensions/pi": { "version": "${version}" },
    "packages/protocol": { "version": "${version}" },
    "packages/shared-utils": { "version": "${version}" },
  },
}\n`);
  return root;
}

function statusFor(paths = RELEASE_CHANGED_FILES) {
  return paths.map((path) => ` M ${path}`).join('\n');
}

function fakeRunner(options: {
  status?: string;
  verifyCode?: number;
  localTag?: boolean;
  remoteTag?: boolean;
  remoteShaAfterWatch?: string;
  workflowRuns?: unknown[];
  workflow?: Record<string, unknown>;
  baselineExtra?: Record<string, unknown>;
} = {}) {
  const log: Invocation[] = [];
  let watched = false;
  let committed = options.status === '';
  let tagged = false;
  const run = async (command: string, args: string[], invocationOptions: Record<string, unknown> = {}) => {
    log.push({ command, args: [...args], options: invocationOptions });
    if (command === 'bun') {
      const verify = args.join(' ') === 'run verify';
      return { code: verify ? (options.verifyCode ?? 0) : 0, stdout: '', stderr: verify && options.verifyCode ? 'verify failed' : '' };
    }
    if (command === 'gh') {
      if (args[0] === 'auth') return { code: 0, stdout: 'github.com\n', stderr: '' };
      if (args[0] === 'run' && args[1] === 'list') {
        return { code: 0, stdout: JSON.stringify(options.workflowRuns ?? [{
          databaseId: WORKFLOW_ID, headSha: SHA, headBranch: 'main', status: 'completed', conclusion: 'success',
        }]), stderr: '' };
      }
      if (args[0] === 'run' && args[1] === 'watch') {
        watched = true;
        return { code: 0, stdout: '', stderr: '' };
      }
      if (args[0] === 'run' && args[1] === 'view') {
        return { code: 0, stdout: JSON.stringify(options.workflow ?? {
          headSha: SHA,
          headBranch: 'main',
          status: 'completed',
          conclusion: 'success',
          jobs: [
            { name: 'Linux', status: 'completed', conclusion: 'success' },
            { name: 'macOS', status: 'completed', conclusion: 'success' },
          ],
        }), stderr: '' };
      }
    }
    if (command !== 'git') return { code: 0, stdout: '', stderr: '' };
    if (args.join(' ') === 'rev-parse --show-toplevel') return { code: 0, stdout: '/fixture\n', stderr: '' };
    if (args.join(' ') === 'symbolic-ref --short HEAD') return { code: 0, stdout: 'main\n', stderr: '' };
    if (args.join(' ') === 'ls-remote --symref origin HEAD') return { code: 0, stdout: 'ref: refs/heads/main\tHEAD\n', stderr: '' };
    if (args.join(' ') === 'rev-parse HEAD') return { code: 0, stdout: `${committed ? SHA : BASE_SHA}\n`, stderr: '' };
    if (args.join(' ') === `rev-parse ${SHA}^`) return { code: 0, stdout: `${BASE_SHA}\n`, stderr: '' };
    if (args.join(' ') === `rev-parse ${TAG}^{}`) return { code: tagged ? 0 : 1, stdout: tagged ? `${SHA}\n` : '', stderr: '' };
    if (args.join(' ') === 'rev-parse refs/remotes/origin/main') {
      const remoteHead = committed ? SHA : BASE_SHA;
      return { code: 0, stdout: `${watched ? (options.remoteShaAfterWatch ?? SHA) : remoteHead}\n`, stderr: '' };
    }
    if (args.join(' ') === 'status --porcelain=v1 --untracked-files=all') {
      return { code: 0, stdout: options.status ?? statusFor(), stderr: '' };
    }
    if (args[0] === 'show-ref') return { code: options.localTag ? 0 : 1, stdout: '', stderr: '' };
    if (args[0] === 'ls-remote' && args[1] === '--tags') return { code: 0, stdout: options.remoteTag ? `${SHA}\trefs/tags/${TAG}\n` : '', stderr: '' };
    if (args[0] === 'show') {
      const [ref, file] = args[1].split(':', 2);
      const baseline = ref === BASE_SHA || ref === `${SHA}^`;
      const version = baseline ? '1.2.2' : VERSION;
      if (file === 'bun.lock') {
        return { code: 0, stdout: JSON.stringify({ workspaces: {
          'apps/bridge': { version },
          'extensions/pi': { version },
          'packages/protocol': { version },
          'packages/shared-utils': { version },
        } }), stderr: '' };
      }
      return { code: 0, stdout: JSON.stringify({ name: file, version, ...(baseline ? options.baselineExtra ?? {} : {}) }), stderr: '' };
    }
    if (args.join(' ') === `diff-tree --no-commit-id --name-only -r ${SHA}`) {
      return { code: 0, stdout: `${RELEASE_CHANGED_FILES.join('\n')}\n`, stderr: '' };
    }
    if (args[0] === 'commit') committed = true;
    if (args[0] === 'tag') tagged = true;
    if (args[0] === 'log' && args[1] === '-1' && args[2] === '--format=%s') return { code: 0, stdout: `release: bump to ${VERSION}\n`, stderr: '' };
    return { code: 0, stdout: '', stderr: '' };
  };
  return { run, log };
}

describe('release flow arguments and local contract', () => {
  test('accepts only push and tag subcommands', () => {
    expect(parseArgs(['push'])).toEqual({ command: 'push' });
    expect(parseArgs(['tag'])).toEqual({ command: 'tag' });
    expect(parseArgs(['--help'])).toEqual({ command: 'help' });
    expect(parseArgs(['-h'])).toEqual({ command: 'help' });
    expect(() => parseArgs([])).toThrow('Usage');
    expect(() => parseArgs(['publish'])).toThrow('unexpected command');
    expect(() => parseArgs(['push', '--force'])).toThrow('unexpected argument');
  });

  test('validates one stable version across packages and JSONC lock workspaces', () => {
    const root = fixture();
    try {
      expect(validateCommonReleaseVersion(root)).toBe(VERSION);
      writeFileSync(join(root, 'extensions/pi/package.json'), `${JSON.stringify({ version: '1.2.4' })}\n`);
      expect(() => validateCommonReleaseVersion(root)).toThrow('version mismatch');
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test('requires exactly the release version files and lockfile to be modified', () => {
    expect(validateReleaseChanges(statusFor())).toEqual(RELEASE_CHANGED_FILES);
    expect(() => validateReleaseChanges(statusFor(RELEASE_CHANGED_FILES.slice(1)))).toThrow('missing release changes');
    expect(() => validateReleaseChanges(`${statusFor()}\n M README.md`)).toThrow('unrelated changes');
    expect(() => validateReleaseChanges('R  package.json -> package-old.json')).toThrow('unsupported git status');
  });

  test('allows only version fields to differ from HEAD in manifests and lockfile', async () => {
    const root = fixture();
    try {
      const clean = fakeRunner();
      await expect(validateReleaseContent(root, SHA, clean.run)).resolves.toBeUndefined();

      const packagePath = join(root, 'package.json');
      writeFileSync(packagePath, `${JSON.stringify({ name: 'package.json', version: VERSION, scripts: { unsafe: 'true' } }, null, 2)}\n`);
      const changed = fakeRunner();
      await expect(validateReleaseContent(root, SHA, changed.run)).rejects.toThrow('non-version content');
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});

describe('release push stage', () => {
  test('verifies, commits only release files, and pushes the default branch without a tag', async () => {
    const root = fixture();
    const fake = fakeRunner();
    try {
      await expect(pushRelease({ root }, { run: fake.run })).resolves.toEqual({ version: VERSION, commit: SHA, branch: 'main' });
      expect(fake.log.filter((entry) => entry.command === 'bun').map((entry) => entry.args)).toEqual([
        ['install', '--frozen-lockfile'],
        ['run', 'verify'],
      ]);
      expect(fake.log.some((entry) => entry.command === 'git' && entry.args[0] === 'add' && RELEASE_CHANGED_FILES.every((path) => entry.args.includes(path)))).toBe(true);
      expect(fake.log.some((entry) => entry.command === 'git' && entry.args.join(' ') === `commit -m release: bump to ${VERSION}`)).toBe(true);
      expect(fake.log.some((entry) => entry.command === 'git' && entry.args.join(' ') === 'push --no-follow-tags origin HEAD:main')).toBe(true);
      expect(fake.log.some((entry) => entry.command === 'git' && entry.args.join(' ') === `diff-tree --no-commit-id --name-only -r ${SHA}`)).toBe(true);
      expect(fake.log.some((entry) => entry.command === 'git' && entry.args[0] === 'tag')).toBe(false);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test('stops before commit and push when verification fails', async () => {
    const root = fixture();
    const fake = fakeRunner({ verifyCode: 1 });
    try {
      await expect(pushRelease({ root }, { run: fake.run })).rejects.toThrow('bun run verify failed');
      expect(fake.log.some((entry) => entry.args[0] === 'commit' || entry.args[0] === 'push')).toBe(false);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});

describe('release tag stage', () => {
  test('waits for exact successful Linux and macOS CI before pushing an annotated tag', async () => {
    const root = fixture();
    const fake = fakeRunner({ status: '' });
    try {
      await expect(tagRelease({ root }, { run: fake.run })).resolves.toEqual({ version: VERSION, tag: TAG, commit: SHA, workflowRunId: WORKFLOW_ID });
      expect(fake.log.some((entry) => entry.command === 'gh' && entry.args.join(' ') === `run watch ${WORKFLOW_ID} --exit-status`)).toBe(true);
      expect(fake.log.some((entry) => entry.command === 'gh' && entry.args.some((arg) => arg.includes('headBranch')))).toBe(true);
      expect(fake.log.some((entry) => entry.command === 'git' && entry.args.join(' ') === `tag -a ${TAG} -m Release v${VERSION} ${SHA}`)).toBe(true);
      expect(fake.log.some((entry) => entry.command === 'git' && entry.args.join(' ') === `rev-parse ${TAG}^{}`)).toBe(true);
      expect(fake.log.some((entry) => entry.command === 'git' && entry.args.join(' ') === `push --no-follow-tags origin refs/tags/${TAG}`)).toBe(true);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test('refuses missing host jobs, tag conflicts, and remote drift', async () => {
    const root = fixture();
    try {
      const missingMac = fakeRunner({ status: '', workflow: { headSha: SHA, headBranch: 'main', status: 'completed', conclusion: 'success', jobs: [{ name: 'Linux', status: 'completed', conclusion: 'success' }] } });
      await expect(tagRelease({ root }, { run: missingMac.run })).rejects.toThrow('macOS');
      expect(missingMac.log.some((entry) => entry.command === 'git' && entry.args[0] === 'tag')).toBe(false);

      const conflict = fakeRunner({ status: '', remoteTag: true });
      await expect(tagRelease({ root }, { run: conflict.run })).rejects.toThrow('already exists');

      const drift = fakeRunner({ status: '', remoteShaAfterWatch: 'b'.repeat(40) });
      await expect(tagRelease({ root }, { run: drift.run })).rejects.toThrow('origin/main changed');
      expect(drift.log.some((entry) => entry.command === 'git' && entry.args[0] === 'tag')).toBe(false);

      const wrongBranch = fakeRunner({ status: '', workflowRuns: [{ databaseId: WORKFLOW_ID, headSha: SHA, headBranch: 'feature', status: 'completed', conclusion: 'success' }] });
      await expect(tagRelease({ root }, { run: wrongBranch.run })).rejects.toThrow('main');
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
