import { describe, expect, test } from 'bun:test';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  OFFICIAL_REGISTRY,
  REGISTRY_VERIFY_ATTEMPTS,
  REGISTRY_VERIFY_BASE_DELAY_MS,
  REGISTRY_VERIFY_MAX_DELAY_MS,
  RELEASE_PACKAGES,
  classifyRegistryResult,
  createControlledNpmConfigs,
  loadAndVerifyPreparedArtifacts,
  parseStableTag,
  parseStableNpmVersion,
  prepareRelease,
  publishPrepared,
  registryVerifyBackoffMs,
  validateCommonVersions,
  validateGitRelease,
  validateReleaseManifest,
} from './npm-release-lib.mjs';
import { executeCommand, parseArgs, readOtp, usage } from './npm-release.mjs';

const SHA = 'a'.repeat(40);
const VERSION = '1.2.3';
const TAG = `v${VERSION}`;
const DEFAULT_REF = 'refs/remotes/origin/main';
const sourceFiles = [
  'package.json', 'apps/bridge/package.json', 'extensions/pi/package.json',
  'packages/protocol/package.json', 'packages/shared-utils/package.json',
  'extensions/pi/bundle/package.json',
];

type Invocation = { command: string; args: string[]; options?: any };
type RegistryState = 'missing' | 'matching' | 'mismatch' | 'network';

function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'ariava-release-test-'));
  for (const file of sourceFiles) {
    mkdirSync(join(root, file, '..'), { recursive: true });
    const name = file === 'package.json' ? 'ariava' : file === 'extensions/pi/bundle/package.json' || file === 'extensions/pi/package.json'
      ? '@ariava/pi-extension' : `@ariava/${file.split('/')[1]}`;
    writeFileSync(join(root, file), `${JSON.stringify({ name, version: VERSION })}\n`);
  }
  writeFileSync(join(root, 'bun.lock'), JSON.stringify({ workspaces: {
    'apps/bridge': { version: VERSION }, 'extensions/pi': { version: VERSION },
    'packages/protocol': { version: VERSION }, 'packages/shared-utils': { version: VERSION },
  } }));
  return root;
}

function digest(bytes: Buffer) {
  return {
    sha256: createHash('sha256').update(bytes).digest('hex'),
    sha1: createHash('sha1').update(bytes).digest('hex'),
    integrity: `sha512-${createHash('sha512').update(bytes).digest('base64')}`,
    size: bytes.length,
  };
}

function prepared(root: string) {
  const directory = join(root, 'prepared');
  mkdirSync(directory);
  const packageFiles = [
    { name: 'ariava', filename: 'ariava-1.2.3.tgz', bytes: Buffer.from('root artifact') },
    { name: '@ariava/pi-extension', filename: 'ariava-pi-extension-1.2.3.tgz', bytes: Buffer.from('pi artifact') },
  ];
  for (const item of packageFiles) writeFileSync(join(directory, item.filename), item.bytes);
  const manifest = {
    schemaVersion: 1, version: VERSION, gitTag: TAG, gitCommit: SHA,
    packages: packageFiles.map((item) => ({ name: item.name, version: VERSION, filename: item.filename, ...digest(item.bytes) })),
  };
  writeFileSync(join(directory, 'release-manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`);
  return { directory, manifest };
}

function fakeRun(options: { states?: RegistryState[]; log?: Invocation[]; pack?: boolean } = {}) {
  const log = options.log ?? [];
  const states = [...(options.states ?? ['missing', 'missing'])];
  const digests = [digest(Buffer.from('root artifact')), digest(Buffer.from('pi artifact'))];
  const run = async (command: string, args: string[], invocationOptions: any = {}) => {
    log.push({ command, args: [...args], options: invocationOptions });
    if (command === 'git' && args[0] === 'ls-remote') return { code: 0, stdout: 'ref: refs/heads/main\tHEAD\n', stderr: '' };
    if (command === 'git' && args[0] === 'rev-parse') return { code: 0, stdout: `${SHA}\n`, stderr: '' };
    if (command === 'git' && args[0] === 'show') return { code: 0, stdout: '1784678400\n', stderr: '' };
    if (command === 'git') return { code: 0, stdout: '', stderr: '' };
    if (command === 'node' || command === 'bun') return { code: 0, stdout: command === 'node' && args[0] === '--version' ? 'v22.0.0\n' : 'ok\n', stderr: '' };
    if (command.includes('/bin/ariava')) {
      if (args[0] === 'status') return { code: 0, stdout: '{"ok":true}', stderr: '' };
      if (args[0] === 'doctor') return { code: 1, stdout: '{"ok":false}', stderr: '' };
      return { code: 0, stdout: 'help', stderr: '' };
    }
    if (command !== 'npm') return { code: 0, stdout: '', stderr: '' };
    if (args[0] === '--version') return { code: 0, stdout: '11.5.1\n', stderr: '' };
    if (args.slice(0, 3).join(' ') === 'config get registry') return { code: 0, stdout: `${OFFICIAL_REGISTRY}\n`, stderr: '' };
    if (args[0] === 'whoami') return { code: 0, stdout: 'maintainer\n', stderr: '' };
    if (args[0] === 'pack') {
      const output = args[args.indexOf('--pack-destination') + 1];
      const pi = invocationOptions.cwd.endsWith('/extensions/pi/bundle');
      const filename = pi ? 'ariava-pi-extension-1.2.3.tgz' : 'ariava-1.2.3.tgz';
      writeFileSync(join(output, filename), pi ? 'prepared pi' : 'prepared root');
      return { code: 0, stdout: JSON.stringify([{ name: pi ? '@ariava/pi-extension' : 'ariava', version: VERSION, filename }]), stderr: '' };
    }
    if (args[0] === 'install') return { code: 0, stdout: '', stderr: '' };
    if (args[0] === 'publish') {
      const index = args[1].includes('pi-extension') ? 1 : 0;
      states[index] = 'matching';
      return { code: 0, stdout: 'published', stderr: '' };
    }
    if (args[0] === 'view' && args[2] === 'dist-tags') {
      const index = args[1] === 'ariava' ? 0 : 1;
      return { code: 0, stdout: JSON.stringify({ latest: states[index] === 'matching' ? VERSION : '0.0.1' }), stderr: '' };
    }
    if (args[0] === 'view') {
      const index = args[1].startsWith('ariava@') ? 0 : 1;
      const state = states[index];
      if (state === 'missing') return { code: 1, stdout: '', stderr: `npm error code E404\nnpm error 404 Not Found - GET ${OFFICIAL_REGISTRY}${index ? '@ariava%2fpi-extension' : 'ariava'}` };
      if (state === 'network') return { code: 1, stdout: '', stderr: 'npm error code ETIMEDOUT' };
      const name = RELEASE_PACKAGES[index];
      return { code: 0, stdout: JSON.stringify({ name, version: VERSION, dist: {
        shasum: state === 'mismatch' ? 'f'.repeat(40) : digests[index].sha1,
        integrity: state === 'mismatch' ? `sha512-${Buffer.alloc(64).toString('base64')}` : digests[index].integrity,
      } }), stderr: '' };
    }
    return { code: 0, stdout: '', stderr: '' };
  };
  return { run, log, states };
}

function trustedEnv() {
  return {
    GITHUB_ACTIONS: 'true', ACTIONS_ID_TOKEN_REQUEST_URL: 'https://oidc.invalid', ACTIONS_ID_TOKEN_REQUEST_TOKEN: 'redacted',
    GITHUB_REPOSITORY: 'noyyyy/ariava', GITHUB_REF_NAME: TAG, GITHUB_SHA: SHA,
    GITHUB_WORKFLOW_REF: `noyyyy/ariava/.github/workflows/publish-npm.yml@refs/tags/${TAG}`,
  };
}

function publishOptions(root: string, directory: string, mode: 'trusted' | 'manual' = 'trusted') {
  return { root, directory, mode, tag: TAG, defaultBranchRef: DEFAULT_REF, env: trustedEnv(), verifyAttempts: 2, retryDelayMs: 0 };
}

const deps = (run: any, log: Invocation[], sleeps: number[] = []) => ({
  run,
  sleep: async (ms: number) => { sleeps.push(ms); },
  makeTempDir: (prefix: string) => mkdtempSync(join(tmpdir(), prefix)),
  inspectTarball: async (path: string) => ({ name: path.includes('pi-extension') ? '@ariava/pi-extension' : 'ariava', version: VERSION }),
});

describe('registry verify backoff', () => {
  test('uses exponential delays capped at the max, and zero base stays instantaneous', () => {
    expect(registryVerifyBackoffMs(1)).toBe(REGISTRY_VERIFY_BASE_DELAY_MS);
    expect(registryVerifyBackoffMs(2)).toBe(REGISTRY_VERIFY_BASE_DELAY_MS * 2);
    expect(registryVerifyBackoffMs(3)).toBe(REGISTRY_VERIFY_BASE_DELAY_MS * 4);
    expect(registryVerifyBackoffMs(5)).toBe(REGISTRY_VERIFY_BASE_DELAY_MS * 16);
    expect(registryVerifyBackoffMs(6)).toBe(REGISTRY_VERIFY_MAX_DELAY_MS);
    expect(registryVerifyBackoffMs(10)).toBe(REGISTRY_VERIFY_MAX_DELAY_MS);
    expect(registryVerifyBackoffMs(1, { baseDelayMs: 0 })).toBe(0);
    expect(registryVerifyBackoffMs(5, { baseDelayMs: 500, maxDelayMs: 2_000 })).toBe(2_000);
    expect(REGISTRY_VERIFY_ATTEMPTS).toBe(10);
  });

  test('rejects invalid attempt or delay configuration', () => {
    expect(() => registryVerifyBackoffMs(0)).toThrow('positive integer');
    expect(() => registryVerifyBackoffMs(1.5)).toThrow('positive integer');
    expect(() => registryVerifyBackoffMs(1, { baseDelayMs: -1 })).toThrow('baseDelayMs');
    expect(() => registryVerifyBackoffMs(1, { maxDelayMs: Number.NaN })).toThrow('maxDelayMs');
  });
});

describe('release contract', () => {
  test('accepts only canonical stable vX.Y.Z tags', () => {
    expect(parseStableTag('v0.0.0')).toBe('0.0.0');
    expect(parseStableTag('v10.20.30')).toBe('10.20.30');
    for (const value of ['1.2.3', 'v01.2.3', 'v1.02.3', 'v1.2', 'v1.2.3-beta.1', 'release-v1.2.3']) {
      expect(() => parseStableTag(value), value).toThrow();
    }
  });

  test('accepts only stable npm X.Y.Z output', () => {
    expect(parseStableNpmVersion('11.5.1')).toEqual([11, 5, 1]);
    for (const value of ['', 'npm 11.5.1', '11.5', '11.5.1-beta.1', 'v11.5.1', 'NaN.5.1']) {
      expect(() => parseStableNpmVersion(value), value).toThrow();
    }
  });

  test('validates peeled annotated-tag commit, HEAD, and explicit default-branch ancestry using argument arrays', async () => {
    const { run, log } = fakeRun();
    await expect(validateGitRelease({ run, tag: TAG, defaultBranchRef: DEFAULT_REF })).resolves.toEqual({ version: VERSION, gitTag: TAG, gitCommit: SHA });
    expect(log.filter((item) => item.command === 'git').map((item) => item.args)).toEqual([
      ['rev-parse', `${TAG}^{}`], ['rev-parse', 'HEAD'], ['show-ref', '--verify', DEFAULT_REF], ['merge-base', '--is-ancestor', SHA, DEFAULT_REF],
    ]);
  });

  test('manual validation rejects a tag as default branch before fetch, registry access, or writes', async () => {
    const { run, log } = fakeRun();
    await expect(validateGitRelease({ run, tag: TAG, defaultBranchRef: `refs/tags/${TAG}`, verifyOriginDefault: true })).rejects.toThrow('remote-tracking origin ref');
    expect(log).toHaveLength(0);
  });

  test('manual validation derives and freshly fetches origins advertised default branch', async () => {
    const { run, log } = fakeRun();
    await expect(validateGitRelease({ run, tag: TAG, verifyOriginDefault: true })).resolves.toEqual({ version: VERSION, gitTag: TAG, gitCommit: SHA });
    expect(log.filter((item) => item.command === 'git').map((item) => item.args).slice(0, 2)).toEqual([
      ['ls-remote', '--symref', 'origin', 'HEAD'],
      ['fetch', '--no-tags', 'origin', '+refs/heads/main:refs/remotes/origin/main'],
    ]);
  });

  test('common versions exactly cover bump-script manifests and Public Core lock workspaces', () => {
    const root = fixture();
    try {
      expect(validateCommonVersions(root, VERSION, { includeGenerated: true })).toBe(VERSION);
      const pi = JSON.parse(readFileSync(join(root, 'extensions/pi/package.json'), 'utf8'));
      pi.version = '1.2.4'; writeFileSync(join(root, 'extensions/pi/package.json'), JSON.stringify(pi));
      expect(() => validateCommonVersions(root, VERSION, { includeGenerated: true })).toThrow('version mismatch');
    } finally { rmSync(root, { recursive: true, force: true }); }
  });

  test('registry classification recognizes npm E404 as missing and fails closed otherwise', () => {
    const artifact = { name: 'ariava', version: VERSION, sha1: 'a'.repeat(40), integrity: `sha512-${Buffer.alloc(64).toString('base64')}` };
    for (const result of [
      { code: 1, stdout: '', stderr: 'npm error code E404\nnpm error 404 No match found for version 1.2.3' },
      { code: 1, stdout: JSON.stringify({ error: { code: 'E404', summary: 'No match found for version 1.2.3' } }), stderr: 'npm error code E404' },
      { code: 1, stdout: '', stderr: `E404 404 Not Found ${OFFICIAL_REGISTRY}ariava` },
    ]) expect(classifyRegistryResult(result, artifact).state).toBe('missing');
    for (const result of [
      { code: 1, stdout: '', stderr: 'ETIMEDOUT' }, { code: 1, stdout: '', stderr: 'E401 auth' },
      { code: 1, stdout: '', stderr: 'E429 rate limit' }, { code: 0, stdout: 'not json', stderr: '' },
    ]) expect(classifyRegistryResult(result, artifact).state).toBe('present-but-invalid');
    expect(classifyRegistryResult({ code: 0, stdout: JSON.stringify({ name: 'ariava', version: VERSION, dist: { shasum: artifact.sha1, integrity: artifact.integrity } }), stderr: '' }, artifact).state).toBe('present-and-matching');
    expect(classifyRegistryResult({ code: 0, stdout: JSON.stringify({ name: 'ariava', version: VERSION, dist: { shasum: 'b'.repeat(40), integrity: artifact.integrity } }), stderr: '' }, artifact).state).toBe('present-but-invalid');
    expect(classifyRegistryResult({ code: 0, stdout: JSON.stringify({ name: 'ariava', version: VERSION, dist: { shasum: artifact.sha1, integrity: `sha512-${Buffer.alloc(64, 1).toString('base64')}` } }), stderr: '' }, artifact).state).toBe('present-but-invalid');
  });

  test('manifest rejects malformed schema, traversal, duplicates, package-order drift, and bad digests', () => {
    const root = fixture();
    try {
      const { manifest } = prepared(root);
      expect(validateReleaseManifest(manifest)).toBe(manifest);
      for (const mutate of [
        (copy: any) => { copy.schemaVersion = 2; },
        (copy: any) => { copy.packages[0].filename = '../escape.tgz'; },
        (copy: any) => { copy.packages[1].filename = copy.packages[0].filename; },
        (copy: any) => { copy.packages.reverse(); },
        (copy: any) => { copy.packages[0].sha256 = 'bad'; },
      ]) {
        const copy = structuredClone(manifest); mutate(copy); expect(() => validateReleaseManifest(copy)).toThrow();
      }
    } finally { rmSync(root, { recursive: true, force: true }); }
  });

  test('prepared artifact verification rejects SHA and size mismatch and unexpected files', () => {
    const root = fixture();
    try {
      const { directory } = prepared(root);
      expect(loadAndVerifyPreparedArtifacts(directory, { listFiles: readdirSync })).toBeTruthy();
      writeFileSync(join(directory, 'ariava-1.2.3.tgz'), 'tampered');
      expect(() => loadAndVerifyPreparedArtifacts(directory, { listFiles: readdirSync })).toThrow('mismatch');
    } finally { rmSync(root, { recursive: true, force: true }); }
  });

  test('prepared artifact verification rejects symlinks and realpath escapes', () => {
    const root = fixture();
    try {
      const { directory } = prepared(root);
      const artifact = join(directory, 'ariava-1.2.3.tgz');
      const outside = join(root, 'outside.tgz');
      writeFileSync(outside, 'root artifact');
      rmSync(artifact);
      symlinkSync(outside, artifact);
      expect(() => loadAndVerifyPreparedArtifacts(directory, { listFiles: readdirSync })).toThrow(/realpath escapes|regular file/);
    } finally { rmSync(root, { recursive: true, force: true }); }
  });
});

describe('preparation orchestrator', () => {
  test('runs frozen install/full verify, both exact pack assertions, isolated smoke, and emits only tarballs plus manifest without auth/write', async () => {
    const root = fixture(); const outputDir = join(root, 'output'); const { run, log } = fakeRun({ pack: true });
    try {
      const manifest = await prepareRelease({ root, outputDir, tag: TAG, defaultBranchRef: DEFAULT_REF, env: {} }, {
        run, makeTempDir: (prefix: string) => mkdtempSync(join(tmpdir(), prefix)),
      });
      expect(log.some((entry) => entry.command === 'bun' && entry.args.join(' ') === 'install --frozen-lockfile')).toBe(true);
      expect(log.some((entry) => entry.command === 'bun' && entry.args.join(' ') === 'run verify')).toBe(true);
      expect(log.filter((entry) => entry.command === 'npm' && entry.args[0] === 'pack')).toHaveLength(2);
      expect(log.filter((entry) => entry.command === 'node' && entry.args.includes('--kind')).map((entry) => entry.args[entry.args.indexOf('--kind') + 1])).toEqual(['root', 'pi']);
      const smoke = log.find((entry) => entry.command.includes('/bin/ariava'));
      expect(smoke?.command).toContain('/prefix/bin/ariava');
      expect(log.some((entry) => entry.args.includes('publish') || entry.args.includes('whoami'))).toBe(false);
      expect(readdirSync(outputDir).sort()).toEqual(['ariava-1.2.3.tgz', 'ariava-pi-extension-1.2.3.tgz', 'release-manifest.json']);
      for (const artifact of manifest.packages) expect({ ...digest(readFileSync(join(outputDir, artifact.filename))) }).toEqual({ sha256: artifact.sha256, sha1: artifact.sha1, integrity: artifact.integrity, size: artifact.size });
      const smokeEntries = log.filter((entry) => entry.options?.replaceEnv);
      expect(smokeEntries.length).toBeGreaterThan(0);
      expect(smokeEntries.every((entry) => entry.options.env.NPM_CONFIG_USERCONFIG !== entry.options.env.NPM_CONFIG_GLOBALCONFIG)).toBe(true);
      expect(smokeEntries.every((entry) => entry.options.env.NPM_CONFIG_USERCONFIG.endsWith('/user.npmrc') && entry.options.env.NPM_CONFIG_GLOBALCONFIG.endsWith('/global.npmrc'))).toBe(true);
      expect(smokeEntries.every((entry) => !('NODE_AUTH_TOKEN' in entry.options.env) && !('GITHUB_TOKEN' in entry.options.env))).toBe(true);
    } finally { rmSync(root, { recursive: true, force: true }); }
  });

  test('rejects npm below the reviewed Trusted Publishing minimum before install or packing', async () => {
    const root = fixture(); const outputDir = join(root, 'output'); const fake = fakeRun({ pack: true });
    const run = async (command: string, args: string[], options: any) => {
      if (command === 'npm' && args[0] === '--version') { fake.log.push({ command, args, options }); return { code: 0, stdout: '11.5.0\n', stderr: '' }; }
      return fake.run(command, args, options);
    };
    try {
      await expect(prepareRelease({ root, outputDir, tag: TAG, defaultBranchRef: DEFAULT_REF }, { run, makeTempDir: () => '' })).rejects.toThrow('11.5.1+');
      expect(fake.log.some((entry) => entry.command === 'bun' && entry.args[0] === 'install')).toBe(false);
      expect(fake.log.some((entry) => entry.command === 'npm' && entry.args[0] === 'pack')).toBe(false);
    } finally { rmSync(root, { recursive: true, force: true }); }
  });

  test('refuses stale nonempty output', async () => {
    const root = fixture(); const outputDir = join(root, 'output'); mkdirSync(outputDir); writeFileSync(join(outputDir, 'stale.tgz'), 'x');
    const { run, log } = fakeRun();
    try { await expect(prepareRelease({ root, outputDir, tag: TAG, defaultBranchRef: DEFAULT_REF }, { run, makeTempDir: () => '' })).rejects.toThrow('must be empty'); expect(log).toHaveLength(0); }
    finally { rmSync(root, { recursive: true, force: true }); }
  });

  test('real npm loads distinct controlled user and global config files', async () => {
    const root = mkdtempSync(join(tmpdir(), 'ariava-npm-config-test-'));
    try {
      const configs = createControlledNpmConfigs(root);
      expect(configs.userConfig).not.toBe(configs.globalConfig);
      const result = await executeCommand('npm', ['config', 'get', 'registry'], {
        env: { PATH: process.env.PATH ?? '', NPM_CONFIG_USERCONFIG: configs.userConfig, NPM_CONFIG_GLOBALCONFIG: configs.globalConfig },
        replaceEnv: true,
      });
      expect(result.code).toBe(0);
      expect(result.stderr).not.toContain('double-loading config');
      expect(result.stdout.trim()).toBe(OFFICIAL_REGISTRY);
    } finally { rmSync(root, { recursive: true, force: true }); }
  });
});

describe('prepared publication and partial-success recovery', () => {
  test.each([
    ['both missing', ['missing', 'missing'], ['ariava-1.2.3.tgz', 'ariava-pi-extension-1.2.3.tgz']],
    ['both matching', ['matching', 'matching'], []],
    ['root matching', ['matching', 'missing'], ['ariava-pi-extension-1.2.3.tgz']],
    ['pi matching', ['missing', 'matching'], ['ariava-1.2.3.tgz']],
  ] as const)('%s publishes only missing exact tarballs in stable order', async (_name, states, expectedWrites) => {
    const root = fixture(); const { directory } = prepared(root); const fake = fakeRun({ states: [...states] });
    try {
      const summary = await publishPrepared(publishOptions(root, directory), deps(fake.run, fake.log));
      const writes = fake.log.filter((entry) => entry.command === 'npm' && entry.args[0] === 'publish');
      expect(writes.map((entry) => entry.args[1].split('/').at(-1))).toEqual(expectedWrites);
      for (const write of writes) {
        expect(write.args).toContain('--access'); expect(write.args).toContain('public');
        expect(write.args).toContain('--provenance'); expect(write.args).not.toContain('--otp');
      }
      expect(fake.log.some((entry) => entry.args[0] === 'whoami')).toBe(false);
      expect(summary.packages.every((item: any) => item.final === 'present-and-matching' && item.latest === VERSION)).toBe(true);
    } finally { rmSync(root, { recursive: true, force: true }); }
  });

  test('manual OTP path authenticates and passes OTP through npm environment, never argv', async () => {
    const root = fixture(); const { directory } = prepared(root); const fake = fakeRun({ states: ['missing', 'missing'] });
    try {
      await publishPrepared({ ...publishOptions(root, directory, 'manual'), otp: '123456', env: {} }, deps(fake.run, fake.log));
      expect(fake.log.some((entry) => entry.command === 'npm' && entry.args[0] === 'whoami')).toBe(true);
      const writes = fake.log.filter((entry) => entry.args[0] === 'publish');
      expect(writes).toHaveLength(2);
      expect(writes.every((entry) => !entry.args.includes('--otp') && !entry.args.includes('123456') && entry.options.env.NPM_CONFIG_OTP === '123456')).toBe(true);
    } finally { rmSync(root, { recursive: true, force: true }); }
  });

  test.each(['mismatch', 'network'] as const)('fails closed on %s before any publish write', async (state) => {
    const root = fixture(); const { directory } = prepared(root); const fake = fakeRun({ states: [state, 'missing'] });
    try {
      await expect(publishPrepared(publishOptions(root, directory), deps(fake.run, fake.log))).rejects.toThrow();
      expect(fake.log.filter((entry) => entry.command === 'npm' && entry.args[0] === 'publish')).toHaveLength(0);
    } finally { rmSync(root, { recursive: true, force: true }); }
  });

  test('artifact mismatch fails before registry reads or writes', async () => {
    const root = fixture(); const { directory } = prepared(root); writeFileSync(join(directory, 'ariava-1.2.3.tgz'), 'tampered'); const fake = fakeRun();
    try {
      await expect(publishPrepared(publishOptions(root, directory), deps(fake.run, fake.log))).rejects.toThrow('mismatch');
      expect(fake.log.some((entry) => entry.command === 'npm' && ['view', 'publish'].includes(entry.args[0]))).toBe(false);
    } finally { rmSync(root, { recursive: true, force: true }); }
  });

  test('revalidates each exact artifact immediately before publishing it', async () => {
    const root = fixture(); const { directory } = prepared(root); const fake = fakeRun({ states: ['missing', 'missing'] });
    let queries = 0;
    const run = async (command: string, args: string[], options: any) => {
      const result = await fake.run(command, args, options);
      if (command === 'npm' && args[0] === 'view' && !args.includes('dist-tags')) {
        queries += 1;
        if (queries === 4) writeFileSync(join(directory, 'ariava-pi-extension-1.2.3.tgz'), 'tampered after preflight');
      }
      return result;
    };
    try {
      await expect(publishPrepared(publishOptions(root, directory), deps(run, fake.log))).rejects.toThrow('mismatch');
      expect(fake.log.filter((entry) => entry.command === 'npm' && entry.args[0] === 'publish')).toHaveLength(1);
    } finally { rmSync(root, { recursive: true, force: true }); }
  });

  test('Trusted Publishing rejects credentials, npm config overrides, and inexact workflow refs before npm runs', async () => {
    expect(() => parseArgs(['--publish-prepared', '/tmp/x', '--trusted-publishing', '--otp', '1', '--tag', TAG, '--default-branch-ref', DEFAULT_REF], {} as any)).toThrow('forbidden');
    const rejected = [
      ['NODE_AUTH_TOKEN', 'secret'], ['NPM_TOKEN', 'secret'], ['NPM_CONFIG_USERCONFIG', '/tmp/user-npmrc'],
      ['NPM_CONFIG_GLOBALCONFIG', '/tmp/global-npmrc'], ['NPM_CONFIG__AUTH', 'secret'], ['NPM_CONFIG_OTP', '123456'],
    ];
    for (const [name, value] of rejected) {
      const root = fixture(); const { directory } = prepared(root); const fake = fakeRun();
      try {
        await expect(publishPrepared({ ...publishOptions(root, directory), env: { ...trustedEnv(), [name]: value } }, deps(fake.run, fake.log))).rejects.toThrow(name);
        expect(fake.log.some((entry) => entry.command === 'npm')).toBe(false);
      } finally { rmSync(root, { recursive: true, force: true }); }
    }
    const root = fixture(); const { directory } = prepared(root); const fake = fakeRun();
    try {
      await expect(publishPrepared({ ...publishOptions(root, directory), env: { ...trustedEnv(), GITHUB_WORKFLOW_REF: `evil/noyyyy/ariava/.github/workflows/publish-npm.yml@refs/tags/${TAG}` } }, deps(fake.run, fake.log))).rejects.toThrow('workflow');
      expect(fake.log.some((entry) => entry.command === 'npm')).toBe(false);
    } finally { rmSync(root, { recursive: true, force: true }); }
  });

  test('Trusted Publishing forces controlled empty npm user and global configs', async () => {
    const root = fixture(); const { directory } = prepared(root); const fake = fakeRun({ states: ['matching', 'matching'] });
    try {
      await publishPrepared(publishOptions(root, directory), deps(fake.run, fake.log));
      const npmCalls = fake.log.filter((entry) => entry.command === 'npm');
      expect(npmCalls.length).toBeGreaterThan(0);
      expect(npmCalls.every((entry) => entry.options.env.NPM_CONFIG_USERCONFIG !== entry.options.env.NPM_CONFIG_GLOBALCONFIG)).toBe(true);
      const configRoot = npmCalls[0].options.env.NPM_CONFIG_USERCONFIG.split('/npm-config/')[0];
      expect(npmCalls.every((entry) => entry.options.env.NPM_CONFIG_USERCONFIG.endsWith('/user.npmrc') && entry.options.env.NPM_CONFIG_GLOBALCONFIG.endsWith('/global.npmrc'))).toBe(true);
      expect(existsSync(configRoot)).toBe(false);
    } finally { rmSync(root, { recursive: true, force: true }); }
  });

  test('failed manual publish redacts OTP from command and npm error detail', async () => {
    const root = fixture(); const { directory } = prepared(root); const fake = fakeRun({ states: ['missing', 'missing'] });
    const otp = '654321';
    const run = async (command: string, args: string[], options: any) => {
      if (command === 'npm' && args[0] === 'publish') return { code: 1, stdout: '', stderr: `publish failed for otp ${otp}` };
      return fake.run(command, args, options);
    };
    try {
      let message = '';
      try { await publishPrepared({ ...publishOptions(root, directory, 'manual'), otp, env: {} }, deps(run, fake.log)); }
      catch (error) { message = String((error as Error).message); }
      expect(message).toContain('[REDACTED]');
      expect(message).not.toContain(otp);
    } finally { rmSync(root, { recursive: true, force: true }); }
  });

  test('malformed or prerelease npm versions fail closed before registry reads or writes', async () => {
    for (const version of ['garbage', '11.5.1-beta.1']) {
      const root = fixture(); const { directory } = prepared(root); const fake = fakeRun();
      const run = async (command: string, args: string[], options: any) => command === 'npm' && args[0] === '--version'
        ? { code: 0, stdout: `${version}\n`, stderr: '' } : fake.run(command, args, options);
      try {
        await expect(publishPrepared(publishOptions(root, directory), deps(run, fake.log))).rejects.toThrow('stable X.Y.Z');
        expect(fake.log.some((entry) => entry.command === 'npm' && ['view', 'publish'].includes(entry.args[0]))).toBe(false);
      } finally { rmSync(root, { recursive: true, force: true }); }
    }
  });

  test('bounded final visibility/dist-tag failures fail the run', async () => {
    const root = fixture(); const { directory } = prepared(root); const fake = fakeRun({ states: ['matching', 'matching'] });
    const run = async (command: string, args: string[], options: any) => {
      if (command === 'npm' && args[0] === 'view' && args[2] === 'dist-tags') return { code: 0, stdout: JSON.stringify({ latest: '0.0.1' }), stderr: '' };
      return fake.run(command, args, options);
    };
    try { await expect(publishPrepared(publishOptions(root, directory), deps(run, fake.log))).rejects.toThrow('after 2 attempts'); }
    finally { rmSync(root, { recursive: true, force: true }); }
  });

  test('final registry verification uses exponential backoff between attempts', async () => {
    const root = fixture(); const { directory } = prepared(root); const fake = fakeRun({ states: ['matching', 'matching'] });
    const sleeps: number[] = [];
    let packageViews = 0;
    const run = async (command: string, args: string[], options: any) => {
      if (command === 'npm' && args[0] === 'view' && args[2] !== 'dist-tags') {
        packageViews += 1;
        // Initial preflight = 2 matching views. Fail the next two full final rounds (4 views),
        // then allow the third final attempt to succeed.
        if (packageViews > 2 && packageViews <= 6) {
          return { code: 1, stdout: '', stderr: 'npm error code E404\nnpm error 404 Not Found' };
        }
      }
      return fake.run(command, args, options);
    };
    try {
      const summary = await publishPrepared(
        { ...publishOptions(root, directory), verifyAttempts: 4, retryDelayMs: 100, retryMaxDelayMs: 1_000 },
        deps(run, fake.log, sleeps),
      );
      expect(summary.packages.every((item: any) => item.final === 'present-and-matching')).toBe(true);
      // Sleeps after failed final attempts 1 and 2: 100, 200 (not after the successful 3rd).
      expect(sleeps).toEqual([100, 200]);
    } finally { rmSync(root, { recursive: true, force: true }); }
  });

  test('OTP stdin/FD input is validated and argv alias remains deprecated compatibility only', () => {
    const root = mkdtempSync(join(tmpdir(), 'ariava-otp-test-'));
    try {
      const input = join(root, 'otp'); writeFileSync(input, '123456\n');
      expect(readOtp(input as any)).toBe('123456');
      writeFileSync(input, 'not-an-otp');
      expect(() => readOtp(input as any)).toThrow('exactly 6 digits');
      expect(parseArgs(['--publish-prepared', '/tmp/x', '--manual', '--otp-stdin', '--tag', TAG], {} as any).otpFd).toBe(0);
      expect(parseArgs(['--publish-prepared', '/tmp/x', '--manual', '--otp-fd', '9', '--tag', TAG], {} as any).otpFd).toBe(9);
      expect(parseArgs(['--publish-prepared', '/tmp/x', '--manual', '--otp', '123456', '--tag', TAG], {} as any).deprecatedOtpArg).toBe(true);
    } finally { rmSync(root, { recursive: true, force: true }); }
  });

  test('help documents safe OTP input, default-branch validation, exact artifacts, and partial success', () => {
    const text = usage();
    for (const term of ['--prepare', '--publish-prepared', '--summary-file', 'Trusted Publishing', 'OTP break-glass', '--otp-stdin', '--otp-fd', 'Deprecated', "origin's actual", 'exact-artifact', 'partial-success', 'no registry writes']) expect(text).toContain(term);
  });
});
