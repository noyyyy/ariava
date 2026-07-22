#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, realpathSync, renameSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { basename, join, resolve, sep } from 'node:path';

export const OFFICIAL_REGISTRY = 'https://registry.npmjs.org/';
export const RELEASE_SCHEMA_VERSION = 1;
export const TRUSTED_NPM_MINIMUM = '11.5.1';
export const RELEASE_PACKAGES = Object.freeze(['ariava', '@ariava/pi-extension']);
export const SOURCE_VERSION_FILES = Object.freeze([
  'package.json',
  'apps/bridge/package.json',
  'extensions/pi/package.json',
  'packages/protocol/package.json',
  'packages/shared-utils/package.json',
]);
export const GENERATED_VERSION_FILE = 'extensions/pi/bundle/package.json';
export const LOCK_WORKSPACES = Object.freeze([
  'apps/bridge',
  'extensions/pi',
  'packages/protocol',
  'packages/shared-utils',
]);

const STABLE_TAG = /^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/u;
const SHA40 = /^[0-9a-f]{40}$/u;
const HEX40 = /^[0-9a-f]{40}$/u;
const HEX64 = /^[0-9a-f]{64}$/u;
const SHA512_INTEGRITY = /^sha512-[A-Za-z0-9+/]{86}==$/u;
const STABLE_NPM_VERSION = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/u;
const SENSITIVE_FLAG = /^--[^=]*(?:otp|token|auth|password|passwd|secret|private-?key)(?:=|$)/iu;
const SENSITIVE_ENV_NAME = /(?:TOKEN|AUTH|PASSWORD|PASSWD|OTP|SECRET|PRIVATE_KEY)/iu;
const TRUSTED_NPM_CONFIG_ALLOWLIST = new Set(['NPM_CONFIG_USER_AGENT']);
const ORIGIN_TRACKING_PREFIX = 'refs/remotes/origin/';

export function parseStableTag(tag) {
  const match = STABLE_TAG.exec(tag ?? '');
  if (!match) throw new Error(`release tag must match ${STABLE_TAG}: ${tag ?? '(missing)'}`);
  return match.slice(1).join('.');
}

export function parseOriginDefaultBranchRef(ref) {
  if (typeof ref !== 'string' || !ref.startsWith(ORIGIN_TRACKING_PREFIX)) {
    throw new Error(`default branch ref must be a remote-tracking origin ref (${ORIGIN_TRACKING_PREFIX}<branch>)`);
  }
  const branch = ref.slice(ORIGIN_TRACKING_PREFIX.length);
  const invalid = branch.length === 0
    || branch.startsWith('.') || branch.endsWith('.') || branch.endsWith('/') || branch.endsWith('.lock')
    || branch.includes('..') || branch.includes('//') || branch.includes('@{')
    || /[\u0000-\u0020~^:?*[\\\u007f]/u.test(branch);
  if (invalid) throw new Error(`invalid origin default-branch ref: ${ref}`);
  return branch;
}

function parseRemoteDefaultBranch(output) {
  const symbolic = String(output).split(/\r?\n/u).find((line) => line.startsWith('ref: '));
  const match = /^ref: (refs\/heads\/(.+))\tHEAD$/u.exec(symbolic ?? '');
  if (!match) throw new Error('origin did not advertise a symbolic default branch');
  const branch = match[2];
  parseOriginDefaultBranchRef(`${ORIGIN_TRACKING_PREFIX}${branch}`);
  return { branch, headRef: match[1], trackingRef: `${ORIGIN_TRACKING_PREFIX}${branch}` };
}

export function parseStableNpmVersion(value) {
  const match = STABLE_NPM_VERSION.exec(String(value).trim());
  if (!match) throw new Error(`npm version output must be a stable X.Y.Z version, got: ${String(value).trim() || '(empty)'}`);
  return match.slice(1).map(Number);
}

export function compareVersions(left, right) {
  const a = parseStableNpmVersion(left);
  const b = parseStableNpmVersion(right);
  for (let index = 0; index < 3; index += 1) {
    const difference = a[index] - b[index];
    if (difference !== 0) return Math.sign(difference);
  }
  return 0;
}

export function sensitiveValues(args = [], env = {}) {
  const values = [];
  for (let index = 0; index < args.length; index += 1) {
    const argument = String(args[index]);
    if (!SENSITIVE_FLAG.test(argument)) continue;
    const equals = argument.indexOf('=');
    const value = equals >= 0 ? argument.slice(equals + 1) : args[index + 1];
    if (typeof value === 'string' && value.length > 0) values.push(value);
  }
  for (const [name, value] of Object.entries(env)) {
    if (SENSITIVE_ENV_NAME.test(name) && typeof value === 'string' && value.length > 0) values.push(value);
  }
  return [...new Set(values)].sort((left, right) => right.length - left.length);
}

export function redactSensitiveText(value, args = [], env = {}) {
  let redacted = String(value ?? '');
  for (const secret of sensitiveValues(args, env)) redacted = redacted.split(secret).join('[REDACTED]');
  return redacted;
}

function formatCommandArgs(args) {
  const output = [];
  for (let index = 0; index < args.length; index += 1) {
    const argument = String(args[index]);
    if (!SENSITIVE_FLAG.test(argument)) { output.push(argument); continue; }
    const equals = argument.indexOf('=');
    if (equals >= 0) output.push(`${argument.slice(0, equals)}=[REDACTED]`);
    else { output.push(argument); if (index + 1 < args.length) { output.push('[REDACTED]'); index += 1; } }
  }
  return output;
}

function stripJsonc(text) {
  let output = '';
  let inString = false;
  let escaped = false;
  let lineComment = false;
  let blockComment = false;
  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];
    const next = text[index + 1];
    if (lineComment) {
      if (char === '\n' || char === '\r') { lineComment = false; output += char; }
      else output += ' ';
      continue;
    }
    if (blockComment) {
      if (char === '*' && next === '/') { output += '  '; blockComment = false; index += 1; }
      else output += char === '\n' || char === '\r' ? char : ' ';
      continue;
    }
    if (inString) {
      output += char;
      if (escaped) escaped = false;
      else if (char === '\\') escaped = true;
      else if (char === '"') inString = false;
      continue;
    }
    if (char === '"') { inString = true; output += char; }
    else if (char === '/' && next === '/') { output += '  '; lineComment = true; index += 1; }
    else if (char === '/' && next === '*') { output += '  '; blockComment = true; index += 1; }
    else output += char;
  }
  return output.replace(/,\s*([}\]])/gu, '$1');
}

function readJson(path, fs = { readFileSync }) {
  return JSON.parse(fs.readFileSync(path, 'utf8'));
}

export function validateCommonVersions(root, expectedVersion, options = {}) {
  const fs = options.fs ?? { readFileSync };
  const includeGenerated = options.includeGenerated ?? false;
  const files = includeGenerated ? [...SOURCE_VERSION_FILES, GENERATED_VERSION_FILE] : [...SOURCE_VERSION_FILES];
  for (const file of files) {
    const version = readJson(join(root, file), fs).version;
    if (version !== expectedVersion) throw new Error(`version mismatch: ${file} is ${version ?? 'missing'}, expected ${expectedVersion}`);
  }
  const lock = JSON.parse(stripJsonc(fs.readFileSync(join(root, 'bun.lock'), 'utf8')));
  for (const workspace of LOCK_WORKSPACES) {
    const version = lock?.workspaces?.[workspace]?.version;
    if (version !== expectedVersion) throw new Error(`version mismatch: bun.lock workspace ${workspace} is ${version ?? 'missing'}, expected ${expectedVersion}`);
  }
  return expectedVersion;
}

async function checked(run, command, args, options = {}) {
  const result = await run(command, args, options);
  if (result.code !== 0) {
    const detail = redactSensitiveText(result.stderr || result.stdout || '', args, options.env).trim();
    throw new Error(`${command} ${formatCommandArgs(args).join(' ')} failed (${result.code}): ${detail}`);
  }
  return result;
}

export async function validateGitRelease({ run, tag, defaultBranchRef, verifyOriginDefault = false }) {
  const version = parseStableTag(tag);
  if (defaultBranchRef) parseOriginDefaultBranchRef(defaultBranchRef);
  if (verifyOriginDefault) {
    const advertised = parseRemoteDefaultBranch((await checked(run, 'git', ['ls-remote', '--symref', 'origin', 'HEAD'])).stdout);
    if (defaultBranchRef && defaultBranchRef !== advertised.trackingRef) {
      throw new Error(`supplied default branch ref ${defaultBranchRef} is not origin's advertised default branch ${advertised.trackingRef}`);
    }
    defaultBranchRef = advertised.trackingRef;
    await checked(run, 'git', ['fetch', '--no-tags', 'origin', `+${advertised.headRef}:${advertised.trackingRef}`]);
  }
  if (!defaultBranchRef) throw new Error('a validated remote-tracking default-branch ref is required');
  const peeled = (await checked(run, 'git', ['rev-parse', `${tag}^{}`])).stdout.trim();
  const head = (await checked(run, 'git', ['rev-parse', 'HEAD'])).stdout.trim();
  if (!SHA40.test(peeled)) throw new Error(`tag did not peel to a 40-character commit SHA: ${peeled}`);
  if (!SHA40.test(head) || head !== peeled) throw new Error(`checked-out HEAD ${head} does not match peeled tag commit ${peeled}`);
  await checked(run, 'git', ['show-ref', '--verify', defaultBranchRef]);
  await checked(run, 'git', ['merge-base', '--is-ancestor', peeled, defaultBranchRef]);
  return { version, gitTag: tag, gitCommit: peeled };
}

export function classifyRegistryResult(result, artifact) {
  if (result.code !== 0) {
    const stdout = result.stdout ?? '';
    const stderr = result.stderr ?? '';
    let structuredCode;
    try {
      structuredCode = JSON.parse(stdout)?.error?.code;
    } catch {
      // npm can emit either structured JSON on stdout or its standard text error on stderr.
    }
    const textualNotFound = /\bE404\b/u.test(`${stdout}\n${stderr}`)
      && /(?:\b404\b|not found|no match found)/iu.test(`${stdout}\n${stderr}`);
    if (structuredCode === 'E404' || textualNotFound) return { state: 'missing' };
    const error = `${stdout}\n${stderr}`;
    return { state: 'present-but-invalid', reason: `registry query failed closed: ${error.trim() || `exit ${result.code}`}` };
  }
  let metadata;
  try {
    metadata = JSON.parse(result.stdout);
  } catch {
    return { state: 'present-but-invalid', reason: 'registry returned malformed JSON' };
  }
  if (metadata?.name !== artifact.name || metadata?.version !== artifact.version) {
    return { state: 'present-but-invalid', reason: 'registry package identity does not match the prepared artifact' };
  }
  if (!HEX40.test(metadata?.dist?.shasum ?? '') || metadata.dist.shasum !== artifact.sha1) {
    return { state: 'present-but-invalid', reason: 'registry dist.shasum does not match the prepared artifact' };
  }
  if (!SHA512_INTEGRITY.test(metadata?.dist?.integrity ?? '') || metadata.dist.integrity !== artifact.integrity) {
    return { state: 'present-but-invalid', reason: 'registry dist.integrity does not match the prepared artifact' };
  }
  return { state: 'present-and-matching', metadata };
}

function assertRegularFileWithin(root, path, fs) {
  const rootRealPath = fs.realpathSync(root);
  const fileRealPath = fs.realpathSync(path);
  if (!fileRealPath.startsWith(`${rootRealPath}${sep}`)) throw new Error(`artifact realpath escapes prepared directory: ${basename(path)}`);
  if (!fs.lstatSync(path).isFile() || !fs.statSync(path).isFile()) throw new Error(`artifact must be a regular file: ${basename(path)}`);
  return fileRealPath;
}

export function digestFile(path, fs = { lstatSync, readFileSync, realpathSync, statSync }, root = undefined) {
  if (root) assertRegularFileWithin(root, path, fs);
  const bytes = fs.readFileSync(path);
  return {
    sha256: createHash('sha256').update(bytes).digest('hex'),
    sha1: createHash('sha1').update(bytes).digest('hex'),
    integrity: `sha512-${createHash('sha512').update(bytes).digest('base64')}`,
    size: fs.statSync(path).size,
  };
}

export function validateReleaseManifest(value, options = {}) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('release manifest must be an object');
  if (value.schemaVersion !== RELEASE_SCHEMA_VERSION) throw new Error(`unsupported release manifest schema: ${value.schemaVersion}`);
  const version = parseStableTag(value.gitTag);
  if (value.version !== version) throw new Error('manifest tag and version do not match');
  if (!SHA40.test(value.gitCommit ?? '')) throw new Error('manifest gitCommit must be a lowercase 40-character SHA');
  if (!Array.isArray(value.packages) || value.packages.length !== RELEASE_PACKAGES.length) {
    throw new Error('manifest must contain exactly the two release packages');
  }
  const seenFiles = new Set();
  for (let index = 0; index < RELEASE_PACKAGES.length; index += 1) {
    const artifact = value.packages[index];
    if (artifact?.name !== RELEASE_PACKAGES[index]) throw new Error(`wrong package order or identity at index ${index}`);
    if (artifact.version !== version) throw new Error(`artifact ${artifact.name} version does not match manifest`);
    if (typeof artifact.filename !== 'string' || artifact.filename.length === 0
      || basename(artifact.filename) !== artifact.filename || artifact.filename.includes('/') || artifact.filename.includes('\\')
      || artifact.filename === '.' || artifact.filename === '..') {
      throw new Error(`unsafe artifact filename: ${artifact?.filename}`);
    }
    if (seenFiles.has(artifact.filename)) throw new Error(`duplicate artifact filename: ${artifact.filename}`);
    seenFiles.add(artifact.filename);
    if (!HEX64.test(artifact.sha256 ?? '') || !HEX40.test(artifact.sha1 ?? '') || !SHA512_INTEGRITY.test(artifact.integrity ?? '')) {
      throw new Error(`invalid artifact digest: ${artifact.filename}`);
    }
    if (!Number.isSafeInteger(artifact.size) || artifact.size <= 0) throw new Error(`invalid artifact size: ${artifact.filename}`);
  }
  if (options.expected) {
    for (const key of ['version', 'gitTag', 'gitCommit']) {
      if (value[key] !== options.expected[key]) throw new Error(`manifest ${key} does not match current release context`);
    }
  }
  return value;
}

function verifyPreparedArtifact(root, artifact, fs) {
  const artifactPath = resolve(root, artifact.filename);
  if (!artifactPath.startsWith(`${root}${sep}`)) throw new Error(`artifact escapes prepared directory: ${artifact.filename}`);
  const actual = digestFile(artifactPath, fs, root);
  for (const key of ['sha256', 'sha1', 'integrity', 'size']) {
    if (actual[key] !== artifact[key]) throw new Error(`artifact ${key} mismatch: ${artifact.filename}`);
  }
  return artifactPath;
}

export function loadAndVerifyPreparedArtifacts(directory, options = {}) {
  const fs = options.fs ?? { lstatSync, readFileSync, realpathSync, statSync };
  const root = resolve(directory);
  const manifestPath = join(root, 'release-manifest.json');
  assertRegularFileWithin(root, manifestPath, fs);
  const manifest = validateReleaseManifest(readJson(manifestPath, fs), { expected: options.expected });
  const expectedNames = new Set(['release-manifest.json', ...manifest.packages.map((item) => item.filename)]);
  if (options.listFiles) {
    const actual = options.listFiles(root).filter((name) => name !== '.DS_Store');
    if (actual.length !== expectedNames.size || actual.some((name) => !expectedNames.has(name))) {
      throw new Error(`prepared directory contains unexpected or missing files: ${actual.join(', ')}`);
    }
  }
  for (const artifact of manifest.packages) verifyPreparedArtifact(root, artifact, fs);
  return manifest;
}

function parsePackOutput(output, expectedName, expectedVersion) {
  let payload;
  try { payload = JSON.parse(output); } catch { throw new Error('npm pack returned malformed JSON'); }
  const entry = Array.isArray(payload) && payload.length === 1 ? payload[0] : undefined;
  if (!entry || entry.name !== expectedName || entry.version !== expectedVersion || typeof entry.filename !== 'string') {
    throw new Error(`npm pack output did not identify ${expectedName}@${expectedVersion}`);
  }
  if (basename(entry.filename) !== entry.filename) throw new Error(`npm pack returned unsafe filename: ${entry.filename}`);
  return entry.filename;
}

function assertEmptyOutputDirectory(outputDir, fs) {
  if (fs.existsSync(outputDir)) {
    const entries = fs.readdirSync(outputDir).filter((name) => name !== '.DS_Store');
    if (entries.length > 0) throw new Error(`prepare output directory must be empty: ${outputDir}`);
  } else fs.mkdirSync(outputDir, { recursive: true });
}

function npmRegistryArgs() {
  return ['--registry', OFFICIAL_REGISTRY];
}

export function createControlledNpmConfigs(root, fs = { mkdirSync, writeFileSync }) {
  const directory = join(root, 'npm-config');
  const userConfig = join(directory, 'user.npmrc');
  const globalConfig = join(directory, 'global.npmrc');
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  fs.writeFileSync(userConfig, '', { flag: 'wx', mode: 0o600 });
  fs.writeFileSync(globalConfig, '', { flag: 'wx', mode: 0o600 });
  if (userConfig === globalConfig) throw new Error('controlled npm user and global configs must be distinct');
  return { directory, userConfig, globalConfig };
}

export async function prepareRelease(options, dependencies) {
  const { run } = dependencies;
  const fs = dependencies.fs ?? { existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, realpathSync, renameSync, rmSync, statSync, writeFileSync };
  const root = resolve(options.root);
  const outputDir = resolve(options.outputDir);
  assertEmptyOutputDirectory(outputDir, fs);
  if (fs.existsSync(join(root, '.npmrc'))) throw new Error('project .npmrc is not allowed in release preparation');

  const context = await validateGitRelease({
    run, tag: options.tag, defaultBranchRef: options.defaultBranchRef, verifyOriginDefault: options.env?.GITHUB_ACTIONS !== 'true',
  });
  validateCommonVersions(root, context.version, { fs, includeGenerated: false });

  await checked(run, 'node', ['--version'], { cwd: root });
  const npmVersion = (await checked(run, 'npm', ['--version'], { cwd: root })).stdout.trim();
  parseStableNpmVersion(npmVersion);
  if (compareVersions(npmVersion, TRUSTED_NPM_MINIMUM) < 0) throw new Error(`npm ${TRUSTED_NPM_MINIMUM}+ is required for release preparation`);
  await checked(run, 'bun', ['--version'], { cwd: root });
  const registry = (await checked(run, 'npm', ['config', 'get', 'registry'], { cwd: root })).stdout.trim();
  if (registry !== OFFICIAL_REGISTRY) throw new Error(`npm registry must be ${OFFICIAL_REGISTRY}, got ${registry}`);

  const commitEpoch = (await checked(run, 'git', ['show', '-s', '--format=%ct', context.gitCommit], { cwd: root })).stdout.trim();
  if (!/^(0|[1-9][0-9]*)$/u.test(commitEpoch)) throw new Error(`release commit has invalid timestamp: ${commitEpoch}`);
  const buildEnv = { ...(options.env ?? {}), SOURCE_DATE_EPOCH: commitEpoch };
  await checked(run, 'bun', ['install', '--frozen-lockfile'], { cwd: root, env: buildEnv });
  await checked(run, 'bun', ['run', 'verify'], { cwd: root, env: buildEnv });
  validateCommonVersions(root, context.version, { fs, includeGenerated: true });

  const rootPack = await checked(run, 'npm', ['pack', '--json', '--pack-destination', outputDir, ...npmRegistryArgs()], { cwd: root });
  const rootFilename = parsePackOutput(rootPack.stdout, 'ariava', context.version);
  const rootPath = join(outputDir, rootFilename);
  await checked(run, 'node', [join(root, 'scripts/assert-npm-package.mjs'), '--kind', 'root', rootPath], { cwd: root });

  const piRoot = join(root, 'extensions/pi/bundle');
  const piPack = await checked(run, 'npm', ['pack', '--json', '--pack-destination', outputDir, ...npmRegistryArgs()], { cwd: piRoot });
  const piFilename = parsePackOutput(piPack.stdout, '@ariava/pi-extension', context.version);
  const piPath = join(outputDir, piFilename);
  await checked(run, 'node', [join(root, 'scripts/assert-npm-package.mjs'), '--kind', 'pi', piPath], { cwd: root });

  const smokeRoot = dependencies.makeTempDir('ariava-release-smoke-');
  try {
    const prefix = join(smokeRoot, 'prefix');
    const npmConfigs = createControlledNpmConfigs(smokeRoot, fs);
    for (const directory of ['home', 'config', 'tmp']) fs.mkdirSync(join(smokeRoot, directory), { recursive: true });
    const smokeEnv = {
      PATH: options.env?.PATH ?? process.env.PATH ?? '',
      HOME: join(smokeRoot, 'home'),
      XDG_CONFIG_HOME: join(smokeRoot, 'config'),
      TMPDIR: join(smokeRoot, 'tmp'),
      NPM_CONFIG_USERCONFIG: npmConfigs.userConfig,
      NPM_CONFIG_GLOBALCONFIG: npmConfigs.globalConfig,
    };
    const smokeOptions = { cwd: root, env: smokeEnv, replaceEnv: true };
    await checked(run, 'npm', ['install', '--global', '--prefix', prefix, rootPath, ...npmRegistryArgs()], smokeOptions);
    const ariavaBinary = join(prefix, 'bin', 'ariava');
    await checked(run, ariavaBinary, ['help'], { ...smokeOptions, cwd: smokeRoot });
    const status = await run(ariavaBinary, ['status', '--json'], { ...smokeOptions, cwd: smokeRoot });
    fs.writeFileSync(join(smokeRoot, 'status.json'), status.stdout);
    await checked(run, 'node', [join(root, 'scripts/assert-cli-envelope.mjs'), join(smokeRoot, 'status.json'), 'status', String(status.code)], smokeOptions);
    const doctor = await run(ariavaBinary, ['doctor', '--json'], { ...smokeOptions, cwd: smokeRoot });
    fs.writeFileSync(join(smokeRoot, 'doctor.json'), doctor.stdout);
    await checked(run, 'node', [join(root, 'scripts/assert-cli-envelope.mjs'), join(smokeRoot, 'doctor.json'), 'doctor', String(doctor.code)], smokeOptions);
  } finally {
    fs.rmSync(smokeRoot, { recursive: true, force: true });
  }

  const manifest = {
    schemaVersion: RELEASE_SCHEMA_VERSION,
    version: context.version,
    gitTag: context.gitTag,
    gitCommit: context.gitCommit,
    packages: [
      { name: 'ariava', version: context.version, filename: rootFilename, ...digestFile(rootPath, fs, outputDir) },
      { name: '@ariava/pi-extension', version: context.version, filename: piFilename, ...digestFile(piPath, fs, outputDir) },
    ],
  };
  validateReleaseManifest(manifest);
  const temporaryManifest = join(outputDir, `.release-manifest.${process.pid}.tmp`);
  fs.writeFileSync(temporaryManifest, `${JSON.stringify(manifest, null, 2)}\n`, { flag: 'wx' });
  fs.renameSync(temporaryManifest, join(outputDir, 'release-manifest.json'));
  const outputs = fs.readdirSync(outputDir).filter((name) => name !== '.DS_Store').sort();
  const expectedOutputs = ['release-manifest.json', rootFilename, piFilename].sort();
  if (JSON.stringify(outputs) !== JSON.stringify(expectedOutputs)) throw new Error(`unexpected preparation outputs: ${outputs.join(', ')}`);
  return manifest;
}

async function queryPackage(run, artifact, cwd, env) {
  const result = await run('npm', ['view', `${artifact.name}@${artifact.version}`, '--json', ...npmRegistryArgs()], { cwd, env });
  const classified = classifyRegistryResult(result, artifact);
  if (classified.reason) classified.reason = redactSensitiveText(classified.reason, [], env);
  return classified;
}

function assertTrustedContext(options, manifest) {
  const env = options.env ?? {};
  if (options.otp) throw new Error('OTP is forbidden in Trusted Publishing mode');
  for (const [name, value] of Object.entries(env)) {
    const npmConfigOverride = /^NPM_CONFIG_/iu.test(name) && !TRUSTED_NPM_CONFIG_ALLOWLIST.has(name.toUpperCase());
    const credential = /^(?:NODE_AUTH_TOKEN|NPM_TOKEN|NPM_(?:AUTH|PASSWORD|PASSWD|OTP|SECRET|TOKEN))$/iu.test(name);
    if ((npmConfigOverride || credential) && value) throw new Error(`${name} is forbidden in Trusted Publishing mode`);
  }
  if (env.GITHUB_ACTIONS !== 'true' || !env.ACTIONS_ID_TOKEN_REQUEST_URL || !env.ACTIONS_ID_TOKEN_REQUEST_TOKEN) {
    throw new Error('Trusted Publishing requires the GitHub Actions OIDC environment');
  }
  if (env.GITHUB_REPOSITORY !== 'noyyyy/ariava') throw new Error('unexpected GitHub repository for Trusted Publishing');
  if (env.GITHUB_REF_NAME !== manifest.gitTag || env.GITHUB_SHA !== manifest.gitCommit) throw new Error('GitHub ref/commit does not match prepared release');
  const expectedWorkflowRef = `noyyyy/ariava/.github/workflows/publish-npm.yml@refs/tags/${manifest.gitTag}`;
  if (env.GITHUB_WORKFLOW_REF !== expectedWorkflowRef) throw new Error('unexpected Trusted Publishing workflow');
}

async function readDistTags(run, artifact, cwd, env) {
  const result = await run('npm', ['view', artifact.name, 'dist-tags', '--json', ...npmRegistryArgs()], { cwd, env });
  if (result.code !== 0) {
    const detail = redactSensitiveText(result.stderr || result.stdout, [], env).trim();
    throw new Error(`dist-tag query failed for ${artifact.name}: ${detail}`);
  }
  let tags;
  try { tags = JSON.parse(result.stdout); } catch { throw new Error(`malformed dist-tag response for ${artifact.name}`); }
  if (tags?.latest !== artifact.version) throw new Error(`${artifact.name} latest is ${tags?.latest ?? 'missing'}, expected ${artifact.version}`);
  return tags.latest;
}

export async function publishPrepared(options, dependencies) {
  const { run } = dependencies;
  const fs = dependencies.fs ?? { existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, realpathSync, rmSync, statSync, writeFileSync };
  const root = resolve(options.root);
  if (fs.existsSync(join(root, '.npmrc'))) throw new Error('project .npmrc is not allowed for release publication');
  const context = await validateGitRelease({
    run, tag: options.tag, defaultBranchRef: options.defaultBranchRef, verifyOriginDefault: options.mode === 'manual',
  });
  validateCommonVersions(root, context.version, { fs, includeGenerated: false });
  const manifest = loadAndVerifyPreparedArtifacts(options.directory, {
    fs,
    expected: context,
    listFiles: (directory) => fs.readdirSync(directory),
  });
  for (const artifact of manifest.packages) {
    const identity = await dependencies.inspectTarball(join(resolve(options.directory), artifact.filename));
    if (identity.name !== artifact.name || identity.version !== artifact.version) throw new Error(`tarball identity mismatch: ${artifact.filename}`);
  }

  if (options.mode === 'trusted') assertTrustedContext(options, manifest);
  let controlledRoot;
  let releaseEnv = { ...(options.env ?? {}) };
  if (options.mode === 'trusted') {
    controlledRoot = dependencies.makeTempDir('ariava-npm-config-');
    const npmConfigs = createControlledNpmConfigs(controlledRoot, fs);
    releaseEnv = { ...releaseEnv, NPM_CONFIG_USERCONFIG: npmConfigs.userConfig, NPM_CONFIG_GLOBALCONFIG: npmConfigs.globalConfig };
  }
  try {
    const npmVersion = (await checked(run, 'npm', ['--version'], { cwd: root, env: releaseEnv })).stdout.trim();
    parseStableNpmVersion(npmVersion);
    if (options.mode === 'trusted') {
      if (compareVersions(npmVersion, TRUSTED_NPM_MINIMUM) < 0) throw new Error(`npm ${TRUSTED_NPM_MINIMUM}+ is required for Trusted Publishing`);
    } else if (options.mode === 'manual') {
      await checked(run, 'npm', ['whoami', ...npmRegistryArgs()], { cwd: root, env: releaseEnv });
    } else throw new Error('publish mode must be trusted or manual');

    const registry = (await checked(run, 'npm', ['config', 'get', 'registry'], { cwd: root, env: releaseEnv })).stdout.trim();
    if (registry !== OFFICIAL_REGISTRY) throw new Error(`npm registry must be ${OFFICIAL_REGISTRY}, got ${registry}`);

    const initial = [];
    for (const artifact of manifest.packages) initial.push(await queryPackage(run, artifact, root, releaseEnv));
    const invalid = initial.find((state) => state.state === 'present-but-invalid');
    if (invalid) throw new Error(invalid.reason);

    const actions = [];
    for (let index = 0; index < manifest.packages.length; index += 1) {
      const artifact = manifest.packages[index];
      if (initial[index].state === 'present-and-matching') {
        actions.push('skipped');
        continue;
      }
      const immediate = await queryPackage(run, artifact, root, releaseEnv);
      if (immediate.state === 'present-but-invalid') throw new Error(immediate.reason);
      if (immediate.state === 'present-and-matching') {
        actions.push('skipped');
        continue;
      }
      verifyPreparedArtifact(resolve(options.directory), artifact, fs);
      const args = ['publish', join(resolve(options.directory), artifact.filename), '--access', 'public', '--tag', 'latest', ...npmRegistryArgs()];
      const publishEnv = options.otp ? { ...releaseEnv, NPM_CONFIG_OTP: options.otp } : releaseEnv;
      if (options.mode === 'trusted') args.push('--provenance');
      await checked(run, 'npm', args, { cwd: root, env: publishEnv });
      actions.push('published');
    }

    const attempts = options.verifyAttempts ?? 5;
    let finalStates;
    let latest;
    let lastError;
    for (let attempt = 1; attempt <= attempts; attempt += 1) {
      try {
        finalStates = [];
        latest = [];
        for (const artifact of manifest.packages) finalStates.push(await queryPackage(run, artifact, root, releaseEnv));
        const finalInvalid = finalStates.find((state) => state.state !== 'present-and-matching');
        if (finalInvalid) throw new Error(finalInvalid.reason ?? `registry still reports ${finalInvalid.state}`);
        for (const artifact of manifest.packages) latest.push(await readDistTags(run, artifact, root, releaseEnv));
        lastError = undefined;
        break;
      } catch (error) {
        lastError = error;
        if (attempt < attempts) await dependencies.sleep(options.retryDelayMs ?? 1_000);
      }
    }
    if (lastError) throw new Error(`final registry verification failed after ${attempts} attempts: ${lastError.message}`);

    return {
      tag: manifest.gitTag,
      commit: manifest.gitCommit,
      packages: manifest.packages.map((artifact, index) => ({
        name: artifact.name,
        sha256: artifact.sha256,
        initial: initial[index].state,
        action: actions[index],
        final: finalStates[index].state,
        registryVersion: artifact.version,
        latest: latest[index],
      })),
    };
  } finally {
    if (controlledRoot) fs.rmSync(controlledRoot, { recursive: true, force: true });
  }
}
