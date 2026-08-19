import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { spawn } from 'node:child_process';

export const RELEASE_PACKAGE_FILES = Object.freeze([
  'package.json',
  'apps/bridge/package.json',
  'extensions/pi/package.json',
  'packages/protocol/package.json',
  'packages/shared-utils/package.json',
]);

export const RELEASE_CHANGED_FILES = Object.freeze([
  'package.json',
  'apps/bridge/package.json',
  'extensions/pi/package.json',
  'packages/protocol/package.json',
  'packages/shared-utils/package.json',
  'bun.lock',
]);

const LOCKFILE_WORKSPACES = Object.freeze([
  'apps/bridge',
  'extensions/pi',
  'packages/protocol',
  'packages/shared-utils',
]);

const CI_WORKFLOW = 'Public Repo CI';
const REQUIRED_CI_JOBS = Object.freeze(['Linux', 'macOS']);
const STABLE_VERSION = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/u;

export function usage() {
  return `Usage: node scripts/release-flow.mjs <push|tag>

Commands:
  push  Verify, commit, and push the already-bumped release to the default branch
  tag   Require successful Linux/macOS CI, then create and push the release tag
`;
}

export function parseArgs(argv) {
  const [command, ...rest] = argv;
  if (!command) throw new Error(usage());
  if (command === '-h' || command === '--help') {
    if (rest.length > 0) throw new Error(`unexpected argument: ${rest[0]}\n\n${usage()}`);
    return { command: 'help' };
  }
  if (command !== 'push' && command !== 'tag') throw new Error(`unexpected command: ${command}\n\n${usage()}`);
  if (rest.length > 0) throw new Error(`unexpected argument: ${rest[0]}\n\n${usage()}`);
  return { command };
}

function stripJsoncComments(original) {
  let result = '';
  let inString = false;
  let escaped = false;
  let lineComment = false;
  let blockComment = false;
  for (let index = 0; index < original.length; index += 1) {
    const char = original[index];
    const next = original[index + 1];
    if (lineComment) {
      if (char === '\n' || char === '\r') {
        lineComment = false;
        result += char;
      } else result += ' ';
      continue;
    }
    if (blockComment) {
      if (char === '*' && next === '/') {
        result += '  ';
        blockComment = false;
        index += 1;
      } else result += char === '\n' || char === '\r' ? char : ' ';
      continue;
    }
    if (inString) {
      result += char;
      if (escaped) escaped = false;
      else if (char === '\\') escaped = true;
      else if (char === '"') inString = false;
      continue;
    }
    if (char === '"') {
      inString = true;
      result += char;
    } else if (char === '/' && next === '/') {
      result += '  ';
      lineComment = true;
      index += 1;
    } else if (char === '/' && next === '*') {
      result += '  ';
      blockComment = true;
      index += 1;
    } else result += char;
  }
  if (blockComment) throw new Error('unterminated block comment');
  return result;
}

function stripJsoncTrailingCommas(original) {
  let result = '';
  let inString = false;
  let escaped = false;
  for (let index = 0; index < original.length; index += 1) {
    const char = original[index];
    if (inString) {
      result += char;
      if (escaped) escaped = false;
      else if (char === '\\') escaped = true;
      else if (char === '"') inString = false;
      continue;
    }
    if (char === '"') {
      inString = true;
      result += char;
      continue;
    }
    if (char === ',') {
      let lookahead = index + 1;
      while (/\s/u.test(original[lookahead] ?? '')) lookahead += 1;
      if (original[lookahead] === '}' || original[lookahead] === ']') continue;
    }
    result += char;
  }
  return result;
}

function readJson(root, file) {
  return JSON.parse(readFileSync(resolve(root, file), 'utf8'));
}

function readLockfile(root) {
  const source = readFileSync(resolve(root, 'bun.lock'), 'utf8');
  try {
    return JSON.parse(stripJsoncTrailingCommas(stripJsoncComments(source)));
  } catch (error) {
    throw new Error(`bun.lock is not valid Bun JSONC: ${error instanceof Error ? error.message : String(error)}`);
  }
}

function assertStableVersion(version, source) {
  if (typeof version !== 'string' || !STABLE_VERSION.test(version)) {
    throw new Error(`${source} has invalid stable version: ${String(version)}`);
  }
  return version;
}

export function validateCommonReleaseVersion(root) {
  const versions = RELEASE_PACKAGE_FILES.map((file) => ({ file, version: readJson(root, file).version }));
  const expected = assertStableVersion(versions[0]?.version, 'package.json');
  for (const { file, version } of versions) {
    if (version !== expected) throw new Error(`version mismatch: package.json is ${expected}, but ${file} is ${String(version)}`);
  }
  const lockfile = readLockfile(root);
  for (const workspace of LOCKFILE_WORKSPACES) {
    const version = lockfile?.workspaces?.[workspace]?.version;
    if (version !== expected) throw new Error(`version mismatch: package.json is ${expected}, but bun.lock workspace ${workspace} is ${String(version)}`);
  }
  return expected;
}

function stableJson(value) {
  if (Array.isArray(value)) return value.map(stableJson);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stableJson(value[key])]));
  }
  return value;
}

function withoutManifestVersion(manifest) {
  const copy = structuredClone(manifest);
  delete copy.version;
  return stableJson(copy);
}

function withoutLockfileVersions(lockfile) {
  const copy = structuredClone(lockfile);
  for (const workspace of LOCKFILE_WORKSPACES) {
    if (copy?.workspaces?.[workspace]) delete copy.workspaces[workspace].version;
  }
  return stableJson(copy);
}

export async function validateReleaseContent(root, head, run) {
  for (const file of RELEASE_CHANGED_FILES) {
    const baselineSource = await checked(run, 'git', ['show', `${head}:${file}`], { cwd: root });
    let baseline;
    try {
      baseline = file === 'bun.lock'
        ? JSON.parse(stripJsoncTrailingCommas(stripJsoncComments(baselineSource)))
        : JSON.parse(baselineSource);
    } catch (error) {
      throw new Error(`could not parse ${file} from HEAD: ${error instanceof Error ? error.message : String(error)}`);
    }
    const current = file === 'bun.lock' ? readLockfile(root) : readJson(root, file);
    const normalizedBaseline = file === 'bun.lock' ? withoutLockfileVersions(baseline) : withoutManifestVersion(baseline);
    const normalizedCurrent = file === 'bun.lock' ? withoutLockfileVersions(current) : withoutManifestVersion(current);
    if (JSON.stringify(normalizedBaseline) !== JSON.stringify(normalizedCurrent)) {
      throw new Error(`${file} contains non-version content changes; commit them separately`);
    }
  }
}

function parseStatusLine(line) {
  if (line.length < 4 || line[2] !== ' ') throw new Error(`unsupported git status entry: ${line}`);
  const status = line.slice(0, 2);
  const path = line.slice(3);
  if (!/^[ MADRCU?!]{2}$/u.test(status) || /[RCU?!]/u.test(status) || path.includes(' -> ')) {
    throw new Error(`unsupported git status entry: ${line}`);
  }
  return path;
}

export function validateReleaseChanges(statusOutput) {
  const paths = statusOutput.split('\n').filter(Boolean).map(parseStatusLine);
  const unrelated = paths.filter((path) => !RELEASE_CHANGED_FILES.includes(path));
  if (unrelated.length > 0) throw new Error(`unrelated changes must be committed separately: ${unrelated.join(', ')}`);
  const missing = RELEASE_CHANGED_FILES.filter((path) => !paths.includes(path));
  if (missing.length > 0) throw new Error(`missing release changes: ${missing.join(', ')}`);
  if (new Set(paths).size !== paths.length) throw new Error('duplicate release change paths in git status');
  return [...RELEASE_CHANGED_FILES];
}

export async function executeCommand(command, args, options = {}) {
  return await new Promise((resolvePromise, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
      env: options.env ?? process.env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('error', reject);
    child.on('close', (code) => resolvePromise({ code: code ?? 1, stdout, stderr }));
  });
}

async function checked(run, command, args, options = {}, label = `${command} ${args.join(' ')}`) {
  const result = await run(command, args, options);
  if (result.code !== 0) {
    const detail = result.stderr.trim() || result.stdout.trim();
    throw new Error(`${label} failed${detail ? `: ${detail}` : ''}`);
  }
  return result.stdout.trim();
}

function parseOriginDefaultBranch(output) {
  const match = /^ref:\s+refs\/heads\/([^\s]+)\s+HEAD$/mu.exec(output);
  if (!match) throw new Error('origin did not advertise a default branch');
  return match[1];
}

async function repositoryContext(root, run) {
  const branch = await checked(run, 'git', ['symbolic-ref', '--short', 'HEAD'], { cwd: root });
  const advertised = await checked(run, 'git', ['ls-remote', '--symref', 'origin', 'HEAD'], { cwd: root });
  const defaultBranch = parseOriginDefaultBranch(advertised);
  if (branch !== defaultBranch) throw new Error(`release commands require origin default branch ${defaultBranch}, current branch is ${branch}`);
  return { branch, defaultBranch, remoteRef: `refs/remotes/origin/${defaultBranch}` };
}

async function fetchDefaultBranch(root, run, context) {
  await checked(run, 'git', [
    'fetch', '--no-tags', 'origin',
    `+refs/heads/${context.defaultBranch}:${context.remoteRef}`,
  ], { cwd: root });
}

async function currentState(root, run, context) {
  const head = await checked(run, 'git', ['rev-parse', 'HEAD'], { cwd: root });
  const remoteHead = await checked(run, 'git', ['rev-parse', context.remoteRef], { cwd: root });
  const statusResult = await run('git', ['status', '--porcelain=v1', '--untracked-files=all'], { cwd: root });
  if (statusResult.code !== 0) {
    const detail = statusResult.stderr.trim() || statusResult.stdout.trim();
    throw new Error(`git status --porcelain=v1 --untracked-files=all failed${detail ? `: ${detail}` : ''}`);
  }
  const status = statusResult.stdout.replace(/\r?\n$/u, '');
  return { head, remoteHead, status };
}

function assertHeadMatchesRemote(state, branch, expectedHead) {
  if (expectedHead && state.head !== expectedHead) throw new Error(`HEAD changed during release flow: expected ${expectedHead}, found ${state.head}`);
  if (state.head !== state.remoteHead) throw new Error(`origin/${branch} changed or local HEAD is not synchronized`);
}

async function assertTagAbsent(root, run, tag) {
  const local = await run('git', ['show-ref', '--verify', '--quiet', `refs/tags/${tag}`], { cwd: root });
  if (local.code === 0) throw new Error(`tag ${tag} already exists locally`);
  if (local.code !== 1) throw new Error(`could not inspect local tag ${tag}: ${local.stderr.trim()}`);
  const remote = await checked(run, 'git', ['ls-remote', '--tags', 'origin', `refs/tags/${tag}`, `refs/tags/${tag}^{}`], { cwd: root });
  if (remote) throw new Error(`tag ${tag} already exists on origin`);
}

function validateExactReleasePaths(output, label) {
  const paths = output.split('\n').filter(Boolean);
  const expected = [...RELEASE_CHANGED_FILES].sort();
  const actual = [...new Set(paths)].sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(`${label} must change exactly the release version files and bun.lock; found: ${actual.join(', ') || 'none'}`);
  }
}

async function validateReleaseCommit(root, run, commit, version) {
  const subject = await checked(run, 'git', ['log', '-1', '--format=%s', commit], { cwd: root });
  const expectedSubject = `release: bump to ${version}`;
  if (subject !== expectedSubject) throw new Error(`release commit subject must be exactly "${expectedSubject}"`);
  const parent = await checked(run, 'git', ['rev-parse', `${commit}^`], { cwd: root });
  const paths = await checked(run, 'git', ['diff-tree', '--no-commit-id', '--name-only', '-r', commit], { cwd: root });
  validateExactReleasePaths(paths, `release commit ${commit}`);
  for (const file of RELEASE_CHANGED_FILES) {
    const baselineSource = await checked(run, 'git', ['show', `${parent}:${file}`], { cwd: root });
    const releaseSource = await checked(run, 'git', ['show', `${commit}:${file}`], { cwd: root });
    let baseline;
    let release;
    try {
      baseline = file === 'bun.lock' ? JSON.parse(stripJsoncTrailingCommas(stripJsoncComments(baselineSource))) : JSON.parse(baselineSource);
      release = file === 'bun.lock' ? JSON.parse(stripJsoncTrailingCommas(stripJsoncComments(releaseSource))) : JSON.parse(releaseSource);
    } catch (error) {
      throw new Error(`could not parse committed ${file}: ${error instanceof Error ? error.message : String(error)}`);
    }
    const normalizedBaseline = file === 'bun.lock' ? withoutLockfileVersions(baseline) : withoutManifestVersion(baseline);
    const normalizedRelease = file === 'bun.lock' ? withoutLockfileVersions(release) : withoutManifestVersion(release);
    if (JSON.stringify(normalizedBaseline) !== JSON.stringify(normalizedRelease)) {
      throw new Error(`release commit ${commit} contains non-version content changes in ${file}`);
    }
  }
}

async function validatePushState(root, run, expected = {}) {
  const context = await repositoryContext(root, run);
  await fetchDefaultBranch(root, run, context);
  const state = await currentState(root, run, context);
  assertHeadMatchesRemote(state, context.defaultBranch, expected.head);
  const version = validateCommonReleaseVersion(root);
  if (expected.version && version !== expected.version) throw new Error(`release version changed during verification: expected ${expected.version}, found ${version}`);
  validateReleaseChanges(state.status);
  await validateReleaseContent(root, state.head, run);
  const tag = `v${version}`;
  await assertTagAbsent(root, run, tag);
  return { ...context, ...state, version, tag };
}

export async function pushRelease(options = {}, dependencies = {}) {
  const root = resolve(options.root ?? process.cwd());
  const run = dependencies.run ?? executeCommand;
  const before = await validatePushState(root, run);
  await checked(run, 'bun', ['install', '--frozen-lockfile'], { cwd: root }, 'bun install --frozen-lockfile');
  await checked(run, 'bun', ['run', 'verify'], { cwd: root }, 'bun run verify');
  const after = await validatePushState(root, run, { head: before.head, version: before.version });
  await checked(run, 'git', ['add', '--', ...RELEASE_CHANGED_FILES], { cwd: root });
  await checked(run, 'git', ['commit', '-m', `release: bump to ${after.version}`], { cwd: root });
  const commit = await checked(run, 'git', ['rev-parse', 'HEAD'], { cwd: root });
  await validateReleaseCommit(root, run, commit, after.version);
  await checked(run, 'git', ['push', '--no-follow-tags', 'origin', `HEAD:${after.defaultBranch}`], { cwd: root });
  return { version: after.version, commit, branch: after.defaultBranch };
}

function parseJson(output, label) {
  try {
    return JSON.parse(output);
  } catch (error) {
    throw new Error(`${label} returned invalid JSON: ${error instanceof Error ? error.message : String(error)}`);
  }
}

function selectWorkflowRun(runs, head, branch) {
  if (!Array.isArray(runs)) throw new Error('gh run list did not return an array');
  const matches = runs.filter((run) => run?.headSha === head && run?.headBranch === branch && Number.isInteger(run?.databaseId));
  if (matches.length !== 1) throw new Error(`expected exactly one ${CI_WORKFLOW} push run for ${head} on ${branch}, found ${matches.length}`);
  return matches[0];
}

function validateWorkflow(workflow, head, branch) {
  if (workflow?.headSha !== head) throw new Error(`CI workflow commit mismatch: expected ${head}, found ${String(workflow?.headSha)}`);
  if (workflow?.headBranch !== branch) throw new Error(`CI workflow branch mismatch: expected ${branch}, found ${String(workflow?.headBranch)}`);
  if (workflow?.status !== 'completed' || workflow?.conclusion !== 'success') {
    throw new Error(`CI workflow did not succeed: status=${String(workflow?.status)} conclusion=${String(workflow?.conclusion)}`);
  }
  if (!Array.isArray(workflow.jobs)) throw new Error('CI workflow jobs are missing');
  for (const required of REQUIRED_CI_JOBS) {
    const jobs = workflow.jobs.filter((job) => job?.name === required);
    if (jobs.length !== 1) throw new Error(`CI workflow must contain exactly one successful ${required} job`);
    if (jobs[0].status !== 'completed' || jobs[0].conclusion !== 'success') {
      throw new Error(`${required} CI job did not succeed: status=${String(jobs[0].status)} conclusion=${String(jobs[0].conclusion)}`);
    }
  }
}

async function validateTagState(root, run, expected = {}) {
  const context = await repositoryContext(root, run);
  await fetchDefaultBranch(root, run, context);
  const state = await currentState(root, run, context);
  assertHeadMatchesRemote(state, context.defaultBranch, expected.head);
  if (state.status) throw new Error('release:tag requires a clean working tree');
  const version = validateCommonReleaseVersion(root);
  if (expected.version && version !== expected.version) throw new Error(`release version changed while waiting for CI: expected ${expected.version}, found ${version}`);
  await validateReleaseCommit(root, run, state.head, version);
  const tag = `v${version}`;
  await assertTagAbsent(root, run, tag);
  return { ...context, ...state, version, tag };
}

export async function tagRelease(options = {}, dependencies = {}) {
  const root = resolve(options.root ?? process.cwd());
  const run = dependencies.run ?? executeCommand;
  const before = await validateTagState(root, run);
  await checked(run, 'gh', ['auth', 'status', '--hostname', 'github.com'], { cwd: root }, 'gh authentication check');
  const runListOutput = await checked(run, 'gh', [
    'run', 'list', '--workflow', CI_WORKFLOW, '--commit', before.head, '--event', 'push',
    '--json', 'databaseId,headSha,headBranch,status,conclusion', '--limit', '20',
  ], { cwd: root });
  const workflowRun = selectWorkflowRun(parseJson(runListOutput, 'gh run list'), before.head, before.defaultBranch);
  await checked(run, 'gh', ['run', 'watch', String(workflowRun.databaseId), '--exit-status'], { cwd: root }, `${CI_WORKFLOW} run ${workflowRun.databaseId}`);
  const workflowOutput = await checked(run, 'gh', [
    'run', 'view', String(workflowRun.databaseId), '--json', 'headSha,headBranch,status,conclusion,jobs',
  ], { cwd: root });
  validateWorkflow(parseJson(workflowOutput, 'gh run view'), before.head, before.defaultBranch);
  const after = await validateTagState(root, run, { head: before.head, version: before.version });
  await checked(run, 'git', ['tag', '-a', after.tag, '-m', `Release ${after.tag}`, after.head], { cwd: root });
  const peeled = await checked(run, 'git', ['rev-parse', `${after.tag}^{}`], { cwd: root });
  if (peeled !== after.head) throw new Error(`tag ${after.tag} target mismatch: expected ${after.head}, found ${peeled}`);
  await checked(run, 'git', ['push', '--no-follow-tags', 'origin', `refs/tags/${after.tag}`], { cwd: root });
  return { version: after.version, tag: after.tag, commit: after.head, workflowRunId: workflowRun.databaseId };
}
