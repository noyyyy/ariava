#!/usr/bin/env node
import { mkdtempSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  OFFICIAL_REGISTRY,
  prepareRelease,
  publishPrepared,
  redactSensitiveText,
} from './npm-release-lib.mjs';

export function usage() {
  return `Usage: ./scripts/publish-npm-safe.sh <mode> [options]

Modes:
  --prepare --output-dir <empty-dir>
      Frozen-install and fully verify Public Core, pack and inspect both exact
      tarballs, smoke-test the prepared ariava tarball in an isolated prefix,
      and atomically create release-manifest.json. This dry preparation makes
      no registry writes and does not require npm login or OIDC.

  --publish-prepared <dir> --trusted-publishing
      Validate the tag/commit/version and every prepared artifact digest, then
      publish with GitHub Actions OIDC Trusted Publishing. No npm whoami, OTP,
      token fallback, rebuild, or repack is performed.

  --publish-prepared <dir> --manual [--otp-stdin | --otp-fd <fd>]
      Manual OTP break-glass. Uses npm whoami, then the same exact-artifact,
      registry preflight, package order, partial-success retry, and final
      verification path as Trusted Publishing. OTP input is passed to npm only
      through its environment and is never logged or added to npm argv.

Compatibility:
  --publish [--otp-stdin | --otp-fd <fd>]
      Prepare into a same-attempt temporary directory and publish it in manual
      break-glass mode. This preserves the old invocation but does not permit
      --skip-install or --skip-verify.

Release rules:
  * Stable tag vX.Y.Z and its peeled commit must equal HEAD and belong to
    origin's advertised, freshly fetched default branch.
  * ariava is processed before @ariava/pi-extension.
  * Existing versions are skipped only when registry shasum matches the exact
    prepared tarball; partial success is safely retryable.
  * All npm operations are pinned to ${OFFICIAL_REGISTRY}.

Required release context:
  --tag <vX.Y.Z>; automation also supplies its validated remote-tracking
  default-branch ref. Local/break-glass runs derive and fetch origin's actual
  default branch, and reject a supplied ref that does not match it.

Options:
  --root <path>                 Public Core checkout (default: repository root)
  --output-dir <path>           Empty preparation output directory
  --tag <tag>                   Stable release tag (default: GITHUB_REF_NAME)
  --default-branch-ref <ref>    Validated refs/remotes/origin/* ref; local runs
                                verify it against origin HEAD (usually omit it)
  --otp-stdin                   Read manual-mode OTP from standard input
  --otp-fd <fd>                 Read manual-mode OTP from an already-open FD
  --otp <code>                  Deprecated compatibility alias; exposes argv
  --summary-file <path>         Write credential-free publish result JSON
  -h, --help                    Show this help
`;
}

export function parseArgs(argv, env = process.env) {
  const options = {
    root: resolve(dirname(fileURLToPath(import.meta.url)), '..'),
    tag: env.GITHUB_REF_NAME,
    defaultBranchRef: env.ARIAVA_DEFAULT_BRANCH_REF,
    env,
  };
  let compatibilityPublish = false;
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    const value = () => {
      const next = argv[index + 1];
      if (!next) throw new Error(`${arg} requires a value`);
      index += 1;
      return next;
    };
    if (arg === '--prepare') options.action = 'prepare';
    else if (arg === '--output-dir') options.outputDir = value();
    else if (arg === '--publish-prepared') { options.action = 'publish'; options.directory = value(); }
    else if (arg === '--trusted-publishing') options.mode = 'trusted';
    else if (arg === '--manual') options.mode = 'manual';
    else if (arg === '--publish') { compatibilityPublish = true; options.action = 'compatibility'; options.mode = 'manual'; }
    else if (arg === '--otp') { options.otp = value(); options.deprecatedOtpArg = true; }
    else if (arg === '--otp-stdin') options.otpFd = 0;
    else if (arg === '--otp-fd') {
      const fd = Number(value());
      if (!Number.isSafeInteger(fd) || fd < 0) throw new Error('--otp-fd requires a non-negative integer file descriptor');
      options.otpFd = fd;
    }
    else if (arg === '--tag') options.tag = value();
    else if (arg === '--default-branch-ref') options.defaultBranchRef = value();
    else if (arg === '--root') options.root = resolve(value());
    else if (arg === '--summary-file') options.summaryFile = resolve(value());
    else if (arg === '--skip-install' || arg === '--skip-verify') throw new Error(`${arg} is not supported by the safe release modes`);
    else if (arg === '--help' || arg === '-h') return { help: true };
    else throw new Error(`unknown option: ${arg}`);
  }
  if (!options.action) throw new Error('choose --prepare, --publish-prepared, or compatibility --publish');
  if (!options.tag) throw new Error('--tag or GITHUB_REF_NAME is required');
  if (!options.defaultBranchRef && env.GITHUB_ACTIONS === 'true') throw new Error('--default-branch-ref or ARIAVA_DEFAULT_BRANCH_REF is required in automation');
  if (options.action === 'prepare' && (!options.outputDir || options.mode || options.otp || options.otpFd !== undefined)) throw new Error('--prepare requires --output-dir and does not accept publishing credentials');
  if (options.action === 'publish' && !options.mode) throw new Error('--publish-prepared requires --trusted-publishing or --manual');
  if (options.otp && options.otpFd !== undefined) throw new Error('choose only one OTP input method');
  if (options.action === 'publish' && options.mode === 'trusted' && (options.otp || options.otpFd !== undefined)) throw new Error('OTP is forbidden with --trusted-publishing');
  if (compatibilityPublish && options.directory) throw new Error('--publish cannot be combined with --publish-prepared');
  if (options.action === 'prepare' && options.summaryFile) throw new Error('--summary-file is accepted only by publishing modes');
  return options;
}

export function readOtp(fd, fs = { readFileSync }) {
  const otp = fs.readFileSync(fd, 'utf8').trim();
  if (!/^[0-9]{6}$/u.test(otp)) throw new Error('OTP input must be exactly 6 digits');
  return otp;
}

export async function executeCommand(command, args, options = {}) {
  return await new Promise((resolvePromise) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
      env: options.replaceEnv ? { ...(options.env ?? {}) } : { ...process.env, ...(options.env ?? {}) },
      shell: false,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('error', (error) => { stderr += error.message; });
    child.on('close', (code) => {
      if (options.forwardOutput !== false) {
        process.stdout.write(redactSensitiveText(stdout, args, options.env));
        process.stderr.write(redactSensitiveText(stderr, args, options.env));
      }
      resolvePromise({ code: code ?? 1, stdout, stderr });
    });
  });
}

async function inspectTarball(path) {
  const result = await executeCommand('tar', ['-xOf', path, 'package/package.json'], { forwardOutput: false });
  if (result.code !== 0) throw new Error(`cannot inspect tarball package.json: ${path}`);
  let manifest;
  try { manifest = JSON.parse(result.stdout); } catch { throw new Error(`tarball package.json is invalid: ${path}`); }
  return { name: manifest.name, version: manifest.version };
}

function dependencies() {
  return {
    run: executeCommand,
    makeTempDir: (prefix) => mkdtempSync(join(tmpdir(), prefix)),
    inspectTarball,
    sleep: (milliseconds) => new Promise((resolvePromise) => setTimeout(resolvePromise, milliseconds)),
  };
}

export async function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  if (options.otpFd !== undefined) options.otp = readOtp(options.otpFd);
  if (options.deprecatedOtpArg) console.error('warning: --otp is deprecated because argv may be exposed; use --otp-stdin or --otp-fd');
  if (options.help) { console.log(usage()); return; }
  const deps = dependencies();
  if (options.action === 'prepare') {
    const manifest = await prepareRelease(options, deps);
    console.log(JSON.stringify({ ok: true, action: 'prepared', manifest }, null, 2));
    return;
  }
  if (options.action === 'compatibility') {
    const directory = mkdtempSync(join(tmpdir(), 'ariava-manual-release-'));
    const manifest = await prepareRelease({ ...options, outputDir: directory }, deps);
    const summary = await publishPrepared({ ...options, action: 'publish', directory, mode: 'manual' }, deps);
    const result = { ok: true, action: 'published', manifest, summary };
    if (options.summaryFile) writeFileSync(options.summaryFile, `${JSON.stringify(result, null, 2)}\n`, { flag: 'wx' });
    console.log(JSON.stringify(result, null, 2));
    return;
  }
  const summary = await publishPrepared(options, deps);
  const result = { ok: true, action: 'published', summary };
  if (options.summaryFile) writeFileSync(options.summaryFile, `${JSON.stringify(result, null, 2)}\n`, { flag: 'wx' });
  console.log(JSON.stringify(result, null, 2));
}

if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
  main().catch((error) => {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`error: ${redactSensitiveText(message, process.argv.slice(2), process.env)}`);
    process.exitCode = 1;
  });
}
