import { dirname, isAbsolute, join, resolve } from 'node:path';
import { AriavaCliError } from '../service/errors';
import type { CommandRunner } from '../service/types';
import type { OnboardingCliEvidence } from './types';

export interface StableBootstrapDependencies {
  runner: CommandRunner;
  realpath(path: string): string;
  readPackageVersion(packageRoot: string): string | undefined;
  assertPrefixWritable(prefix: string): void;
  resolveGlobalPrefix(): string | undefined;
  resolveStableExecutable(prefix: string): string | undefined;
  currentCli: OnboardingCliEvidence;
}

export interface StableBootstrapInput {
  version: string;
  publicArgs: readonly string[];
  resumed: boolean;
  bootstrapVersion?: string;
}

export interface StableBootstrapResult {
  status: 'reused' | 'installed';
  evidence: OnboardingCliEvidence;
  reentry?: { command: string; args: string[] };
}

export function proveStableCli(
  evidence: OnboardingCliEvidence,
  exactVersion: string,
  deps: Pick<StableBootstrapDependencies, 'realpath' | 'readPackageVersion'>,
): OnboardingCliEvidence | undefined {
  if (!evidence.npmPrefix || !evidence.packageRoot || !evidence.npmBinPath) return undefined;
  if (![evidence.executablePath, evidence.packageRoot, evidence.npmPrefix, evidence.npmBinPath].every(isCanonicalAbsolute)) return undefined;
  let executable: string;
  let packageRoot: string;
  let prefix: string;
  let bin: string;
  try {
    executable = deps.realpath(evidence.executablePath);
    packageRoot = deps.realpath(evidence.packageRoot);
    prefix = deps.realpath(evidence.npmPrefix);
    bin = deps.realpath(evidence.npmBinPath);
  } catch {
    return undefined;
  }
  if (deps.readPackageVersion(packageRoot) !== exactVersion || evidence.packageVersion !== exactVersion) return undefined;
  if (dirname(executable) !== bin && !executable.startsWith(`${packageRoot}/`)) return undefined;
  if (!packageRoot.startsWith(`${prefix}/`) || !bin.startsWith(`${prefix}/`)) return undefined;
  // Positive global-prefix containment rejects npm-exec/npx cache packages even
  // when an attacker chooses a cache path without a familiar `_npx` segment.
  return { ...evidence, executablePath: executable, packageRoot, npmPrefix: prefix, npmBinPath: bin };
}

export function bootstrapStableCli(input: StableBootstrapInput, deps: StableBootstrapDependencies): StableBootstrapResult {
  if (input.bootstrapVersion !== undefined && input.bootstrapVersion !== input.version) {
    throw bootstrapError('ERR_STABLE_CLI_PATH', 'Stable CLI re-entry version marker is mismatched.', false);
  }
  const current = proveStableCli(deps.currentCli, input.version, deps);
  if (current) return { status: 'reused', evidence: current };
  if (input.bootstrapVersion !== undefined) {
    throw bootstrapError('ERR_STABLE_CLI_PATH', 'Stable CLI re-entry still points to an unverified location.', false);
  }

  const prefix = deps.resolveGlobalPrefix();
  if (!prefix || !isCanonicalAbsolute(prefix)) {
    throw bootstrapError('ERR_STABLE_CLI_INSTALL', 'npm global prefix could not be resolved safely.', true);
  }
  const stableExecutable = deps.resolveStableExecutable(prefix);
  if (stableExecutable) {
    const stableEvidence = proveStableCli({
      executablePath: stableExecutable,
      packageRoot: join(prefix, 'lib', 'node_modules', 'ariava'),
      packageVersion: input.version,
      npmPrefix: prefix,
      npmBinPath: dirname(stableExecutable),
    }, input.version, deps);
    if (stableEvidence) return reentryResult('reused', stableEvidence, input);
  }
  try {
    deps.assertPrefixWritable(prefix);
  } catch {
    throw bootstrapError('ERR_STABLE_CLI_INSTALL', 'npm global prefix is not writable by the current user.', true, {
      message: 'Configure a user-writable npm global prefix, then retry. Do not use sudo.',
    });
  }
  const installArgs = ['install', '--global', `ariava@${input.version}`];
  const installed = deps.runner.run('npm', installArgs);
  if (installed.status !== 0) {
    throw bootstrapError('ERR_STABLE_CLI_INSTALL', 'Exact Ariava CLI installation failed.', true);
  }
  const executable = deps.resolveStableExecutable(prefix);
  if (!executable) throw bootstrapError('ERR_STABLE_CLI_PATH', 'Installed Ariava executable could not be resolved.', true);
  const packageRoot = join(prefix, 'lib', 'node_modules', 'ariava');
  const evidence = proveStableCli({
    executablePath: executable,
    packageRoot,
    packageVersion: input.version,
    npmPrefix: prefix,
    npmBinPath: dirname(executable),
  }, input.version, deps);
  if (!evidence) throw bootstrapError('ERR_STABLE_CLI_PATH', 'Installed Ariava CLI failed stable path or exact-version proof.', false);
  return reentryResult('installed', evidence, input);
}

function reentryResult(
  status: StableBootstrapResult['status'],
  evidence: OnboardingCliEvidence,
  input: StableBootstrapInput,
): StableBootstrapResult {
  return {
    status,
    evidence,
    reentry: {
      command: evidence.executablePath,
      args: ['setup', ...preservedPublicArgs(input.publicArgs), '--resume', '--bootstrap-version', input.version, '--bootstrap-once'],
    },
  };
}

function preservedPublicArgs(args: readonly string[]): string[] {
  const internal = new Set(['--resume', '--bootstrap-version', '--bootstrap-once']);
  const result: string[] = [];
  for (let index = 0; index < args.length; index += 1) {
    const value = args[index]!;
    if (!internal.has(value)) result.push(value);
    else if (value === '--bootstrap-version') index += 1;
  }
  return result;
}

function isCanonicalAbsolute(path: string): boolean {
  return isAbsolute(path) && resolve(path) === path;
}

function bootstrapError(
  code: 'ERR_STABLE_CLI_INSTALL' | 'ERR_STABLE_CLI_PATH',
  message: string,
  retryable: boolean,
  remediation?: { message: string; command?: string },
  detail: Record<string, unknown> = {},
): AriavaCliError {
  return new AriavaCliError(code, message, { step: 'stable-cli', retryable, ...(remediation ? { remediation } : {}), ...detail });
}
