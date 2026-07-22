import { describe, expect, test } from 'bun:test';
import {
  bootstrapStableCli,
  proveStableCli,
  type OnboardingCliEvidence,
} from '../src/host-manager/onboarding';
import type { CommandResult } from '../src/host-manager/service/types';

const version = '0.1.6';
const prefix = '/home/test/.npm-global';
const executable = `${prefix}/bin/ariava`;
const packageRoot = `${prefix}/lib/node_modules/ariava`;

function evidence(overrides: Partial<OnboardingCliEvidence> = {}): OnboardingCliEvidence {
  return {
    executablePath: executable,
    packageRoot,
    packageVersion: version,
    npmPrefix: prefix,
    npmBinPath: `${prefix}/bin`,
    ...overrides,
  };
}

function dependencies(options: {
  currentCli?: OnboardingCliEvidence;
  installResult?: CommandResult;
  resolvedPrefix?: string;
  writableError?: Error;
  stableExecutable?: string;
  packageVersion?: string;
  installedPackageVersion?: string;
} = {}) {
  const calls: string[] = [];
  let installed = false;
  return {
    calls,
    deps: {
      runner: {
        run(command: string, args: string[]) {
          calls.push(`run ${command} ${args.join(' ')}`);
          const result = options.installResult ?? { status: 0, stdout: '', stderr: '' };
          if (command === 'npm' && result.status === 0) installed = true;
          return result;
        },
      },
      realpath(path: string) {
        calls.push(`realpath ${path}`);
        return path;
      },
      readPackageVersion(path: string) {
        calls.push(`version ${path}`);
        return installed ? options.installedPackageVersion ?? version : options.packageVersion ?? version;
      },
      assertPrefixWritable(path: string) {
        calls.push(`writable ${path}`);
        if (options.writableError) throw options.writableError;
      },
      resolveGlobalPrefix() {
        calls.push('resolve-prefix');
        return options.resolvedPrefix === undefined ? prefix : options.resolvedPrefix;
      },
      resolveStableExecutable(path: string) {
        calls.push(`resolve-executable ${path}`);
        return options.stableExecutable === undefined ? executable : options.stableExecutable;
      },
      currentCli: options.currentCli ?? evidence(),
    },
  };
}

describe('stable onboarding bootstrap', () => {
  test('reuses exact positively proven global npm evidence without installing', () => {
    const fixture = dependencies();
    const result = bootstrapStableCli({ version, publicArgs: ['--json'], resumed: false }, fixture.deps);
    expect(result).toMatchObject({ status: 'reused', evidence: evidence() });
    expect(fixture.calls).not.toContain(`run npm install --global ariava@${version}`);
  });

  test('rejects cache, spoofed prefix, relative, and version-mismatched evidence', () => {
    const deps = dependencies().deps;
    expect(proveStableCli(evidence({ npmPrefix: '/tmp/npm-cache', npmBinPath: '/tmp/npm-cache/bin' }), version, deps)).toBeUndefined();
    expect(proveStableCli(evidence({ executablePath: 'ariava' }), version, deps)).toBeUndefined();
    expect(proveStableCli(evidence({ packageVersion: '0.1.5' }), version, deps)).toBeUndefined();
    expect(proveStableCli(evidence({ packageRoot: '/tmp/npm-cache/lib/node_modules/ariava' }), version, deps)).toBeUndefined();
  });

  test('reuses an existing exact stable installation when invoked from npx', () => {
    const fixture = dependencies({ currentCli: { executablePath: '/tmp/npm-cache/_npx/ariava' } });
    const result = bootstrapStableCli({ version, publicArgs: ['--extension', 'pi'], resumed: false }, fixture.deps);
    expect(fixture.calls).not.toContain(`run npm install --global ariava@${version}`);
    expect(result).toMatchObject({
      status: 'reused',
      reentry: { command: executable, args: ['setup', '--extension', 'pi', '--resume', '--bootstrap-version', version, '--bootstrap-once'] },
    });
  });

  test('installs the exact current version with no sudo and preserves public re-entry arguments', () => {
    const fixture = dependencies({ currentCli: { executablePath: '/tmp/npm-cache/_npx/ariava' }, stableExecutable: undefined, packageVersion: '0.1.5' });
    const result = bootstrapStableCli({
      version,
      publicArgs: ['--extension', 'pi', '--json', '--resume', '--bootstrap-version', 'bad', '--bootstrap-once'],
      resumed: false,
    }, fixture.deps);

    expect(fixture.calls).toContain(`run npm install --global ariava@${version}`);
    expect(fixture.calls.join('\n')).not.toContain('sudo');
    expect(result).toEqual({
      status: 'installed',
      evidence: evidence(),
      reentry: {
        command: executable,
        args: ['setup', '--extension', 'pi', '--json', '--resume', '--bootstrap-version', version, '--bootstrap-once'],
      },
    });
  });

  test('fails before install for an unavailable or unwritable global prefix', () => {
    const unavailable = dependencies({ currentCli: { executablePath: '/tmp/cache/ariava' }, resolvedPrefix: '' });
    expect(() => bootstrapStableCli({ version, publicArgs: [], resumed: false }, unavailable.deps)).toThrow();
    expect(unavailable.calls.some((call) => call.startsWith('run '))).toBe(false);

    const unwritable = dependencies({ currentCli: { executablePath: '/tmp/cache/ariava' }, writableError: new Error('EACCES') });
    try {
      bootstrapStableCli({ version, publicArgs: [], resumed: false }, unwritable.deps);
    } catch (error) {
      expect(error).toMatchObject({ code: 'ERR_STABLE_CLI_INSTALL', data: { step: 'stable-cli', retryable: true } });
    }
    expect(unwritable.calls.some((call) => call.startsWith('run '))).toBe(false);
  });

  test('classifies install failure, exact-version mismatch, and re-entry loops', () => {
    const failed = dependencies({
      currentCli: { executablePath: '/tmp/cache/ariava' },
      installResult: { status: 1, stdout: '', stderr: 'registry token=secret' },
      packageVersion: '0.1.5',
    });
    expect(() => bootstrapStableCli({ version, publicArgs: [], resumed: false }, failed.deps)).toThrow();

    const mismatch = dependencies({
      currentCli: { executablePath: '/tmp/cache/ariava' },
      packageVersion: '0.1.5',
      installedPackageVersion: '0.1.5',
    });
    expect(() => bootstrapStableCli({ version, publicArgs: [], resumed: false }, mismatch.deps)).toThrow();

    for (const input of [
      { version, publicArgs: [] as string[], resumed: true, bootstrapVersion: '0.1.5' },
      { version, publicArgs: [] as string[], resumed: true, bootstrapVersion: version },
    ]) {
      const loop = dependencies({ currentCli: { executablePath: '/tmp/cache/ariava' }, packageVersion: '0.1.5' });
      expect(() => bootstrapStableCli(input, loop.deps)).toThrow();
      expect(loop.calls.some((call) => call.startsWith('run '))).toBe(false);
    }
  });
});
