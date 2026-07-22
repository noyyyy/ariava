import { describe, expect, test } from 'bun:test';
import type { AriavaInstallMetadata } from '../src/host-manager/config';
import type { CommandResult, ServiceSupport } from '../src/host-manager/service/types';
import {
  detectOnboardingEnvironment,
  validateOnboardingSelection,
  type OnboardingDetectorDependencies,
} from '../src/host-manager/onboarding';

const supportedMac: ServiceSupport = {
  platform: 'darwin',
  backend: 'launchd',
  supported: true,
  isWsl: false,
  reason: 'supported',
};

function detector(options: {
  platform?: NodeJS.Platform;
  support?: ServiceSupport;
  results?: CommandResult[];
  installMetadata?: AriavaInstallMetadata;
  devPathExists?: boolean;
} = {}) {
  const calls: string[] = [];
  const results = [...(options.results ?? [
    { status: 0, stdout: '10.8.2\n', stderr: '' },
    { status: 0, stdout: 'pi 0.50.0\n', stderr: '' },
  ])];
  const deps: OnboardingDetectorDependencies = {
    platform: options.platform ?? 'darwin',
    architecture: 'arm64',
    nodeVersion: 'v22.18.0',
    runner: {
      run(command, args) {
        calls.push(`${command} ${args.join(' ')}`);
        return results.shift() ?? { status: 1, stdout: '', stderr: '' };
      },
    },
    detectServiceSupport() {
      calls.push('service-support');
      return options.support ?? supportedMac;
    },
    isTty: true,
    machineOutput: false,
    configPath: '/home/test/.config/ariava/config.json',
    devConfigPath: '/home/test/.config/ariava-dev/config.json',
    pathExists(path) {
      calls.push(`exists ${path}`);
      return path === '/home/test/.config/ariava-dev/config.json' && Boolean(options.devPathExists);
    },
    loadConfig(path) {
      calls.push(`load-config ${path}`);
      return { relayBaseUrl: 'https://ariava-relay.noyx.io' };
    },
    loadInstallMetadata() {
      calls.push('load-install');
      return options.installMetadata ?? {};
    },
    currentCli: { executablePath: '/tmp/npm-cache/ariava' },
  };
  return { calls, deps };
}

describe('onboarding detector', () => {
  test('collects read-only platform, service, npm, and Pi evidence with argument arrays', () => {
    const probe = detector();
    const detection = detectOnboardingEnvironment(probe.deps);

    expect(detection).toMatchObject({
      platform: 'darwin',
      architecture: 'arm64',
      nodeVersion: 'v22.18.0',
      npm: { present: true, version: '10.8.2' },
      pi: { present: true, version: 'pi 0.50.0' },
      interactive: true,
      machineOutput: false,
      serviceSupport: supportedMac,
    });
    expect(probe.calls).toEqual([
      'load-config /home/test/.config/ariava/config.json',
      'load-install',
      'exists /home/test/.config/ariava-dev/config.json',
      'npm --version',
      'pi --version',
      'service-support',
    ]);
  });

  test('distinguishes ENOENT from a nonzero runtime probe', () => {
    const missing = Object.assign(new Error('spawn pi ENOENT'), { code: 'ENOENT' });
    const probe = detector({ results: [
      { status: 2, stdout: '', stderr: 'npm failed' },
      { status: null, stdout: '', stderr: '', error: missing },
    ] });

    const detection = detectOnboardingEnvironment(probe.deps);
    expect(detection.npm).toEqual({ present: false, reason: 'probe-failed' });
    expect(detection.pi).toEqual({ present: false, reason: 'not-found' });
  });

  test('reports Linux and WSL service capability without altering it', () => {
    for (const support of [
      { platform: 'linux', backend: 'systemd-user', supported: true, isWsl: false, reason: 'supported' },
      { platform: 'linux', backend: 'systemd-user', supported: true, isWsl: true, reason: 'supported' },
      { platform: 'linux', backend: 'systemd-user', supported: false, isWsl: true, reason: 'systemd-user-manager-unavailable' },
      { platform: 'win32', supported: false, isWsl: false, reason: 'unsupported-platform' },
    ] satisfies ServiceSupport[]) {
      const probe = detector({ platform: support.platform, support });
      expect(detectOnboardingEnvironment(probe.deps).serviceSupport).toEqual(support);
    }
  });

  test('fails closed for a dev profile or dev source metadata and returns redacted remediation', () => {
    for (const options of [
      { devPathExists: true },
      { installMetadata: { bridgeSource: { kind: 'dev-repo' as const, path: '/secret/repo', updatedAt: 'now' } } },
    ]) {
      const probe = detector(options);
      try {
        detectOnboardingEnvironment(probe.deps);
        throw new Error('expected detector to reject dev evidence');
      } catch (error) {
        expect(error).toMatchObject({
          code: 'ERR_STABLE_CLI_PATH',
          data: {
            step: 'preflight',
            retryable: false,
            remediation: { message: 'Exit Ariava source dev mode explicitly, then retry production onboarding.' },
          },
        });
        expect(JSON.stringify(error)).not.toContain('/secret/repo');
      }
    }
  });

  test('validates explicit extension selections and never lets --yes choose', () => {
    expect(validateOnboardingSelection({ extensions: ['pi'], interactive: false })).toEqual({ target: 'adapter-installed', extensions: ['pi'], adapter: 'pi' });
    expect(validateOnboardingSelection({ noExtensions: true, interactive: false })).toEqual({ target: 'host-ready', extensions: [] });
    expect(() => validateOnboardingSelection({ extensions: ['pi'], noExtensions: true, interactive: true })).toThrow();
    try {
      validateOnboardingSelection({ interactive: false });
      throw new Error('expected non-interactive selection failure');
    } catch (error) {
      expect(error).toMatchObject({ code: 'ERR_ONBOARDING_NOT_READY' });
    }
    try {
      validateOnboardingSelection({ interactive: true, yes: true });
      throw new Error('expected --yes selection failure');
    } catch (error) {
      expect(error).toMatchObject({ code: 'ERR_ONBOARDING_NOT_READY' });
    }
    try {
      validateOnboardingSelection({ extensions: ['cursor'], interactive: true });
      throw new Error('expected unknown adapter failure');
    } catch (error) {
      expect(error).toMatchObject({ code: 'ERR_ADAPTER_UNKNOWN' });
    }
  });
});
