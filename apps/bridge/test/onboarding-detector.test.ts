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
  config?: ReturnType<OnboardingDetectorDependencies['loadConfig']>;
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
      return options.config ?? { relayBaseUrl: 'https://ariava-relay.noyx.io' };
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

  test('classifies an existing dev config as present-isolated and continues detection', () => {
    const probe = detector({ devPathExists: true });
    const detection = detectOnboardingEnvironment(probe.deps);

    expect(detection.sourceDev).toEqual({
      kind: 'present-isolated',
      devRoot: '/home/test/.config/ariava-dev',
      devConfigPath: '/home/test/.config/ariava-dev/config.json',
    });
    expect(detection.installMetadata).toEqual({});
    expect(probe.calls).toEqual([
      'load-config /home/test/.config/ariava/config.json',
      'load-install',
      'exists /home/test/.config/ariava-dev/config.json',
      'npm --version',
      'pi --version',
      'service-support',
    ]);
  });

  test('isolated dev config with normal npm metadata succeeds', () => {
    const probe = detector({
      devPathExists: true,
      installMetadata: {
        bridgeSource: { kind: 'npm-package', package: 'ariava@1.2.3', updatedAt: 'now' },
        piSource: { kind: 'npm-package', package: '@ariava/pi-extension@1.2.3', updatedAt: 'now' },
      },
    });

    const detection = detectOnboardingEnvironment(probe.deps);

    expect(detection.sourceDev.kind).toBe('present-isolated');
    expect(detection.installMetadata.bridgeSource?.kind).toBe('npm-package');
    expect(detection.installMetadata.piSource?.kind).toBe('npm-package');
  });

  test('fails closed for dev source metadata with precise redacted contamination detail', () => {
    const probe = detector({
      installMetadata: {
        bridgeSource: { kind: 'dev-repo' as const, path: '/secret/repo', updatedAt: 'now' },
        piSource: { kind: 'explicit-path' as const, path: '/secret/pi', updatedAt: 'now' },
      },
    });

    try {
      detectOnboardingEnvironment(probe.deps);
      throw new Error('expected detector to reject contaminated production metadata');
    } catch (error) {
      expect(error).toMatchObject({
        code: 'ERR_PRODUCTION_PROFILE_CONTAMINATED',
        message: 'Production onboarding cannot safely continue because production resources point to source development evidence.',
        data: {
          step: 'preflight',
          retryable: false,
          sourceDev: {
            kind: 'production-contaminated',
            issues: [
              { resource: 'installMetadata.bridgeSource', sourceKind: 'dev-repo' },
              { resource: 'installMetadata.piSource', sourceKind: 'explicit-path' },
            ],
          },
          remediation: { message: 'Repair or remove the contaminated production config or install metadata, then retry production onboarding.' },
        },
      });
      expect(JSON.stringify(error)).not.toContain('/secret/repo');
      expect(JSON.stringify(error)).not.toContain('/secret/pi');
      expect(JSON.stringify(error)).not.toContain('Exit Ariava source dev mode explicitly');
    }
  });

  test('fails closed for ambiguous explicit-path metadata without exposing source paths', () => {
    const probe = detector({
      installMetadata: { bridgeSource: { kind: 'explicit-path' as const, path: '/secret/repo', updatedAt: 'now' } },
    });

    try {
      detectOnboardingEnvironment(probe.deps);
      throw new Error('expected detector to reject ambiguous production metadata');
    } catch (error) {
      expect(error).toMatchObject({
        code: 'ERR_PRODUCTION_INSTALL_METADATA_AMBIGUOUS',
        data: {
          sourceDev: {
            kind: 'ambiguous',
            issues: [{ resource: 'installMetadata.bridgeSource', sourceKind: 'explicit-path' }],
          },
        },
      });
      expect(JSON.stringify(error)).not.toContain('/secret/repo');
      expect(JSON.stringify(error)).not.toContain('Exit Ariava source dev mode explicitly');
    }
  });

  test('fails closed when production config points to source dev profile resources', () => {
    for (const [resource, config] of [
      ['productionConfig.agentAdapterConfigPath', { agentAdapterConfigPath: '/home/test/.config/ariava-dev/agent-adapter.json' }],
      ['productionConfig.statePath', { statePath: '/home/test/.config/ariava-dev/state/bridge-state.json' }],
      ['productionConfig.identityPath', { identityPath: '/home/test/.config/ariava-dev/host-identity.json' }],
      ['productionConfig.agentAdapterPort', { agentAdapterPort: 7273 }],
    ] as const) {
      const probe = detector({ config });
      try {
        detectOnboardingEnvironment(probe.deps);
        throw new Error(`expected detector to reject ${resource}`);
      } catch (error) {
        expect(error).toMatchObject({
          code: 'ERR_PRODUCTION_PROFILE_CONTAMINATED',
          data: {
            step: 'preflight',
            retryable: false,
            sourceDev: {
              kind: 'production-contaminated',
              issues: [{ resource }],
            },
          },
        });
        expect(JSON.stringify(error)).not.toContain('Exit Ariava source dev mode explicitly');
      }
    }
    const configPathProbe = detector();
    configPathProbe.deps.configPath = '/home/test/.config/ariava-dev/config.json';
    try {
      detectOnboardingEnvironment(configPathProbe.deps);
      throw new Error('expected detector to reject productionConfig.configPath');
    } catch (error) {
      expect(error).toMatchObject({
        code: 'ERR_PRODUCTION_PROFILE_CONTAMINATED',
        data: {
          sourceDev: {
            kind: 'production-contaminated',
            issues: [{ resource: 'productionConfig.configPath' }],
          },
        },
      });
      expect(JSON.stringify(error)).not.toContain('Exit Ariava source dev mode explicitly');
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
