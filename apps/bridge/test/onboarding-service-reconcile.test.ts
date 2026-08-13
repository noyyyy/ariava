import { describe, expect, test } from 'bun:test';
import type { HostPrivateKeyStorage } from '../src/identity/types';
import type { AriavaInstallMetadata } from '../src/host-manager/config';
import { AriavaCliError } from '../src/host-manager/service/errors';
import type {
  AriavaServiceInstallRecord,
  ServiceBackend,
  ServiceStatus,
} from '../src/host-manager/service/types';
import {
  reconcileOnboardingService,
  type OnboardingServiceManagerPort,
  type OnboardingServiceReconcileDependencies,
} from '../src/host-manager/onboarding/service-reconcile';

const runtimePath = '/usr/bin/node';
const ariavaBinPath = '/prefix/bin/ariava';
const configPath = '/home/test/.config/ariava/config.json';
const identityReference: HostPrivateKeyStorage = {
  type: 'linux-json',
  path: '/home/test/.config/ariava/host-identity.json',
};

function serviceRecord(backend: ServiceBackend = 'systemd-user'): AriavaServiceInstallRecord {
  return {
    backend,
    installedAt: '2026-08-13T00:00:00.000Z',
    runtimePath,
    ariavaBinPath,
    configPath,
    identityReference,
    definitionPath: backend === 'launchd'
      ? '/home/test/Library/LaunchAgents/io.noyx.ariava.bridge.plist'
      : '/home/test/.config/systemd/user/ariava.service',
    serviceId: backend === 'launchd' ? 'io.noyx.ariava.bridge' : 'ariava.service',
  };
}

function status(
  record: AriavaServiceInstallRecord | undefined,
  overrides: Partial<ServiceStatus> = {},
): ServiceStatus {
  return {
    backend: 'systemd-user',
    support: {
      platform: 'linux',
      backend: 'systemd-user',
      supported: true,
      isWsl: false,
      reason: 'supported',
    },
    installed: Boolean(record),
    enabled: Boolean(record),
    loaded: Boolean(record),
    processRunning: Boolean(record),
    runtimePath: record?.runtimePath,
    ariavaBinPath: record?.ariavaBinPath,
    runtimePathMatchesCurrent: Boolean(record),
    ariavaBinPathMatchesCurrent: Boolean(record),
    logBackend: 'journald',
    ...overrides,
  };
}

function managerFixture(options: {
  backend?: ServiceBackend;
  status(record: AriavaServiceInstallRecord | undefined): ServiceStatus;
  start?(): void;
}) {
  const calls: string[] = [];
  const backend = options.backend ?? 'systemd-user';
  const manager: OnboardingServiceManagerPort = {
    backend,
    install(input) {
      calls.push('install');
      return { ...serviceRecord(backend), ...input };
    },
    start() {
      calls.push('start');
      options.start?.();
    },
    status(record) {
      calls.push('status');
      return options.status(record);
    },
  };
  return { calls, manager };
}

function input(metadata: AriavaInstallMetadata) {
  return { runtimePath, ariavaBinPath, configPath, identityReference, metadata };
}

function dependencies(
  manager: OnboardingServiceManagerPort,
  calls: string[],
  overrides: Partial<OnboardingServiceReconcileDependencies> = {},
): OnboardingServiceReconcileDependencies {
  return {
    serviceManager: manager,
    persistServiceInstallMetadata: () => { calls.push('metadata.save'); },
    throwIfCancelled: () => { calls.push('cancel'); },
    sleep: async (milliseconds) => { calls.push(`sleep:${milliseconds}`); },
    now: () => '2026-08-13T00:00:00.000Z',
    ...overrides,
  };
}

function releaseMetadata(service = serviceRecord()): AriavaInstallMetadata {
  return {
    installer: { manager: 'npm', ariavaBinRealPath: ariavaBinPath, recordedAt: '2026-08-13T00:00:00.000Z' },
    bridgeSource: { kind: 'npm-package', package: 'ariava@1.2.3', updatedAt: '2026-08-13T00:00:00.000Z' },
    service,
  };
}

describe('onboarding service reconciliation', () => {
  test('returns reused for a fully ready service without install, metadata persistence, or start', async () => {
    const fixture = managerFixture({ status: (record) => status(record) });
    const metadata = releaseMetadata();

    const result = await reconcileOnboardingService(input(metadata), dependencies(fixture.manager, fixture.calls));

    expect(result).toEqual({ record: metadata.service, metadata, reused: true, action: 'reused' });
    expect(fixture.calls).toEqual(['status']);
  });

  test('reconciles stale release-owned service with exact install, persist, status order and no start when ready', async () => {
    const fixture = managerFixture({ status: (record) => status(record, {
      runtimePath: record?.runtimePath === runtimePath ? runtimePath : '/old/node',
      ariavaBinPath: record?.ariavaBinPath === ariavaBinPath ? ariavaBinPath : '/old/ariava',
      runtimePathMatchesCurrent: record?.runtimePath === runtimePath,
      ariavaBinPathMatchesCurrent: record?.ariavaBinPath === ariavaBinPath,
    }) });
    const metadata = releaseMetadata({
      ...serviceRecord(),
      runtimePath: '/old/node',
      ariavaBinPath: '/old/ariava',
    });

    const result = await reconcileOnboardingService(input(metadata), dependencies(fixture.manager, fixture.calls));

    expect(result).toEqual({
      record: serviceRecord(),
      metadata: {
        ...metadata,
        service: serviceRecord(),
      },
      reused: false,
      action: 'reconciled',
    });
    expect(fixture.calls).toEqual(['status', 'cancel', 'install', 'metadata.save', 'status', 'status']);
    expect(fixture.calls).not.toContain('start');
  });


  test('rejects service metadata from a different backend before status or effects', async () => {
    const fixture = managerFixture({ status: (record) => status(record) });

    try {
      await reconcileOnboardingService(input(releaseMetadata(serviceRecord('launchd'))), dependencies(fixture.manager, fixture.calls));
      throw new Error('expected backend mismatch');
    } catch (error) {
      expect(error).toBeInstanceOf(AriavaCliError);
      expect(error).toMatchObject({
        code: 'ERR_SERVICE_METADATA',
        message: 'Service metadata belongs to a different backend.',
        data: { step: 'bridge-service', retryable: false },
      });
    }
    expect(fixture.calls).toEqual([]);
  });

  test('refuses stale service reconciliation when release ownership is unproven', async () => {
    const fixture = managerFixture({
      status: (record) => status(record, {
        runtimePath: '/old/node',
        ariavaBinPath: '/old/ariava',
        runtimePathMatchesCurrent: false,
        ariavaBinPathMatchesCurrent: false,
      }),
    });
    const metadata: AriavaInstallMetadata = {
      ...releaseMetadata(),
      bridgeSource: { kind: 'dev-repo', path: '/repo/ariava', updatedAt: '2026-08-13T00:00:00.000Z' },
    };

    try {
      await reconcileOnboardingService(input(metadata), dependencies(fixture.manager, fixture.calls));
      throw new Error('expected stale ownership rejection');
    } catch (error) {
      expect(error).toBeInstanceOf(AriavaCliError);
      expect(error).toMatchObject({
        code: 'ERR_SERVICE_METADATA',
        message: 'Stale service state cannot be reconciled without proven release ownership.',
        data: { step: 'bridge-service', retryable: false },
      });
    }
    expect(fixture.calls).toEqual(['status']);
  });

  test('starts an installed but stopped service without reinstalling or saving metadata', async () => {
    let running = false;
    const fixture = managerFixture({
      status: (record) => status(record, { processRunning: running }),
      start: () => { running = true; },
    });
    const metadata = releaseMetadata();

    const result = await reconcileOnboardingService(input(metadata), dependencies(fixture.manager, fixture.calls));

    expect(result).toEqual({ record: metadata.service, metadata, reused: false, action: 'started' });
    expect(fixture.calls).toEqual(['status', 'cancel', 'cancel', 'start', 'status']);
  });

  test('persists a fresh install record before status, start, and readiness polling', async () => {
    let installed = false;
    let running = false;
    const fixture = managerFixture({
      status: (record) => status(record, {
        installed: installed && Boolean(record),
        enabled: installed && Boolean(record),
        loaded: installed && Boolean(record),
        processRunning: running,
      }),
      start: () => { running = true; },
    });
    const originalInstall = fixture.manager.install.bind(fixture.manager);
    fixture.manager.install = (installInput) => {
      const record = originalInstall(installInput);
      installed = true;
      return record;
    };
    const metadata: AriavaInstallMetadata = {
      installer: { manager: 'npm', ariavaBinRealPath: ariavaBinPath, recordedAt: '2026-08-13T00:00:00.000Z' },
      bridgeSource: { kind: 'npm-package', package: 'ariava@1.2.3', updatedAt: '2026-08-13T00:00:00.000Z' },
    };

    const result = await reconcileOnboardingService(input(metadata), dependencies(fixture.manager, fixture.calls));

    expect(result.action).toBe('installed');
    expect(result.metadata.service).toEqual(result.record);
    expect(fixture.calls).toEqual([
      'status', 'cancel', 'install', 'metadata.save', 'status', 'cancel', 'start', 'status',
    ]);
  });

  test('times out after bounded polling with the existing retryable service failure', async () => {
    const fixture = managerFixture({ status: (record) => status(record, { processRunning: false }) });

    try {
      await reconcileOnboardingService(
        input(releaseMetadata()),
        dependencies(fixture.manager, fixture.calls, { timeoutMs: 5, pollIntervalMs: 2 }),
      );
      throw new Error('expected service timeout');
    } catch (error) {
      expect(error).toBeInstanceOf(AriavaCliError);
      expect(error).toMatchObject({
        code: 'ERR_ONBOARDING_NOT_READY',
        message: 'Bridge service did not reach running state.',
        data: { step: 'bridge-service', retryable: true },
      });
    }
    expect(fixture.calls).toEqual([
      'status', 'cancel', 'cancel', 'start', 'status',
      'cancel', 'sleep:2', 'status', 'cancel', 'sleep:2', 'status', 'cancel', 'sleep:1', 'status',
    ]);
  });

  test('propagates cancellation during readiness wait before sleeping or further status reads', async () => {
    const fixture = managerFixture({ status: (record) => status(record, { processRunning: false }) });
    let cancellationChecks = 0;
    const cancellation = new Error('cancelled during service wait');
    const deps = dependencies(fixture.manager, fixture.calls, {
      throwIfCancelled: () => {
        fixture.calls.push('cancel');
        cancellationChecks += 1;
        if (cancellationChecks === 3) throw cancellation;
      },
    });

    await expect(reconcileOnboardingService(input(releaseMetadata()), deps)).rejects.toBe(cancellation);
    expect(fixture.calls).toEqual(['status', 'cancel', 'cancel', 'start', 'status', 'cancel']);
  });
});
