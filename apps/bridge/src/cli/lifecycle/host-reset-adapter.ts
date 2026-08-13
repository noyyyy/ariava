import type { HostPrivateKeyStorage } from '../../identity/types';
import type { AriavaInstallMetadata, ResolvedAriavaConfig } from '../../host-manager/config';
import type { InstallMetadataLoadResult } from '../../host-manager/service/migration';
import { AriavaCliError } from '../../host-manager/service/errors';
import { supportError } from '../../host-manager/service/platform';
import type {
  AriavaServiceInstallRecord,
  ServiceInstallInput,
  ServiceInstallOptions,
  ServiceStatus,
  ServiceSupport,
} from '../../host-manager/service/types';
import type { HostDomainResetLifecycleAdapter } from '../operations/host-domain-reset';

interface HostResetServiceManagerPort {
  readonly backend?: AriavaServiceInstallRecord['backend'];
  readonly support: ServiceSupport;
  install(input: ServiceInstallInput, options?: ServiceInstallOptions): AriavaServiceInstallRecord;
  start(record?: AriavaServiceInstallRecord): void;
  stop(record?: AriavaServiceInstallRecord): void;
  status(
    record: AriavaServiceInstallRecord | undefined,
    currentRuntimePath: string,
    currentAriavaBinPath: string,
  ): ServiceStatus;
}

export interface DefaultHostResetAdapterDependencies {
  createServiceManager(): HostResetServiceManagerPort;
  loadInstallMetadataDetailed(): InstallMetadataLoadResult;
  resolveAriavaConfig(): ResolvedAriavaConfig;
  serviceInstallInput(resolved: ResolvedAriavaConfig): ServiceInstallInput;
  mergeInstallMetadata(patch: Partial<AriavaInstallMetadata>): AriavaInstallMetadata;
  realpath(path: string): string;
  currentRuntimePath(): string;
  currentAriavaBinPath(): string;
}

export function createDefaultHostDomainResetLifecycle(
  deps: DefaultHostResetAdapterDependencies,
): HostDomainResetLifecycleAdapter {
  let manager: HostResetServiceManagerPort | undefined;
  let record: AriavaInstallMetadata['service'];
  const runtimePath = () => deps.realpath(deps.currentRuntimePath());
  const binPath = () => deps.realpath(deps.currentAriavaBinPath());
  return {
    prepare() {
      manager = deps.createServiceManager();
      requireServiceSupport(manager);
      const metadata = deps.loadInstallMetadataDetailed();
      if (!metadata.diagnostics.serviceMetadataValid) {
        throw new AriavaCliError('ERR_SERVICE_METADATA', 'Service metadata is invalid; repair it before Host reset.');
      }
      record = metadata.metadata.service;
      if (!record) {
        return { managed: true, installed: false, enabled: false, wasRunning: false, backend: manager.backend! };
      }
      if (record.backend !== manager.backend) {
        throw new AriavaCliError('ERR_SERVICE_METADATA', 'Service backend does not match the current platform.');
      }
      const status = manager.status(record, runtimePath(), binPath());
      if (!status.installed) {
        throw new AriavaCliError(
          'ERR_SERVICE_METADATA',
          'Service install metadata is stale; remove or repair it before Host reset.',
        );
      }
      return { managed: true, installed: true, enabled: status.enabled, wasRunning: status.processRunning, backend: record.backend };
    },
    stopAndConfirm(snapshot) {
      if (!snapshot.installed || !record || !manager) return;
      if (snapshot.wasRunning) manager.stop(record);
      const status = manager.status(record, runtimePath(), binPath());
      if (status.processRunning) throw new AriavaCliError('ERR_SERVICE_COMMAND', 'Ariava service did not stop before Host reset.');
    },
    synchronizeMetadata(snapshot, identityReference) {
      if (!snapshot.installed || !record || !manager) return;
      const resolved = deps.resolveAriavaConfig();
      const refreshed = manager.install({ ...deps.serviceInstallInput(resolved), identityReference }, {
        enabled: snapshot.enabled,
        start: false,
      });
      record = refreshed;
      deps.mergeInstallMetadata({ service: refreshed, identityPath: resolved.identityPath });
    },
    restoreAndConfirm(snapshot, identityReference) {
      if (!snapshot.installed || !record || !manager) return false;
      assertIdentityReference(record, identityReference);
      const current = manager.status(record, runtimePath(), binPath());
      if (snapshot.wasRunning && !current.processRunning) manager.start(record);
      return assertRestoredState(snapshot, record, manager, runtimePath(), binPath());
    },
    validateRestored(snapshot, identityReference) {
      if (!snapshot.installed || !record || !manager) return false;
      assertIdentityReference(record, identityReference);
      return assertRestoredState(snapshot, record, manager, runtimePath(), binPath());
    },
  };
}

function assertIdentityReference(
  record: AriavaServiceInstallRecord,
  expected: HostPrivateKeyStorage,
): void {
  if (JSON.stringify(record.identityReference) !== JSON.stringify(expected)) {
    throw new AriavaCliError('ERR_SERVICE_METADATA', 'Service metadata identity does not match the replacement Host.');
  }
}

function assertRestoredState(
  snapshot: Parameters<HostDomainResetLifecycleAdapter['restoreAndConfirm']>[0],
  record: AriavaServiceInstallRecord,
  manager: HostResetServiceManagerPort,
  runtimePath: string,
  binPath: string,
): boolean {
  const status = manager.status(record, runtimePath, binPath);
  if (status.processRunning !== snapshot.wasRunning) {
    throw new AriavaCliError('ERR_SERVICE_COMMAND', 'Ariava service state could not be restored after Host reset.');
  }
  return status.processRunning;
}

function requireServiceSupport(manager: HostResetServiceManagerPort): void {
  if (!manager.support.supported) throw supportError(manager.support);
}
