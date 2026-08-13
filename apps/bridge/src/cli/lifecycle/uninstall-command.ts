import { okEnvelope, printJson } from '../../host-manager/output';
import { supportError } from '../../host-manager/service/platform';
import type {
  AriavaServiceInstallRecord,
  ServiceBackend,
  ServiceSupport,
} from '../../host-manager/service/types';

type UninstallAssetSourceKind =
  | 'release-bundle'
  | 'npm-package'
  | 'dev-repo'
  | 'explicit-path';

interface UninstallAssetSource {
  kind: UninstallAssetSourceKind;
  path?: string;
  package?: string;
  updatedAt: string;
}

interface UninstallPiInstallRecord {
  installedAt: string;
  version: string;
  managedPath: string;
  source: UninstallAssetSource;
}

export interface UninstallServiceManager {
  readonly backend?: ServiceBackend;
  readonly support: ServiceSupport;
  uninstall(record?: AriavaServiceInstallRecord): void;
}

export interface UninstallInstallMetadata {
  service?: AriavaServiceInstallRecord;
  piExtension?: UninstallPiInstallRecord;
  piSource?: UninstallAssetSource;
}

export interface UninstallCommandDependencies {
  createServiceManager(): UninstallServiceManager;
  loadInstallMetadata(): UninstallInstallMetadata;
  saveInstallMetadata(metadata: UninstallInstallMetadata): void;
  removePath(path: string): void;
  stdout: NodeJS.WritableStream;
}

export interface UninstallCommandPorts {
  removePiPackage(): void;
  configRoot: string;
}

export async function runUninstallCommand(
  deps: UninstallCommandDependencies,
  ports: UninstallCommandPorts,
  argv: string[],
  json: boolean,
): Promise<void> {
  const purge = argv.includes('--purge');
  const removePi = argv.includes('--remove-pi') || purge;
  const installMetadata = deps.loadInstallMetadata();
  const manager = deps.createServiceManager();
  const currentService = installMetadata.service?.backend === manager.backend
    ? installMetadata.service
    : undefined;
  const backendMismatch = Boolean(installMetadata.service && !currentService);

  if (!backendMismatch) {
    requireServiceSupport(manager);
    manager.uninstall(currentService);
  }

  if (removePi) ports.removePiPackage();

  if (purge) {
    deps.removePath(ports.configRoot);
  } else {
    deps.saveInstallMetadata({
      ...installMetadata,
      service: currentService ? undefined : installMetadata.service,
      ...(removePi ? { piExtension: undefined, piSource: undefined } : {}),
    });
  }

  const data = {
    purge,
    removedPi: removePi,
    ...(backendMismatch ? { backendMismatch: true } : {}),
  };
  const human = purge
    ? 'Ariava config, service, and managed assets removed.'
    : backendMismatch
      ? 'Current service backend is not installed. Foreign service metadata retained.'
      : 'Ariava service removed. Config retained.';
  print(
    deps,
    json,
    okEnvelope('ok', 'Ariava uninstall completed.', data),
    human,
  );
}

function requireServiceSupport(manager: UninstallServiceManager): void {
  if (!manager.support.supported) throw supportError(manager.support);
}

function print(
  deps: Pick<UninstallCommandDependencies, 'stdout'>,
  json: boolean,
  envelope: unknown,
  human: string,
): void {
  if (json) {
    printJson(envelope, deps.stdout);
    return;
  }
  deps.stdout.write(`${human}\n`);
}
