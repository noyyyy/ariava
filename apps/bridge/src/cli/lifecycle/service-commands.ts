import { AriavaCliError } from '../../host-manager/service/errors';
import { supportError } from '../../host-manager/service/platform';
import type { ServiceInstallInput } from '../../host-manager/service/types';
import { okEnvelope, printJson } from '../../host-manager/output';
import type { AriavaInstallMetadata, ResolvedAriavaConfig } from '../../host-manager/config';
import type { PublicCliDependencies } from './default-context';
import { formatServiceStatus, selectDefaultPresentation } from './default-presenters';
import { probeCurrentServiceStatus } from './default-probes';

type ServiceCommandDependencies = Pick<PublicCliDependencies,
  | 'createServiceManager'
  | 'loadInstallMetadata'
  | 'resolveAriavaConfig'
  | 'mergeInstallMetadata'
  | 'realpath'
  | 'currentRuntimePath'
  | 'currentAriavaBinPath'
  | 'stdout'>;

type LogsCommandDependencies = Pick<PublicCliDependencies,
  | 'createServiceManager'
  | 'loadInstallMetadata'
  | 'stdout'>;

export interface ServiceCommandPorts {
  serviceInstallInput(resolved: ResolvedAriavaConfig): ServiceInstallInput;
  installerPatch(metadata: AriavaInstallMetadata): Partial<AriavaInstallMetadata>;
  relayBaseUrl(): string;
}

const SERVICE_WRITE_COMMANDS = new Set([
  'install',
  'reinstall',
  'uninstall',
  'start',
  'stop',
  'restart',
]);

export async function runServiceCommand(
  deps: ServiceCommandDependencies,
  ports: ServiceCommandPorts,
  argv: string[],
  json: boolean,
): Promise<void> {
  const subcommand = argv[0] ?? 'status';
  const manager = deps.createServiceManager();
  if (SERVICE_WRITE_COMMANDS.has(subcommand)) requireServiceSupport(manager);

  const installMetadata = deps.loadInstallMetadata();
  const service = installMetadata.service;

  switch (subcommand) {
    case 'install':
    case 'reinstall': {
      const resolved = deps.resolveAriavaConfig();
      const record = manager.install(ports.serviceInstallInput(resolved));
      deps.mergeInstallMetadata({
        service: record,
        identityPath: resolved.identityPath,
        bridgeSource: installMetadata.bridgeSource ?? { kind: 'release-bundle', updatedAt: record.installedAt },
        ...ports.installerPatch(installMetadata),
      });
      print(
        deps,
        json,
        okEnvelope('ok', `Ariava service ${subcommand}ed.`, record),
        `Installed ${record.backend} service at ${record.definitionPath}`,
      );
      return;
    }
    case 'uninstall':
      if (service?.backend === manager.backend) {
        manager.uninstall(service);
        deps.mergeInstallMetadata({ service: undefined });
      } else if (!service) {
        manager.uninstall();
      }
      print(
        deps,
        json,
        okEnvelope('ok', 'Ariava service uninstalled.', {}),
        service && service.backend !== manager.backend
          ? 'Current service backend is not installed. Foreign service metadata retained.'
          : 'Service uninstalled.',
      );
      return;
    case 'status': {
      const status = probeCurrentServiceStatus(deps, manager, installMetadata);
      const resolved = deps.resolveAriavaConfig();
      const data = { ...status, relayBaseUrl: ports.relayBaseUrl(), logDir: resolved.logDir };
      print(deps, json, okEnvelope('ok', 'Ariava service status.', data), formatServiceStatus(data));
      return;
    }
    case 'start':
    case 'restart': {
      if (!service || service.backend !== manager.backend
        || !probeCurrentServiceStatus(deps, manager, installMetadata).installed) {
        throw new AriavaCliError(
          'ERR_SERVICE_NOT_INSTALLED',
          'Ariava service is not installed. Run `ariava service install` first.',
          { advice: 'ariava service install' },
        );
      }
      manager[subcommand](service);
      print(
        deps,
        json,
        okEnvelope('ok', `Ariava service ${subcommand}ed.`, {}),
        `Service ${subcommand}ed.`,
      );
      return;
    }
    case 'stop':
      if (service?.backend === manager.backend
        && probeCurrentServiceStatus(deps, manager, installMetadata).loaded) {
        manager.stop(service);
      }
      print(deps, json, okEnvelope('ok', 'Ariava service stopped.', {}), 'Service stopped.');
      return;
    default:
      throw new Error(`Unknown service command: ${subcommand}`);
  }
}

export async function runLogsCommand(
  deps: LogsCommandDependencies,
  json: boolean,
): Promise<void> {
  const manager = deps.createServiceManager();
  requireServiceSupport(manager);
  const record = deps.loadInstallMetadata().service;
  const logs = manager.logs(record?.backend === manager.backend ? record : undefined);
  const human = logs.source === 'files'
    ? [`Stdout: ${logs.stdoutPath}`, `Stderr: ${logs.stderrPath}`, logs.text].join('\n')
    : logs.text;
  print(deps, json, okEnvelope('ok', 'Ariava service logs.', logs), human);
}

function requireServiceSupport(manager: ReturnType<PublicCliDependencies['createServiceManager']>): void {
  if (!manager.support.supported) throw supportError(manager.support);
}

function print(
  deps: Pick<PublicCliDependencies, 'stdout'>,
  json: boolean,
  envelope: unknown,
  human: string,
): void {
  const presentation = selectDefaultPresentation(json, envelope, human);
  if (presentation.channel === 'json') {
    printJson(presentation.value, deps.stdout);
    return;
  }
  deps.stdout.write(`${presentation.value}\n`);
}
