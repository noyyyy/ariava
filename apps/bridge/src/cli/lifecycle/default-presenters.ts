import type { PiExtensionStatus } from '../../host-manager/pi-extension';
import type { ServiceStatus } from '../../host-manager/service/types';
import type { HostManagerStatus } from '../../host-manager/status';
import type { BridgeRuntimeHealth } from '../../types';

export interface DevSourcePresentation {
  bridgeSource: { kind: string; path?: string; package?: string };
  piSource: { kind: string; path?: string; package?: string };
}

export interface UpgradeResultPresentation {
  cliVersion: string;
  selfUpgrade: { skipped: boolean; reason?: string; manager?: string };
  config: { updated: boolean; configPath: string };
  service: { updated: boolean; restarted: boolean; installed: boolean; reason?: string; detail?: string };
  piExtension: { updated: boolean; record: { managedPath: string } };
  doctor: Record<string, unknown>;
}

export type DefaultPresentation =
  | { channel: 'json'; value: unknown }
  | { channel: 'human'; value: string };

export function selectDefaultPresentation(
  json: boolean,
  envelope: unknown,
  human: string,
): DefaultPresentation {
  return json ? { channel: 'json', value: envelope } : { channel: 'human', value: human };
}


export function formatStatus(status: HostManagerStatus): string {
  const hostId = status.hostId || status.identity.hostId;
  const fields = [
    { label: 'Version', value: status.cliVersion },
    { label: 'Bridge', value: status.bridgeHealth },
    ...(status.runtimeHealth ? [{
      label: 'Runtime', value: status.runtimeHealth.status, detail: runtimeHealthDetail(status.runtimeHealth),
    }] : []),
    { label: 'Host', value: status.hostName, detail: hostId },
    { label: 'Identity', value: status.identity.status, detail: status.identity.keyId },
    { label: 'Relay', value: status.relayBaseUrl },
    { label: 'Agent', value: `Pi · ${status.piExtension.installed ? 'installed' : 'not installed'}` },
  ];
  const labelWidth = Math.max(...fields.map(({ label }) => label.length));

  return [
    'Ariava',
    '',
    ...fields.flatMap(({ label, value, detail }) => [
      `  ${label.padEnd(labelWidth)}  ${value}`,
      ...(detail ? [`  ${' '.repeat(labelWidth)}  ${detail}`] : []),
    ]),
  ].join('\n');
}

export function formatDevSourceStatus(data: DevSourcePresentation): string {
  const fields = [
    { label: 'Bridge source', value: describeDevSource(data.bridgeSource) },
    { label: 'Pi source', value: describeDevSource(data.piSource) },
  ];
  const labelWidth = Math.max(...fields.map(({ label }) => label.length));
  return [
    'Ariava dev sources',
    '',
    ...fields.map(({ label, value }) => `  ${label.padEnd(labelWidth)}  ${value}`),
  ].join('\n');
}

export function formatServiceStatus(
  status: ServiceStatus & { relayBaseUrl?: string; logDir?: string },
): string {
  return [
    `Service backend: ${status.backend ?? '(unavailable)'}`,
    `Supported: ${status.support.supported}`,
    `Installed: ${status.installed}`,
    `Enabled: ${status.enabled}`,
    `Loaded: ${status.loaded}`,
    `Running: ${status.processRunning}`,
    `Relay base URL: ${status.relayBaseUrl ?? '(not configured)'}`,
    `Log dir: ${status.logDir ?? '(not configured)'}`,
    ...(status.stdoutLogPath ? [`Stdout log: ${status.stdoutLogPath}`] : []),
    ...(status.stderrLogPath ? [`Stderr log: ${status.stderrLogPath}`] : []),
    `Definition: ${status.definitionPath ?? '(not recorded)'}`,
    `Runtime path: ${status.runtimePath ?? '(not recorded)'}`,
    `Ariava bin: ${status.ariavaBinPath ?? '(not recorded)'}`,
  ].join('\n');
}

export function formatUpgradeResult(data: UpgradeResultPresentation): string {
  return [
    'Ariava upgrade',
    `CLI version: ${data.cliVersion}`,
    `Self upgrade: ${data.selfUpgrade.skipped ? `skipped (${data.selfUpgrade.reason ?? 'unknown'})` : data.selfUpgrade.manager ?? 'completed'}`,
    `Config: ${data.config.updated ? 'updated' : 'unchanged'} (${data.config.configPath})`,
    `Service: ${data.service.installed ? data.service.updated ? 'updated' : 'unchanged' : `skipped (${data.service.reason ?? 'not installed'})`}`,
    `Service restart: ${data.service.restarted ? 'yes' : 'no'}`,
    `pi extension: updated (${data.piExtension.record.managedPath})`,
    `Doctor: ${JSON.stringify(data.doctor)}`,
  ].join('\n');
}

export function formatPiStatus(status: PiExtensionStatus): string {
  return [
    `Installed: ${status.installed}`,
    `Managed: ${status.managed}`,
    `Install path: ${status.installPath}`,
    `Installed version: ${status.installedVersion ?? '(unknown)'}`,
    `Bundled version: ${status.bundledVersion ?? '(unknown)'}`,
    `Source: ${status.source?.kind ?? 'unknown'}${status.source?.path ? ` (${status.source.path})` : ''}`,
  ].join('\n');
}

function runtimeHealthDetail(health: BridgeRuntimeHealth): string | undefined {
  if (health.status === 'healthy') return undefined;
  const codes = [...health.drivers.map((item) => `${item.driver}:${item.code}`),
    ...(health.relayPresence ? [health.relayPresence.code] : [])];
  return codes.join(', ');
}

function describeDevSource(source: { kind: string; path?: string; package?: string }): string {
  const kind = source.kind === 'release-bundle' ? 'release bundle' : source.kind.replaceAll('-', ' ');
  return source.path || source.package ? `${kind} (${source.path ?? source.package})` : kind;
}
