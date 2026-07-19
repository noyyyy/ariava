import type { AriavaServiceInstallRecord, CommandRunner, ServiceStatus } from './types';

export type ServiceRuntimeProbe = Pick<ServiceStatus,
  | 'runtimeName'
  | 'runtimeVersion'
  | 'recordedRuntimeVersion'
  | 'runtimeNameIsNode'
  | 'runtimeVersionSupported'
  | 'runtimeVersionMatchesRecorded'
>;

export function probeRecordedServiceRuntime(
  runner: CommandRunner,
  record: AriavaServiceInstallRecord,
): ServiceRuntimeProbe {
  const result = runner.run(record.runtimePath, ['--version']);
  const runtimeVersion = result.stdout.trim();
  const runtimeNameIsNode = result.status === 0 && /^v\d+(?:\.|$)/u.test(runtimeVersion);
  const runtimeVersionSupported = runtimeNameIsNode && supportedNodeVersion(runtimeVersion);
  return {
    ...(runtimeNameIsNode ? { runtimeName: 'node' as const, runtimeVersion } : {}),
    ...(record.runtimeVersion ? { recordedRuntimeVersion: record.runtimeVersion } : {}),
    runtimeNameIsNode,
    runtimeVersionSupported,
    ...(record.runtimeVersion
      ? { runtimeVersionMatchesRecorded: runtimeNameIsNode && runtimeVersion === record.runtimeVersion }
      : {}),
  };
}

function supportedNodeVersion(version: string): boolean {
  const major = /^v?(\d+)(?:\.|$)/u.exec(version.trim())?.[1];
  return major !== undefined && Number(major) >= 22;
}
