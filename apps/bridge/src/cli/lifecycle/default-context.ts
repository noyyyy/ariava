import type { spawnSync } from 'node:child_process';
import type { HostIdentityStore } from '../../identity/types';
import type {
  AriavaInstallMetadata,
  AriavaInstallerManager,
  AriavaPiInstallRecord,
  AriavaUserConfig,
  ResolvedAriavaConfig,
} from '../../host-manager/config';
import type { OnboardingDetection, OnboardingResult } from '../../host-manager/onboarding/types';
import type { PiExtensionStatus } from '../../host-manager/pi-extension';
import type { InstallMetadataLoadResult } from '../../host-manager/service/migration';
import type { ServiceManager } from '../../host-manager/service/types';
import type { inspectCurrentNodeRuntime, probeNodeRuntimePath } from '../../runtime/node-runtime';
import type { OnboardingPrompt, OnboardingTerminal } from '../../ui/onboarding-renderer';
import type { AriavaProfileCliContext, ProfileHostIdentityOperationLock } from '../context';
import type { createDefaultPairProfileDependencies } from '../operations/pair';
import type { AriavaProfileDescriptor } from '../profile';

export interface PiPackageLifecyclePorts {
  install(version: string): AriavaPiInstallRecord;
  upgrade(version: string): AriavaPiInstallRecord;
  remove(): void;
  status(version: string): PiExtensionStatus;
}

export interface PublicCliDependencies {
  createServiceManager(): ServiceManager;
  currentRuntimePath(): string;
  currentAriavaBinPath(): string;
  stdout: NodeJS.WritableStream;
  stderr: NodeJS.WritableStream;
  loadUserConfig(): AriavaUserConfig;
  saveUserConfig(config: AriavaUserConfig): void;
  resolveAriavaConfig(): ResolvedAriavaConfig;
  loadInstallMetadata(): AriavaInstallMetadata;
  loadInstallMetadataDetailed(): InstallMetadataLoadResult;
  mergeInstallMetadata(patch: Partial<AriavaInstallMetadata>): AriavaInstallMetadata;
  saveInstallMetadata(metadata: AriavaInstallMetadata): void;
  commandExists(name: string): boolean;
  pathExists(path: string): boolean;
  removePath(path: string): void;
  realpath(path: string): string;
  spawn(command: string, args: string[], options?: Parameters<typeof spawnSync>[2]): ReturnType<typeof spawnSync>;
  spawnAsync(command: string, args: string[], options: { signal?: AbortSignal }): Promise<{
    status: number | null;
    stdout: string;
    stderr: string;
    error?: Error;
  }>;
  createHostIdentityStore(
    path: string,
    platform: NodeJS.Platform | string,
    identityProfile?: AriavaProfileDescriptor['resources']['identityProfile'],
  ): HostIdentityStore;
  createProfile(): AriavaProfileDescriptor;
  inspectRuntime(): ReturnType<typeof inspectCurrentNodeRuntime>;
  probeRuntimePath(path: string): ReturnType<typeof probeNodeRuntimePath>;
  cryptoSelfTest(): boolean;
  createPairDependencies(bridgeVersion: string): ReturnType<typeof createDefaultPairProfileDependencies>;
  piPackageLifecycle?: PiPackageLifecyclePorts;
  hostIdentityOperationLock?: ProfileHostIdentityOperationLock;
}

export interface PublicCliOnboardingDependencies {
  detect(machineOutput: boolean, interactive: boolean): OnboardingDetection;
  run(input: {
    target: 'host-ready' | 'adapter-installed';
    publicArgs: readonly string[];
    resumed: boolean;
    bootstrapVersion?: string;
    relayBaseUrl?: string;
    signal?: AbortSignal;
  }): Promise<OnboardingResult>;
  prompt: OnboardingPrompt;
  terminal: OnboardingTerminal;
}

export type DefaultProfileContext = AriavaProfileCliContext;
export type PackageManagerCommand = {
  manager: AriavaInstallerManager;
  command: string;
  args: string[];
};
