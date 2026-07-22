import type { AriavaInstallMetadata, AriavaUserConfig } from '../config';
import type { CommandRunner, ServiceSupport } from '../service/types';

export const ONBOARDING_STEP_IDS = [
  'preflight',
  'stable-cli',
  'relay-config',
  'host-init',
  'bridge-service',
  'adapter-detect',
  'adapter-install',
  'strict-readiness',
  'completion',
] as const;
export type OnboardingStepId = (typeof ONBOARDING_STEP_IDS)[number];
export type OnboardingStepStatus = 'pending' | 'reused' | 'installed' | 'ready' | 'reload-pending' | 'failed' | 'skipped';
export type OnboardingTarget = 'host-ready' | 'adapter-installed';
export type OnboardingReadiness = 'host-ready' | 'adapter-installed' | 'reload-pending' | 'adapter-ready' | 'collaboration-ready' | 'failed';

export interface OnboardingRemediation {
  message: string;
  command?: string;
}

export interface OnboardingErrorData {
  step: OnboardingStepId;
  retryable: boolean;
  remediation?: OnboardingRemediation;
  [key: string]: unknown;
}

export interface OnboardingStepResult {
  id: OnboardingStepId;
  status: OnboardingStepStatus;
  detail?: Record<string, unknown>;
}

export interface OnboardingResult {
  target: OnboardingTarget;
  readiness: OnboardingReadiness;
  steps: OnboardingStepResult[];
  nextActions: Array<{ id: string; command?: string; message?: string }>;
}

export type OnboardingAdapterId = 'pi';
export interface OnboardingAdapterDefinition {
  id: OnboardingAdapterId;
  displayName: string;
  availability: 'production';
  detect: { commands: readonly string[] };
  installer: {
    kind: 'pi-package';
    package: 'npm:@ariava/pi-extension';
    versionPolicy: 'exact-cli-version';
  };
  readiness: { requiresReload: true };
}

export interface OnboardingCliEvidence {
  executablePath: string;
  packageRoot?: string;
  packageVersion?: string;
  npmPrefix?: string;
  npmBinPath?: string;
}

export interface RuntimeProbe {
  present: boolean;
  version?: string;
  reason?: 'not-found' | 'probe-failed';
}

export interface OnboardingDetection {
  platform: NodeJS.Platform;
  architecture: string;
  nodeVersion: string;
  npm: RuntimeProbe;
  pi: RuntimeProbe;
  serviceSupport: ServiceSupport;
  interactive: boolean;
  machineOutput: boolean;
  configPath: string;
  config: AriavaUserConfig;
  installMetadata: AriavaInstallMetadata;
  currentCli: OnboardingCliEvidence;
  stableCli?: OnboardingCliEvidence;
}

export interface OnboardingDetectorDependencies {
  platform: NodeJS.Platform;
  architecture: string;
  nodeVersion: string;
  runner: CommandRunner;
  detectServiceSupport(): ServiceSupport;
  isTty: boolean;
  machineOutput: boolean;
  configPath: string;
  devConfigPath: string;
  pathExists(path: string): boolean;
  loadConfig(path: string): AriavaUserConfig;
  loadInstallMetadata(): AriavaInstallMetadata;
  currentCli: OnboardingCliEvidence;
  stableCli?: OnboardingCliEvidence;
}

export interface OnboardingSelectionInput {
  extensions?: string[];
  noExtensions?: boolean;
  yes?: boolean;
  interactive: boolean;
}

export interface OnboardingSelection {
  target: OnboardingTarget;
  extensions: OnboardingAdapterId[];
  adapter?: OnboardingAdapterId;
}

export const HOST_READINESS_CHECK_IDS = [
  'stable-cli',
  'persisted-config',
  'identity',
  'service-support',
  'service-installed',
  'service-enabled',
  'service-loaded',
  'service-running',
  'service-paths',
  'service-references',
  'agent-adapter-discovery',
  'agent-adapter-health',
  'relay-health',
  'relay-enrollment',
] as const;

export type HostReadinessCheckId = (typeof HOST_READINESS_CHECK_IDS)[number];

export interface HostReadinessCheck {
  id: HostReadinessCheckId;
  ready: boolean;
  code?: string;
}

export interface StrictReadinessResult {
  ready: boolean;
  readiness: OnboardingReadiness;
  checks: HostReadinessCheck[];
  nextActions: Array<{ id: string; command?: string; message?: string }>;
}
