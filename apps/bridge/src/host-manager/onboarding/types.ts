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
export const ONBOARDING_STEP_STATUSES = [
  'pending',
  'reused',
  'installed',
  'ready',
  'reload-pending',
  'failed',
  'skipped',
] as const;
export type OnboardingStepStatus = (typeof ONBOARDING_STEP_STATUSES)[number];
export type OnboardingTarget = 'host-ready' | 'adapter-installed';
export type OnboardingReadiness = 'host-ready' | 'adapter-installed' | 'reload-pending' | 'adapter-ready' | 'collaboration-ready' | 'failed';
export const PRODUCTION_ONBOARDING_RESULT_READINESS = ['host-ready', 'reload-pending', 'failed'] as const;
export const ONBOARDING_SUCCESS_CODE = 'ok';
export const ONBOARDING_SUCCESS_MESSAGE = 'Ariava onboarding completed.';

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

export function isProductionOnboardingResult(value: unknown): value is OnboardingResult {
  if (!isPlainRecord(value) || !hasExactKeys(value, ['target', 'readiness', 'steps', 'nextActions'])) return false;
  if (value.target !== 'host-ready' && value.target !== 'adapter-installed') return false;
  if (!includes(PRODUCTION_ONBOARDING_RESULT_READINESS, value.readiness)) return false;
  if (value.readiness === 'host-ready' && value.target !== 'host-ready') return false;
  if (value.readiness === 'reload-pending' && value.target !== 'adapter-installed') return false;
  if (!Array.isArray(value.steps) || !value.steps.every(isOnboardingStepResult)) return false;
  return Array.isArray(value.nextActions) && value.nextActions.every(isOnboardingNextAction);
}

function isOnboardingStepResult(value: unknown): value is OnboardingStepResult {
  if (!isPlainRecord(value)) return false;
  const keys = Object.keys(value);
  if (keys.length < 2 || keys.length > 3 || !keys.includes('id') || !keys.includes('status')) return false;
  if (keys.some((key) => key !== 'id' && key !== 'status' && key !== 'detail')) return false;
  return includes(ONBOARDING_STEP_IDS, value.id)
    && includes(ONBOARDING_STEP_STATUSES, value.status)
    && (!('detail' in value) || isPlainRecord(value.detail));
}

function isOnboardingNextAction(value: unknown): value is OnboardingResult['nextActions'][number] {
  if (!isPlainRecord(value) || !hasOnlyKeys(value, ['id', 'command', 'message'])) return false;
  return typeof value.id === 'string' && value.id.trim().length > 0
    && (!('command' in value) || typeof value.command === 'string')
    && (!('message' in value) || typeof value.message === 'string');
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function hasExactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const keys = Object.keys(value);
  return keys.length === expected.length && expected.every((key) => keys.includes(key));
}

function hasOnlyKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  return Object.keys(value).every((key) => expected.includes(key));
}

function includes<const Values extends readonly unknown[]>(values: Values, value: unknown): value is Values[number] {
  return values.includes(value);
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

export interface ProductionContaminationIssue {
  resource: string;
  reason: string;
  sourceKind?: 'dev-repo' | 'explicit-path';
}

export type SourceDevObservation =
  | { kind: 'absent' }
  | { kind: 'present-isolated'; devRoot: string; devConfigPath: string; devPort?: number; devBridgeRunning?: boolean }
  | { kind: 'production-contaminated'; issues: ProductionContaminationIssue[] }
  | { kind: 'ambiguous'; issues: ProductionContaminationIssue[] };

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
  sourceDev: SourceDevObservation;
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
  'bridge-runtime-health',
  'relay-health',
  'relay-enrollment',
] as const;

export type HostReadinessCheckId = (typeof HOST_READINESS_CHECK_IDS)[number];

export interface HostReadinessCheck {
  id: HostReadinessCheckId;
  ready: boolean;
  code?: string;
  message?: string;
}

export interface StrictReadinessResult {
  ready: boolean;
  readiness: OnboardingReadiness;
  checks: HostReadinessCheck[];
  nextActions: Array<{ id: string; command?: string; message?: string }>;
}
