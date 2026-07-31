import { dirname, resolve, sep } from 'node:path';
import type { AriavaUserConfig } from '../config';
import { AriavaCliError } from '../service/errors';
import type { CommandResult } from '../service/types';
import type {
  OnboardingDetection,
  OnboardingDetectorDependencies,
  OnboardingSelection,
  OnboardingSelectionInput,
  ProductionContaminationIssue,
  RuntimeProbe,
  SourceDevObservation,
} from './types';
import { getProductionAdapter } from './catalog';

export function detectOnboardingEnvironment(deps: OnboardingDetectorDependencies): OnboardingDetection {
  const config = deps.loadConfig(deps.configPath);
  const installMetadata = deps.loadInstallMetadata();
  const sourceDev = observeSourceDev(deps, config, installMetadata);
  assertProductionEvidence(sourceDev);
  return {
    platform: deps.platform,
    architecture: deps.architecture,
    nodeVersion: deps.nodeVersion,
    npm: probeVersion(deps.runner.run('npm', ['--version'])),
    pi: probeVersion(deps.runner.run('pi', ['--version'])),
    serviceSupport: deps.detectServiceSupport(),
    interactive: deps.isTty && !deps.machineOutput,
    machineOutput: deps.machineOutput,
    configPath: deps.configPath,
    config,
    installMetadata,
    sourceDev,
    currentCli: deps.currentCli,
    ...(deps.stableCli ? { stableCli: deps.stableCli } : {}),
  };
}

export function validateOnboardingSelection(input: OnboardingSelectionInput): OnboardingSelection {
  if (input.extensions?.length && input.noExtensions) {
    throw selectionError(
      'ERR_ONBOARDING_NOT_READY',
      'Conflicting extension selection: use either --extension or --no-extensions.',
    );
  }
  if (input.extensions) {
    const extensions = [...new Set(input.extensions.map((id) => getProductionAdapter(id).id))];
    return selectionFromExtensions(extensions);
  }
  if (input.noExtensions) return selectionFromExtensions([]);
  if (!input.interactive || input.yes) {
    throw selectionError(
      'ERR_ONBOARDING_NOT_READY',
      'Non-interactive onboarding requires --extension pi or --no-extensions.',
    );
  }
  throw selectionError('ERR_ONBOARDING_NOT_READY', 'Select the agent extensions to install.');
}

function selectionFromExtensions(extensions: OnboardingSelection['extensions']): OnboardingSelection {
  return extensions.includes('pi')
    ? { target: 'adapter-installed', extensions, adapter: 'pi' }
    : { target: 'host-ready', extensions };
}

function probeVersion(result: CommandResult): RuntimeProbe {
  if (result.error?.code === 'ENOENT') return { present: false, reason: 'not-found' };
  if (result.error || result.status !== 0) return { present: false, reason: 'probe-failed' };
  const version = result.stdout.trim() || result.stderr.trim();
  return { present: true, ...(version ? { version } : {}) };
}

function observeSourceDev(
  deps: OnboardingDetectorDependencies,
  config: AriavaUserConfig,
  installMetadata: ReturnType<OnboardingDetectorDependencies['loadInstallMetadata']>,
): SourceDevObservation {
  const devConfigExists = deps.pathExists(deps.devConfigPath);
  const devRoot = dirname(deps.devConfigPath);
  const issues = productionContaminationIssues(deps.configPath, config, installMetadata, devRoot);
  if (issues.length > 0) {
    const allIssuesAreExplicitPaths = issues.every((issue) => issue.sourceKind === 'explicit-path');
    return { kind: allIssuesAreExplicitPaths ? 'ambiguous' : 'production-contaminated', issues };
  }
  if (devConfigExists) {
    return { kind: 'present-isolated', devRoot, devConfigPath: deps.devConfigPath };
  }
  return { kind: 'absent' };
}

function productionContaminationIssues(
  configPath: string,
  config: AriavaUserConfig,
  installMetadata: ReturnType<OnboardingDetectorDependencies['loadInstallMetadata']>,
  devRoot: string,
 ): ProductionContaminationIssue[] {
  return [
    sourceIssue('installMetadata.bridgeSource', installMetadata.bridgeSource?.kind),
    sourceIssue('installMetadata.piSource', installMetadata.piSource?.kind),
    configPathIssue('productionConfig.configPath', configPath, devRoot),
    configPathIssue('productionConfig.agentAdapterConfigPath', config.agentAdapterConfigPath, devRoot),
    configPathIssue('productionConfig.statePath', config.statePath, devRoot),
    configPathIssue('productionConfig.identityPath', config.identityPath, devRoot),
    config.agentAdapterPort === 7273 ? {
      resource: 'productionConfig.agentAdapterPort',
      reason: 'production config uses the source dev Agent Adapter port',
    } : undefined,
  ].filter((issue): issue is ProductionContaminationIssue => issue !== undefined);
}

function sourceIssue(
  resource: string,
  sourceKind: string | undefined,
): ProductionContaminationIssue | undefined {
  if (sourceKind === 'dev-repo') {
    return {
      resource,
      sourceKind,
      reason: 'production install metadata points to a source development repository',
    };
  }
  if (sourceKind === 'explicit-path') {
    return {
      resource,
      sourceKind,
      reason: 'production install metadata points to an explicit local path that is not safe to persist for production onboarding',
    };
  }
  return undefined;
}

function configPathIssue(resource: string, path: string | undefined, devRoot: string): ProductionContaminationIssue | undefined {
  if (!path || !isInsidePath(path, devRoot)) return undefined;
  return {
    resource,
    reason: 'production config points to the source dev profile path',
  };
}

function isInsidePath(path: string, root: string): boolean {
  const resolvedPath = resolve(path);
  const resolvedRoot = resolve(root);
  return resolvedPath === resolvedRoot || resolvedPath.startsWith(`${resolvedRoot}${sep}`);
}

function assertProductionEvidence(sourceDev: SourceDevObservation): void {
  if (sourceDev.kind === 'absent' || sourceDev.kind === 'present-isolated') return;
  let code: AriavaCliError['code'];
  let message: string;
  if (sourceDev.kind === 'ambiguous') {
    code = 'ERR_PRODUCTION_INSTALL_METADATA_AMBIGUOUS';
    message = 'Production onboarding cannot safely continue because production evidence contains ambiguous local path metadata.';
  } else {
    code = 'ERR_PRODUCTION_PROFILE_CONTAMINATED';
    message = 'Production onboarding cannot safely continue because production resources point to source development evidence.';
  }
  throw new AriavaCliError(code, message, {
    step: 'preflight',
    retryable: false,
    sourceDev,
    issues: sourceDev.issues,
    remediation: {
      message: 'Repair or remove the contaminated production config or install metadata, then retry production onboarding.',
    },
  });
}

function selectionError(code: AriavaCliError['code'], message: string): AriavaCliError {
  return new AriavaCliError(code, message, {
    step: 'adapter-detect',
    retryable: false,
    remediation: { message: 'Pass --extension pi or --no-extensions.' },
  });
}
