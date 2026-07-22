import { AriavaCliError } from '../service/errors';
import type { CommandResult } from '../service/types';
import type {
  OnboardingDetection,
  OnboardingDetectorDependencies,
  OnboardingSelection,
  OnboardingSelectionInput,
  RuntimeProbe,
} from './types';
import { getProductionAdapter } from './catalog';

export function detectOnboardingEnvironment(deps: OnboardingDetectorDependencies): OnboardingDetection {
  const config = deps.loadConfig(deps.configPath);
  const installMetadata = deps.loadInstallMetadata();
  assertProductionEvidence(deps, installMetadata);
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

function assertProductionEvidence(
  deps: OnboardingDetectorDependencies,
  installMetadata: ReturnType<OnboardingDetectorDependencies['loadInstallMetadata']>,
): void {
  const sourceKinds = [installMetadata.bridgeSource?.kind, installMetadata.piSource?.kind];
  const devEvidence = deps.pathExists(deps.devConfigPath) || sourceKinds.includes('dev-repo') || sourceKinds.includes('explicit-path');
  if (!devEvidence) return;
  throw new AriavaCliError('ERR_STABLE_CLI_PATH', 'Production onboarding cannot continue while source-dev or ambiguous install evidence is present.', {
    step: 'preflight',
    retryable: false,
    remediation: {
      message: 'Exit Ariava source dev mode explicitly, then retry production onboarding.',
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
