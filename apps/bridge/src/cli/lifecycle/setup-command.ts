import { validateOnboardingSelection } from '../../host-manager/onboarding/detector';
import type { OnboardingDetection, OnboardingResult, OnboardingSelection } from '../../host-manager/onboarding/types';
import { printJson } from '../../host-manager/output';
import { AriavaCliError } from '../../host-manager/service/errors';
import {
  createReadlineOnboardingPrompt,
  promptForOnboardingSelection,
  renderOnboardingProgress,
  renderOnboardingResult,
  restoreOnboardingTerminal,
  type OnboardingPrompt,
  type OnboardingTerminal,
} from '../../ui/onboarding-renderer';
import type { CliFailure } from '../failure';
import { renderCliFailure } from '../output';
import type { PublicCliOnboardingDependencies } from './default-context';

export interface SetupCommandDependencies {
  stdout: NodeJS.WritableStream;
  stderr: NodeJS.WritableStream;
  cliVersion: string;
  detect: PublicCliOnboardingDependencies['detect'];
  run: PublicCliOnboardingDependencies['run'];
  validateSelection(selection: OnboardingSelection, detection: OnboardingDetection): void;
  normalizeError(error: unknown): CliFailure;
  prompt?: OnboardingPrompt;
  terminal?: OnboardingTerminal;
}

export async function runSetupCommand(
  argv: string[],
  json: boolean,
  deps: SetupCommandDependencies,
): Promise<number> {
  const terminal = deps.terminal ?? onboardingTerminal(deps, json);
  let prompt = deps.prompt;
  const cancellation = new AbortController();
  let closedPrompt: OnboardingPrompt | undefined;
  const closePrompt = () => {
    if (!prompt || closedPrompt === prompt) return;
    closedPrompt = prompt;
    prompt.close?.();
  };
  let terminalRestored = false;
  const restoreTerminal = () => {
    if (terminalRestored) return;
    terminalRestored = true;
    restoreOnboardingTerminal(terminal);
  };
  const signalHandler = () => {
    cancellation.abort();
    try {
      closePrompt();
    } finally {
      restoreTerminal();
    }
  };
  process.once('SIGINT', signalHandler);
  process.once('SIGTERM', signalHandler);
  try {
    const options = parseOnboardingArguments(argv, deps.cliVersion);
    const detection = deps.detect(json || !terminal.interactive, terminal.interactive);
    let selection;
    if (options.extensions || options.noExtensions || !terminal.interactive || options.yes) {
      selection = validateOnboardingSelection({
        extensions: options.extensions,
        noExtensions: options.noExtensions,
        yes: options.yes,
        interactive: terminal.interactive,
      });
    } else {
      prompt ??= createReadlineOnboardingPrompt(process.stdin, deps.stdout);
      selection = await promptForOnboardingSelection(detection, prompt, options.yes);
    }
    deps.validateSelection(selection, detection);
    renderOnboardingProgress('Setting up Ariava…', terminal);
    const publicArgs = selectionPublicArgs(selection, options.publicArgs);
    const result = await deps.run({
      target: selection.target,
      publicArgs,
      resumed: options.resumed,
      bootstrapVersion: options.bootstrapVersion,
      relayBaseUrl: options.relayBaseUrl,
      signal: cancellation.signal,
    });
    restoreTerminal();
    const failed = result.readiness === 'failed';
    if (json) {
      printJson({
        ok: !failed,
        code: failed ? onboardingFailureCode(result) : 'ok',
        message: failed ? onboardingFailureMessage(result) : 'Ariava onboarding completed.',
        data: result,
      }, deps.stdout);
    } else {
      deps.stdout.write(`${renderOnboardingResult(result, { terminal })}\n`);
    }
    return failed ? 1 : 0;
  } catch (error) {
    restoreTerminal();
    renderCliFailure(
      { stdout: deps.stdout, stderr: deps.stderr },
      json,
      deps.normalizeError(error),
    );
    return 1;
  } finally {
    process.off('SIGINT', signalHandler);
    process.off('SIGTERM', signalHandler);
    try {
      restoreTerminal();
    } finally {
      closePrompt();
    }
  }
}

interface ParsedOnboardingArguments {
  extensions?: string[];
  noExtensions: boolean;
  resumed: boolean;
  yes: boolean;
  relayBaseUrl?: string;
  bootstrapVersion?: string;
  publicArgs: string[];
}

function parseOnboardingArguments(argv: string[], cliVersion: string): ParsedOnboardingArguments {
  const result: ParsedOnboardingArguments = {
    noExtensions: false,
    resumed: false,
    yes: false,
    publicArgs: [],
  };
  let bootstrapOnce = false;
  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index]!;
    if (value === '--extension' || value === '--relay-base-url' || value === '--bootstrap-version') {
      const option = argv[++index];
      if (!option || option.startsWith('--')) {
        throw new AriavaCliError(
          'ERR_ONBOARDING_NOT_READY',
          `${value} requires a value.`,
          { step: 'preflight', retryable: false },
        );
      }
      if (value === '--extension') (result.extensions ??= []).push(option);
      else if (value === '--relay-base-url') result.relayBaseUrl = validateRelayUrl(option);
      else result.bootstrapVersion = option;
      if (value !== '--bootstrap-version') result.publicArgs.push(value, option);
      continue;
    }
    if (value === '--no-extensions') {
      result.noExtensions = true;
      result.publicArgs.push(value);
      continue;
    }
    if (value === '--resume') {
      result.resumed = true;
      continue;
    }
    if (value === '--yes') {
      result.yes = true;
      result.publicArgs.push(value);
      continue;
    }
    if (value === '--bootstrap-once') {
      bootstrapOnce = true;
      continue;
    }
    throw new AriavaCliError(
      'ERR_ONBOARDING_NOT_READY',
      `Unknown onboarding option: ${value}`,
      { step: 'preflight', retryable: false },
    );
  }
  const internalPresent = result.bootstrapVersion !== undefined || bootstrapOnce;
  if (internalPresent && (!result.resumed || !bootstrapOnce || result.bootstrapVersion !== cliVersion)) {
    throw new AriavaCliError(
      'ERR_STABLE_CLI_PATH',
      'Internal onboarding re-entry markers are incomplete or mismatched.',
      { step: 'stable-cli', retryable: false },
    );
  }
  return result;
}

function validateRelayUrl(value: string): string {
  try {
    const url = new URL(value);
    if ((url.protocol !== 'https:' && url.protocol !== 'http:')
      || url.username
      || url.password
      || url.pathname !== '/'
      || url.search
      || url.hash) {
      throw new Error('invalid');
    }
    return url.origin;
  } catch {
    throw new AriavaCliError(
      'ERR_RELAY_CONFIG_REQUIRED',
      'Relay base URL must be an HTTP(S) origin without credentials, path, query, or fragment.',
      { step: 'relay-config', retryable: false },
    );
  }
}

function onboardingTerminal(
  deps: Pick<SetupCommandDependencies, 'stdout' | 'stderr'>,
  json: boolean,
): OnboardingTerminal {
  const stdout = deps.stdout as NodeJS.WritableStream & { isTTY?: boolean; columns?: number };
  const interactive = !json
    && stdout.isTTY === true
    && process.stdin.isTTY === true
    && process.env.CI === undefined
    && process.env.TERM !== 'dumb';
  return {
    stdout: deps.stdout,
    stderr: deps.stderr,
    columns: stdout.columns,
    interactive,
    color: interactive && process.env.NO_COLOR === undefined,
  };
}


function onboardingFailureCode(result: OnboardingResult): string {
  const failed = result.steps.find((step) => step.status === 'failed');
  if (typeof failed?.detail?.code === 'string') return failed.detail.code;
  const checks = failed?.detail?.checks;
  if (Array.isArray(checks)) {
    for (const check of checks) {
      if (!check || typeof check !== 'object' || Array.isArray(check)) continue;
      const entry = check as { ready?: unknown; code?: unknown };
      if (entry.ready === false && typeof entry.code === 'string') return entry.code;
    }
  }
  return 'ERR_ONBOARDING_NOT_READY';
}

function onboardingFailureMessage(result: OnboardingResult): string {
  const failed = result.steps.find((step) => step.status === 'failed');
  const detail = failed?.detail;
  if (detail && typeof detail.message === 'string' && detail.message.length > 0) {
    return detail.message;
  }
  if (detail?.remediation && typeof detail.remediation === 'object' && !Array.isArray(detail.remediation)) {
    const remediation = detail.remediation as { message?: unknown };
    if (typeof remediation.message === 'string' && remediation.message.length > 0) {
      return remediation.message;
    }
  }
  const action = result.nextActions[0];
  if (action?.message && action.message.length > 0) return action.message;
  const code = onboardingFailureCode(result);
  return code === 'ERR_ONBOARDING_NOT_READY' ? 'Ariava onboarding is incomplete.' : code;
}

function selectionPublicArgs(
  selection: { extensions: readonly string[] },
  publicArgs: readonly string[],
): string[] {
  if (publicArgs.includes('--extension') || publicArgs.includes('--no-extensions')) {
    return [...publicArgs];
  }
  if (selection.extensions.includes('pi')) return ['--extension', 'pi', ...publicArgs];
  return ['--no-extensions', ...publicArgs];
}
