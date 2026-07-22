import { isCancel, multiselect } from '@clack/prompts';
import { readFileSync } from 'node:fs';
import { basename, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { OnboardingDetection, OnboardingResult, OnboardingSelection } from '../host-manager/onboarding/types';

export const ARIAVA_SUCCESS_ART_SOURCE_SHA256 = 'a8d6fa09ed9569a97ec6ac3f493596b86b22df33957b1933ed6efc0a67016683';
export const ONBOARDING_WIDE_MIN_COLUMNS = 64;
export const ONBOARDING_COMPACT_MIN_COLUMNS = 38;

// Source execution resolves src/ui/assets; the bundled CLI is emitted at dist/*.js
// and resolves the copied dist/ui/assets directory. Neither path depends on cwd.
const moduleDirectory = dirname(fileURLToPath(import.meta.url));
const ASSET_DIRECTORY = resolve(moduleDirectory, basename(moduleDirectory) === 'dist' ? 'ui/assets' : 'assets');

export interface OnboardingPromptChoice {
  value: 'pi';
  label: string;
  description?: string;
  disabled?: boolean | string;
  selectedByDefault: boolean;
}

export interface OnboardingPrompt {
  multiselect(input: { message: string; choices: readonly OnboardingPromptChoice[]; initialValues: 'pi'[] }): Promise<'pi'[]>;
  close?(): void;
}

export interface OnboardingTerminal {
  stdout: NodeJS.WritableStream;
  stderr: NodeJS.WritableStream;
  columns?: number;
  interactive: boolean;
  color: boolean;
}

export interface RenderOnboardingOptions {
  terminal: OnboardingTerminal;
  assetLoader?: (name: 'wide' | 'compact') => string;
}

export function createReadlineOnboardingPrompt(
  _input: NodeJS.ReadableStream,
  _output: NodeJS.WritableStream,
): OnboardingPrompt {
  return {
    async multiselect({ message, choices, initialValues }) {
      const selected = await multiselect({
        message,
        options: choices.map((choice) => ({
          value: choice.value, label: choice.label, hint: choice.description, disabled: choice.disabled,
        })),
        initialValues,
        required: false,
      });
      if (isCancel(selected)) throw new Error('Onboarding cancelled. No changes were made.');
      return selected as 'pi'[];
    },
  };
}

export function onboardingPromptChoices(detection: Pick<OnboardingDetection, 'pi'>): OnboardingPromptChoice[] {
  return [{
    value: 'pi',
    label: 'Pi',
    ...(detection.pi.present ? {} : { description: 'Unavailable — install Pi first.' }),
    ...(detection.pi.present ? {} : { disabled: 'Pi is not installed' }),
    selectedByDefault: detection.pi.present,
  }];
}

export async function promptForOnboardingSelection(
  detection: Pick<OnboardingDetection, 'pi'>,
  prompt: OnboardingPrompt,
  _yes: boolean,
): Promise<OnboardingSelection> {
  const choices = onboardingPromptChoices(detection);
  const initialValues = choices.filter((choice) => choice.selectedByDefault).map((choice) => choice.value);
  const extensions = await prompt.multiselect({
    message: 'Select agent extensions to install', choices, initialValues,
  });
  return extensions.includes('pi')
    ? { target: 'adapter-installed', extensions, adapter: 'pi' }
    : { target: 'host-ready', extensions };
}

export function loadOnboardingSuccessAsset(name: 'wide' | 'compact'): string {
  return readFileSync(resolve(ASSET_DIRECTORY, `ariava-success-${name}.txt`), 'utf8').replace(/\n+$/, '');
}

export function renderOnboardingResult(result: OnboardingResult, options: RenderOnboardingOptions): string {
  const { terminal } = options;
  const successful = result.readiness === 'host-ready' || result.readiness === 'reload-pending';
  if (!successful) return renderFailure(result);

  const title = result.target === 'host-ready' ? 'Host ready' : 'Ariava ready';
  const lines: string[] = [];
  if (terminal.interactive) {
    const asset = selectAsset(terminal.columns, options.assetLoader ?? loadOnboardingSuccessAsset);
    if (asset) lines.push(terminal.color ? `\u001b[36m${asset}\u001b[0m` : asset);
    else lines.push(result.target === 'host-ready' ? 'Host ready' : 'ARIAVA READY');
  } else {
    lines.push(title);
  }
  if (lines.at(-1) !== title) lines.push(title);
  if (result.readiness === 'reload-pending') lines.push('Reload Pi: run /reload in an existing session');
  for (const action of result.nextActions) {
    if (action.id === 'reload-pi') continue;
    const detail = action.command ?? action.message;
    if (detail) lines.push(`Next: ${detail}`);
  }
  return lines.join('\n');
}

export function renderOnboardingProgress(step: string, terminal: OnboardingTerminal): void {
  if (!terminal.interactive) return;
  terminal.stdout.write(`\r\u001b[2K${terminal.color ? '\u001b[36m' : ''}${step}${terminal.color ? '\u001b[0m' : ''}`);
}

export function restoreOnboardingTerminal(terminal: OnboardingTerminal): void {
  if (terminal.interactive) terminal.stdout.write('\r\u001b[2K\u001b[?25h');
}

function selectAsset(columns: number | undefined, load: (name: 'wide' | 'compact') => string): string | undefined {
  if (columns === undefined || columns < ONBOARDING_COMPACT_MIN_COLUMNS) return undefined;
  if (columns >= ONBOARDING_WIDE_MIN_COLUMNS) return assertFits(load('wide'), columns);
  return assertFits(load('compact'), columns);
}

function assertFits(asset: string, columns: number): string {
  if (asset.split('\n').some((line) => line.length > columns)) throw new Error('Onboarding success asset exceeds terminal width.');
  return asset;
}

function renderFailure(result: OnboardingResult): string {
  const failed = result.steps.find((step) => step.status === 'failed');
  let code = typeof failed?.detail?.code === 'string' ? failed.detail.code : 'ERR_ONBOARDING_NOT_READY';
  if (code === 'ERR_ONBOARDING_NOT_READY' && Array.isArray(failed?.detail?.checks)) {
    for (const check of failed.detail.checks) {
      if (!check || typeof check !== 'object' || Array.isArray(check)) continue;
      const entry = check as { ready?: unknown; code?: unknown };
      if (entry.ready === false && typeof entry.code === 'string') {
        code = entry.code;
        break;
      }
    }
  }
  const action = result.nextActions[0];
  let next = 'Retry onboarding after correcting the reported condition.';
  if (action?.command) next = `Next: ${action.command}`;
  else if (action?.message) next = `Next: ${action.message}`;
  return [`Onboarding incomplete: ${code}`, next].join('\n');
}
