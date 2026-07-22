import { describe, expect, test } from 'bun:test';
import type { OnboardingDetection, OnboardingResult } from '../src/host-manager';
import {
  onboardingPromptChoices,
  promptForOnboardingSelection,
  renderOnboardingProgress,
  renderOnboardingResult,
  restoreOnboardingTerminal,
  type OnboardingPrompt,
  type OnboardingTerminal,
} from '../src/ui/onboarding-renderer';

function result(target: OnboardingResult['target'], readiness: OnboardingResult['readiness']): OnboardingResult {
  return {
    target, readiness,
    steps: [{ id: 'completion', status: readiness === 'failed' ? 'failed' : 'ready', ...(readiness === 'failed' ? { detail: { code: 'ERR_RELAY_UNREACHABLE' } } : {}) }],
    nextActions: readiness === 'reload-pending'
      ? [{ id: 'reload-pi', command: '/reload' }, { id: 'pair-watch', command: 'ariava pair <PAIRING_CODE>' }]
      : readiness === 'failed' ? [{ id: 'retry-onboarding', message: 'ERR_RELAY_UNREACHABLE' }] : [],
  };
}

function terminal(columns: number | undefined, interactive = true, color = false): OnboardingTerminal {
  return { stdout: { write: () => true } as never, stderr: { write: () => true } as never, columns, interactive, color };
}

const asset = (name: 'wide' | 'compact') => name === 'wide' ? 'WIDE ART' : 'COMPACT ART';

describe('onboarding renderer', () => {
  test('selects wide, compact, and plain accessible renderings without wrapping', () => {
    expect(renderOnboardingResult(result('adapter-installed', 'reload-pending'), { terminal: terminal(80), assetLoader: asset })).toStartWith('WIDE ART\nAriava ready\nReload Pi: run /reload in an existing session');
    expect(renderOnboardingResult(result('adapter-installed', 'reload-pending'), { terminal: terminal(50), assetLoader: asset })).toStartWith('COMPACT ART\nAriava ready');
    expect(renderOnboardingResult(result('adapter-installed', 'reload-pending'), { terminal: terminal(30), assetLoader: asset })).toStartWith('ARIAVA READY\nAriava ready');
    expect(renderOnboardingResult(result('host-ready', 'host-ready'), { terminal: terminal(undefined), assetLoader: asset })).toBe('Host ready');
  });

  test('NO_COLOR-style output retains art but has zero ANSI', () => {
    const plain = renderOnboardingResult(result('host-ready', 'host-ready'), { terminal: terminal(80, true, false), assetLoader: asset });
    const colored = renderOnboardingResult(result('host-ready', 'host-ready'), { terminal: terminal(80, true, true), assetLoader: asset });
    expect(plain).toContain('WIDE ART');
    expect(plain).not.toContain('\u001b[');
    expect(colored).toContain('\u001b[36m');
  });

  test('pipe/JSON/CI/dumb terminal seam is plain and carries no art or ANSI', () => {
    const output = renderOnboardingResult(result('adapter-installed', 'reload-pending'), { terminal: terminal(undefined, false, false), assetLoader: () => { throw new Error('must not load'); } });
    expect(output).toBe('Ariava ready\nReload Pi: run /reload in an existing session\nNext: ariava pair <PAIRING_CODE>');
    expect(output).not.toMatch(/ART|\u001b\[/);
  });

  test('partial failures never render success art or identifying values', () => {
    const output = renderOnboardingResult(result('adapter-installed', 'failed'), { terminal: terminal(80), assetLoader: () => { throw new Error('must not load'); } });
    expect(output).toBe('Onboarding incomplete: ERR_RELAY_UNREACHABLE\nNext: ERR_RELAY_UNREACHABLE');
    expect(output).not.toMatch(/Ariava ready|Host ready|host_|watch_|secret/i);
  });

  test('selector presents agent extensions as an optional multi-select', async () => {
    const calls: string[] = [];
    const prompt: OnboardingPrompt = {
      async multiselect({ choices, initialValues }) {
        calls.push(`multiselect:${choices.map((choice) => choice.value).join(',')}:${initialValues.join(',')}`);
        return ['pi'];
      },
    };
    expect(await promptForOnboardingSelection({ pi: { present: true } }, prompt, false)).toEqual({
      target: 'adapter-installed', extensions: ['pi'], adapter: 'pi',
    });
    expect(calls).toEqual(['multiselect:pi:pi']);
  });

  test('absent Pi is disabled and no selection means Bridge-only setup', async () => {
    const choices = onboardingPromptChoices({ pi: { present: false, reason: 'not-found' } });
    expect(choices).toMatchObject([{ value: 'pi', selectedByDefault: false, disabled: 'Pi is not installed' }]);
    const prompt: OnboardingPrompt = { async multiselect() { return []; } };
    expect(await promptForOnboardingSelection({ pi: { present: false } }, prompt, false)).toEqual({
      target: 'host-ready', extensions: [],
    });
  });

  test('interactive progress and restoration own cursor controls; noninteractive mode writes nothing', () => {
    let text = '';
    const tty = { ...terminal(80), stdout: { write(value: string) { text += value; return true; } } as never };
    renderOnboardingProgress('Working', tty);
    restoreOnboardingTerminal(tty);
    expect(text).toContain('\u001b[2K');
    expect(text).toContain('\u001b[?25h');
    text = '';
    renderOnboardingProgress('Working', { ...tty, interactive: false });
    restoreOnboardingTerminal({ ...tty, interactive: false });
    expect(text).toBe('');
  });
});
