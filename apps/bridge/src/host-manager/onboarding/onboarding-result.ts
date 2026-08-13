import type {
  OnboardingResult,
  OnboardingStepId,
  OnboardingStepResult,
  OnboardingTarget,
} from './types';

export function onboardingStep(
  id: OnboardingStepId,
  status: OnboardingStepResult['status'],
  detail?: Record<string, unknown>,
): OnboardingStepResult {
  return { id, status, ...(detail && Object.keys(detail).length > 0 ? { detail } : {}) };
}

export function appendSkippedOnboardingSteps(steps: OnboardingStepResult[]): void {
  const ordered: OnboardingStepId[] = [
    'preflight', 'stable-cli', 'relay-config', 'host-init', 'bridge-service',
    'adapter-detect', 'adapter-install', 'strict-readiness', 'completion',
  ];
  const last = steps.at(-1)?.id;
  const start = last ? ordered.indexOf(last) + 1 : 0;
  for (const id of ordered.slice(start)) steps.push(onboardingStep(id, 'skipped'));
}

export function completionActions(target: OnboardingTarget): OnboardingResult['nextActions'] {
  return target === 'adapter-installed'
    ? [
        { id: 'reload-pi', command: '/reload' },
        { id: 'pair-watch', command: 'ariava pair <PAIRING_CODE>' },
      ]
    : [{ id: 'pair-watch', command: 'ariava pair <PAIRING_CODE>' }];
}
