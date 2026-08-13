import { describe, expect, test } from 'bun:test';
import { AriavaCliError } from '../src/host-manager/service/errors';
import { failureFromError } from '../src/host-manager/onboarding/onboarding-failure';
import type {
  OnboardingResult,
  OnboardingStepId,
  OnboardingStepResult,
} from '../src/host-manager/onboarding/types';

const completedThroughHostInit: OnboardingStepResult[] = [
  { id: 'preflight', status: 'reused' },
  { id: 'stable-cli', status: 'reused' },
  { id: 'relay-config', status: 'reused' },
  { id: 'host-init', status: 'reused' },
];

const completedThroughBridgeService: OnboardingStepResult[] = [
  ...completedThroughHostInit,
  { id: 'bridge-service', status: 'reused' },
];

const cases: Array<{
  name: string;
  completed: OnboardingStepResult[];
  current: OnboardingStepId;
  error: unknown;
  expected: OnboardingResult;
}> = [
  {
    name: 'non-retryable unsupported preflight failure',
    completed: [],
    current: 'preflight',
    error: new AriavaCliError(
      'ERR_UNSUPPORTED_PLATFORM',
      'Ariava setup is not supported on this platform.',
      {
        step: 'preflight',
        retryable: false,
        reason: 'unsupported-platform',
        remediation: { message: 'Run Ariava setup on macOS or supported Linux.' },
      },
    ),
    expected: {
      target: 'adapter-installed',
      readiness: 'failed',
      steps: [
        {
          id: 'preflight',
          status: 'failed',
          detail: {
            step: 'preflight',
            retryable: false,
            reason: 'unsupported-platform',
            remediation: { message: 'Run Ariava setup on macOS or supported Linux.' },
            code: 'ERR_UNSUPPORTED_PLATFORM',
            message: 'Ariava setup is not supported on this platform.',
          },
        },
        { id: 'stable-cli', status: 'skipped' },
        { id: 'relay-config', status: 'skipped' },
        { id: 'host-init', status: 'skipped' },
        { id: 'bridge-service', status: 'skipped' },
        { id: 'adapter-detect', status: 'skipped' },
        { id: 'adapter-install', status: 'skipped' },
        { id: 'strict-readiness', status: 'skipped' },
        { id: 'completion', status: 'skipped' },
      ],
      nextActions: [
        {
          id: 'resolve-failure',
          message: 'Run Ariava setup on macOS or supported Linux.',
        },
      ],
    },
  },
  {
    name: 'cancellation-like unknown failure during Bridge service',
    completed: completedThroughHostInit,
    current: 'bridge-service',
    error: new Error('Onboarding was cancelled.'),
    expected: {
      target: 'adapter-installed',
      readiness: 'failed',
      steps: [
        ...completedThroughHostInit,
        {
          id: 'bridge-service',
          status: 'failed',
          detail: {
            step: 'bridge-service',
            code: 'ERR_ONBOARDING_NOT_READY',
            message: 'Onboarding was cancelled.',
            retryable: true,
          },
        },
        { id: 'adapter-detect', status: 'skipped' },
        { id: 'adapter-install', status: 'skipped' },
        { id: 'strict-readiness', status: 'skipped' },
        { id: 'completion', status: 'skipped' },
      ],
      nextActions: [
        {
          id: 'retry-onboarding',
          message: 'Onboarding was cancelled.',
        },
      ],
    },
  },
  {
    name: 'missing Pi failure during adapter detection',
    completed: completedThroughBridgeService,
    current: 'adapter-detect',
    error: new AriavaCliError(
      'ERR_AGENT_RUNTIME_NOT_FOUND',
      'Pi is not available for adapter installation.',
      { step: 'adapter-detect', retryable: true },
    ),
    expected: {
      target: 'adapter-installed',
      readiness: 'failed',
      steps: [
        ...completedThroughBridgeService,
        {
          id: 'adapter-detect',
          status: 'failed',
          detail: {
            step: 'adapter-detect',
            retryable: true,
            remediation: {
              message: 'Pi is not available for adapter installation.',
              command: 'ariava setup --extension pi',
            },
            code: 'ERR_AGENT_RUNTIME_NOT_FOUND',
            message: 'Pi is not available for adapter installation.',
          },
        },
        { id: 'adapter-install', status: 'skipped' },
        { id: 'strict-readiness', status: 'skipped' },
        { id: 'completion', status: 'skipped' },
      ],
      nextActions: [
        {
          id: 'install-pi',
          message: 'Pi is not available for adapter installation.',
          command: 'ariava setup --extension pi',
        },
      ],
    },
  },
];

describe('onboarding failure shaping', () => {
  test.each(cases)('$name returns exact ordered steps and next actions', ({ completed, current, error, expected }) => {
    const result = failureFromError('adapter-installed', completed, current, error);

    expect(result.steps.map(({ id, status }) => ({ id, status }))).toEqual(
      expected.steps.map(({ id, status }) => ({ id, status })),
    );
    expect(result.nextActions).toEqual(expected.nextActions);
    expect(result).toEqual(expected);
  });
});
