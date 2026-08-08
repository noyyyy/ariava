import { describe, expect, test } from 'bun:test';
import { buildSimulatedEvent, buildSimulatedSession } from '../src/simulate';

describe('Bridge event simulator', () => {
  test.each([
    ['done', 'done', 'idle', undefined],
    ['blocked', 'need_human', 'need_human', 'blocked'],
    ['question', 'need_human', 'need_human', 'question'],
  ] as const)('builds canonical %s payloads', (scenario, type, status, reason) => {
    const session = buildSimulatedSession('host-test', scenario);
    const event = buildSimulatedEvent(session, scenario);

    expect(event).toMatchObject({ type, status });
    if (reason) {
      expect(event).toMatchObject({ needHuman: { reason } });
    } else {
      expect(event.needHuman).toBeUndefined();
    }
    if (scenario === 'question') {
      expect(event.actionablePrompt).toMatchObject({ type: 'question' });
    } else {
      expect(event.actionablePrompt).toBeUndefined();
    }
  });
});
