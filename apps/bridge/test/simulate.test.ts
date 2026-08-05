import { describe, expect, test } from 'bun:test';
import { buildSimulatedEvent, buildSimulatedSession } from '../src/simulate';

describe('Bridge event simulator', () => {
  test.each([
    ['done', 'done', 'Task complete'],
    ['need_human', 'blocked', 'Needs attention'],
  ] as const)('builds canonical %s payloads', (scenario, status, typeLabel) => {
    const session = buildSimulatedSession('host-test', scenario);
    const event = buildSimulatedEvent(session, scenario);

    expect(event).toMatchObject({ type: scenario, status, typeLabel });
    expect(event.actionablePrompt).toBeUndefined();
  });
});
