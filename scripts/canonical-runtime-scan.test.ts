import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const root = join(import.meta.dir, '..');

function read(path: string): string {
  return readFileSync(join(root, path), 'utf8');
}

describe('canonical runtime active-source and documentation scan', () => {
  test('enforces the exact versioned Agent Adapter cutover', () => {
    const server = read('apps/bridge/src/agent-adapter/server.ts');
    const client = read('extensions/pi/src/adapter.ts');
    const discovery = read('apps/bridge/src/agent-adapter/config.ts');
    expect(server).toContain('AGENT_ADAPTER_PROTOCOL_HEADER');
    expect(client).toContain('[AGENT_ADAPTER_PROTOCOL_HEADER]: String(discovery.protocolVersion)');
    expect(discovery).toContain("keys.includes('protocolVersion')");
    expect(discovery).toContain('record.protocolVersion !== AGENT_ADAPTER_PROTOCOL_VERSION');
  });

  test('documents the exact canonical model without compatibility claims', () => {
    const protocol = read('packages/protocol/src/events.ts');
    expect(protocol).toContain("export const EVENT_TYPES = ['done', 'need_human'] as const;");
    expect(protocol).toContain("export const SESSION_STATUSES = ['idle', 'working', 'need_human'] as const;");
    expect(protocol).toContain("export const NEED_HUMAN_REASONS = ['question', 'blocked', 'error'] as const;");

    const readme = read('README.md');
    for (const marker of [
      'Event type is exactly `done | need_human`',
      'Session status is exactly `idle | working | need_human`',
      'Normal completion atomically produces one `done` Event and an `idle` Session',
      'Driver failures are Bridge health/log/retry concerns',
      'Host availability is a Relay-presence concern',
      '`event-content-v2`, `session-content-v2`, and `notification-preview-v2`',
      '`agent.done` and `agent.need_human`',
      'There is no compatibility decoder, negotiation, dual read/write, or fallback',
    ]) expect(readme, marker).toContain(marker);

    const fixtures = read('packages/protocol/test/fixtures/README.md');
    expect(fixtures).toContain('`need-human-error-validation-v2.json`');
  });
});
