import { describe, expect, test } from 'bun:test';
import { readdirSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';

const root = join(import.meta.dir, '..');
const activeRoots = [
  'apps/bridge/src',
  'extensions/pi/src',
  'packages/protocol/src',
  'packages/shared-utils/src',
] as const;
const testRoots = [
  'apps/bridge/test',
  'apps/bridge/test-node',
  'extensions/pi/test',
  'packages/protocol/test',
  'packages/shared-utils/test',
] as const;
const packageRoots = [
  'apps/bridge/dist',
  'extensions/pi/bundle',
  'packages/protocol/dist',
  'packages/shared-utils/dist',
] as const;
const forbiddenRuntime = /event-content-v1|session-content-v1|notification-preview-v1|agent\.(?:working|question|blocked)|question_requested|driver_error|host_unavailable|event\.diagnostic_ingested|statusToStateLabel|\bstateLabel\b/gu;
const expectedLegacyTestFixtures: Record<string, Record<string, number>> = {
  'apps/bridge/test/state-store.test.ts': { stateLabel: 1 },
  'apps/bridge/test-node/envelope.test.mjs': { 'event-content-v1': 1 },
  'apps/bridge/test-node/state-spool-migration.test.mjs': { stateLabel: 1 },
  'packages/protocol/test/encryption.test.ts': { 'event-content-v1': 1 },
  'packages/protocol/test/protocol.test.ts': { driver_error: 2, host_unavailable: 2, question_requested: 2 },
};

function sourceFiles(directory: string): string[] {
  return readdirSync(join(root, directory), { recursive: true, withFileTypes: true })
    .filter((entry) => entry.isFile() && /\.(?:mjs|js|json)$/u.test(entry.name) || entry.isFile() && /(?<!\.d)\.ts$/u.test(entry.name))
    .map((entry) => join(entry.parentPath, entry.name));
}

function read(path: string): string {
  return readFileSync(join(root, path), 'utf8');
}

function legacyTokenCounts(source: string): Record<string, number> {
  return Object.fromEntries([...source.matchAll(forbiddenRuntime)].reduce((counts, match) => {
    const token = match[0];
    counts.set(token, (counts.get(token) ?? 0) + 1);
    return counts;
  }, new Map<string, number>()));
}

function stripRecognizedPriorResetDecoder(source: string, path: string): string {
  const resetDecoderArtifact = path === 'apps/bridge/src/state-store.ts'
    || path.match(/^apps\/bridge\/dist\/(?:cli|daemon|dev-profile-cli|public-cli|state-store)\.js$/u);
  if (!resetDecoderArtifact || !source.match(forbiddenRuntime)) return source;
  const priorSessionKeys = source.match(/(?:^|\n)[ \t]*(?:(?:const|var) PRIOR_SESSION_REQUIRED_KEYS = \[\.\.\.SESSION_REQUIRED_KEYS, ["']stateLabel["']\](?: as const)?|PRIOR_SESSION_REQUIRED_KEYS = \[\.\.\.SESSION_REQUIRED_KEYS, ["']stateLabel["']\]);/u)?.[0];
  const decoder = source.match(/function isRecognizedPriorSession[^]*?function isRecognizedPriorSpoolMigration\([^)]*\)(?:: boolean)? \{[^]*?\}(?=\s*(?:function|$))/u)?.[0];
  expect(priorSessionKeys, path).toBeDefined();
  expect(decoder, path).toBeDefined();
  return source.replace(priorSessionKeys!, '').replace(decoder!, '');
}

describe('canonical runtime active-source and documentation scan', () => {
  test('keeps active producers and contracts canonical while prior schemas are reset-only', () => {
    const files = activeRoots.flatMap(sourceFiles);
    for (const file of files) {
      const path = relative(root, file);
      const active = stripRecognizedPriorResetDecoder(readFileSync(file, 'utf8'), path);
      expect(active, path).not.toMatch(forbiddenRuntime);
    }

    const stateStore = read('apps/bridge/src/state-store.ts');
    expect(stateStore.match(/\bstateLabel\b/gu)).toHaveLength(1);
    expect(stateStore.match(/question_requested/gu)).toHaveLength(1);
    expect(stateStore).toContain("const PRIOR_SESSION_REQUIRED_KEYS = [...SESSION_REQUIRED_KEYS, 'stateLabel'] as const;");
    expect(stateStore).toMatch(/function isRecognizedPriorEvent[^]*?question_requested[^]*?function isRecognizedPriorSpoolMigration/u);
    const currentSessionKeys = stateStore.match(/const SESSION_REQUIRED_KEYS = \[[^]*?\] as const;/u)?.[0];
    expect(currentSessionKeys).toBeDefined();
    expect(currentSessionKeys).not.toContain('stateLabel');
  });

  test('allows legacy tokens only in explicit rejection and recognized-prior reset fixtures', () => {
    const actualFixtures: Record<string, Record<string, number>> = {};
    for (const file of testRoots.flatMap(sourceFiles)) {
      const counts = legacyTokenCounts(readFileSync(file, 'utf8'));
      if (Object.keys(counts).length > 0) actualFixtures[relative(root, file)] = counts;
    }
    expect(actualFixtures).toEqual(expectedLegacyTestFixtures);
  });

  test('keeps generated Public package contents canonical except the reset-only prior-state decoder', () => {
    for (const file of packageRoots.flatMap(sourceFiles)) {
      const path = relative(root, file);
      const active = stripRecognizedPriorResetDecoder(readFileSync(file, 'utf8'), path);
      expect(active, path).not.toMatch(forbiddenRuntime);
    }
  });

  test('strips only the complete recognized-prior decoder in source and bundled forms', () => {
    const decoder = [
      'function isRecognizedPriorSession(value) { return value.stateLabel; }',
      'function isRecognizedPriorEvent(value) { return value === "question_requested"; }',
      'function isRecognizedPriorSpoolMigration(value) { return Boolean(value); }',
      'function nextBundledHelper() {}',
    ].join('\n');
    const declarations = [
      "const PRIOR_SESSION_REQUIRED_KEYS = [...SESSION_REQUIRED_KEYS, 'stateLabel'] as const;",
      'var PRIOR_SESSION_REQUIRED_KEYS = [...SESSION_REQUIRED_KEYS, "stateLabel"];',
      '  PRIOR_SESSION_REQUIRED_KEYS = [...SESSION_REQUIRED_KEYS, "stateLabel"];',
    ];

    for (const declaration of declarations) {
      const active = stripRecognizedPriorResetDecoder(`${declaration}\n${decoder}`, 'apps/bridge/dist/dev-profile-cli.js');
      expect(active).not.toMatch(forbiddenRuntime);
    }

    expect(() => stripRecognizedPriorResetDecoder(
      `${declarations[2]}\nfunction isRecognizedPriorSession(value) { return value.stateLabel; }`,
      'apps/bridge/dist/dev-profile-cli.js',
    )).toThrow();

    const unrelatedLegacyContent = stripRecognizedPriorResetDecoder(
      `${declarations[2]}\n${decoder}\nconst unrelated = "stateLabel";`,
      'apps/bridge/dist/dev-profile-cli.js',
    );
    expect(unrelatedLegacyContent).toMatch(forbiddenRuntime);
  });

  test('enforces the exact versioned Agent Adapter cutover', () => {
    const protocol = read('packages/protocol/src/events.ts');
    const server = read('apps/bridge/src/agent-adapter/server.ts');
    const client = read('extensions/pi/src/adapter.ts');
    const discovery = read('apps/bridge/src/agent-adapter/config.ts');
    const active = [protocol, server, client].join('\n');

    expect(active).not.toMatch(/latestSeenEventId|normalizeMarkSessionReadRequest|handleSessionReadAlias/u);
    expect(server).not.toMatch(/sessions\\\/\(\[\^\/\]\+\)\\\/read/u);
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
    expect(fixtures).toContain('must never contain an event/session/preview runtime v1 fixture');
  });
});
