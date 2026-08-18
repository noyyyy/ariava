import { describe, expect, test } from 'bun:test';
import { inventorySchema, REVIEWED_SCHEMA_SURFACE, schemaFingerprint, type SchemaSurface } from './schema-inventory';

describe('schema inventory', () => {
  test('reviewed schema surface has complete methods/notifications/server requests', () => {
    expect(REVIEWED_SCHEMA_SURFACE.methods).toContain('initialize');
    expect(REVIEWED_SCHEMA_SURFACE.methods).toContain('thread.list');
    expect(REVIEWED_SCHEMA_SURFACE.methods).toContain('thread.read');
    expect(REVIEWED_SCHEMA_SURFACE.methods).toContain('turn.start');
    expect(REVIEWED_SCHEMA_SURFACE.methods).toContain('turn.steer');
    expect(REVIEWED_SCHEMA_SURFACE.methods).toContain('turn.interrupt');
    expect(REVIEWED_SCHEMA_SURFACE.notifications).toContain('initialized');
    expect(REVIEWED_SCHEMA_SURFACE.notifications).toContain('loaded');
    expect(REVIEWED_SCHEMA_SURFACE.notifications).toContain('unloaded');
    expect(REVIEWED_SCHEMA_SURFACE.notifications).toContain('turn.item.completed');
    expect(REVIEWED_SCHEMA_SURFACE.notifications).toContain('turn.completed');
    expect(REVIEWED_SCHEMA_SURFACE.notifications).toContain('turn.error');
    expect(REVIEWED_SCHEMA_SURFACE.notifications).toContain('approval.request');
    expect(REVIEWED_SCHEMA_SURFACE.serverRequests).toContain('approval.request');
  });

  test('schema fingerprint is stable sha256 over canonical allowlist', () => {
    const first = schemaFingerprint();
    const second = schemaFingerprint(REVIEWED_SCHEMA_SURFACE);
    expect(first).toBe(second);
    expect(first).toMatch(/^[0-9a-f]{64}$/u);
  });

  test('fingerprint changes when a method is added', () => {
    const withExtra: SchemaSurface = {
      methods: [...REVIEWED_SCHEMA_SURFACE.methods, 'turn.cancel'],
      notifications: REVIEWED_SCHEMA_SURFACE.notifications,
      serverRequests: REVIEWED_SCHEMA_SURFACE.serverRequests,
      unknownAuthorityChanging: REVIEWED_SCHEMA_SURFACE.unknownAuthorityChanging,
    };
    expect(schemaFingerprint(withExtra)).not.toBe(schemaFingerprint());
  });

  test('inventory reports complete when the full reviewed surface is discovered', () => {
    const result = inventorySchema(REVIEWED_SCHEMA_SURFACE);
    expect(result.complete).toBe(true);
    expect(result.fingerprint).toBe(schemaFingerprint());
  });

  test('inventory reports incomplete when a reviewed method is missing', () => {
    const missing: SchemaSurface = {
      methods: REVIEWED_SCHEMA_SURFACE.methods.filter((method) => method !== 'turn.interrupt'),
      notifications: REVIEWED_SCHEMA_SURFACE.notifications,
      serverRequests: REVIEWED_SCHEMA_SURFACE.serverRequests,
      unknownAuthorityChanging: [],
    };
    const result = inventorySchema(missing);
    expect(result.complete).toBe(false);
  });

  test('inventory reports incomplete when a reviewed notification is missing', () => {
    const missing: SchemaSurface = {
      methods: REVIEWED_SCHEMA_SURFACE.methods,
      notifications: REVIEWED_SCHEMA_SURFACE.notifications.filter((notification) => notification !== 'approval.request'),
      serverRequests: REVIEWED_SCHEMA_SURFACE.serverRequests,
      unknownAuthorityChanging: [],
    };
    const result = inventorySchema(missing);
    expect(result.complete).toBe(false);
  });

  test('unknown authority-changing notifications are surfaced for verdict input', () => {
    const withUnknown: SchemaSurface = {
      methods: REVIEWED_SCHEMA_SURFACE.methods,
      notifications: [...REVIEWED_SCHEMA_SURFACE.notifications, 'approval.dismiss'],
      serverRequests: REVIEWED_SCHEMA_SURFACE.serverRequests,
      unknownAuthorityChanging: ['approval.dismiss'],
    };
    const result = inventorySchema(withUnknown);
    expect(result.surface.unknownAuthorityChanging).toContain('approval.dismiss');
  });
});
