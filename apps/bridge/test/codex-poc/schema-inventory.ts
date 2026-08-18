/**
 * Schema inventory for the Codex Exact-Release Capability PoC (spec §8.1).
 *
 * Extracts and fingerprints the app-server schema surface: methods,
 * notifications, and server requests. The schema fingerprint is the SHA-256 of
 * the RFC 8785 JCS-canonical allowlist bytes and feeds the tuple's
 * `schemaFingerprint` field.
 *
 * Unknown notifications that could change thread/turn/approval/command
 * authority disqualify a tuple from `GO` (spec §8.1); the verdict module
 * consumes `unknownAuthorityChangingCount` accordingly.
 *
 * Research-only harness code; never part of the production import graph.
 */

import { createHash } from 'node:crypto';
import { jcs } from './jcs';

export interface SchemaSurface {
  methods: string[];
  notifications: string[];
  serverRequests: string[];
  /** Unknown notifications that could change authority. */
  unknownAuthorityChanging: string[];
}

/** Reviewed canonical schema allowlist (placeholder pending real inventory). */
export const REVIEWED_SCHEMA_SURFACE: SchemaSurface = Object.freeze({
  methods: Object.freeze([
    'initialize',
    'thread.list',
    'thread.read',
    'turn.start',
    'turn.steer',
    'turn.interrupt',
    'daemon.version',
    'daemon.status',
  ]),
  notifications: Object.freeze([
    'initialized',
    'loaded',
    'unloaded',
    'turn.item.completed',
    'turn.completed',
    'turn.error',
    'approval.request',
  ]),
  serverRequests: Object.freeze([
    'approval.request',
  ]),
  unknownAuthorityChanging: Object.freeze([]),
});

/** Compute the canonical schema fingerprint over the reviewed allowlist. */
export function schemaFingerprint(surface: SchemaSurface = REVIEWED_SCHEMA_SURFACE): string {
  const canonical = jcs({
    methods: [...surface.methods].sort(),
    notifications: [...surface.notifications].sort(),
    serverRequests: [...surface.serverRequests].sort(),
    unknownAuthorityChanging: [...surface.unknownAuthorityChanging].sort(),
  });
  return createHash('sha256').update(canonical).digest('hex');
}

export interface SchemaInventoryResult {
  fingerprint: string;
  surface: SchemaSurface;
  complete: boolean;
}

/**
 * Validate a discovered schema surface against the reviewed allowlist.
 * Returns completeness (no missing reviewed method/notification) and whether any
 * unknown authority-changing notification exists.
 */
export function inventorySchema(discovered: SchemaSurface): SchemaInventoryResult {
  const missingMethods = REVIEWED_SCHEMA_SURFACE.methods.filter((method) => !discovered.methods.includes(method));
  const missingNotifications = REVIEWED_SCHEMA_SURFACE.notifications.filter((notification) => !discovered.notifications.includes(notification));
  const missingServerRequests = REVIEWED_SCHEMA_SURFACE.serverRequests.filter((request) => !discovered.serverRequests.includes(request));
  const complete = missingMethods.length === 0 && missingNotifications.length === 0 && missingServerRequests.length === 0;
  return {
    fingerprint: schemaFingerprint(discovered),
    surface: discovered,
    complete,
  };
}
