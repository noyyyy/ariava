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

/**
 * Reviewed exact-release schema allowlist (slash RPC names from
 * `codex app-server generate-json-schema`).
 *
 * Dotted placeholders (`thread.list`, `daemon.version`, `approval.request`,
 * `loaded`/`unloaded`) are not on the exact-release wire. Equivalents:
 *   - thread list/read → `thread/list`, `thread/read`
 *   - loaded-set → `thread/loaded/list` plus `thread/started` / `thread/closed`
 *   - turn start/steer/interrupt RPC → `turn/start`, `turn/steer`, `turn/interrupt`
 *   - turn/item lifecycle notifications → `turn/started`, `item/started`,
 *     `item/completed`, `turn/completed`, `thread/realtime/error`
 *   - approval/blocking → `item/<kind>/requestApproval` server requests
 *   - runtime identity → `initialize` result (no `daemon/version` method)
 */
export const REVIEWED_SCHEMA_SURFACE: SchemaSurface = Object.freeze({
  methods: Object.freeze([
    'initialize',
    'thread/list',
    'thread/read',
    'thread/loaded/list',
    'turn/start',
    'turn/steer',
    'turn/interrupt',
  ]),
  notifications: Object.freeze([
    'initialized',
    'thread/started',
    'thread/closed',
    'turn/started',
    'item/started',
    'item/completed',
    'turn/completed',
    'thread/realtime/error',
  ]),
  serverRequests: Object.freeze([
    'item/commandExecution/requestApproval',
    'item/fileChange/requestApproval',
    'item/permissions/requestApproval',
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
