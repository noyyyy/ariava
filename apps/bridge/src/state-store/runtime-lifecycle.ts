import { randomUUID } from 'node:crypto';
import type { PersistedBridgeState } from '../types';
import { spoolPathForState } from '../e2e/local-spool';
import {
  acquireRuntimeCoordinator,
  assertRuntimeCoordinatorPaths,
  assertRuntimeWriterAllowed,
  type RuntimeCoordinator,
} from '../runtime-lock';
import { emptyState } from './state-codec';

/**
 * Lifecycle-owned fresh-state constructor. Random epoch generation stays outside
 * the deterministic codec/transition core.
 */
export function loadCurrentOrFresh(filePath: string): PersistedBridgeState {
  if (filePath !== '') {
    throw new TypeError('path-backed state loading is owned by BridgeStateStore');
  }
  return emptyState(randomUUID());
}

/**
 * Canonical state/spool path derivation (§8.2): an empty state path means
 * in-memory operation, so no spool path is derived.
 */
function runtimeCoordinatorPaths(filePath: string): { statePath: string | undefined; spoolPath: string | undefined } {
  return { statePath: filePath || undefined, spoolPath: filePath ? spoolPathForState(filePath) : undefined };
}

/** Coordinator acquisition with the canonical spool-path derivation (§8.2). */
export function acquireRuntimeCoordinatorForState(filePath: string): RuntimeCoordinator {
  const { statePath, spoolPath } = runtimeCoordinatorPaths(filePath);
  return acquireRuntimeCoordinator(statePath, spoolPath);
}

/** Coordinator/path assertion with the same canonical spool-path derivation. */
export function assertRuntimeCoordinatorForState(coordinator: RuntimeCoordinator, filePath: string): void {
  const { statePath, spoolPath } = runtimeCoordinatorPaths(filePath);
  assertRuntimeCoordinatorPaths(coordinator, statePath, spoolPath);
}

/** Disposed-access guard shared by the shell (§8.2: access rejected after dispose). */
export function assertStateStoreAccess(disposed: boolean, coordinator: RuntimeCoordinator): void {
  if (disposed) throw new Error('Bridge state store is disposed');
  assertRuntimeWriterAllowed(coordinator);
}
