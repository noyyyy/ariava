import { randomUUID } from 'node:crypto';
import type { PersistedBridgeState } from '../types';
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
