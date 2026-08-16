import type { ReplaceE2ECurrentSessionsRequestV1 } from '@ariava/protocol';
import type { PersistedBridgeState } from '../types';
import type { StateTransition } from './state-transitions';

/** Deterministic current-Sessions lifecycle publication metadata calculations (spec §6.1). */

export interface CurrentSessionsPublicationParameters {
  hostId: string;
  contentDigest: string;
  recipientSetVersion: number;
  observedAt: string;
  minimumRevision: number;
}

export interface CurrentSessionsPublicationResult {
  request: ReplaceE2ECurrentSessionsRequestV1;
  contentDigest: string;
}

/** Mutate-first revision allocation; identical content is a no-op (no write). */
export function createCurrentSessionsPublicationTransition(
  state: PersistedBridgeState,
  parameters: CurrentSessionsPublicationParameters,
): StateTransition<CurrentSessionsPublicationResult | undefined> {
  const current = state.currentSessionsSnapshot;
  if (current.lastAcceptedContentDigest === parameters.contentDigest
    && current.lastAcceptedRecipientSetVersion === parameters.recipientSetVersion
    && current.lastAcceptedRevision >= parameters.minimumRevision) {
    return { state, result: undefined };
  }
  const revision = Math.max(
    current.lastAllocatedRevision + 1,
    current.lastAcceptedRevision + 1,
    parameters.minimumRevision,
  );
  const request: ReplaceE2ECurrentSessionsRequestV1 = {
    hostId: parameters.hostId, revision, observedAt: parameters.observedAt,
    recipientSetVersion: parameters.recipientSetVersion, sessions: [],
  };
  const currentSessionsSnapshot = { ...current, version: 1 as const, lastAllocatedRevision: revision };
  return {
    state: { ...state, currentSessionsSnapshot },
    result: { request, contentDigest: parameters.contentDigest },
  };
}

/** Mutate-first acceptance; stale revision is a no-op (no write). */
export function acceptCurrentSessionsPublicationTransition(
  state: PersistedBridgeState,
  request: ReplaceE2ECurrentSessionsRequestV1,
  digest: string,
  contentDigest: string,
): StateTransition<boolean> {
  const current = state.currentSessionsSnapshot;
  if (state.recipientSetVersion !== request.recipientSetVersion) {
    throw new TypeError('current Sessions publication recipient set is not locally committed');
  }
  if (request.revision < current.lastAcceptedRevision) return { state, result: false };
  const currentSessionsSnapshot = {
    version: 1 as const,
    lastAllocatedRevision: Math.max(current.lastAllocatedRevision, request.revision),
    lastAcceptedRevision: Math.max(current.lastAcceptedRevision, request.revision),
    lastAcceptedDigest: digest,
    lastAcceptedContentDigest: contentDigest,
    lastAcceptedRecipientSetVersion: request.recipientSetVersion,
  };
  return { state: { ...state, currentSessionsSnapshot }, result: true };
}

/** Mutate-first lower-bound bump; no-op when the cursor already satisfies it. */
export function noteCurrentSessionsSnapshotRevisionLowerBoundTransition(
  state: PersistedBridgeState,
  revision: number,
): StateTransition<void> {
  const current = state.currentSessionsSnapshot;
  const nextAllocated = Math.max(current.lastAllocatedRevision, revision);
  if (nextAllocated === current.lastAllocatedRevision) return { state, result: undefined };
  return {
    state: { ...state, currentSessionsSnapshot: { ...current, lastAllocatedRevision: nextAllocated } },
    result: undefined,
  };
}

/** Mutate-first recipient-set version commit; rollback rejected (validation throws before any write). */
export function setRecipientSetVersionTransition(
  state: PersistedBridgeState,
  version: number,
): StateTransition<void> {
  if (!Number.isSafeInteger(version) || version < 1
    || (state.recipientSetVersion !== undefined && version < state.recipientSetVersion)) {
    throw new TypeError('recipient set version rollback rejected');
  }
  return { state: { ...state, recipientSetVersion: version }, result: undefined };
}
