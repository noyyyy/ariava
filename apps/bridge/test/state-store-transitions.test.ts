import { describe, expect, test } from 'bun:test';
import type { CanonicalEvent, CanonicalSessionState, HostProjection, PendingSessionHandle } from '@ariava/protocol';
import { buildCommandReceiptEnvelopeBindingBytes, buildEncryptedCommandEnvelopeBindingBytes, contentSha256 } from '@ariava/protocol';
import { emptyState as createEmptyState } from '../src/state-store/state-codec';
import { loadCurrentOrFresh } from '../src/state-store/runtime-lifecycle';
import {
  readRuntimeHealth,
  recordDriverReconciliationFailureTransition,
  recordDriverReconciliationSuccessTransition,
  recordRelayPresenceFailureTransition,
  recordRelayPresenceSuccessTransition,
  sanitizePersistedHost,
  setHostTransition,
} from '../src/state-store/host-health-transitions';
import {
  commitSessionRevisionTransition,
  queuePendingSessionHandleTransition,
  readCurrentSessionRevision,
  readNextSessionRevision,
  removePendingSessionHandleTransition,
  removeSessionDriverTransition,
  removeSessionTransition,
  replaceDriverSessionsTransition,
  setSessionDriverTransition,
  updateSessionTransition,
} from '../src/state-store/session-transitions';
import {
  acceptCurrentSessionsPublicationTransition,
  createCurrentSessionsPublicationTransition,
  noteCurrentSessionsSnapshotRevisionLowerBoundTransition,
  setRecipientSetVersionTransition,
} from '../src/state-store/current-sessions-transitions';
import {
  claimCommandExecutionTransition,
  markCommandDispatchStartedTransition,
  markCommandOutcomeUnknownTransition,
  markCommandReceiptOutboxTransition,
  persistTerminalCommandReceiptTransition,
  persistTerminalReceiptBlockedTransition,
  pruneEligibleCommandExecutionsTransition,
  readCommandExecutionPinRetentionReferences,
  recoverOrphanedCommandExecutionsTransition,
  validateCommandExecutionPinsState,
} from '../src/state-store/command-transitions';
import { MAX_RECENT_EVENTS } from '../src/state-store/session-transitions';
import {
  appendRecentEventTransition,
  buildQuarantineRecord,
  isNewerTerminalSession,
  reserveProducerEventTransition,
  sameEventCompletion,
} from '../src/state-store/event-transitions';
import {
  commitState,
  type StateTransition,
} from '../src/state-store/state-transitions';
import type { PersistedBridgeState } from '../src/types';

const TEST_RUNTIME_RESET_EPOCH = 'test-runtime-reset-epoch';

function emptyState(): PersistedBridgeState {
  return createEmptyState(TEST_RUNTIME_RESET_EPOCH);
}

function makeSession(sessionId = 'sess-1', provider = 'pi'): CanonicalSessionState {
  return {
    sessionId, hostId: 'host-1', provider, projectName: 'project', nameText: 'Session',
    status: 'idle', updatedAt: '2026-07-20T00:00:00.000Z',
  };
}

function makeHandle(sessionId = 'sess-1', eventId = 'evt-1'): PendingSessionHandle {
  return {
    hostId: 'host-1', sessionId, handledThroughEventId: eventId,
    handledAt: '2026-07-20T00:00:10.000Z', action: 'pi_input', updatedAt: '2026-07-20T00:00:10.000Z',
  };
}

const host: HostProjection = {
  hostId: 'host-1', hostName: 'Host', createdAt: '2026-07-20T00:00:00.000Z', version: 1,
} as HostProjection;

describe('state codec pure constructors', () => {
  test('emptyState uses the caller-provided runtime reset epoch deterministically', () => {
    expect(createEmptyState(TEST_RUNTIME_RESET_EPOCH)).toEqual(createEmptyState(TEST_RUNTIME_RESET_EPOCH));
    expect(createEmptyState(TEST_RUNTIME_RESET_EPOCH).runtimeResetEpoch).toBe(TEST_RUNTIME_RESET_EPOCH);
  });

  test('fresh lifecycle states receive valid distinct runtime reset epochs', () => {
    const first = loadCurrentOrFresh('');
    const second = loadCurrentOrFresh('');
    const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
    expect(first.runtimeResetEpoch).toMatch(uuidPattern);
    expect(second.runtimeResetEpoch).toMatch(uuidPattern);
    expect(second.runtimeResetEpoch).not.toBe(first.runtimeResetEpoch);
  });
});

describe('host-health pure transitions', () => {
  test('setHostTransition sanitizes claims and does not mutate the input', () => {
    const state = emptyState();
    const snapshot = structuredClone(state);
    const claimed = { ...host, claimCode: 'SECRET', claimCodeExpiresAt: '2026-07-20T00:01:00.000Z', ownerUserId: 'u' } as HostProjection;
    const transition = setHostTransition(state, claimed);
    expect(transition.state.host).toEqual(sanitizePersistedHost(claimed));
    expect(transition.state.host).not.toHaveProperty('claimCode');
    expect(transition.state.host).not.toHaveProperty('claimCodeExpiresAt');
    expect(transition.state.host).not.toHaveProperty('ownerUserId');
    expect(state).toEqual(snapshot); // input immutable
    expect(transition.state.sessions).toBe(state.sessions);
    expect(transition.state.sessionRevisions).toBe(state.sessionRevisions);
  });

  test('driver and Relay-presence transitions are deterministic, bounded, and immutable', () => {
    const state = emptyState();
    const snapshot = structuredClone(state);
    const first = recordDriverReconciliationFailureTransition(state, 'pi', '2026-08-10T00:00:00.000Z', '2026-08-10T00:00:30.000Z');
    const second = recordDriverReconciliationFailureTransition(first.state, 'pi', '2026-08-10T00:00:15.000Z', '2026-08-10T00:00:30.000Z');
    expect(second.state.runtimeHealth?.drivers[0]).toMatchObject({ driver: 'pi', count: 2 });
    expect(readRuntimeHealth(second.state)).toEqual(readRuntimeHealth(second.state)); // deterministic view
    const relay = recordRelayPresenceFailureTransition(second.state, '2026-08-10T00:00:15.000Z', '2026-08-10T00:00:30.000Z');
    expect(relay.state.runtimeHealth?.status).toBe('degraded');
    expect(relay.state.runtimeHealth?.relayPresence).toMatchObject({ code: 'relay_presence_refresh_failed', count: 1 });
    const success = recordRelayPresenceSuccessTransition(relay.state);
    expect(success.result).toEqual({ count: 1 });
    expect(success.state.runtimeHealth).not.toHaveProperty('relayPresence');
    const recovered = recordDriverReconciliationSuccessTransition(success.state, 'pi');
    expect(recovered.result).toEqual({ count: 2 });
    expect(recovered.state.runtimeHealth?.status).toBe('healthy');
    // no-op success on absent driver is a no-write (same reference)
    const noopState = emptyState();
    const noop = recordDriverReconciliationSuccessTransition(noopState, 'missing');
    expect(noop.result).toBeUndefined();
    expect(noop.state).toBe(noopState);
    expect(state).toEqual(snapshot);
  });
});

describe('session pure transitions', () => {
  test('replaceDriverSessions prunes stale bindings and upserts without mutating input', () => {
    const state = emptyState();
    const kept = makeSession('kept');
    const transition = replaceDriverSessionsTransition(state, 'pi', [kept]);
    expect(transition.state.sessions).toEqual({ kept });
    expect(transition.state.sessionDrivers).toEqual({ kept: 'pi' });
    expect(transition.state.reconciledDrivers.pi).toBe(true);
    expect(state.sessions).toEqual({});
  });

  test('setSessionDriver validates binding, removeSession/removeSessionDriver are no-write on no-op', () => {
    const state = emptyState();
    state.sessions['sess-1'] = makeSession('sess-1');
    state.sessionDrivers['sess-1'] = 'pi';
    const bound = setSessionDriverTransition(state, 'sess-1', 'pi', makeSession('sess-1'));
    expect(bound.state.sessionDrivers['sess-1']).toBe('pi');
    expect(() => setSessionDriverTransition(state, 'sess-1', 'codex', makeSession('sess-1', 'pi'))).toThrow(TypeError);
    const removed = removeSessionTransition(state, 'sess-1', 'pi');
    expect(removed.result).toBe(true);
    expect(removed.state.sessions).not.toHaveProperty('sess-1');
    const noop = removeSessionTransition(state, 'sess-1', 'codex');
    expect(noop.result).toBe(false);
    expect(noop.state).toBe(state); // no write
    const driver = removeSessionDriverTransition(state, 'sess-1');
    expect(driver.state.sessionDrivers).toEqual({});
    const driverNoop = removeSessionDriverTransition(state, 'missing');
    expect(driverNoop.state).toBe(state);
  });

  test('updateSessionTransition is mutate-first with the same returned reference stored in state', () => {
    const state = emptyState();
    state.sessions['sess-1'] = makeSession('sess-1');
    state.sessions['sess-2'] = makeSession('sess-2');
    state.host = host;
    const transition = updateSessionTransition(state, 'sess-1', { nameText: 'Renamed' });
    expect(transition.result?.nameText).toBe('Renamed');
    expect(transition.state.sessions['sess-1']).toBe(transition.result); // same reference
    expect(transition.state.sessions).not.toBe(state.sessions);
    expect(transition.state.sessions['sess-2']).toBe(state.sessions['sess-2']);
    expect(transition.state.host).toBe(state.host);
    const missing = updateSessionTransition(state, 'missing', { nameText: 'x' });
    expect(missing.result).toBeUndefined();
    expect(missing.state).toBe(state);
  });

  test('session revisions advance monotonically and are no-write on no-op', () => {
    const state = emptyState();
    expect(readCurrentSessionRevision(state, 'sess-1')).toBe(0);
    expect(readNextSessionRevision(state, 'sess-1')).toBe(1);
    const first = commitSessionRevisionTransition(state, 'sess-1', 1);
    expect(readCurrentSessionRevision(first.state, 'sess-1')).toBe(1);
    expect(first.state.sessions).toBe(state.sessions);
    expect(first.state.host).toBe(state.host);
    expect(() => commitSessionRevisionTransition(first.state, 'sess-1', 3)).toThrow(TypeError);
    const same = commitSessionRevisionTransition(first.state, 'sess-1', 1);
    expect(same.state).toBe(first.state); // no write
    expect(readNextSessionRevision(first.state, 'sess-1')).toBe(2);
  });

  test('pending-handle queueing validates the durable Event binding and ordering', () => {
    const state = emptyState();
    const event = {
      eventId: 'evt-1', hostId: 'host-1', sessionId: 'sess-1', provider: 'pi',
      createdAt: '2026-07-20T00:00:00.000Z', kind: 'session_updated' as const, updatedAt: '2026-07-20T00:00:00.000Z',
    };
    state.recentEvents = [event];
    const queued = queuePendingSessionHandleTransition(state, makeHandle());
    expect(queued.state.pendingHandles['host-1:sess-1']).toMatchObject({ handledThroughEventCreatedAt: event.createdAt });
    expect(() => queuePendingSessionHandleTransition(state, makeHandle('sess-1', 'missing'))).toThrow(TypeError);
    const removed = removePendingSessionHandleTransition(queued.state, 'host-1', 'sess-1');
    expect(removed.state.pendingHandles).toEqual({});
    const noop = removePendingSessionHandleTransition(queued.state, 'host-1', 'other');
    expect(noop.state).toBe(queued.state);
  });
});

describe('current-sessions pure transitions', () => {
  test('publication allocation is deterministic and content-identical publication is a no-op', () => {
    const state = emptyState();
    state.recipientSetVersion = 1;
    state.currentSessionsSnapshot = { version: 1, lastAllocatedRevision: 0, lastAcceptedRevision: 0 };
    const created = createCurrentSessionsPublicationTransition(state, {
      hostId: 'host-1', contentDigest: 'digest-1', recipientSetVersion: 1,
      observedAt: '2026-07-20T00:00:01.000Z', minimumRevision: 0,
    });
    expect(created.result?.request.revision).toBe(1);
    expect(created.state.currentSessionsSnapshot.lastAllocatedRevision).toBe(1);
    expect(created.state.sessions).toBe(state.sessions);
    expect(created.state.host).toBe(state.host);
    // identical semantic content only suppresses publication once it has been accepted
    const accepted = acceptCurrentSessionsPublicationTransition(created.state, created.result!.request, 'digest', 'digest-1');
    expect(accepted.result).toBe(true);
    const noop = createCurrentSessionsPublicationTransition(accepted.state, {
      hostId: 'host-1', contentDigest: 'digest-1', recipientSetVersion: 1,
      observedAt: '2026-07-20T00:00:02.000Z', minimumRevision: 0,
    });
    expect(noop.result).toBeUndefined();
    expect(noop.state).toBe(accepted.state);
  });

  test('acceptance validates committed recipient set and rejects stale revisions without writing', () => {
    const state = emptyState();
    state.recipientSetVersion = 1;
    const accepted = acceptCurrentSessionsPublicationTransition(state, {
      hostId: 'host-1', revision: 1, observedAt: '2026-07-20T00:00:01.000Z', recipientSetVersion: 1, sessions: [],
    }, 'digest', 'content-digest');
    expect(accepted.result).toBe(true);
    expect(accepted.state.currentSessionsSnapshot.lastAcceptedRevision).toBe(1);
    expect(accepted.state.sessions).toBe(state.sessions);
    expect(accepted.state.host).toBe(state.host);
    expect(() => acceptCurrentSessionsPublicationTransition(state, {
      hostId: 'host-1', revision: 1, observedAt: '2026-07-20T00:00:01.000Z', recipientSetVersion: 2, sessions: [],
    }, 'digest', 'content-digest')).toThrow(TypeError);
    const stale = acceptCurrentSessionsPublicationTransition(accepted.state, {
      hostId: 'host-1', revision: 0, observedAt: '2026-07-20T00:00:01.000Z', recipientSetVersion: 1, sessions: [],
    }, 'digest', 'content-digest');
    expect(stale.result).toBe(false);
    expect(stale.state).toBe(accepted.state);
  });

  test('lower-bound note and recipient-set version are deterministic and no-op on no change', () => {
    const state = emptyState();
    const bumped = noteCurrentSessionsSnapshotRevisionLowerBoundTransition(state, 5);
    expect(bumped.state.currentSessionsSnapshot.lastAllocatedRevision).toBe(5);
    const noop = noteCurrentSessionsSnapshotRevisionLowerBoundTransition(bumped.state, 3);
    expect(noop.state).toBe(bumped.state);
    const version = setRecipientSetVersionTransition(state, 2);
    expect(version.state.recipientSetVersion).toBe(2);
    expect(() => setRecipientSetVersionTransition(version.state, 1)).toThrow(TypeError);
  });
});

describe('command pure transitions', () => {
  const LEGACY_AT = '2026-08-07T00:00:00.000Z';
  const encryptedCommand = {
    commandId: 'command-v4', hostId: 'host-1', sessionId: 'sess-1', type: 'interrupt', issuedAt: LEGACY_AT,
    expiresAt: '2026-08-07T00:05:00.000Z', nonce: 'nonce-v4', watchDeviceId: 'watch-1', linkId: 'link-1',
    linkGeneration: 1, epoch: 1, payload: {
      content: { version: 1, suite: 'x25519-hkdf-sha256-chachapoly-v1', contentId: 'content-command',
        payloadKind: 'interrupt-content-v1', nonce: 'A'.repeat(16), ciphertext: 'A'.repeat(67) },
      keyWrap: { version: 1, suite: 'x25519-hkdf-sha256-chachapoly-v1', contentId: 'content-command', linkId: 'link-1',
        linkGeneration: 1, epoch: 1, senderEncryptionKeyId: `ekey_${'W'.repeat(43)}` as const,
        recipientEncryptionKeyId: `ekey_${'H'.repeat(43)}` as const, nonce: 'B'.repeat(16), ciphertext: 'C'.repeat(64) },
    },
  };
  const pinReference = { version: 1, linkId: 'link-1', linkGeneration: 1, epoch: 1, transcriptDigest: 'T'.repeat(43),
    hostEncryptionKeyId: `ekey_${'H'.repeat(43)}`, watchEncryptionKeyId: `ekey_${'W'.repeat(43)}` };
  const claimedAt = '2026-08-07T00:00:01.000Z';
  const terminalResult = { commandId: 'command-v4', hostId: 'host-1', sessionId: 'sess-1', accepted: true,
    status: 'executed', updatedAt: '2026-08-07T00:00:02.000Z' };
  const commandDigest = 'D'.repeat(43);
  function receipt(commandDigestValue = commandDigest) {
    return { version: 1, hostId: 'host-1', watchDeviceId: 'watch-1', sessionId: 'sess-1',
      commandId: 'command-v4', commandType: 'interrupt', commandDigest: commandDigestValue, completedAt: terminalResult.updatedAt,
      linkId: 'link-1', linkGeneration: 1, epoch: 1, content: { version: 1, suite: 'x25519-hkdf-sha256-chachapoly-v1',
        contentId: 'content-receipt', payloadKind: 'command-receipt-content-v1', nonce: 'D'.repeat(16), ciphertext: 'E'.repeat(192) },
      keyWrap: { version: 1, suite: 'x25519-hkdf-sha256-chachapoly-v1', contentId: 'content-receipt', linkId: 'link-1',
        linkGeneration: 1, epoch: 1, senderEncryptionKeyId: pinReference.hostEncryptionKeyId,
        recipientEncryptionKeyId: pinReference.watchEncryptionKeyId, nonce: 'F'.repeat(16), ciphertext: 'G'.repeat(64) } };
  }

  async function claim(state = emptyState(), overrides: Partial<typeof encryptedCommand> = {}) {
    const command = { ...encryptedCommand, ...overrides };
    const digest = await contentSha256(buildEncryptedCommandEnvelopeBindingBytes(command as typeof encryptedCommand));
    return claimCommandExecutionTransition(state, {
      originalEncryptedCommand: command, commandDigest: digest, pinReference, claimedAt,
    });
  }

  test('claim returns claimed with a new state, duplicate/conflict with the same reference', async () => {
    const state = emptyState();
    const snapshot = structuredClone(state);
    const first = await claim(state);
    expect(first.result).toMatchObject({ status: 'claimed' });
    expect(first.state.commandExecutions['command-v4']).toMatchObject({ state: 'claimed', claimedAt });
    expect(first.state).not.toBe(state);

    const duplicate = await claim(first.state);
    expect(duplicate.result).toMatchObject({ status: 'duplicate' });
    expect(duplicate.state).toBe(first.state); // no write

    const conflict = await claim(first.state, { nonce: 'nonce-v4-other' });
    expect(conflict.result).toEqual({ status: 'conflict' });
    expect(conflict.state).toBe(first.state);

    const nonceConflict = await claim(first.state, { commandId: 'command-other' });
    expect(nonceConflict.result).toEqual({ status: 'conflict' });
    expect(nonceConflict.state).toBe(first.state);
    expect(state).toEqual(snapshot); // input immutable
  });

  test('dispatch start, outcome-unknown, and orphan recovery follow the v4 state machine', async () => {
    const state = emptyState();
    const claimed = (await claim(state)).state;
    const started = markCommandDispatchStartedTransition(claimed, 'command-v4', '2026-08-07T00:00:01.500Z');
    expect(started.result).toMatchObject({ state: 'dispatch_started', dispatchStartedAt: '2026-08-07T00:00:01.500Z' });
    expect(() => markCommandDispatchStartedTransition(started.state, 'command-v4', '2026-08-07T00:00:02.000Z')).toThrow(TypeError);

    const orphaned = recoverOrphanedCommandExecutionsTransition(started.state);
    expect(orphaned.result).toBe(1);
    expect(orphaned.state.commandExecutions['command-v4'].state).toBe('outcome_unknown');
    const noop = recoverOrphanedCommandExecutionsTransition(orphaned.state);
    expect(noop.result).toBe(0);
    expect(noop.state).toBe(orphaned.state);

    const unknown = markCommandOutcomeUnknownTransition((await claim(state)).state, 'command-v4');
    expect(unknown.result.state).toBe('outcome_unknown');
    expect(() => markCommandOutcomeUnknownTransition(unknown.state, 'command-v4')).toThrow(TypeError);
  });

  test('terminal receipt persistence is atomic and immutable, and the outbox advances', async () => {
    const command = encryptedCommand as typeof encryptedCommand;
    const executionDigest = await contentSha256(buildEncryptedCommandEnvelopeBindingBytes(command));
    const state = (await claim(emptyState())).state;
    const blocked = persistTerminalReceiptBlockedTransition(state, 'command-v4', terminalResult);
    expect(blocked.result).toMatchObject({ state: 'terminal_receipt_blocked' });
    expect(blocked.result.receiptOutbox).toBeUndefined(); // blocked persists no receipt
    // already-blocked executions cannot be blocked again
    expect(() => persistTerminalReceiptBlockedTransition(blocked.state, 'command-v4',
      { ...terminalResult, status: 'rejected' })).toThrow(TypeError);

    const receiptValue = receipt(executionDigest);
    const canonicalBody = JSON.stringify(receiptValue);
    const receiptDigest = await contentSha256(buildCommandReceiptEnvelopeBindingBytes(receiptValue));
    const terminal = persistTerminalCommandReceiptTransition(blocked.state, 'command-v4', terminalResult, {
      canonicalBody, receiptDigest, receipt: receiptValue,
    });
    expect(terminal.result).toMatchObject({ state: 'terminal', receiptOutbox: { state: 'pending' } });
    // terminal result is immutable once a terminal state is persisted
    expect(() => persistTerminalCommandReceiptTransition(terminal.state, 'command-v4',
      { ...terminalResult, status: 'rejected' }, { canonicalBody, receiptDigest, receipt: receiptValue })).toThrow(TypeError);

    const acked = markCommandReceiptOutboxTransition(terminal.state, 'command-v4', 'acknowledged');
    expect(acked.result.receiptOutbox?.state).toBe('acknowledged');
    expect(() => markCommandReceiptOutboxTransition(acked.state, 'command-v4', 'undeliverable')).toThrow(TypeError);
  });

  test('prune, pin validation, and retention references are deterministic', async () => {
    const state = (await claim(emptyState())).state;
    expect(() => pruneEligibleCommandExecutionsTransition(state, 'not-a-timestamp')).toThrow(TypeError);
    expect(pruneEligibleCommandExecutionsTransition(state, '2026-08-07T00:00:00.000Z')).toMatchObject({ result: [] });
    const pruned = pruneEligibleCommandExecutionsTransition(state, '2030-01-01T00:00:00.000Z');
    expect(pruned.result).toHaveLength(1);
    expect(pruned.state.commandExecutions).toEqual({});

    expect(() => validateCommandExecutionPinsState(state, {
      resolvePinReference: () => undefined,
    })).toThrow('unavailable or inconsistent');
    validateCommandExecutionPinsState(state, { resolvePinReference: () => pinReference });

    const references = readCommandExecutionPinRetentionReferences(state);
    expect(references.executionRetainedThrough?.['link-1:1:1']).toBeDefined();
  });
});

describe('event pure transitions', () => {
  function makeEvent(eventId = 'evt-1', createdAt = '2026-07-20T00:00:00.000Z'): CanonicalEvent {
    return { eventId, hostId: 'host-1', sessionId: 'sess-1', provider: 'pi', type: 'done',
      createdAt, updatedAt: createdAt } as CanonicalEvent;
  }

  test('appendRecentEventTransition is clone-first, bounded, and immutable', () => {
    const state = emptyState();
    const snapshot = structuredClone(state);
    const first = appendRecentEventTransition(state, makeEvent());
    expect(first.state.recentEvents).toHaveLength(1);
    expect(first.state).not.toBe(state); // new state reference
    expect(state).toEqual(snapshot); // input immutable
    // newest first ordering
    const second = appendRecentEventTransition(first.state, makeEvent('evt-2', '2026-07-20T00:00:01.000Z'));
    expect(second.state.recentEvents.map((event) => event.eventId)).toEqual(['evt-2', 'evt-1']);
    // bounded history
    let bounded = emptyState();
    for (let index = 0; index < MAX_RECENT_EVENTS + 25; index += 1) {
      bounded = appendRecentEventTransition(bounded, makeEvent(`evt-${index}`, `2026-07-20T00:00:${String(index).padStart(2, '0')}.000Z`)).state;
    }
    expect(bounded.recentEvents).toHaveLength(MAX_RECENT_EVENTS);
  });

  test('appendRecentEventTransition preserves protected handled-through Events beyond the cap', () => {
    let state = emptyState();
    const protectedEvent = makeEvent('evt-protected', '2026-07-20T00:00:00.000Z');
    state.recentEvents = [protectedEvent];
    state.pendingHandles['host-1:sess-1'] = makeHandle('sess-1', 'evt-protected');
    for (let index = 0; index < MAX_RECENT_EVENTS + 25; index += 1) {
      state = appendRecentEventTransition(
        state,
        makeEvent(`evt-${index}`, `2026-07-20T00:01:${String(index).padStart(2, '0')}.000Z`),
      ).state;
    }
    expect(state.recentEvents).toHaveLength(MAX_RECENT_EVENTS);
    expect(state.recentEvents.some((event) => event.eventId === 'evt-protected')).toBe(true);
  });

  test('sameEventCompletion compares baseline identity fields while ignoring committedAt', () => {
    const completion = { version: 1, eventId: 'evt-1', sessionId: 'sess-1', revision: 4,
      eventContentId: 'event-content', sessionContentId: 'session-content', committedAt: '2026-07-20T00:00:00.000Z' };
    expect(sameEventCompletion(completion, { ...completion })).toBe(true);
    expect(sameEventCompletion(completion, { ...completion, committedAt: '2026-07-20T00:01:00.000Z' })).toBe(true);
    expect(sameEventCompletion(completion, { ...completion, eventId: 'other' })).toBe(false);
    expect(sameEventCompletion(completion, { ...completion, revision: 5 })).toBe(false);
    expect(sameEventCompletion(completion, { ...completion, eventContentId: 'other' })).toBe(false);
    expect(sameEventCompletion(completion, { ...completion, sessionContentId: 'other' })).toBe(false);
    expect(sameEventCompletion(completion, { ...completion, sessionId: 'other' })).toBe(false);
  });

  test('isNewerTerminalSession compares only when a newer durable cursor exists', () => {
    const base = makeSession();
    const older = { ...base, updatedAt: '2026-07-20T00:00:01.000Z', lastEventId: 'evt-1' };
    const newer = { ...older, updatedAt: '2026-07-20T00:00:02.000Z', lastEventId: 'evt-2' };
    expect(isNewerTerminalSession(newer, older)).toBe(true);
    expect(isNewerTerminalSession(older, newer)).toBe(false);
    expect(isNewerTerminalSession(newer, { ...newer })).toBe(false); // same lastEventId
    expect(isNewerTerminalSession({ ...older, lastEventId: undefined }, newer)).toBe(false); // no cursor
  });

  test('buildQuarantineRecord constructs the exact dead-letter record without mutating source', () => {
    const source = { eventId: 'evt-1', sessionId: 'sess-1' };
    const snapshot = structuredClone(source);
    const record = buildQuarantineRecord('evt-1', 'sess-1', 'boom', '2026-07-20T00:00:03.000Z', source);
    expect(record).toEqual({ version: 1, eventId: 'evt-1', sessionId: 'sess-1', reason: 'boom',
      quarantinedAt: '2026-07-20T00:00:03.000Z', source });
    expect(record).not.toHaveProperty('inflight');
    expect(source).toEqual(snapshot);
    const withInflight = buildQuarantineRecord('evt-1', 'sess-1', 'boom', '2026-07-20T00:00:03.000Z', source, { upload: 'in-flight' });
    expect(withInflight.inflight).toEqual({ upload: 'in-flight' });
  });
});

describe('commitState shell helper', () => {
  function makeShell() {
    const state = emptyState();
    const writes: Array<PersistedBridgeState> = [];
    return {
      state,
      writes,
      shell: {
        get state() { return state; },
        commit: (nextState: PersistedBridgeState) => { writes.push(nextState); },
      } as const,
    };
  }

  test('persists and returns the result when the transition derives a new state', () => {
    const { state, writes, shell } = makeShell();
    const result = commitState(shell, (current) => {
      const nextState = structuredClone(current);
      nextState.recipientSetVersion = 7;
      return { state: nextState, result: 'applied' as const };
    });
    expect(result).toBe('applied');
    expect(writes).toHaveLength(1);
    expect(writes[0]).not.toBe(state);
    expect(writes[0].recipientSetVersion).toBe(7);
  });

  test('skips the durable write when the transition returns the same reference', () => {
    const { shell, writes } = makeShell();
    const result = commitState(shell, (current) => ({ state: current, result: 'noop' as const }));
    expect(result).toBe('noop');
    expect(writes).toHaveLength(0);
  });

  test('propagates the commit error and never swaps without a durable write', () => {
    const { state } = makeShell();
    let currentState = state;
    const failing = {
      get state() { return currentState; },
      commit: (_nextState: PersistedBridgeState) => { throw new Error('injected write failure'); },
    };
    expect(() => commitState(failing, (current) => {
      const nextState = structuredClone(current);
      nextState.recipientSetVersion = 1;
      return { state: nextState, result: undefined };
    })).toThrow('injected write failure');
    expect(failing.state).toBe(state);
    expect(currentState.recipientSetVersion).toBeUndefined();
  });
});

describe('reserveProducerEventTransition', () => {
  const reservation = { version: 1 as const, eventId: 'evt-1', sessionId: 'sess-1', fingerprint: 'fp',
    createdAt: '2026-07-20T00:00:00.000Z' };

  test('is clone-first, bounded, and immutable', () => {
    const state = emptyState();
    const snapshot = structuredClone(state);
    const first = reserveProducerEventTransition(state, reservation);
    expect(first.state.producerEventReservations?.['sess-1\nfp']).toEqual(reservation);
    expect(first.state).not.toBe(state);
    expect(state).toEqual(snapshot);
  });

  test('returns the same reference for an identical duplicate', () => {
    const state = emptyState();
    state.producerEventReservations = { ['sess-1\nfp']: { ...reservation } };
    const duplicate = reserveProducerEventTransition(state, reservation);
    expect(duplicate.state).toBe(state);
  });

  test('throws a conflict for a mismatched duplicate', () => {
    const state = emptyState();
    state.producerEventReservations = { ['sess-1\nfp']: { ...reservation, eventId: 'evt-other' } };
    expect(() => reserveProducerEventTransition(state, reservation)).toThrow('producer Event reservation conflict');
  });

  test('bounds the reservation history to the last 200 entries', () => {
    let state = emptyState();
    for (let index = 0; index < 205; index += 1) {
      state = reserveProducerEventTransition(state, { ...reservation, eventId: `evt-${index}`,
        sessionId: `sess-${index}` }).state;
    }
    expect(Object.keys(state.producerEventReservations ?? {})).toHaveLength(200);
  });
});
