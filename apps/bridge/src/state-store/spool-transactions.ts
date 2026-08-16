import { readSecureJson } from '../host-manager/secure-files';
import type { LocalEncryptedSpool } from '../e2e/local-spool';
import type {
  CanonicalEvent,
  CanonicalSessionState,
} from '@ariava/protocol';
import type {
  EventUploadCompletionV1,
  PersistedBridgeState,
  PersistedProducerEventReservationV1,
  PersistedTerminalCancellationV1,
} from '../types';
import { assertEventSessionBinding, producerReservationKey, terminalCancellationItemId } from './state-codec';
import { retainRecentEvents } from './session-transitions';
import { isNewerTerminalSession, reserveProducerEventTransition, sameEventCompletion } from './event-transitions';
import { commitState } from './state-transitions';

/** Minimal descriptor for one pending Event source item (§5.1); no payload decode. */
export interface PendingEventDescriptor {
  eventId: string;
  sessionId: string;
}

/** Decoded pending Event source tuple (§5.2 step 4). */
export interface PendingEventSource {
  event: CanonicalEvent;
  session: CanonicalSessionState;
  producerFingerprint?: string;
}

/**
 * Narrow imperative shell surface the cross-medium spool transaction workflows
 * need (spec §6.2). These workflows keep journal-before-effect / effect-before-
 * state / rollback ordering and the state/spool/key-store failure matrix in the
 * shell primitives; they are NEVER routed through `commitState` (spec §6.3).
 */
export interface SpoolTransactionShell {
  /** Encrypted spool journal, absent until Host-bound initialization. */
  readonly spool: LocalEncryptedSpool | undefined;
  /** Runtime state file path (crash-consistency disk evidence). */
  readonly filePath: string;
  /** Current live in-memory runtime state (guarded access). */
  readState(): PersistedBridgeState;
  /** Replace the live in-memory state (rollback path only). */
  setState(nextState: PersistedBridgeState): void;
  /** Durable write of the current live state (fail-closed on write). */
  persist(): void;
  /** Persist-before-swap durable commit of a derived next state. */
  commit(nextState: PersistedBridgeState): void;
  /** Open one spool item as parsed JSON (zeroed buffer). */
  openSpoolJson(itemId: string): unknown | undefined;
  /** Open one producer tuple from the spool journal by kind/eventId/fingerprint. */
  openProducerTuple(kind: 'event-source-v3' | 'event-reservation-v3', eventId: string, fingerprint: string):
    { event: CanonicalEvent; session: CanonicalSessionState } | undefined;
  /** Current state producer reservation for one session/fingerprint (clone). */
  getProducerEventReservation(sessionId: string, fingerprint: string): PersistedProducerEventReservationV1 | undefined;
  /** Pending Event descriptors in stable order, without decoding payloads. */
  listPendingEventDescriptors(): PendingEventDescriptor[];
  /** Decode one pending Event source; malformed sources classify, never throw. */
  openPendingEventSource(descriptor: PendingEventDescriptor):
    | { ok: true; source: PendingEventSource }
    | { ok: false; reason: 'source-utf8-invalid' | 'source-json-invalid' | 'source-shape-invalid' | 'source-binding-invalid' | 'source-missing' };
  /** Commit one Session revision through the session-revision transition. */
  commitSessionRevision(sessionId: string, revision: number): void;
}

/** Clone-first reservation transition (persist-before-swap via the shell commit). */
export function reserveProducerEvent(
  shell: SpoolTransactionShell,
  reservation: PersistedProducerEventReservationV1,
): void {
  commitState(
    { state: shell.readState(), commit: (nextState) => shell.commit(nextState) },
    (state) => reserveProducerEventTransition(state, reservation),
  );
}

/** Journal a producer reservation tuple to the spool (spool-only, no state write). */
export function reserveProducerEventTuple(
  shell: SpoolTransactionShell,
  event: CanonicalEvent,
  terminalSession: CanonicalSessionState,
  fingerprint: string,
): void {
  enqueuePendingEvent(shell, event, terminalSession, fingerprint, 'event-reservation-v3');
}

/**
 * Cancel a terminal Event: journal the cancellation intent to the spool first,
 * commit the state transition, then finish the cancellation by removing the
 * spool source/journal and clearing the terminal-cancellation state. A write
 * failure keeps the journal intent and — only when the disk already carries the
 * same cancellation evidence — adopts the derived state instead.
 */
export function cancelTerminalEvent(shell: SpoolTransactionShell, input: {
  eventId: string; sessionId: string; fingerprint: string; removeSession?: boolean;
  nextDriverName?: string; createdAt?: string;
}): void {
  if (!shell.spool) throw new Error('encrypted spool is not initialized');
  const reservationKey = producerReservationKey(input.sessionId, input.fingerprint);
  const reservation = shell.readState().producerEventReservations?.[reservationKey];
  const source = shell.spool.get(input.eventId);
  if ((!reservation || reservation.eventId !== input.eventId) && source?.payloadKind !== 'event-reservation-v3') return;
  const requested: PersistedTerminalCancellationV1 = {
    version: 1, sessionId: input.sessionId, eventId: input.eventId, fingerprint: input.fingerprint,
    removeSession: input.removeSession === true, createdAt: input.createdAt ?? new Date().toISOString(),
  };
  const itemId = terminalCancellationItemId(input.eventId);
  const existingIntent = shell.openSpoolJson(itemId) as PersistedTerminalCancellationV1 | undefined;
  if (existingIntent && (existingIntent.version !== 1 || existingIntent.sessionId !== requested.sessionId
    || existingIntent.eventId !== requested.eventId || existingIntent.fingerprint !== requested.fingerprint
    || existingIntent.removeSession !== requested.removeSession)) {
    throw new TypeError('terminal cancellation journal conflict');
  }
  const cancellation = existingIntent ?? requested;
  if (!existingIntent) shell.spool.enqueue({ spoolItemId: itemId, sessionId: input.sessionId, eventId: input.eventId,
    payloadKind: 'terminal-cancellation-v3', createdAt: cancellation.createdAt,
    plaintext: new TextEncoder().encode(JSON.stringify(cancellation)) });
  const nextState = structuredClone(shell.readState());
  delete nextState.producerEventReservations?.[reservationKey];
  if (nextState.producerEventReservations && Object.keys(nextState.producerEventReservations).length === 0) {
    delete nextState.producerEventReservations;
  }
  (nextState.terminalCancellations ??= {})[input.eventId] = cancellation;
  if (input.removeSession) {
    delete nextState.sessions[input.sessionId];
    delete nextState.sessionDrivers[input.sessionId];
  } else if (input.nextDriverName !== undefined) {
    nextState.sessionDrivers[input.sessionId] = input.nextDriverName;
  }
  try {
    shell.commit(nextState);
  } catch (error) {
    if (!diskHasTerminalCancellation(shell, cancellation)) throw error;
    shell.setState(nextState);
  }
  finishTerminalCancellation(shell, cancellation);
}

/** Confirm the spool source for one terminal cancellation still matches state. */
function assertTerminalCancellationSource(shell: SpoolTransactionShell, cancellation: PersistedTerminalCancellationV1): void {
  if (!shell.spool) return;
  const source = shell.spool.get(cancellation.eventId);
  if (!source) return;
  if (source.payloadKind !== 'event-reservation-v3'
    || source.eventId !== cancellation.eventId
    || source.sessionId !== cancellation.sessionId) {
    throw new TypeError('terminal cancellation source conflicts with state');
  }
  const tuple = shell.openProducerTuple('event-reservation-v3', cancellation.eventId, cancellation.fingerprint);
  if (!tuple || tuple.event.eventId !== cancellation.eventId || tuple.event.sessionId !== cancellation.sessionId
    || tuple.session.sessionId !== cancellation.sessionId) {
    throw new TypeError('terminal cancellation source conflicts with state');
  }
}

/** Remove the terminal-cancellation spool items and clear the state journal. */
function finishTerminalCancellation(shell: SpoolTransactionShell, cancellation: PersistedTerminalCancellationV1): void {
  if (!shell.spool) return;
  const itemId = terminalCancellationItemId(cancellation.eventId);
  const sourceExists = shell.spool.get(cancellation.eventId) !== undefined;
  const intentExists = shell.spool.get(itemId) !== undefined;
  if (sourceExists || intentExists) {
    try { shell.spool.removeMany([cancellation.eventId, itemId]); } catch { return; }
  }
  const nextState = structuredClone(shell.readState());
  delete nextState.terminalCancellations?.[cancellation.eventId];
  if (nextState.terminalCancellations && Object.keys(nextState.terminalCancellations).length === 0) {
    delete nextState.terminalCancellations;
  }
  try { shell.commit(nextState); } catch {}
}

/** Crash-consistency evidence: the disk state file already carries this cancellation. */
function diskHasTerminalCancellation(shell: SpoolTransactionShell, cancellation: PersistedTerminalCancellationV1): boolean {
  try {
    const disk = readSecureJson<PersistedBridgeState>(shell.filePath);
    return JSON.stringify(disk.terminalCancellations?.[cancellation.eventId]) === JSON.stringify(cancellation);
  } catch {
    return false;
  }
}

/** Startup recovery: reconcile the terminal-cancellation journal with state. */
export function reconcileTerminalCancellations(shell: SpoolTransactionShell): void {
  if (!shell.spool) return;
  const intents = new Map(shell.spool.list('terminal-cancellation-v3').map((item) => [item.eventId, item]));
  for (const cancellation of Object.values(shell.readState().terminalCancellations ?? {})) {
    const item = intents.get(cancellation.eventId);
    if (item) {
      const persisted = shell.openSpoolJson(item.spoolItemId);
      if (JSON.stringify(persisted) !== JSON.stringify(cancellation)) {
        throw new TypeError('terminal cancellation recovery journal conflicts with state');
      }
    }
    assertTerminalCancellationSource(shell, cancellation);
    finishTerminalCancellation(shell, cancellation);
    if (shell.readState().terminalCancellations?.[cancellation.eventId]) {
      throw new Error('terminal cancellation recovery requires retry');
    }
    intents.delete(cancellation.eventId);
  }
  for (const item of intents.values()) {
    const cancellation = shell.openSpoolJson(item.spoolItemId) as PersistedTerminalCancellationV1;
    const reservationKey = producerReservationKey(cancellation.sessionId, cancellation.fingerprint);
    const reservation = shell.readState().producerEventReservations?.[reservationKey];
    const source = shell.spool.get(cancellation.eventId);
    if (!reservation || reservation.eventId !== cancellation.eventId
      || source?.payloadKind !== 'event-reservation-v3' || source.sessionId !== cancellation.sessionId) {
      throw new TypeError('terminal cancellation recovery journal conflicts with pending Event evidence');
    }
    assertTerminalCancellationSource(shell, cancellation);
    const nextState = structuredClone(shell.readState());
    delete nextState.producerEventReservations?.[reservationKey];
    if (nextState.producerEventReservations && Object.keys(nextState.producerEventReservations).length === 0) {
      delete nextState.producerEventReservations;
    }
    (nextState.terminalCancellations ??= {})[cancellation.eventId] = cancellation;
    if (cancellation.removeSession) {
      delete nextState.sessions[cancellation.sessionId];
      delete nextState.sessionDrivers[cancellation.sessionId];
    }
    shell.commit(nextState);
    finishTerminalCancellation(shell, cancellation);
    if (shell.readState().terminalCancellations?.[cancellation.eventId]) {
      throw new Error('terminal cancellation recovery requires retry');
    }
  }
}

/**
 * Queue one pending Event: journal (or promote) the spool source first, apply
 * the state transition on a clone, then persist — rollback the live state to
 * the previous object on write failure (mutate-first failure semantics).
 */
export function queuePendingEvent(
  shell: SpoolTransactionShell,
  event: CanonicalEvent,
  terminalSession: CanonicalSessionState,
  producerFingerprint?: string,
): void {
  assertEventSessionBinding(event, terminalSession);
  if (!shell.spool) throw new Error('encrypted spool is not initialized');
  const existingKind = shell.spool.get(event.eventId)?.payloadKind;
  if (producerFingerprint && existingKind === 'event-reservation-v3') {
    promoteProducerEventTuple(shell, event, terminalSession, producerFingerprint);
  } else if (producerFingerprint && existingKind === 'event-source-v3') {
    const existing = shell.openProducerTuple('event-source-v3', event.eventId, producerFingerprint);
    if (!existing || JSON.stringify(existing) !== JSON.stringify({ event, session: terminalSession })) {
      throw new TypeError('pending Event retry journal conflicts with the bound tuple');
    }
  } else {
    enqueuePendingEvent(shell, event, terminalSession, producerFingerprint);
  }
  const previousState = shell.readState();
  const nextState = structuredClone(previousState);
  shell.setState(nextState);
  applyPendingEventState(shell, event, terminalSession);
  if (producerFingerprint) applyProducerReservation(shell, event, producerFingerprint);
  try {
    shell.persist();
  } catch (error) {
    shell.setState(previousState);
    throw error;
  }
}

/** Apply the recent-events + session binding of one pending Event in place. */
function applyPendingEventState(shell: SpoolTransactionShell, event: CanonicalEvent, terminalSession: CanonicalSessionState): void {
  const state = shell.readState();
  state.recentEvents = retainRecentEvents(
    [event, ...state.recentEvents.filter((candidate) => candidate.eventId !== event.eventId)],
    state.pendingHandles,
  );
  state.sessions[event.sessionId] = terminalSession;
  state.sessionDrivers[event.sessionId] = event.provider;
}

/** Apply/merge one producer reservation for a fingerprinted Event in place. */
function applyProducerReservation(shell: SpoolTransactionShell, event: CanonicalEvent, fingerprint: string): void {
  const state = shell.readState();
  const key = producerReservationKey(event.sessionId, fingerprint);
  const existing = state.producerEventReservations?.[key];
  if (existing && existing.eventId !== event.eventId) throw new TypeError('producer Event reservation conflict');
  (state.producerEventReservations ??= {})[key] = {
    version: 1, eventId: event.eventId, sessionId: event.sessionId, fingerprint, createdAt: event.createdAt,
  };
}

/** Journal one pending Event tuple to the spool and verify the round trip. */
function enqueuePendingEvent(
  shell: SpoolTransactionShell,
  event: CanonicalEvent,
  terminalSession: CanonicalSessionState,
  producerFingerprint?: string,
  payloadKind: 'event-source-v3' | 'event-reservation-v3' = 'event-source-v3',
): void {
  if (!shell.spool) throw new Error('encrypted spool is not initialized');
  const serialized = JSON.stringify({ event, session: terminalSession, ...(producerFingerprint ? { producerFingerprint } : {}) });
  const payload = new TextEncoder().encode(serialized);
  const item = shell.spool.enqueue({ spoolItemId: event.eventId, sessionId: event.sessionId, eventId: event.eventId,
    payloadKind, createdAt: event.createdAt, plaintext: payload });
  const stored = shell.spool.open(item);
  try {
    if (new TextDecoder('utf-8', { fatal: true }).decode(stored) !== serialized) {
      throw new TypeError('pending Event retry journal conflicts with the bound tuple');
    }
  } finally { stored.fill(0); }
}

/** Promote a reserved producer tuple to a pending Event source in the spool. */
function promoteProducerEventTuple(
  shell: SpoolTransactionShell,
  event: CanonicalEvent,
  terminalSession: CanonicalSessionState,
  fingerprint: string,
): void {
  if (!shell.spool) throw new Error('encrypted spool is not initialized');
  const serialized = JSON.stringify({ event, session: terminalSession, producerFingerprint: fingerprint });
  const existing = shell.openProducerTuple('event-reservation-v3', event.eventId, fingerprint);
  if (!existing || JSON.stringify(existing) !== JSON.stringify({ event, session: terminalSession })) {
    throw new TypeError('pending Event retry journal conflicts with the bound tuple');
  }
  shell.spool.replace([event.eventId], [{ spoolItemId: event.eventId, sessionId: event.sessionId, eventId: event.eventId,
    payloadKind: 'event-source-v3', createdAt: event.createdAt, plaintext: new TextEncoder().encode(serialized) }]);
}

/** Startup recovery: replay reservation tuples into state before the upload processor runs. */
export function reconcileProducerEventReservations(shell: SpoolTransactionShell): void {
  if (!shell.spool) return;
  let changed = false;
  for (const item of shell.spool.list('event-reservation-v3')) {
    const bytes = shell.spool.open(item);
    try {
      const pending = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as {
        event: CanonicalEvent; session: CanonicalSessionState; producerFingerprint?: string;
      };
      assertEventSessionBinding(pending.event, pending.session);
      if (typeof pending.producerFingerprint !== 'string') throw new TypeError('pending Event producer fingerprint is invalid');
      const existing = shell.getProducerEventReservation(pending.event.sessionId, pending.producerFingerprint);
      if (!existing) { applyProducerReservation(shell, pending.event, pending.producerFingerprint); changed = true; }
      else if (existing.eventId !== pending.event.eventId) throw new TypeError('pending Event producer reservation conflicts with state');
    } finally { bytes.fill(0); }
  }
  if (changed) shell.persist();
}

/** Startup recovery: forward pending journal sources into current state. */
export function reconcilePendingEventJournal(shell: SpoolTransactionShell): void {
  if (!shell.spool) return;
  let changed = false;
  // Per-item safe decode: malformed sources are left untouched for the upload
  // processor (§5.2) instead of failing the whole startup, which is exactly the
  // eager-decode head-of-line failure the 64 KiB spec eliminates.
  for (const descriptor of shell.listPendingEventDescriptors()) {
    const loaded = shell.openPendingEventSource(descriptor);
    if (!loaded.ok) continue;
    const { event, session, producerFingerprint } = loaded.source;
    const state = shell.readState();
    const current = state.sessions[event.sessionId];
    const recent = state.recentEvents.some((candidate) => candidate.eventId === event.eventId);
    if (producerFingerprint) {
      const reservation = shell.getProducerEventReservation(event.sessionId, producerFingerprint);
      if (!reservation) { applyProducerReservation(shell, event, producerFingerprint); changed = true; }
      else if (reservation.eventId !== event.eventId) throw new TypeError('pending Event producer reservation conflicts with state');
    }
    if (recent && current?.lastEventId === event.eventId) continue;
    if (current && isNewerTerminalSession(current, session)) continue;
    applyPendingEventState(shell, event, session);
    changed = true;
  }
  if (changed) shell.persist();
}

/** Atomically journal one Event upload completion before any durable step runs. */
export function beginEventUploadCompletion(shell: SpoolTransactionShell, completion: EventUploadCompletionV1): void {
  const state = shell.readState();
  const existing = state.eventUploadCompletions?.[completion.eventId];
  if (existing && !sameEventCompletion(existing, completion)) throw new TypeError('event completion journal conflict');
  if (!existing) { (state.eventUploadCompletions ??= {})[completion.eventId] = structuredClone(completion); shell.persist(); }
}

/** Apply one journaled completion step and persist immediately. */
function updateEventCompletion(
  shell: SpoolTransactionShell,
  eventId: string,
  patch: Partial<EventUploadCompletionV1>,
): EventUploadCompletionV1 {
  const state = shell.readState();
  const current = state.eventUploadCompletions?.[eventId];
  if (!current) throw new TypeError('event completion journal is missing');
  const next = { ...current, ...patch };
  state.eventUploadCompletions![eventId] = next;
  shell.persist();
  return next;
}

/**
 * Cross-medium completion workflow: commit the Session revision, drop the
 * inflight Event upload and the source item, then clear the journal. Each step
 * persists before the next; a failing persist stops the journal exactly there.
 */
export function completeEventUpload(
  shell: SpoolTransactionShell,
  eventId: string,
  step?: (phase: 'revision-committed' | 'inflight-removed' | 'source-removed' | 'journal-removed') => void,
): void {
  let completion = shell.readState().eventUploadCompletions?.[eventId];
  if (!completion) return;
  if (!completion.revisionCommitted) {
    shell.commitSessionRevision(completion.sessionId, completion.revision);
    completion = updateEventCompletion(shell, eventId, { revisionCommitted: true });
  }
  step?.('revision-committed');
  if (!completion.inflightRemoved) {
    shell.spool?.remove(`inflight:event:${eventId}`);
    completion = updateEventCompletion(shell, eventId, { inflightRemoved: true });
  }
  step?.('inflight-removed');
  if (!completion.sourceRemoved) {
    shell.spool?.remove(eventId);
    completion = updateEventCompletion(shell, eventId, { sourceRemoved: true });
  }
  step?.('source-removed');
  const state = shell.readState();
  delete state.eventUploadCompletions?.[eventId];
  if (state.eventUploadCompletions && Object.keys(state.eventUploadCompletions).length === 0) delete state.eventUploadCompletions;
  shell.persist();
  step?.('journal-removed');
}

/** Startup recovery: resume every journaled Event upload completion. */
export function resumeEventUploadCompletions(shell: SpoolTransactionShell): void {
  for (const eventId of Object.keys(shell.readState().eventUploadCompletions ?? {})) completeEventUpload(shell, eventId);
}