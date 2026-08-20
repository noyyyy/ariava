import type {
  CanonicalEvent,
  CanonicalSessionState,
  E2EEventAndSessionUploadV3,
  E2ERecipientSnapshotV1,
  EncryptedSessionSnapshotUploadV3,
} from '@ariava/protocol';
import type { EventUploadCompletionV1 } from '../types';
import type {
  EventDeadLetterReasonCode,
  LoadPendingEventPartsResult,
  LoadedEventInflight,
  PendingEventDescriptor,
  SessionInflightLookup,
  SessionInflightRecordV2,
} from '../state-store';
import { encryptEventUpload, encryptSessionSnapshot, type ActiveRecipientMaterial } from './envelope';
import { RECIPIENT_SET_CHANGED_REASON, decideEventUpload, decideSessionUpload, type EventUploadDecision, type SessionUploadDecision } from './upload-decisions';
import { isPermanentEventConflict, isRelayConflict, relayErrorStatus, relayFailureCategory, type UploadFailureCategory } from './upload-failures';
import { attachNotificationPreviews, eventEncryptionInput, sessionEncryptionInput, type EncryptedEventAndSession } from './upload-inputs';
import { digestsEqual, eventSourceDigest, preflightEventSource, preflightSessionSource, sessionSourceDigest } from './upload-preflight';

/** Consumer-owned State Store capability port for encrypted uploads. */
export interface EncryptedUploadStateStore {
  getSession(sessionId: string): CanonicalSessionState | undefined;
  listSessions(): CanonicalSessionState[];
  listPendingEventDescriptors(): PendingEventDescriptor[];
  listEventInflightRecords(): Array<{ eventId: string; sessionId: string; kind: 'v2' | 'legacy' | 'malformed' }>;
  loadPendingEventParts(descriptor: PendingEventDescriptor): LoadPendingEventPartsResult;
  hasEventUploadCompletion(eventId: string): boolean;
  openInflightEventRaw(eventId: string): Uint8Array | undefined;
  getInflightEventUpload(eventId: string): unknown | undefined;
  persistInflightEventUpload(eventId: string, sessionId: string, upload: unknown, sourceDigest?: string): void;
  replaceInflightEventUpload(eventId: string, sessionId: string, upload: unknown, sourceDigest?: string): void;
  listInflightSessionIds(): string[];
  getInflightSessionUpload(sessionId: string): unknown | undefined;
  getSessionInflightLookup(sessionId: string): SessionInflightLookup;
  getSessionInflightRecordV2(sessionId: string): SessionInflightRecordV2 | undefined;
  persistInflightSessionUpload(sessionId: string, upload: unknown, sourceDigest?: string): void;
  replaceInflightSessionUpload(sessionId: string, upload: unknown, sourceDigest?: string): void;
  removeInflightSessionUpload(sessionId: string): void;
  nextSessionRevision(sessionId: string): number;
  commitSessionRevision(sessionId: string, revision: number): void;
  getRecipientSetVersion(): number | undefined;
  setRecipientSetVersion(version: number): void;
  beginEventUploadCompletion(completion: EventUploadCompletionV1): void;
  completeEventUpload(eventId: string, step?: (phase: 'revision-committed' | 'inflight-removed' | 'source-removed' | 'journal-removed') => void): void;
  quarantinePendingEventRaw(
    descriptor: PendingEventDescriptor,
    reasonCode: EventDeadLetterReasonCode,
    provenUncommittedInflight?: Uint8Array,
    quarantinedAt?: string,
  ): boolean;
}

/** Relay capabilities used by encrypted upload workflows, and no others. */
export interface EncryptedUploadRelayClient {
  recipientSnapshot(): Promise<E2ERecipientSnapshotV1>;
  publishEncryptedEvent(event: E2EEventAndSessionUploadV3['event'], session: E2EEventAndSessionUploadV3['session']): Promise<unknown>;
  reconcileEncryptedEvent(event: E2EEventAndSessionUploadV3['event'], session: E2EEventAndSessionUploadV3['session']): Promise<{ committed: boolean }>;
  reconcileEncryptedSession(session: EncryptedSessionSnapshotUploadV3): Promise<boolean>;
  publishEncryptedSession(session: EncryptedSessionSnapshotUploadV3): Promise<unknown>;
}

/** Opaque recipient capability; its secret-bearing material is visible only to crypto. */
export type EncryptedUploadRecipientMaterial = unknown;

/** Keyring capability used to reconcile one authoritative recipient snapshot. */
export interface EncryptedUploadKeyring {
  reconcileRecipients(snapshot: E2ERecipientSnapshotV1): EncryptedUploadRecipientMaterial[];
}

/** Imperative encryption boundary. Secret key bytes never enter upload decisions or results. */
export interface EncryptedUploadCryptoPort {
  encryptSessionSnapshot(input: {
    session: CanonicalSessionState;
    revision: number;
    recipientSetVersion: number;
    recipients: EncryptedUploadRecipientMaterial[];
  }): EncryptedSessionSnapshotUploadV3;
  encryptEventUpload(input: {
    event: CanonicalEvent;
    session: CanonicalSessionState;
    revision: number;
    recipientSetVersion: number;
    recipients: EncryptedUploadRecipientMaterial[];
  }): EncryptedEventAndSession;
}

export interface EncryptedEventFailure {
  eventId: string;
  sessionId: string;
  outcome: 'retry-deferred' | 'quarantined';
  status?: number;
  category: UploadFailureCategory;
}

export interface EncryptedUploadHooks {
  eventCompletionStep?: (phase: 'journaled' | 'revision-committed' | 'inflight-removed' | 'source-removed' | 'journal-removed', eventId: string) => void;
  eventFailure?: (failure: EncryptedEventFailure) => void;
}

export interface CreateEncryptedUploadActionsParameters {
  stateStore: EncryptedUploadStateStore;
  relayClient: EncryptedUploadRelayClient;
  crypto: EncryptedUploadCryptoPort;
  keyring: EncryptedUploadKeyring;
  hooks?: EncryptedUploadHooks;
}

/** Production crypto adapter used only by the actions factory. */
export const DEFAULT_ENCRYPTED_UPLOAD_CRYPTO: EncryptedUploadCryptoPort = {
  encryptSessionSnapshot: ({ session, revision, recipientSetVersion, recipients }) =>
    encryptSessionSnapshot({ ...sessionEncryptionInput(session), revision, recipientSetVersion,
      recipients: recipients as ActiveRecipientMaterial[] }),
  encryptEventUpload: ({ event, session, revision, recipientSetVersion, recipients }) => {
    const activeRecipients = recipients as ActiveRecipientMaterial[];
    const upload = encryptEventUpload({ ...eventEncryptionInput(event, session), revision, recipientSetVersion,
      recipients: activeRecipients } as Parameters<typeof encryptEventUpload>[0]);
    attachNotificationPreviews(upload, event, session, activeRecipients);
    return upload;
  },
};

/**
 * §6.2 Session publication outcome taxonomy for one authoritative publish pass.
 * `published` carries the data the daemon needs to build the exact manifest;
 * `locally-blocked` is a deterministic content block (never a revision allocation,
 * inflight mutation, or manifest send); `deferred`/`fail-closed` keep the existing
 * network/recipient-churn/error semantics.
 */
export type SessionPublicationBlockReason = 'protected_content_invalid' | 'session_source_invalid';

export type AuthoritativeSnapshotOutcome =
  | { type: 'published'; recipientSetVersion: number; revisions: Map<string, number> }
  | { type: 'locally-blocked'; reason: SessionPublicationBlockReason }
  | { type: 'deferred'; reason: 'network' | 'recipient-set' }
  | { type: 'fail-closed' };

export function createEncryptedUploadActions(parameters: CreateEncryptedUploadActionsParameters) {
  const { stateStore, relayClient, crypto, keyring, hooks } = parameters;

  async function publishAuthoritativeSnapshots(snapshot: E2ERecipientSnapshotV1, recipients: EncryptedUploadRecipientMaterial[], sessions: readonly CanonicalSessionState[]): Promise<AuthoritativeSnapshotOutcome> {
    // §6.1 full-set preflight FIRST, before any revision allocation / inflight
    // creation / manifest. Any invalid-content returns locally-blocked with zero
    // mutation; keyring/crypto/storage errors throw and keep fail-closed semantics.
    const blockedBeforeStart = preflightAuthoritativeSessionSet(sessions);
    if (blockedBeforeStart.blockedSessionCount > 0) {
      return { type: 'locally-blocked', reason: blockedBeforeStart.reason };
    }

    // A recipient change invalidates the whole authoritative set, including Sessions
    // already committed during this pass. Restart until every returned revision was
    // encrypted for one final recipient-set version.
    let sameVersionCommitRetryExhausted = false;
    for (;;) {
      const passVersion = snapshot.recipientSetVersion;
      const revisions = new Map<string, number>();
      let restart = false;
      // §6.1/§4.4: the immutable caller-supplied Session snapshot is the single
      // source for preflight, digest, encryption, and the manifest — the mutable
      // store is never re-read mid-pass (no split snapshot / TOCTOU).
      for (const session of sessions) {
        const sessionId = session.sessionId;
        let upload = stateStore.getInflightSessionUpload(sessionId) as EncryptedSessionSnapshotUploadV3 | undefined;

        // §4.4 / §6.1: an existing Session inflight must be reconciled BEFORE reuse or
        // rebuild. Committed → complete the old evidence first (old revision committed,
        // inflight removed) and continue from the current source on the next revision.
        // Explicitly uncommitted → reuse only when the inflight matches the immutable
        // current source digest AND the recipient version; otherwise rebuild from the
        // current source keeping the inflight's approved revision (never drop below it).
        if (upload) {
          let committed: boolean;
          try { committed = await relayClient.reconcileEncryptedSession(upload); }
          catch (error) {
            reportDeferredFailure({ eventId: sessionId, sessionId }, error);
            return { type: 'deferred', reason: 'network' };
          }
          if (committed) {
            stateStore.commitSessionRevision(sessionId, upload.revision);
            stateStore.removeInflightSessionUpload(sessionId);
            upload = undefined;
          } else {
            let sourceDigest: string;
            try { sourceDigest = sessionSourceDigest(session); } catch { sourceDigest = ''; }
            const v2 = stateStore.getSessionInflightRecordV2(sessionId);
            const digestMatches = v2 !== undefined && sourceDigest !== '' && digestsEqual(v2.sourceDigest, sourceDigest);
            if (!digestMatches || upload.recipientSetVersion !== passVersion) {
              const preflight = preflightSessionSource(session);
              if (preflight.type !== 'ready') return { type: 'locally-blocked', reason: publicationBlockReason(preflight) };
              const replacement = crypto.encryptSessionSnapshot({ session, revision: upload.revision,
                recipientSetVersion: passVersion, recipients });
              stateStore.replaceInflightSessionUpload(sessionId, replacement, sourceDigest);
              upload = replacement;
            }
          }
        }

        if (!upload || upload.recipientSetVersion !== passVersion) {
          const preflight = preflightSessionSource(session);
          if (preflight.type !== 'ready') return { type: 'locally-blocked', reason: publicationBlockReason(preflight) };
          const next = crypto.encryptSessionSnapshot({ session, revision: upload?.revision ?? stateStore.nextSessionRevision(sessionId),
            recipientSetVersion: passVersion, recipients });
          if (upload) stateStore.replaceInflightSessionUpload(sessionId, next, sessionSourceDigest(session)); else stateStore.persistInflightSessionUpload(sessionId, next, sessionSourceDigest(session));
          upload = next;
        }
        let currentSnapshot = snapshot;
        let currentRecipients = recipients;
        let refreshed = false;
        let decision: SessionUploadDecision;
        for (;;) {
          try { await relayClient.publishEncryptedSession(upload); } catch (error) {
            if (!isRelayConflict(error)) return { type: 'deferred', reason: 'network' };
            // §4.4: a reconcile network/identity failure is not an explicit uncommitted
            // verdict; defer with the inflight evidence preserved.
            let committed: boolean;
            try { committed = await relayClient.reconcileEncryptedSession(upload); }
            catch (reconcileError) {
              reportDeferredFailure({ eventId: sessionId, sessionId }, reconcileError);
              return { type: 'deferred', reason: 'network' };
            }
            if (error.reason === RECIPIENT_SET_CHANGED_REASON) {
              try {
                currentSnapshot = await relayClient.recipientSnapshot();
                currentRecipients = keyring.reconcileRecipients(currentSnapshot);
              } catch { return { type: 'deferred', reason: 'recipient-set' }; }
              refreshed = true;
            }
            decision = decideSessionUpload({
              publishSucceeded: false,
              conflictReason: error.reason,
              reconcileCommitted: committed,
              attemptedRecipientVersion: passVersion,
              refreshedRecipientVersion: refreshed ? currentSnapshot.recipientSetVersion : undefined,
              currentRevision: upload.revision,
              sameVersionCommitRetryExhausted,
              failureCategory: relayFailureCategory(error),
            });
            switch (decision.type) {
              case 'commit':
                stateStore.commitSessionRevision(sessionId, decision.acceptedRevision);
                stateStore.removeInflightSessionUpload(sessionId);
                revisions.set(sessionId, decision.acceptedRevision);
                break;
              case 'defer':
                return { type: 'deferred', reason: decision.reason === 'recipient-set' ? 'recipient-set' : 'network' };
              case 'fail-closed':
                return { type: 'fail-closed' };
              case 'reconcile':
                return { type: 'deferred', reason: 'network' };
              case 'refresh-reencrypt': {
                const preflight = preflightSessionSource(session);
                if (preflight.type !== 'ready') return { type: 'locally-blocked', reason: publicationBlockReason(preflight) };
                const replacement = crypto.encryptSessionSnapshot({ session, revision: decision.revision,
                  recipientSetVersion: currentSnapshot.recipientSetVersion, recipients: currentRecipients });
                stateStore.replaceInflightSessionUpload(sessionId, replacement, sessionSourceDigest(session));
                snapshot = currentSnapshot; recipients = currentRecipients;
                restart = true;
                break;
              }
              case 'retry-next-revision': {
                sameVersionCommitRetryExhausted = currentSnapshot.recipientSetVersion === passVersion;
                stateStore.commitSessionRevision(sessionId, upload.revision);
                stateStore.removeInflightSessionUpload(sessionId);
                snapshot = currentSnapshot; recipients = currentRecipients;
                restart = true;
                break;
              }
            }
            // Every decision ends this pass; refresh/retry re-run the outer loop via `restart`.
            break;
          }
          stateStore.commitSessionRevision(sessionId, upload.revision);
          stateStore.removeInflightSessionUpload(sessionId);
          revisions.set(sessionId, upload.revision);
          break;
        }
        if (restart) break;
      }
      if (restart) continue;
      stateStore.setRecipientSetVersion(passVersion);
      return { type: 'published', recipientSetVersion: passVersion, revisions };
    }
  }

  /**
   * §6.1 full-set content preflight over the immutable active Session snapshot,
   * used by the daemon BEFORE `createCurrentSessionsPublication()` so a content
   * block never allocates a publication revision, never creates/replaces inflight,
   * and never sends a manifest. Returns the number of blocked Sessions; throws
   * (fail-closed) on keyring/crypto/storage/invariant errors — those must NOT be
   * reclassified as content blocks.
   */
  function preflightAuthoritativeSessionSet(sessions: readonly CanonicalSessionState[]): {
    blockedSessionCount: number;
    reason: SessionPublicationBlockReason;
  } {
    let blockedSessionCount = 0;
    let reason: SessionPublicationBlockReason = 'protected_content_invalid';
    for (const session of sessions) {
      const result = preflightSessionSource(session);
      if (result.type === 'ready') continue;
      blockedSessionCount += 1;
      if (result.type === 'invalid-source-binding') reason = 'session_source_invalid';
    }
    return { blockedSessionCount, reason };
  }

  /**
   * §4.4/§6.2: converge committed Session inflight evidence WITHOUT publishing.
   * Used when the authoritative set is content-blocked or during snapshot-pipeline
   * recovery: committed evidence is completed (revision + inflight removal),
   * explicitly uncommitted evidence stays byte-preserved for a later pass, and
   * malformed/cross-bound evidence defers (fail-closed — never cleared).
   */
  async function reconcileSessionInflights(sessions: readonly CanonicalSessionState[]): Promise<{ deferred: boolean }> {
    const activeSessionIds = new Set(sessions.map((session) => session.sessionId));
    let deferred = false;
    for (const sessionId of stateStore.listInflightSessionIds()) {
      const lookup = stateStore.getSessionInflightLookup(sessionId);
      if (lookup.kind === 'missing') continue;
      if (lookup.kind === 'malformed' || lookup.kind === 'cross-bound') {
        // §4.4: unknown/malformed/cross-bound evidence is never removed without an
        // exact reconcile; recovery surfaces it as recovery-required.
        deferred = true;
        continue;
      }
      let committed: boolean;
      try { committed = await relayClient.reconcileEncryptedSession(lookup.upload); }
      catch (error) {
        reportDeferredFailure({ eventId: sessionId, sessionId }, error);
        deferred = true;
        continue;
      }
      if (committed) {
        stateStore.commitSessionRevision(sessionId, lookup.upload.revision);
        stateStore.removeInflightSessionUpload(sessionId);
      } else if (!activeSessionIds.has(sessionId)) {
        // Explicitly uncommitted orphan evidence has no authoritative source from
        // which it can be rebuilt. Preserve it byte-for-byte and fail closed.
        deferred = true;
      }
      // Explicitly uncommitted evidence for an active Session remains byte-preserved;
      // the publication flow owns reuse/rebuild when content preflight succeeds.
    }
    return { deferred };
  }

  /**
   * §4.5.5 online migration phase: after identity/keyring/Relay initialization,
   * reconcile legacy raw inflight per item and convert explicitly uncommitted
   * evidence to the V2 source-digest wrapper. Idempotent and interruptible:
   * V2 records and items without inflight are skipped, committed evidence is
   * completed first (completion journal / session revision), network-unknown or
   * malformed evidence stays byte-preserved and defers to a later pass (the
   * §5.2 per-descriptor flow surfaces recovery-required for malformed cases).
   * Content-blocked sources are skipped so the §5.2 flow reconciles + dead-letters
   * them instead of the conversion pass.
   */
  async function convertLegacyInflightToV2(): Promise<boolean> {
    let deferred = false;
    // §4.5.5: enumerate every event inflight item (NOT only descriptors with a
    // source). Source-less legacy records are otherwise unreachable forever.
    for (const record of stateStore.listEventInflightRecords()) {
      if (record.kind === 'v2') continue; // already converted
      if (record.kind === 'malformed') { deferred = true; continue; } // byte-preserved, fail closed
      const upload = stateStore.getInflightEventUpload(record.eventId) as E2EEventAndSessionUploadV3;
      if (!upload) { deferred = true; continue; }
      const sessionId = record.sessionId || upload.session.sessionId;
      const loaded = stateStore.loadPendingEventParts({ eventId: record.eventId, sessionId });
      let wrapDigest: string | undefined;
      if (loaded.ok) {
        const preflight = preflightEventSource(loaded.source.event, loaded.source.session);
        if (preflight.type !== 'ready') continue; // content-blocked source: §5.2 reconciles + dead-letters
        wrapDigest = preflight.sourceDigest;
      } else if (loaded.reason !== 'source-missing') {
        continue; // malformed source: §5.2 reconciles then dead-letters / recovery-required
      }
      // Here the conversion pass owns the reconcile: the source is ready (wrap on
      // explicit uncommitted) or missing entirely (nothing else will ever touch it).
      // §4.5.5: only the reconcile round-trip is network-dependent; local completion/
      // wrap failures propagate (fail-closed) and are never reclassified as deferrals.
      let committed: boolean;
      try { committed = (await relayClient.reconcileEncryptedEvent(upload.event, upload.session)).committed; }
      catch (error) {
        reportDeferredFailure({ eventId: record.eventId, sessionId }, error);
        deferred = true;
        continue;
      }
      if (committed) {
        completeFromInflight(record.eventId, sessionId, upload);
      } else if (wrapDigest !== undefined) {
        stateStore.replaceInflightEventUpload(record.eventId, sessionId, upload, wrapDigest);
      } else {
        // Explicitly uncommitted with no wrap-able source: keep the raw legacy
        // evidence byte-preserved and fail closed — nothing else can resolve it.
        deferred = true;
      }
    }
    for (const sessionId of stateStore.listInflightSessionIds()) {
      const lookup = stateStore.getSessionInflightLookup(sessionId);
      if (lookup.kind === 'missing' || lookup.kind === 'v2') continue; // nothing to convert
      if (lookup.kind === 'malformed' || lookup.kind === 'cross-bound') {
        // §4.4/§5.1: byte-preserved and fail closed — recovery-required surfaces
        // through the publication/recovery flows, never completed or wrapped.
        deferred = true;
        continue;
      }
      const legacy = lookup.upload;
      const session = stateStore.getSession(sessionId);
      if (session && preflightSessionSource(session).type !== 'ready') continue; // content-blocked: §6.1/§4.4 own it
      // §4.5.5: the reconcile round-trip is the only network-dependent step; local
      // completion/wrap failures propagate (fail-closed) and are never reclassified
      // as network deferrals.
      let committed: boolean;
      try { committed = await relayClient.reconcileEncryptedSession(legacy); }
      catch (error) {
        reportDeferredFailure({ eventId: sessionId, sessionId }, error);
        deferred = true;
        continue;
      }
      if (committed) {
        stateStore.commitSessionRevision(sessionId, legacy.revision);
        stateStore.removeInflightSessionUpload(sessionId);
      } else if (session) {
        const readySource = preflightSessionSource(session) as Extract<
          ReturnType<typeof preflightSessionSource>, { type: 'ready' }
        >;
        stateStore.replaceInflightSessionUpload(sessionId, legacy, readySource.sourceDigest);
      } else {
        // Explicitly uncommitted with no runtime Session to derive a source digest:
        // keep the raw legacy evidence byte-preserved and fail closed.
        deferred = true;
      }
    }
    return !deferred;
  }


  async function flushPendingEvents(): Promise<number> {
    // §4.5.5: run the online legacy-inflight conversion first; it is idempotent
    // and interruptible. When conversion cannot converge (source-less/malformed
    // legacy evidence or a network-unknown reconcile), Event drain stops — §6.2
    // keeps the stop semantics for unconverged legacy inflight evidence.
    if (!await convertLegacyInflightToV2()) return 0;
    let snapshot: E2ERecipientSnapshotV1;
    try { snapshot = await relayClient.recipientSnapshot(); } catch (error) {
      reportDeferredFailure(undefined, error);
      return 0;
    }
    let recipients: EncryptedUploadRecipientMaterial[];
    try { recipients = keyring.reconcileRecipients(snapshot); } catch (error) {
      reportDeferredFailure(undefined, error);
      return 0;
    }
    if (snapshot.recipientSetVersion !== stateStore.getRecipientSetVersion()) {
      if (!await publishRecipientChangeSnapshots(snapshot, recipients)) return 0;
    }
    const ctx: EventFlushContext = { snapshot, recipients };
    let flushed = 0;
    for (const descriptor of stateStore.listPendingEventDescriptors()) {
      const outcome = await processPendingEventDescriptor(descriptor, ctx);
      switch (outcome.outcome) {
        case 'completed':
        case 'flushed':
          flushed += 1;
          continue;
        case 'quarantined':
          continue;
        case 'deferred':
        case 'recovery-required':
          return flushed;
      }
    }
    return flushed;
  }

  /**
   * §5.2 per-descriptor state machine, shared by the normal flush and startup
   * reconciliation (entry point 6 of §4.2). A malformed inflight or an internal
   * spool/AEAD failure never reaches the quarantine path.
   */
  async function processPendingEventDescriptor(descriptor: PendingEventDescriptor, ctx: EventFlushContext): Promise<PendingEventDescriptorOutcome> {
    const { eventId, sessionId } = descriptor;

    // §5.2 step 1: completion journal recovery wins over everything.
    if (stateStore.hasEventUploadCompletion(eventId)) {
      stateStore.completeEventUpload(eventId, (phase) => hooks?.eventCompletionStep?.(phase, eventId));
      return { outcome: 'completed' };
    }

    // §5.2 steps 2-3: load inflight first; malformed inflight is recovery-required.
    const loaded = stateStore.loadPendingEventParts(descriptor);
    if (isInflightLoadFailure(loaded)) {
      return { outcome: 'recovery-required' };
    }
    const inflight = loaded.inflight;
    try {
      // §5.2 step 4: malformed source → dead-letter (reconcile any inflight first).
      if (!loaded.ok) {
        const reason = sourceDeadLetterReason(loaded.reason);
        if (!reason) return { outcome: 'recovery-required' };
        if (inflight) {
          const reconciled = await reconcileInflightBeforeOverwrite(eventId, sessionId, inflight);
          if ('outcome' in reconciled) return reconciled;
        }
        return quarantineEvent(descriptor, reason, inflight?.raw);
      }

      const { event, session } = loaded.source;

      // §5.2 step 5: typed preflight before any sealing/wrapping.
      const preflight = preflightEventSource(event, session);
      if (preflight.type !== 'ready') {
        const reason = preflight.type === 'invalid-content' ? 'protected-content-invalid' : 'event-session-binding-invalid';
        if (inflight) {
          const reconciled = await reconcileInflightBeforeOverwrite(eventId, sessionId, inflight);
          if ('outcome' in reconciled) return reconciled;
          // Explicitly uncommitted: dead-letter only when no proven digest mismatch.
          const currentDigest = sourceDigestOrUndefined(event, session);
          if (currentDigest !== undefined && inflight.kind === 'v2' && !digestsEqual(inflight.sourceDigest, currentDigest)) {
            return { outcome: 'recovery-required' };
          }
        }
        return quarantineEvent(descriptor, reason, inflight?.raw);
      }
      const sourceDigest = preflight.sourceDigest;

      // §5.2 step 6 / §4.4: a proven V2 digest mismatch against the immutable
      // source is local invariant corruption: reconcile first; committed →
      // complete, explicitly uncommitted → recovery-required, never rebuild.
      const digestMismatch = inflight !== undefined && inflight.kind === 'v2' && !digestsEqual(inflight.sourceDigest, sourceDigest);
      const recipientMismatch = inflight !== undefined
        && (inflight.upload.event.recipientSetVersion !== ctx.snapshot.recipientSetVersion
          || inflight.upload.session.recipientSetVersion !== ctx.snapshot.recipientSetVersion);
      if (inflight && (digestMismatch || recipientMismatch)) {
        const reconciled = await reconcileInflightBeforeOverwrite(eventId, sessionId, inflight);
        if ('outcome' in reconciled) return reconciled;
        if (digestMismatch) return { outcome: 'recovery-required' };
      }

      // §5.2 step 7: reuse an unchanged inflight, otherwise encrypt fresh.
      const canReuse = inflight !== undefined && !recipientMismatch;
      let upload: EncryptedEventAndSession;
      if (canReuse) {
        upload = inflight.upload;
      } else {
        upload = encryptEvent(event, session, inflight?.upload.session.revision ?? stateStore.nextSessionRevision(event.sessionId),
          ctx.snapshot.recipientSetVersion, ctx.recipients);
        if (inflight) stateStore.replaceInflightEventUpload(eventId, sessionId, upload, sourceDigest);
        else stateStore.persistInflightEventUpload(eventId, sessionId, upload, sourceDigest);
      }
      return publishEventUpload(event, session, eventId, sessionId, upload, ctx);
    } finally {
      inflight?.raw.fill(0);
    }
  }

  /**
   * §4.4 reconcile-before-overwrite: submits the ORIGINAL inflight envelope to
   * the Relay exactly before it would be replaced or dead-lettered. Committed →
   * complete old evidence; network/identity/malformed/uncertain → defer with all
   * evidence preserved (never treated as uncommitted).
   */
  async function reconcileInflightBeforeOverwrite(
    eventId: string,
    sessionId: string,
    inflight: LoadedEventInflight,
  ): Promise<PendingEventDescriptorOutcome | { committed: false; provenUncommitted: true }> {
    let committed: boolean;
    try {
      committed = (await relayClient.reconcileEncryptedEvent(inflight.upload.event, inflight.upload.session)).committed;
    } catch (error) {
      reportDeferredFailure({ eventId, sessionId }, error);
      return { outcome: 'deferred' };
    }
    if (committed) {
      completeFromInflight(eventId, sessionId, inflight.upload);
      return { outcome: 'completed' };
    }
    return { committed: false as const, provenUncommitted: true as const };
  }

  function completeFromInflight(eventId: string, sessionId: string, upload: EncryptedEventAndSession): void {
    stateStore.beginEventUploadCompletion({
      version: 1, eventId, sessionId, revision: upload.session.revision,
      eventContentId: upload.event.content.contentId, sessionContentId: upload.session.content.contentId,
      committedAt: new Date().toISOString(),
    });
    hooks?.eventCompletionStep?.('journaled', eventId);
    stateStore.completeEventUpload(eventId, (phase) => hooks?.eventCompletionStep?.(phase, eventId));
  }

  function quarantineEvent(
    descriptor: PendingEventDescriptor,
    reasonCode: EventDeadLetterReasonCode,
    provenUncommittedInflight?: Uint8Array,
  ): PendingEventDescriptorOutcome {
    let quarantined: boolean;
    try {
      quarantined = stateStore.quarantinePendingEventRaw(descriptor, reasonCode, provenUncommittedInflight);
    } catch (error) {
      // The source and inflight records stay untouched and retryable; a local
      // spool write failure is a storage fault, never a Relay network category.
      reportDeferredFailure({ eventId: descriptor.eventId, sessionId: descriptor.sessionId }, error, 'local-spool-record');
      return { outcome: 'deferred' };
    }
    if (!quarantined) return { outcome: 'deferred' };
    hooks?.eventFailure?.({
      eventId: descriptor.eventId, sessionId: descriptor.sessionId, outcome: 'quarantined', category: 'local-validation',
    });
    return { outcome: 'quarantined' };
  }

  function sourceDigestOrUndefined(
    event: import('@ariava/protocol').CanonicalEvent,
    session: import('@ariava/protocol').CanonicalSessionState,
  ): string | undefined {
    try { return eventSourceDigest(event, session); } catch { return undefined; }
  }

  /**
   * §5.2 step 7 publish loop: reuse-or-fresh upload, conflict handling via the
   * existing decision model, recipient refresh at most once, completion journal.
   */
  async function publishEventUpload(
    event: import('@ariava/protocol').CanonicalEvent,
    session: import('@ariava/protocol').CanonicalSessionState,
    eventId: string,
    sessionId: string,
    initialUpload: EncryptedEventAndSession,
    ctx: EventFlushContext,
  ): Promise<PendingEventDescriptorOutcome> {
    let inflight = initialUpload;
    let decision: EventUploadDecision;
    let conflictError: unknown;
    try {
      await relayClient.publishEncryptedEvent(inflight.event, inflight.session);
      decision = { type: 'complete' };
    } catch (error) {
      conflictError = error;
      if (!isRelayConflict(error)) {
        reportDeferredFailure({ eventId, sessionId }, error);
        return { outcome: 'deferred' };
      }
      // §4.4: reconcile the ORIGINAL envelope exactly; a reconcile network/identity
      // failure is NOT an explicit uncommitted verdict — defer with all evidence
      // preserved and never quarantine on unknown commit state.
      let reconciled: { committed: boolean };
      try {
        reconciled = await relayClient.reconcileEncryptedEvent(inflight.event, inflight.session);
      } catch (reconcileError) {
        reportDeferredFailure({ eventId, sessionId }, reconcileError);
        return { outcome: 'deferred' };
      }
      decision = decideEventUpload({
        publishSucceeded: false,
        conflictReason: error.reason,
        reconcileCommitted: reconciled.committed,
        permanentEventConflict: isPermanentEventConflict(error),
        failureCategory: relayFailureCategory(error),
      });
    }
    if (decision.type === 'refresh-session-and-reencrypt') {
      try {
        ctx.snapshot = await relayClient.recipientSnapshot();
        ctx.recipients = keyring.reconcileRecipients(ctx.snapshot);
      } catch (refreshError) {
        reportDeferredFailure({ eventId, sessionId }, refreshError);
        return { outcome: 'deferred' };
      }
      const replacement = encryptEvent(event, session, inflight.session.revision, ctx.snapshot.recipientSetVersion, ctx.recipients);
      stateStore.replaceInflightEventUpload(eventId, sessionId, replacement, eventSourceDigest(event, session));
      inflight = replacement;
      try {
        await relayClient.publishEncryptedEvent(inflight.event, inflight.session);
        decision = { type: 'complete' };
      } catch (retryError) {
        conflictError = retryError;
        // §4.4: the refresh-retry path must also reconcile exactly before any
        // quarantine decision; an unknown reconcile outcome defers, never quarantines.
        let retryReconciled: { committed: boolean } | undefined;
        if (isRelayConflict(retryError)) {
          try {
            retryReconciled = await relayClient.reconcileEncryptedEvent(inflight.event, inflight.session);
          } catch (reconcileError) {
            reportDeferredFailure({ eventId, sessionId }, reconcileError);
            return { outcome: 'deferred' };
          }
        }
        decision = decideEventUpload({
          publishSucceeded: false,
          conflictReason: isRelayConflict(retryError) ? retryError.reason : undefined,
          reconcileCommitted: retryReconciled?.committed,
          permanentEventConflict: isPermanentEventConflict(retryError),
          recipientRefreshExhausted: true,
          failureCategory: relayFailureCategory(retryError),
        });
      }
    }
    if (decision.type === 'complete') {
      completeFromInflight(eventId, sessionId, inflight);
      return { outcome: 'flushed' };
    }
    if (decision.type === 'quarantine') {
      if (!quarantinePermanentlyConflictingEvent(event, conflictError)) return { outcome: 'deferred' };
      return { outcome: 'quarantined' };
    }
    reportDeferredFailure({ eventId, sessionId }, conflictError);
    return { outcome: 'deferred' };
  }

  function quarantinePermanentlyConflictingEvent(event: import('@ariava/protocol').CanonicalEvent, error: unknown): boolean {
    const relayError = isRelayConflict(error) ? error : undefined;
    const inflightRaw = stateStore.openInflightEventRaw(event.eventId);
    let quarantined: boolean;
    try {
      quarantined = stateStore.quarantinePendingEventRaw(
        { eventId: event.eventId, sessionId: event.sessionId },
        'relay-permanent-conflict',
        inflightRaw,
      );
    } catch {
      // The encrypted source and inflight records must remain retryable; a local
      // spool write failure is a storage fault, never a Relay network category.
      reportDeferredFailure(event, error, 'local-spool-record');
      return false;
    } finally {
      inflightRaw?.fill(0);
    }
    if (!quarantined) {
      reportDeferredFailure(event, error, 'local-spool-record');
      return false;
    }
    hooks?.eventFailure?.({
      eventId: event.eventId,
      sessionId: event.sessionId,
      outcome: 'quarantined',
      status: relayErrorStatus(error),
      category: relayFailureCategory(error),
    });
    return true;
  }

  function encryptEvent(
    event: import('@ariava/protocol').CanonicalEvent,
    session: import('@ariava/protocol').CanonicalSessionState,
    revision: number,
    recipientSetVersion: number,
    recipients: EncryptedUploadRecipientMaterial[],
  ): EncryptedEventAndSession {
    return crypto.encryptEventUpload({ event, session, revision, recipientSetVersion, recipients });
  }

  function reportDeferredFailure(event: { eventId?: string; sessionId?: string } | undefined, error: unknown, categoryOverride?: UploadFailureCategory): void {
    const status = relayErrorStatus(error);
    hooks?.eventFailure?.({ eventId: event?.eventId ?? 'pending-events', sessionId: event?.sessionId ?? 'unknown',
      outcome: 'retry-deferred', ...(status !== undefined ? { status } : {}), category: categoryOverride ?? relayFailureCategory(error) });
  }

  async function publishRecipientChangeSnapshots(snapshot: E2ERecipientSnapshotV1, recipients: EncryptedUploadRecipientMaterial[]): Promise<boolean> {
    const pendingIds = new Set(stateStore.listInflightSessionIds());
    for (const session of stateStore.listSessions()) {
      if (!stateStore.getInflightSessionUpload(session.sessionId)) {
        if (preflightSessionSource(session).type !== 'ready') return false;
        const upload = crypto.encryptSessionSnapshot({ session, revision: stateStore.nextSessionRevision(session.sessionId),
          recipientSetVersion: snapshot.recipientSetVersion, recipients });
        stateStore.persistInflightSessionUpload(session.sessionId, upload, sessionSourceDigest(session)); pendingIds.add(session.sessionId);
      }
    }
    for (const sessionId of pendingIds) {
      let upload = stateStore.getInflightSessionUpload(sessionId) as EncryptedSessionSnapshotUploadV3 | undefined; if (!upload) return false;
      let sameVersionCommitRetryExhausted = false;
      for (;;) {
        let decision: SessionUploadDecision;
        let conflictError: unknown;
        let currentSnapshot: E2ERecipientSnapshotV1 | undefined;
        let currentRecipients: EncryptedUploadRecipientMaterial[] | undefined;
        let session: import('@ariava/protocol').CanonicalSessionState | undefined;
        try {
          await relayClient.publishEncryptedSession(upload);
          decision = decideSessionUpload({
            publishSucceeded: true,
            attemptedRecipientVersion: upload.recipientSetVersion,
            currentRevision: upload.revision,
            failureCategory: 'http',
          });
        } catch (error) {
          conflictError = error;
          if (!isRelayConflict(error)) {
            decision = decideSessionUpload({
              publishSucceeded: false,
              attemptedRecipientVersion: upload.recipientSetVersion,
              currentRevision: upload.revision,
              failureCategory: relayFailureCategory(error),
            });
          } else {
            let committed: boolean;
            try { committed = await relayClient.reconcileEncryptedSession(upload); }
            catch (reconcileError) {
              reportDeferredFailure(undefined, reconcileError);
              return false;
            }
            if (error.reason === RECIPIENT_SET_CHANGED_REASON) {
              session = stateStore.getSession(sessionId);
              if (!session) return false;
              try {
                currentSnapshot = await relayClient.recipientSnapshot();
                currentRecipients = keyring.reconcileRecipients(currentSnapshot);
              } catch { return false; }
              snapshot = currentSnapshot;
              recipients = currentRecipients;
            }
            decision = decideSessionUpload({
              publishSucceeded: false,
              conflictReason: error.reason,
              reconcileCommitted: committed,
              attemptedRecipientVersion: upload.recipientSetVersion,
              refreshedRecipientVersion: currentSnapshot?.recipientSetVersion,
              currentRevision: upload.revision,
              sameVersionCommitRetryExhausted,
              failureCategory: relayFailureCategory(error),
            });
          }
        }
        switch (decision.type) {
          case 'commit':
            stateStore.commitSessionRevision(sessionId, decision.acceptedRevision);
            stateStore.removeInflightSessionUpload(sessionId);
            break;
          case 'defer':
          case 'reconcile':
            return false;
          case 'fail-closed':
            reportDeferredFailure(undefined, conflictError);
            return false;
          case 'refresh-reencrypt': {
            if (!session || !currentSnapshot || !currentRecipients) return false;
            if (preflightSessionSource(session).type !== 'ready') return false;
            const replacement = crypto.encryptSessionSnapshot({ session, revision: decision.revision,
              recipientSetVersion: currentSnapshot.recipientSetVersion, recipients: currentRecipients });
            stateStore.replaceInflightSessionUpload(sessionId, replacement, sessionSourceDigest(session));
            upload = replacement;
            break;
          }
          case 'retry-next-revision': {
            if (!session || !currentSnapshot || !currentRecipients) return false;
            if (preflightSessionSource(session).type !== 'ready') return false;
            sameVersionCommitRetryExhausted = currentSnapshot.recipientSetVersion === upload.recipientSetVersion;
            stateStore.commitSessionRevision(sessionId, upload.revision);
            stateStore.removeInflightSessionUpload(sessionId);
            upload = crypto.encryptSessionSnapshot({ session, revision: decision.revision,
              recipientSetVersion: currentSnapshot.recipientSetVersion, recipients: currentRecipients });
            stateStore.persistInflightSessionUpload(sessionId, upload, sessionSourceDigest(session));
            break;
          }
        }
        if (decision.type === 'commit') break;
      }
    }
    stateStore.setRecipientSetVersion(snapshot.recipientSetVersion);
    return true;
  }

  return {
    publishAuthoritativeSnapshots,
    preflightAuthoritativeSessionSet,
    reconcileSessionInflights,
    convertLegacyInflightToV2,
    flushPendingEvents,
    publishRecipientChangeSnapshots,
  };
}

export type EncryptedUploadActions = ReturnType<typeof createEncryptedUploadActions>;

/** Per-descriptor outcome taxonomy (§5.2/§5.4). `deferred` keeps the existing
 * network stop semantics; `recovery-required` preserves evidence and fails
 * closed without quarantining; `quarantined`/`completed`/`flushed` continue to
 * the next descriptor.
 */
type PendingEventDescriptorOutcome = { outcome: 'completed' | 'flushed' | 'quarantined' | 'deferred' | 'recovery-required' };

interface EventFlushContext {
  snapshot: E2ERecipientSnapshotV1;
  recipients: EncryptedUploadRecipientMaterial[];
}

type InflightLoadFailure = Extract<
  LoadPendingEventPartsResult,
  { ok: false; reason: `inflight-${string}` }
>;

function publicationBlockReason(
  preflight: Exclude<ReturnType<typeof preflightSessionSource>, { type: 'ready' }>,
): SessionPublicationBlockReason {
  return preflight.type === 'invalid-source-binding'
    ? 'session_source_invalid'
    : 'protected_content_invalid';
}

function isInflightLoadFailure(result: LoadPendingEventPartsResult): result is InflightLoadFailure {
  return !result.ok && result.reason.startsWith('inflight-');
}

function sourceDeadLetterReason(
  reason: 'source-utf8-invalid' | 'source-json-invalid' | 'source-shape-invalid' | 'source-binding-invalid' | 'source-missing',
): EventDeadLetterReasonCode | undefined {
  switch (reason) {
    case 'source-utf8-invalid': return 'source-utf8-invalid';
    case 'source-json-invalid': return 'source-json-invalid';
    case 'source-shape-invalid': return 'source-json-invalid'; // non-canonical field set → quarantined as an invalid source
    case 'source-binding-invalid': return 'event-session-binding-invalid';
    case 'source-missing': return undefined; // nothing to quarantine → recovery-required
  }
}
