import type { E2EEventAndSessionUploadV3, E2ERecipientSnapshotV1, EncryptedSessionSnapshotUploadV3 } from '@ariava/protocol';
import type { RelayClient } from '../relay-client';
import type { BridgeStateStore } from '../state-store';
import { encryptEventUpload, encryptSessionSnapshot, type ActiveRecipientMaterial } from './envelope';
import type { LocalLinkKeyring } from './link-keyring';
import { RECIPIENT_SET_CHANGED_REASON, decideEventUpload, decideSessionUpload, type EventUploadDecision, type SessionUploadDecision } from './upload-decisions';
import { isPermanentEventConflict, isRelayConflict, relayErrorStatus, relayFailureCategory, type UploadFailureCategory } from './upload-failures';
import { attachNotificationPreviews, assertEventSessionBinding, eventEncryptionInput, sessionEncryptionInput, type EncryptedEventAndSession } from './upload-inputs';

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

export class EncryptedUploadOrchestrator {
  constructor(private readonly stateStore: BridgeStateStore, private readonly client: RelayClient,
    private readonly keyring: LocalLinkKeyring,
    private readonly hooks?: EncryptedUploadHooks) {}

  async publishAuthoritativeSnapshots(snapshot: E2ERecipientSnapshotV1, recipients: ActiveRecipientMaterial[], sessionIds: readonly string[]): Promise<{ recipientSetVersion: number; revisions: Map<string, number> } | undefined> {
    // A recipient change invalidates the whole authoritative set, including Sessions
    // already committed during this pass. Restart until every returned revision was
    // encrypted for one final recipient-set version.
    let sameVersionCommitRetryExhausted = false;
    for (;;) {
      const passVersion = snapshot.recipientSetVersion;
      const revisions = new Map<string, number>();
      let restart = false;
      for (const sessionId of sessionIds) {
        const session = this.stateStore.getSession(sessionId);
        if (!session) return undefined;
        let upload = this.stateStore.getInflightSessionUpload(sessionId) as EncryptedSessionSnapshotUploadV3 | undefined;
        if (!upload || upload.recipientSetVersion !== passVersion) {
          const next = encryptSessionSnapshot({ ...sessionEncryptionInput(session), revision: upload?.revision ?? this.stateStore.nextSessionRevision(sessionId),
            recipientSetVersion: passVersion, recipients });
          if (upload) this.stateStore.replaceInflightSessionUpload(sessionId, next); else this.stateStore.persistInflightSessionUpload(sessionId, next);
          upload = next;
        }
        let currentSnapshot = snapshot;
        let currentRecipients = recipients;
        let refreshed = false;
        let decision: SessionUploadDecision;
        for (;;) {
          try { await this.client.publishEncryptedSession(upload); } catch (error) {
            if (!isRelayConflict(error)) return undefined;
            const committed = await this.client.reconcileEncryptedSession(upload).catch(() => false);
            if (error.reason === RECIPIENT_SET_CHANGED_REASON) {
              try {
                currentSnapshot = await this.client.recipientSnapshot();
                currentRecipients = this.keyring.reconcileRecipients(currentSnapshot);
              } catch { return undefined; }
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
                this.stateStore.commitSessionRevision(sessionId, decision.acceptedRevision);
                this.stateStore.removeInflightSessionUpload(sessionId);
                revisions.set(sessionId, decision.acceptedRevision);
                break;
              case 'defer':
              case 'fail-closed':
              case 'reconcile':
                return undefined;
              case 'refresh-reencrypt': {
                const replacement = encryptSessionSnapshot({ ...sessionEncryptionInput(session), revision: decision.revision,
                  recipientSetVersion: currentSnapshot.recipientSetVersion, recipients: currentRecipients });
                this.stateStore.replaceInflightSessionUpload(sessionId, replacement);
                snapshot = currentSnapshot; recipients = currentRecipients;
                restart = true;
                break;
              }
              case 'retry-next-revision': {
                sameVersionCommitRetryExhausted = currentSnapshot.recipientSetVersion === passVersion;
                this.stateStore.commitSessionRevision(sessionId, upload.revision);
                this.stateStore.removeInflightSessionUpload(sessionId);
                snapshot = currentSnapshot; recipients = currentRecipients;
                restart = true;
                break;
              }
            }
            // Every decision ends this pass; refresh/retry re-run the outer loop via `restart`.
            break;
          }
          this.stateStore.commitSessionRevision(sessionId, upload.revision);
          this.stateStore.removeInflightSessionUpload(sessionId);
          revisions.set(sessionId, upload.revision);
          break;
        }
        if (restart) break;
      }
      if (restart) continue;
      this.stateStore.setRecipientSetVersion(passVersion);
      return { recipientSetVersion: passVersion, revisions };
    }
  }

  async flushPendingEvents(): Promise<number> {
    let snapshot: E2ERecipientSnapshotV1;
    try { snapshot = await this.client.recipientSnapshot(); } catch (error) {
      this.reportDeferredFailure(undefined, error);
      return 0;
    }
    let recipients: ActiveRecipientMaterial[];
    try { recipients = this.keyring.reconcileRecipients(snapshot); } catch (error) {
      this.reportDeferredFailure(undefined, error);
      return 0;
    }
    if (snapshot.recipientSetVersion !== this.stateStore.getRecipientSetVersion()) {
      if (!await this.publishRecipientChangeSnapshots(snapshot, recipients)) return 0;
    }
    let flushed = 0;
    for (const pending of this.stateStore.peekPendingUploads()) {
      const event = pending.event;
      const session = pending.session;
      assertEventSessionBinding(event, session);
      let inflight = this.stateStore.getInflightEventUpload(event.eventId) as EncryptedEventAndSession | undefined;
      if (!inflight || inflight.event.recipientSetVersion !== snapshot.recipientSetVersion
        || inflight.session.recipientSetVersion !== snapshot.recipientSetVersion) {
        const replacement = this.encryptEvent(event, session, inflight?.session.revision ?? this.stateStore.nextSessionRevision(event.sessionId),
          snapshot.recipientSetVersion, recipients);
        if (inflight) this.stateStore.replaceInflightEventUpload(event.eventId, event.sessionId, replacement);
        else this.stateStore.persistInflightEventUpload(event.eventId, event.sessionId, replacement);
        inflight = replacement;
      }
      let decision: EventUploadDecision;
      let conflictError: unknown;
      try {
        await this.client.publishEncryptedEvent(inflight.event, inflight.session);
        decision = { type: 'complete' };
      } catch (error) {
        conflictError = error;
        if (!isRelayConflict(error)) {
          this.reportDeferredFailure(event, error);
          return flushed;
        }
        const reconciled = await this.client.reconcileEncryptedEvent(inflight.event, inflight.session).catch(() => ({ committed: false }));
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
          snapshot = await this.client.recipientSnapshot();
          recipients = this.keyring.reconcileRecipients(snapshot);
        } catch (refreshError) {
          this.reportDeferredFailure(event, refreshError);
          return flushed;
        }
        const replacement = this.encryptEvent(event, session, inflight.session.revision, snapshot.recipientSetVersion, recipients);
        this.stateStore.replaceInflightEventUpload(event.eventId, event.sessionId, replacement);
        inflight = replacement;
        try {
          await this.client.publishEncryptedEvent(inflight.event, inflight.session);
          decision = { type: 'complete' };
        } catch (retryError) {
          conflictError = retryError;
          decision = decideEventUpload({
            publishSucceeded: false,
            conflictReason: isRelayConflict(retryError) ? retryError.reason : undefined,
            reconcileCommitted: false,
            permanentEventConflict: isPermanentEventConflict(retryError),
            recipientRefreshExhausted: true,
            failureCategory: relayFailureCategory(retryError),
          });
        }
      }
      if (decision.type === 'complete') {
        this.stateStore.beginEventUploadCompletion({ version: 1, eventId: event.eventId, sessionId: event.sessionId,
          revision: inflight.session.revision, eventContentId: inflight.event.content.contentId,
          sessionContentId: inflight.session.content.contentId, committedAt: new Date().toISOString() });
        this.hooks?.eventCompletionStep?.('journaled', event.eventId);
        this.stateStore.completeEventUpload(event.eventId, (phase) => this.hooks?.eventCompletionStep?.(phase, event.eventId));
        flushed += 1;
        continue;
      }
      if (decision.type === 'quarantine') {
        if (!this.quarantinePermanentlyConflictingEvent(event, conflictError)) return flushed;
        continue;
      }
      this.reportDeferredFailure(event, conflictError);
      return flushed;
    }
    return flushed;
  }

  private quarantinePermanentlyConflictingEvent(event: import('@ariava/protocol').CanonicalEvent, error: unknown): boolean {
    const relayError = isRelayConflict(error) ? error : undefined;
    let quarantined: boolean;
    try {
      quarantined = this.stateStore.quarantinePendingEvent(event.eventId, event.sessionId, relayError?.reason ?? 'encrypted event conflict');
    } catch {
      // The encrypted source and inflight records must remain retryable.
      this.reportDeferredFailure(event, error);
      return false;
    }
    if (!quarantined) {
      this.reportDeferredFailure(event, error);
      return false;
    }
    this.hooks?.eventFailure?.({
      eventId: event.eventId,
      sessionId: event.sessionId,
      outcome: 'quarantined',
      status: relayErrorStatus(error),
      category: relayFailureCategory(error),
    });
    return true;
  }

  private encryptEvent(
    event: import('@ariava/protocol').CanonicalEvent,
    session: import('@ariava/protocol').CanonicalSessionState,
    revision: number,
    recipientSetVersion: number,
    recipients: ActiveRecipientMaterial[],
  ): EncryptedEventAndSession {
    const upload = encryptEventUpload({ ...eventEncryptionInput(event, session), revision, recipientSetVersion, recipients });
    attachNotificationPreviews(upload, event, session, recipients);
    return upload;
  }

  private reportDeferredFailure(event: import('@ariava/protocol').CanonicalEvent | undefined, error: unknown): void {
    const status = relayErrorStatus(error);
    this.hooks?.eventFailure?.({ eventId: event?.eventId ?? 'pending-events', sessionId: event?.sessionId ?? 'unknown',
      outcome: 'retry-deferred', ...(status !== undefined ? { status } : {}), category: relayFailureCategory(error) });
  }

  async publishRecipientChangeSnapshots(snapshot: E2ERecipientSnapshotV1, recipients: ActiveRecipientMaterial[]): Promise<boolean> {
    const pendingIds = new Set(this.stateStore.listInflightSessionIds());
    for (const session of this.stateStore.listSessions()) {
      if (!this.stateStore.getInflightSessionUpload(session.sessionId)) {
        const upload = encryptSessionSnapshot({ ...sessionEncryptionInput(session), revision: this.stateStore.nextSessionRevision(session.sessionId),
          recipientSetVersion: snapshot.recipientSetVersion, recipients });
        this.stateStore.persistInflightSessionUpload(session.sessionId, upload); pendingIds.add(session.sessionId);
      }
    }
    for (const sessionId of pendingIds) {
      let upload = this.stateStore.getInflightSessionUpload(sessionId) as EncryptedSessionSnapshotUploadV3 | undefined; if (!upload) return false;
      let sameVersionCommitRetryExhausted = false;
      for (;;) {
        let decision: SessionUploadDecision;
        let conflictError: unknown;
        let currentSnapshot: E2ERecipientSnapshotV1 | undefined;
        let currentRecipients: ActiveRecipientMaterial[] | undefined;
        let session: import('@ariava/protocol').CanonicalSessionState | undefined;
        try {
          await this.client.publishEncryptedSession(upload);
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
            const committed = await this.client.reconcileEncryptedSession(upload).catch(() => false);
            if (error.reason === RECIPIENT_SET_CHANGED_REASON) {
              session = this.stateStore.getSession(sessionId);
              if (!session) return false;
              try {
                currentSnapshot = await this.client.recipientSnapshot();
                currentRecipients = this.keyring.reconcileRecipients(currentSnapshot);
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
            this.stateStore.commitSessionRevision(sessionId, decision.acceptedRevision);
            this.stateStore.removeInflightSessionUpload(sessionId);
            break;
          case 'defer':
          case 'reconcile':
            return false;
          case 'fail-closed':
            this.reportDeferredFailure(undefined, conflictError);
            return false;
          case 'refresh-reencrypt': {
            if (!session || !currentSnapshot || !currentRecipients) return false;
            const replacement = encryptSessionSnapshot({ ...sessionEncryptionInput(session), revision: decision.revision,
              recipientSetVersion: currentSnapshot.recipientSetVersion, recipients: currentRecipients });
            this.stateStore.replaceInflightSessionUpload(sessionId, replacement);
            upload = replacement;
            break;
          }
          case 'retry-next-revision': {
            if (!session || !currentSnapshot || !currentRecipients) return false;
            sameVersionCommitRetryExhausted = currentSnapshot.recipientSetVersion === upload.recipientSetVersion;
            this.stateStore.commitSessionRevision(sessionId, upload.revision);
            this.stateStore.removeInflightSessionUpload(sessionId);
            upload = encryptSessionSnapshot({ ...sessionEncryptionInput(session), revision: decision.revision,
              recipientSetVersion: currentSnapshot.recipientSetVersion, recipients: currentRecipients });
            this.stateStore.persistInflightSessionUpload(sessionId, upload);
            break;
          }
        }
        if (decision.type === 'commit') break;
      }
    }
    this.stateStore.setRecipientSetVersion(snapshot.recipientSetVersion);
    return true;
  }
}
