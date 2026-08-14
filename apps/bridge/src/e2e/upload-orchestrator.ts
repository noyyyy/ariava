import type { E2ERecipientSnapshotV1, EncryptedEventUploadV2, EncryptedSessionSnapshotUploadV2 } from '@ariava/protocol';
import type { RelayClient } from '../relay-client';
import { RelayClientError } from '../relay-client';
import type { BridgeStateStore } from '../state-store';
import { encryptEventUpload, encryptNotificationPreviews, encryptSessionSnapshot, type ActiveRecipientMaterial } from './envelope';
import type { LocalLinkKeyring } from './link-keyring';
import { buildNotificationPreview } from './notification-preview';

export interface EncryptedEventFailure {
  eventId: string;
  sessionId: string;
  outcome: 'retry-deferred' | 'quarantined';
  status?: number;
  category: 'network' | 'http' | 'recipient-set' | 'session-revision' | 'event-content';
}

export interface EncryptedUploadHooks {
  eventCompletionStep?: (phase: 'journaled' | 'revision-committed' | 'inflight-removed' | 'source-removed' | 'journal-removed', eventId: string) => void;
  eventFailure?: (failure: EncryptedEventFailure) => void;
}

type EncryptedEventAndSession = { event: EncryptedEventUploadV2; session: EncryptedSessionSnapshotUploadV2 };

export class EncryptedUploadOrchestrator {
  constructor(private readonly stateStore: BridgeStateStore, private readonly client: RelayClient,
    private readonly keyring: LocalLinkKeyring,
    private readonly hooks?: EncryptedUploadHooks) {}

  async publishAuthoritativeSnapshots(snapshot: E2ERecipientSnapshotV1, recipients: ActiveRecipientMaterial[], sessionIds: readonly string[]): Promise<{ recipientSetVersion: number; revisions: Map<string, number> } | undefined> {
    // A recipient change invalidates the whole authoritative set, including Sessions
    // already committed during this pass. Restart until every returned revision was
    // encrypted for one final recipient-set version.
    for (;;) {
      const passVersion = snapshot.recipientSetVersion;
      const revisions = new Map<string, number>();
      let restart = false;
      for (const sessionId of sessionIds) {
        const session = this.stateStore.getSession(sessionId);
        if (!session) return undefined;
        let upload = this.stateStore.getInflightSessionUpload(sessionId) as EncryptedSessionSnapshotUploadV2 | undefined;
        if (!upload || upload.recipientSetVersion !== passVersion) {
          const next = encryptSessionSnapshot({ ...sessionEncryptionInput(session), revision: upload?.revision ?? this.stateStore.nextSessionRevision(sessionId),
            recipientSetVersion: passVersion, recipients });
          if (upload) this.stateStore.replaceInflightSessionUpload(sessionId, next); else this.stateStore.persistInflightSessionUpload(sessionId, next);
          upload = next;
        }
        for (;;) {
          try { await this.client.publishEncryptedSession(upload); } catch (error) {
            if (!isRelayConflict(error)) return undefined;
            const committed = await this.client.reconcileEncryptedSession(upload).catch(() => false);
            if (error.reason !== 'e2e_recipient_set_changed') { if (!committed) return undefined; }
            else {
              let refreshed: E2ERecipientSnapshotV1; let refreshedRecipients: ActiveRecipientMaterial[];
              try { refreshed = await this.client.recipientSnapshot(); refreshedRecipients = this.keyring.reconcileRecipients(refreshed); } catch { return undefined; }
              // A same-version recipient conflict cannot make progress and must not spin.
              if (refreshed.recipientSetVersion === passVersion) return undefined;
              if (committed) {
                this.stateStore.commitSessionRevision(sessionId, upload.revision);
                this.stateStore.removeInflightSessionUpload(sessionId);
              } else {
                const replacement = encryptSessionSnapshot({ ...sessionEncryptionInput(session), revision: upload.revision,
                  recipientSetVersion: refreshed.recipientSetVersion, recipients: refreshedRecipients });
                this.stateStore.replaceInflightSessionUpload(sessionId, replacement);
              }
              snapshot = refreshed; recipients = refreshedRecipients; restart = true; break;
            }
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
      try {
        await this.client.publishEncryptedEvent(inflight.event, inflight.session);
      } catch (error) {
        if (!isRelayConflict(error)) {
          this.reportDeferredFailure(event, error);
          return flushed;
        }
        if (!(await this.client.reconcileEncryptedEvent(inflight.event, inflight.session).catch(() => ({ committed: false }))).committed) {
          if (error.reason === 'e2e_recipient_set_changed') {
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
            } catch (retryError) {
              if (isPermanentEventConflict(retryError)) {
                if (!this.quarantinePermanentlyConflictingEvent(event, retryError)) return flushed;
                continue;
              }
              this.reportDeferredFailure(event, retryError);
              return flushed;
            }
          } else if (isPermanentEventConflict(error)) {
            if (!this.quarantinePermanentlyConflictingEvent(event, error)) return flushed;
            continue;
          } else {
            this.reportDeferredFailure(event, error);
            return flushed;
          }
        }
      }
      this.stateStore.beginEventUploadCompletion({ version: 1, eventId: event.eventId, sessionId: event.sessionId,
        revision: inflight.session.revision, eventContentId: inflight.event.content.contentId,
        sessionContentId: inflight.session.content.contentId, committedAt: new Date().toISOString() });
      this.hooks?.eventCompletionStep?.('journaled', event.eventId);
      this.stateStore.completeEventUpload(event.eventId, (phase) => this.hooks?.eventCompletionStep?.(phase, event.eventId));
      flushed += 1;
    }
    return flushed;
  }

  private quarantinePermanentlyConflictingEvent(event: import('@ariava/protocol').CanonicalEvent, error: RelayClientError): boolean {
    let quarantined: boolean;
    try {
      quarantined = this.stateStore.quarantinePendingEvent(event.eventId, event.sessionId, error.reason);
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
      status: error.status,
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
      let upload = this.stateStore.getInflightSessionUpload(sessionId) as EncryptedSessionSnapshotUploadV2 | undefined; if (!upload) return false;
      for (;;) {
        try {
          await this.client.publishEncryptedSession(upload);
          this.stateStore.commitSessionRevision(sessionId, upload.revision);
          this.stateStore.removeInflightSessionUpload(sessionId);
          break;
        } catch (error) {
          if (!isRelayConflict(error)) return false;
          const committed = await this.client.reconcileEncryptedSession(upload).catch(() => false);
          if (error.reason !== 'e2e_recipient_set_changed') {
            if (!committed) return false;
            this.stateStore.commitSessionRevision(sessionId, upload.revision);
            this.stateStore.removeInflightSessionUpload(sessionId);
            break;
          }
          const session = this.stateStore.getSession(sessionId); if (!session) return false;
          let currentSnapshot: E2ERecipientSnapshotV1; let currentRecipients: ActiveRecipientMaterial[];
          try {
            currentSnapshot = await this.client.recipientSnapshot();
            currentRecipients = this.keyring.reconcileRecipients(currentSnapshot);
          } catch { return false; }
          snapshot = currentSnapshot; recipients = currentRecipients;
          if (committed) {
            this.stateStore.commitSessionRevision(sessionId, upload.revision);
            this.stateStore.removeInflightSessionUpload(sessionId);
            if (currentSnapshot.recipientSetVersion === upload.recipientSetVersion) return false;
            upload = encryptSessionSnapshot({ ...sessionEncryptionInput(session), revision: this.stateStore.nextSessionRevision(sessionId),
              recipientSetVersion: currentSnapshot.recipientSetVersion, recipients: currentRecipients });
            this.stateStore.persistInflightSessionUpload(sessionId, upload);
          } else {
            const replacement = encryptSessionSnapshot({ ...sessionEncryptionInput(session), revision: upload.revision,
              recipientSetVersion: currentSnapshot.recipientSetVersion, recipients: currentRecipients });
            this.stateStore.replaceInflightSessionUpload(sessionId, replacement); upload = replacement;
          }
        }
      }
    }
    this.stateStore.setRecipientSetVersion(snapshot.recipientSetVersion);
    return true;
  }
}

function eventEncryptionInput(event: import('@ariava/protocol').CanonicalEvent, session: import('@ariava/protocol').CanonicalSessionState) {
  assertEventSessionBinding(event, session);
  return {
    event: { eventId: event.eventId, hostId: event.hostId, sessionId: event.sessionId, provider: event.provider,
      type: event.type, status: event.status, ...(event.correlationId ? { correlationId: event.correlationId } : {}),
      createdAt: event.createdAt },
    protectedEvent: { version: 2 as const, agentText: event.agentText,
      ...(event.humanText !== undefined ? { humanText: event.humanText } : {}),
      ...(event.projectName !== undefined ? { projectName: event.projectName } : {}),
      ...(event.contextText !== undefined ? { contextText: event.contextText } : {}),
      ...(event.workingDirectory !== undefined ? { workingDirectory: event.workingDirectory } : {}),
      ...(event.hbaseSessionKey !== undefined ? { hbaseSessionKey: event.hbaseSessionKey } : {}),
      ...(event.harnessProvider !== undefined ? { harnessProvider: event.harnessProvider } : {}),
      ...(event.actionablePrompt ? { actionablePrompt: event.actionablePrompt } : {}),
      ...(event.type === 'need_human' ? { needHuman: event.needHuman } : {}) },
    ...sessionEncryptionInput(session),
  };
}
function sessionEncryptionInput(session: import('@ariava/protocol').CanonicalSessionState) {
  return {
    session: { hostId: session.hostId, sessionId: session.sessionId, provider: session.provider, status: session.status,
      updatedAt: session.updatedAt, ...(session.lastEventId ? { lastEventId: session.lastEventId } : {}),
      ...(session.snoozedUntil ? { snoozedUntil: session.snoozedUntil } : {}) },
    protectedSession: { version: 2 as const, projectName: session.projectName, nameText: session.nameText,
      ...(session.openingText !== undefined ? { openingText: session.openingText } : {}),
      ...(session.latestActivityText !== undefined ? { latestActivityText: session.latestActivityText } : {}),
      ...(session.workingDirectory !== undefined ? { workingDirectory: session.workingDirectory } : {}),
      ...(session.hbaseSessionKey !== undefined ? { hbaseSessionKey: session.hbaseSessionKey } : {}),
      ...(session.harnessProvider !== undefined ? { harnessProvider: session.harnessProvider } : {}) },
  };
}
function attachNotificationPreviews(
  upload: EncryptedEventAndSession,
  event: import('@ariava/protocol').CanonicalEvent,
  session: import('@ariava/protocol').CanonicalSessionState,
  recipients: ActiveRecipientMaterial[],
  ): void {
  try {
    const plaintext = buildNotificationPreview(event, session);
    if (!plaintext) {
      upload.event.notificationPreviews = [];
      return;
    }
    upload.event.notificationPreviews = encryptNotificationPreviews({
      event: upload.event,
      plaintext,
      recipients,
    });
  } catch {
    upload.event.notificationPreviews = [];
  }
}

function assertEventSessionBinding(
  event: import('@ariava/protocol').CanonicalEvent,
  session: import('@ariava/protocol').CanonicalSessionState,
 ): void {
  if (event.hostId !== session.hostId || event.sessionId !== session.sessionId || event.provider !== session.provider
    || event.status !== session.status || session.lastEventId !== event.eventId) {
    throw new TypeError('Event upload requires its corresponding terminal Session snapshot');
  }
}

function isRelayConflict(error: unknown): error is RelayClientError {
  if (error instanceof RelayClientError) return error.status === 409;
  if (!error || typeof error !== 'object') return false;
  const candidate = error as { status?: unknown; reason?: unknown };
  return candidate.status === 409 && typeof candidate.reason === 'string';
}

const PERMANENT_EVENT_CONFLICT_CATEGORIES = new Map<string, EncryptedEventFailure['category']>([
  ['session_revision_stale', 'session-revision'],
  ['session_revision_gap', 'session-revision'],
  ['session revision conflict', 'session-revision'],
  ['encrypted event conflict', 'event-content'],
  ['encrypted upload conflict', 'event-content'],
]);

function isPermanentEventConflict(error: unknown): error is RelayClientError {
  return isRelayConflict(error) && PERMANENT_EVENT_CONFLICT_CATEGORIES.has(error.reason);
}

function relayErrorStatus(error: unknown): number | undefined {
  if (typeof error !== 'object' || error === null) return undefined;
  const status = (error as { status?: unknown }).status;
  return typeof status === 'number' ? status : undefined;
}

function relayErrorReason(error: unknown): string | undefined {
  if (typeof error !== 'object' || error === null) return undefined;
  const reason = (error as { reason?: unknown }).reason;
  return typeof reason === 'string' ? reason : undefined;
}

function relayFailureCategory(error: unknown): EncryptedEventFailure['category'] {
  const reason = relayErrorReason(error);
  if (reason === 'e2e_recipient_set_changed') return 'recipient-set';
  const permanentCategory = PERMANENT_EVENT_CONFLICT_CATEGORIES.get(reason ?? '');
  if (permanentCategory) return permanentCategory;
  return relayErrorStatus(error) === undefined ? 'network' : 'http';
}
