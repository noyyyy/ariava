import type { E2ERecipientSnapshotV1, EncryptedEventUploadV1, EncryptedSessionSnapshotUploadV1 } from '@ariava/protocol';
import type { HostEncryptionIdentity } from '../identity';
import type { RelayClient } from '../relay-client';
import { RelayClientError } from '../relay-client';
import type { BridgeStateStore } from '../state-store';
import { encryptEventUpload, encryptSessionSnapshot, type ActiveRecipientMaterial } from './envelope';
import type { LocalLinkKeyring } from './link-keyring';

export interface EncryptedUploadHooks {
  eventCompletionStep?: (phase: 'journaled' | 'revision-committed' | 'inflight-removed' | 'source-removed' | 'journal-removed', eventId: string) => void;
}

type EncryptedEventAndSession = { event: EncryptedEventUploadV1; session: EncryptedSessionSnapshotUploadV1 };

export class EncryptedUploadOrchestrator {
  constructor(private readonly stateStore: BridgeStateStore, private readonly client: RelayClient,
    private readonly encryptionIdentity: HostEncryptionIdentity, private readonly keyring: LocalLinkKeyring,
    private readonly hooks?: EncryptedUploadHooks) {}

  async flushPendingEvents(): Promise<number> {
    let snapshot: E2ERecipientSnapshotV1;
    try { snapshot = await this.client.recipientSnapshot(); } catch { return 0; }
    let recipients: ActiveRecipientMaterial[];
    try { recipients = this.keyring.reconcileRecipients(snapshot); } catch { return 0; }
    if (snapshot.recipientSetVersion !== this.stateStore.getRecipientSetVersion()) {
      if (!await this.publishRecipientChangeSnapshots(snapshot, recipients)) return 0;
    }
    let flushed = 0;
    for (const pending of this.stateStore.peekPendingUploads()) {
      const event = pending.event; const session = pending.session ?? this.stateStore.getSession(event.sessionId) ?? syntheticSessionForEvent(event);
      let inflight = this.stateStore.getInflightEventUpload(event.eventId) as EncryptedEventAndSession | undefined;
      if (!inflight) {
        inflight = encryptEventUpload({ ...eventEncryptionInput(event, session), revision: this.stateStore.nextSessionRevision(event.sessionId),
          recipientSetVersion: snapshot.recipientSetVersion, recipients, hostIdentity: this.encryptionIdentity });
        this.stateStore.persistInflightEventUpload(event.eventId, event.sessionId, inflight);
      }
      try { await this.client.publishEncryptedEvent(inflight.event, inflight.session); } catch (error) {
        if (!isRelayConflict(error)) return flushed;
        if (error.reason === 'e2e_recipient_set_changed') {
          if (!(await this.client.reconcileEncryptedEvent(inflight.event, inflight.session).catch(() => ({ committed: false }))).committed) {
            try { snapshot = await this.client.recipientSnapshot(); recipients = this.keyring.reconcileRecipients(snapshot); } catch { return flushed; }
            const replacement = encryptEventUpload({ ...eventEncryptionInput(event, session), revision: inflight.session.revision,
              recipientSetVersion: snapshot.recipientSetVersion, recipients, hostIdentity: this.encryptionIdentity });
            this.stateStore.replaceInflightEventUpload(event.eventId, event.sessionId, replacement); inflight = replacement;
            try { await this.client.publishEncryptedEvent(inflight.event, inflight.session); } catch { return flushed; }
          }
        } else if (!(await this.client.reconcileEncryptedEvent(inflight.event, inflight.session).catch(() => ({ committed: false }))).committed) return flushed;
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

  async publishRecipientChangeSnapshots(snapshot: E2ERecipientSnapshotV1, recipients: ActiveRecipientMaterial[]): Promise<boolean> {
    const pendingIds = new Set(this.stateStore.listInflightSessionIds());
    for (const session of this.stateStore.listSessions()) {
      if (!this.stateStore.getInflightSessionUpload(session.sessionId)) {
        const upload = encryptSessionSnapshot({ ...sessionEncryptionInput(session), revision: this.stateStore.nextSessionRevision(session.sessionId),
          recipientSetVersion: snapshot.recipientSetVersion, recipients, hostIdentity: this.encryptionIdentity });
        this.stateStore.persistInflightSessionUpload(session.sessionId, upload); pendingIds.add(session.sessionId);
      }
    }
    for (const sessionId of pendingIds) {
      let upload = this.stateStore.getInflightSessionUpload(sessionId) as EncryptedSessionSnapshotUploadV1 | undefined; if (!upload) return false;
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
              recipientSetVersion: currentSnapshot.recipientSetVersion, recipients: currentRecipients, hostIdentity: this.encryptionIdentity });
            this.stateStore.persistInflightSessionUpload(sessionId, upload);
          } else {
            const replacement = encryptSessionSnapshot({ ...sessionEncryptionInput(session), revision: upload.revision,
              recipientSetVersion: currentSnapshot.recipientSetVersion, recipients: currentRecipients, hostIdentity: this.encryptionIdentity });
            this.stateStore.replaceInflightSessionUpload(sessionId, replacement); upload = replacement;
          }
        }
      }
    }
    this.stateStore.setRecipientSetVersion(snapshot.recipientSetVersion);
    return true;
  }
}

function syntheticSessionForEvent(event: import('@ariava/protocol').CanonicalEvent): import('@ariava/protocol').CanonicalSessionState {
  return { sessionId: event.sessionId, hostId: event.hostId, provider: event.provider, projectName: 'system',
    nameText: event.contextText ?? event.sessionId, latestActivityText: event.assistantText, stateLabel: 'Unknown', status: event.status, updatedAt: event.createdAt };
}
function eventEncryptionInput(event: import('@ariava/protocol').CanonicalEvent, session: import('@ariava/protocol').CanonicalSessionState) {
  return { event: { eventId: event.eventId, hostId: event.hostId, sessionId: event.sessionId, provider: event.provider, type: event.type, status: event.status,
    ...(event.correlationId ? { correlationId: event.correlationId } : {}), createdAt: event.createdAt }, protectedEvent: { version: 1 as const, assistantText: event.assistantText,
    ...(event.userMessageText !== undefined ? { userMessageText: event.userMessageText } : {}), ...(event.contextText !== undefined ? { contextText: event.contextText } : {}),
    ...(event.actionablePrompt ? { actionablePrompt: event.actionablePrompt } : {}) }, ...sessionEncryptionInput(session) };
}
function sessionEncryptionInput(session: import('@ariava/protocol').CanonicalSessionState) {
  return { session: { hostId: session.hostId, sessionId: session.sessionId, provider: session.provider, status: session.status, updatedAt: session.updatedAt,
    ...(session.lastEventId ? { lastEventId: session.lastEventId } : {}), ...(session.snoozedUntil ? { snoozedUntil: session.snoozedUntil } : {}) },
    protectedSession: { version: 1 as const, projectName: session.projectName, nameText: session.nameText,
      ...(session.openingText !== undefined ? { openingText: session.openingText } : {}),
      ...(session.latestActivityText !== undefined ? { latestActivityText: session.latestActivityText } : {}) } };
}
function isRelayConflict(error: unknown): error is RelayClientError {
  return error instanceof RelayClientError || (Boolean(error) && typeof error === 'object'
    && (error as { status?: unknown }).status === 409 && typeof (error as { reason?: unknown }).reason === 'string');
}
