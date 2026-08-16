import type { E2EEventAndSessionUploadV3 } from '@ariava/protocol';
import { encryptNotificationPreviews, type ActiveRecipientMaterial } from './envelope';
import { buildNotificationPreview } from './notification-preview';

export class PendingUploadBindingError extends Error {
  readonly code = 'event-session-binding-invalid' as const;
  constructor(message = 'Event upload requires its corresponding terminal Session snapshot') {
    super(message);
    this.name = 'PendingUploadBindingError';
  }
}

export type EncryptedEventAndSession = E2EEventAndSessionUploadV3;

/** Canonical encryption input builder for a terminal Event and its terminal Session snapshot. */
export function eventEncryptionInput(
  event: import('@ariava/protocol').CanonicalEvent,
  session: import('@ariava/protocol').CanonicalSessionState,
) {
  assertEventSessionBinding(event, session);
  return {
    event: { eventId: event.eventId, hostId: event.hostId, sessionId: event.sessionId, provider: event.provider,
      type: event.type, status: event.status, createdAt: event.createdAt },
    protectedEvent: { version: 3 as const, agentText: event.agentText,
      ...(event.humanText !== undefined ? { humanText: event.humanText } : {}),
      ...(event.projectName !== undefined ? { projectName: event.projectName } : {}),
      ...(event.workingDirectory !== undefined ? { workingDirectory: event.workingDirectory } : {}),
      ...(event.harnessProvider !== undefined ? { harnessProvider: event.harnessProvider } : {}),
      ...(event.type === 'need_human' ? { needHuman: event.needHuman } : {}) },
    ...sessionEncryptionInput(session),
  };
}

/** Canonical encryption input builder for a Session snapshot. */
export function sessionEncryptionInput(session: import('@ariava/protocol').CanonicalSessionState) {
  return {
    session: { hostId: session.hostId, sessionId: session.sessionId, provider: session.provider, status: session.status,
      updatedAt: session.updatedAt, ...(session.lastEventId ? { lastEventId: session.lastEventId } : {}),
      ...(session.snoozedUntil ? { snoozedUntil: session.snoozedUntil } : {}) },
    protectedSession: { version: 3 as const, projectName: session.projectName, nameText: session.nameText,
      ...(session.openingText !== undefined ? { openingText: session.openingText } : {}),
      ...(session.latestActivityText !== undefined ? { latestActivityText: session.latestActivityText } : {}),
      ...(session.workingDirectory !== undefined ? { workingDirectory: session.workingDirectory } : {}),
      ...(session.harnessProvider !== undefined ? { harnessProvider: session.harnessProvider } : {}) },
  };
}

/** Best-effort notification preview attachment; preview failures degrade to an empty list. */
export function attachNotificationPreviews(
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

export function assertEventSessionBinding(
  event: import('@ariava/protocol').CanonicalEvent,
  session: import('@ariava/protocol').CanonicalSessionState,
): void {
  if (event.hostId !== session.hostId || event.sessionId !== session.sessionId || event.provider !== session.provider
    || event.status !== session.status || session.lastEventId !== event.eventId) {
    throw new PendingUploadBindingError('Event upload requires its corresponding terminal Session snapshot');
  }
}
