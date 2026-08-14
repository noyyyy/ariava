// @ts-expect-error RotationPayload is intentionally absent from the public protocol
import type { RotationPayload } from '../src';
// @ts-expect-error KeyRotationRequest is intentionally absent from the public protocol
import type { KeyRotationRequest } from '../src';
// @ts-expect-error KeyRotationResponse is intentionally absent from the public protocol
import type { KeyRotationResponse } from '../src';

import type {
  ActionablePrompt,
  ActiveSessionSnapshot,
  BridgePairWatchDeviceProjection,
  BridgePairWatchRequest,
  BridgePairWatchResponse,
  BridgeStatus,
  CanonicalEvent,
  CanonicalSessionState,
  CommandEnvelope,
  CommandResult,
  CommandSubmissionAckV1,
  CommandReceiptEnvelopeV1,
  EncryptedCommandEnvelopeV1,
  EncryptedInterruptPayloadV1,
  ProtectedCommandReceiptV1,
  ProtectedInterruptContentV1,
  EntityType,
  EventCursor,
  EventType,
  EncryptedNotificationPreviewPlaintextV2,
  EncryptedEventProjectionV2,
  EncryptedEventUploadV2,
  EncryptedSessionCurrentProjectionV2,
  EncryptedSessionProjectionV2,
  EncryptedSessionSnapshotUploadV2,
  NotificationPreviewAADInput,
  NotificationPreviewEnvelopeV2,
  HandleSessionRequest,
  HostEnrollmentRequest,
  HostEnrollmentResponse,
  HostMetadataUpdateRequest,
  HostPlatform,
  HostProjection,
  HostWatchLink,
  IdentityAlgorithm,
  IdentityRevokeRequest,
  IdentityRevokeResponse,
  IdentityStatus,
  KeyStatus,
  LinkRevokeReason,
  LinkedWatchProjection,
  MarkSessionReadRequest,
  NeedHumanContext,
  NeedHumanError,
  NeedHumanErrorKind,
  NeedHumanReason,
  ReplaceE2ECurrentSessionsErrorResponseV1,
  ReplaceE2ECurrentSessionsRequestV1,
  ReplaceE2ECurrentSessionsResponseV1,
  MarkSessionReadResponse,
  PublicIdentity,
  ProtectedEventContentV2,
  ProtectedSessionContentV2,
  RelayEventMetadataV2,
  RelaySessionMetadataV2,
  SessionHandleAction,
  SessionHandleActorKind,
  SessionReadSource,
  SessionPresence,
  SessionSnapshotErrorCode,
  SessionStatus,
  SessionSummaryAssistant,
  SignedRequestHeaders,
  ValidationResult,
} from '../src';

// This file is compiled by the protocol strict typecheck. Keeping the intended
// public contracts in one tuple makes accidental barrel removals a compile error.
type IntendedPublicContracts = [
  ActionablePrompt,
  ActiveSessionSnapshot,
  BridgePairWatchDeviceProjection,
  BridgePairWatchRequest,
  BridgePairWatchResponse,
  BridgeStatus,
  CanonicalEvent,
  CanonicalSessionState,
  CommandEnvelope,
  CommandResult,
  CommandSubmissionAckV1,
  CommandReceiptEnvelopeV1,
  EncryptedCommandEnvelopeV1,
  EncryptedInterruptPayloadV1,
  ProtectedCommandReceiptV1,
  ProtectedInterruptContentV1,
  EntityType,
  EventCursor,
  EventType,
  EncryptedNotificationPreviewPlaintextV2,
  EncryptedEventProjectionV2,
  EncryptedEventUploadV2,
  EncryptedSessionCurrentProjectionV2,
  EncryptedSessionProjectionV2,
  EncryptedSessionSnapshotUploadV2,
  NotificationPreviewAADInput,
  NotificationPreviewEnvelopeV2,
  HandleSessionRequest,
  HostEnrollmentRequest,
  HostEnrollmentResponse,
  HostMetadataUpdateRequest,
  HostPlatform,
  HostProjection,
  HostWatchLink,
  IdentityAlgorithm,
  IdentityRevokeRequest,
  IdentityRevokeResponse,
  IdentityStatus,
  KeyStatus,
  LinkRevokeReason,
  LinkedWatchProjection,
  MarkSessionReadRequest,
  NeedHumanContext,
  NeedHumanError,
  NeedHumanErrorKind,
  NeedHumanReason,
  ReplaceE2ECurrentSessionsErrorResponseV1,
  ReplaceE2ECurrentSessionsRequestV1,
  ReplaceE2ECurrentSessionsResponseV1,
  MarkSessionReadResponse,
  PublicIdentity,
  ProtectedEventContentV2,
  ProtectedSessionContentV2,
  RelayEventMetadataV2,
  RelaySessionMetadataV2,
  SessionHandleAction,
  SessionHandleActorKind,
  SessionReadSource,
  SessionPresence,
  SessionSnapshotErrorCode,
  SessionStatus,
  SessionSummaryAssistant,
  SignedRequestHeaders,
  ValidationResult<unknown>,
];

const handleAction: SessionHandleAction = 'watch_reply';
const pairWatchDevice: BridgePairWatchDeviceProjection = {
  watchDeviceId: 'watch_public-contract',
  selectedHostIds: ['host_public-contract'],
  registeredAt: '2026-07-16T00:00:00.000Z',
  lastSeenAt: '2026-07-16T00:00:00.000Z',
  pairingStatus: 'paired',
};

const linkedWatch: LinkedWatchProjection = {
  watchDeviceId: 'watch_public-contract',
  pairedAt: '2026-07-16T00:00:00.000Z',
  lastSeenAt: '2026-07-16T00:00:00.000Z',
  linkGeneration: 1,
};
void (null as unknown as IntendedPublicContracts);
void handleAction;
void pairWatchDevice;
void linkedWatch;

const validExecutedResult: CommandResult = {
  commandId: 'command_1', hostId: 'host_1', sessionId: 'session_1',
  accepted: true, status: 'executed', updatedAt: '2026-08-12T00:00:00.000Z',
};
const validFailedResult: CommandResult = {
  commandId: 'command_1', hostId: 'host_1', sessionId: 'session_1',
  accepted: false, status: 'failed', updatedAt: '2026-08-12T00:00:00.000Z',
};
const validAck: CommandSubmissionAckV1 = { commandId: 'command_1', receivedAt: '2026-08-12T00:00:00.000Z' };

// @ts-expect-error accepted true requires executed
const illegalAcceptedFailure: CommandResult = { ...validExecutedResult, accepted: true, status: 'failed' };
// @ts-expect-error accepted false cannot use executed
const illegalRejectedExecution: CommandResult = { ...validFailedResult, accepted: false, status: 'executed' };
// @ts-expect-error CommandResult has no free-text message
const resultWithMessage: CommandResult = { ...validExecutedResult, message: 'forbidden' };
// @ts-expect-error CommandResult has no reason
const resultWithReason: CommandResult = { ...validExecutedResult, reason: 'forbidden' };
// @ts-expect-error CommandResult has no detail
const resultWithDetail: CommandResult = { ...validExecutedResult, detail: 'forbidden' };
// @ts-expect-error CommandResult has no error
const resultWithError: CommandResult = { ...validExecutedResult, error: 'forbidden' };
// @ts-expect-error CommandResult has no correlation ID
const resultWithCorrelationId: CommandResult = { ...validExecutedResult, correlationId: 'forbidden' };
// @ts-expect-error submission acknowledgment has no terminal status
const ackWithStatus: CommandSubmissionAckV1 = { ...validAck, status: 'executed' };
// @ts-expect-error submission acknowledgment has no accepted flag
const ackWithAccepted: CommandSubmissionAckV1 = { ...validAck, accepted: true };
// @ts-expect-error submission acknowledgment has no result payload
const ackWithResult: CommandSubmissionAckV1 = { ...validAck, result: validExecutedResult };
