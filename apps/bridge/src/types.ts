import type {
  CanonicalEvent,
  CanonicalSessionState,
  CommandEnvelope,
  CommandReceiptEnvelopeV1,
  CommandResult,
  EncryptedCommandEnvelopeV1,
  HostProjection,
  HostPlatform,
  ReplaceE2ECurrentSessionsRequestV1,
} from '@ariava/protocol';
import type { HostIdentityMetadata } from './identity/types';

export interface DriverCommandContext {
  command: CommandEnvelope;
  session: CanonicalSessionState;
}

export interface AgentDriver {
  readonly name: string;
  listSessions(hostId: string): Promise<CanonicalSessionState[]>;
  isAuthoritativeSetReady?(persistedSessions: CanonicalSessionState[]): boolean;
  preflightCommandDispatch?(context: DriverCommandContext): void | Promise<void>;
  releaseCommandDispatch?(context: DriverCommandContext): void | Promise<void>;
  executeCommand(context: DriverCommandContext): Promise<CommandResult>;
}

export interface AgentAdapterConfig {
  port: number;
  secret: string;
  configPath: string;
}

export interface BridgeConfig {
  hostId: string;
  hostName: string;
  hostPlatform: HostPlatform;
  relayBaseUrl: string;
  statePath: string;
  identityPath: string;
  configPath: string;
  runtimePlatform?: NodeJS.Platform;
  identity?: HostIdentityMetadata;
  pollIntervalMs: number;
  bridgeVersion: string;
  agentAdapter: AgentAdapterConfig;
}

export interface BridgeSyncResult {
  host: HostProjection | null;
  sessions: CanonicalSessionState[];
  emittedEvents: CanonicalEvent[];
  flushedEvents: number;
  flushedReads: number;
  handledCommands: CommandResult[];
  offline: boolean;
}

export interface CommandHandlingOutcome {
  result: CommandResult;
  followUpEvents: CanonicalEvent[];
}

export interface PendingSessionHandle {
  hostId: string;
  sessionId: string;
  handledThroughEventId: string;
  handledThroughEventCreatedAt?: string;
  handledAt: string;
  action: 'pi_input' | 'bridge_recovery';
  updatedAt: string;
}


/** Host-wide active-set revisions; never reuse these as per-session content revisions. */
export interface PersistedCurrentSessionsSnapshotState {
  version: 1;
  lastAllocatedRevision: number;
  lastAcceptedRevision: number;
  lastAcceptedDigest?: string;
  lastAcceptedContentDigest?: string;
  lastAcceptedRecipientSetVersion?: number;
}

export interface PersistedProducerEventReservationV1 {
  version: 1;
  eventId: string;
  sessionId: string;
  fingerprint: string;
  createdAt: string;
}

export interface PersistedTerminalCancellationV1 {
  version: 1;
  sessionId: string;
  eventId: string;
  fingerprint: string;
  removeSession: boolean;
  createdAt: string;
}

export interface EventUploadCompletionV1 {
  version: 1;
  eventId: string;
  sessionId: string;
  revision: number;
  eventContentId: string;
  sessionContentId: string;
  committedAt: string;
  revisionCommitted?: boolean;
  inflightRemoved?: boolean;
  sourceRemoved?: boolean;
}

export interface DriverRuntimeHealth {
  driver: string;
  code: 'driver_reconciliation_failed';
  count: number;
  firstSeenAt: string;
  lastSeenAt: string;
  lastSuccessAt?: string;
  nextRetryAt: string;
}

export interface RelayPresenceRuntimeHealth {
  code: 'relay_presence_refresh_failed';
  count: number;
  firstSeenAt: string;
  lastSeenAt: string;
  lastSuccessAt?: string;
  nextRetryAt: string;
}

export interface BridgeRuntimeHealth {
  status: 'healthy' | 'degraded';
  drivers: DriverRuntimeHealth[];
  relayPresence?: RelayPresenceRuntimeHealth;
}

export interface PersistedCommandPinReferenceV1 {
  version: 1;
  linkId: string;
  linkGeneration: number;
  epoch: number;
  transcriptDigest: string;
  hostEncryptionKeyId: string;
  watchEncryptionKeyId: string;
}

export interface PersistedCommandReceiptOutboxV1 {
  version: 1;
  state: 'pending' | 'acknowledged' | 'undeliverable';
  canonicalBody: string;
  receiptDigest: string;
}

export interface PersistedCommandExecutionV4 {
  version: 1;
  originalEncryptedCommand: EncryptedCommandEnvelopeV1;
  commandDigest: string;
  pinReference: PersistedCommandPinReferenceV1;
  watchDeviceId: string;
  nonce: string;
  expiresAt: string;
  state: 'claimed' | 'dispatch_started' | 'outcome_unknown' | 'terminal_receipt_blocked' | 'terminal';
  claimedAt: string;
  dispatchStartedAt?: string;
  terminalResult?: CommandResult;
  receiptOutbox?: PersistedCommandReceiptOutboxV1;
}

export interface CommandReceiptOutboxInputV1 {
  canonicalBody: string;
  receiptDigest: string;
  receipt: CommandReceiptEnvelopeV1;
}

export interface PersistedBridgeState {
  schemaVersion: 4;
  runtimeResetEpoch: string;
  host: HostProjection | null;
  sessions: Record<string, CanonicalSessionState>;
  sessionDrivers: Record<string, string>;
  reconciledDrivers: Record<string, true>;
  recentEvents: CanonicalEvent[];
  sessionRevisions: Record<string, number>;
  recipientSetVersion?: number;
  eventUploadCompletions?: Record<string, EventUploadCompletionV1>;
  producerEventReservations?: Record<string, PersistedProducerEventReservationV1>;
  terminalCancellations?: Record<string, PersistedTerminalCancellationV1>;
  pendingHandles: Record<string, PendingSessionHandle>;
  commandExecutions: Record<string, PersistedCommandExecutionV4>;
  currentSessionsSnapshot: PersistedCurrentSessionsSnapshotState;
  runtimeHealth?: BridgeRuntimeHealth;
}
