import type {
  CanonicalEvent,
  CanonicalSessionState,
  CommandEnvelope,
  CommandResult,
  HostProjection,
  HostPlatform,
  ReplaceCurrentSessionsRequest,
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

export interface PendingCurrentSessionsSnapshot {
  digest: string;
  contentDigest: string;
  request: ReplaceCurrentSessionsRequest;
}

/** Host-wide active-set revisions; never reuse these as per-session content revisions. */
export interface PersistedCurrentSessionsSnapshotState {
  version: 1;
  lastAllocatedRevision: number;
  lastAcceptedRevision: number;
  lastAcceptedDigest?: string;
  lastAcceptedContentDigest?: string;
  pending?: PendingCurrentSessionsSnapshot;
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

export interface PersistedBridgeState {
  host: HostProjection | null;
  sessions: Record<string, CanonicalSessionState>;
  sessionDrivers: Record<string, string>;
  reconciledDrivers: Record<string, true>;
  recentEvents: CanonicalEvent[];
  /** Legacy load-only plaintext queue. New state writes always remove this field. */
  pendingEvents?: CanonicalEvent[];
  sessionRevisions: Record<string, number>;
  recipientSetVersion?: number;
  spoolMigration?: { version: 1; remainingEventIds: string[]; startedAt: string };
  eventUploadCompletions?: Record<string, EventUploadCompletionV1>;
  pendingHandles: Record<string, PendingSessionHandle>;
  commandResults: Record<string, CommandResult>;
  seenCommands: Record<string, string>;
  currentSessionsSnapshot: PersistedCurrentSessionsSnapshotState;
}
