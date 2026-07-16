import type {
  CanonicalEvent,
  CanonicalSessionState,
  CommandEnvelope,
  CommandResult,
  HostProjection,
  HostPlatform,
} from '@ariava/protocol';
import type { HostIdentityMetadata } from './identity/types';

export interface DriverCommandContext {
  command: CommandEnvelope;
  session: CanonicalSessionState;
}

export interface AgentDriver {
  readonly name: string;
  listSessions(hostId: string): Promise<CanonicalSessionState[]>;
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

export interface PersistedBridgeState {
  host: HostProjection | null;
  sessions: Record<string, CanonicalSessionState>;
  sessionDrivers: Record<string, string>;
  recentEvents: CanonicalEvent[];
  pendingEvents: CanonicalEvent[];
  pendingHandles: Record<string, PendingSessionHandle>;
  commandResults: Record<string, CommandResult>;
  seenCommands: Record<string, string>;
}
