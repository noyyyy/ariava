import type { CanonicalEvent, CommandEnvelope, CommandResult, HandleSessionRequest, SessionStatus } from '@ariava/protocol';
import type { PiSessionInfo } from './session';

type WithoutBridgeIdentity<T> = T extends CanonicalEvent ? Omit<T, 'eventId' | 'hostId'> : never;
export type AgentAdapterEvent = WithoutBridgeIdentity<CanonicalEvent>;

export interface AgentAdapter {
  registerSession(session: PiSessionInfo): Promise<{ sessionId: string; registeredAt: string }> ;
  unregisterSession(sessionId: string): Promise<void>;
  pushEvent(event: AgentAdapterEvent): Promise<{ eventId: string }>;
  handleSession(sessionId: string, request: HandleSessionRequest): Promise<{ ok: true; hostId: string; sessionId: string; handledThroughEventId: string }>;
  heartbeat(sessionId: string, status: SessionStatus, latestActivityText?: string | null, session?: PiSessionInfo): Promise<void>;
  pollCommands(sessionId: string, timeoutMs: number, session?: PiSessionInfo): Promise<CommandEnvelope | null>;
  submitResult(commandId: string, result: CommandResult): Promise<void>;
}
