import type { CanonicalEvent, CommandEnvelope, CommandResult, HandleSessionRequest, SessionStatus } from '@ariava/protocol';
import type { PiSessionInfo } from './session';

export interface AgentAdapter {
  registerSession(session: PiSessionInfo): Promise<{ sessionId: string; registeredAt: string }> ;
  unregisterSession(sessionId: string): Promise<void>;
  pushEvent(event: Partial<CanonicalEvent>): Promise<{ eventId: string }> ;
  handleSession(sessionId: string, request: HandleSessionRequest): Promise<{ ok: true; hostId: string; sessionId: string; handledThroughEventId: string }>;
  heartbeat(sessionId: string, status: SessionStatus, latestActivityText?: string): Promise<void>;
  pollCommands(sessionId: string, timeoutMs: number): Promise<CommandEnvelope | null>;
  submitResult(commandId: string, result: CommandResult): Promise<void>;
}
