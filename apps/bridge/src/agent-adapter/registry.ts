import type { CanonicalEvent, CanonicalSessionState, CommandEnvelope, CommandResult, HandleSessionRequest, MarkSessionReadRequest, SessionStatus } from '@ariava/protocol';
import { statusToStateLabel } from '@ariava/protocol';
import { createId, isoNow } from '@ariava/shared-utils';
import type { BridgeStateStore } from '../../state-store';

export interface RegisteredSession {
  sessionId: string;
  provider: string;
  projectName: string;
  cwd: string;
  nameText: string;
  openingText?: string;
  latestActivityText?: string;
  pid?: number;
  hostId: string;
  registeredAt: string;
  lastHeartbeatAt: string;
  status: SessionStatus;
  semanticUpdatedAt: string;
}

export interface RegisterSessionInput {
  sessionId: string;
  provider: string;
  projectName?: string;
  project?: string;
  cwd: string;
  nameText?: string;
  title?: string;
  openingText?: string;
  latestActivityText?: string;
  summary?: string;
  pid?: number;
  status?: SessionStatus;
}

const SESSION_TTL_MS = 45_000;

export type RegistryMutationReason = 'register' | 'semantic' | 'unregister' | 'ttl';
export type RegistryMutationCallback = (reason: RegistryMutationReason) => void;

export class AgentAdapterRegistry {
  private readonly recoveryDeadlineMs: number;
  private sessions = new Map<string, RegisteredSession>();
  private commandQueues = new Map<string, CommandEnvelope[]>();
  private commandWaiters = new Map<string, Array<(command: CommandEnvelope | null) => void>>();
  private results = new Map<string, CommandResult>();
  private resultWaiters = new Map<string, Array<(result: CommandResult) => void>>();
  private inFlightCommands = new Map<string, Set<string>>();
  private delayedTerminalEvents = new Map<string, CanonicalEvent>();

  constructor(
    private readonly hostId: string,
    private readonly stateStore: BridgeStateStore,
    private readonly onMutation: RegistryMutationCallback = () => {},
    private readonly now: () => Date = () => new Date(),
  ) {
    this.recoveryDeadlineMs = this.now().getTime() + SESSION_TTL_MS;
  }

  register(input: RegisterSessionInput): RegisteredSession {
    const now = this.nowIso();
    const previous = this.sessions.get(input.sessionId);
    const projectName = input.projectName ?? input.project ?? 'unknown';
    const nameText = input.nameText ?? input.title ?? projectName;
    const session: RegisteredSession = {
      sessionId: input.sessionId,
      provider: input.provider,
      projectName,
      cwd: input.cwd,
      nameText,
      openingText: input.openingText,
      latestActivityText: input.latestActivityText ?? input.summary,
      pid: input.pid,
      hostId: this.hostId,
      registeredAt: previous?.registeredAt ?? now,
      lastHeartbeatAt: now,
      status: input.status ?? 'idle',
      semanticUpdatedAt: previous?.semanticUpdatedAt ?? now,
    };
    const changed = !previous || semanticFingerprint(previous) !== semanticFingerprint(session);
    if (changed && previous) session.semanticUpdatedAt = now;
    this.sessions.set(input.sessionId, session);
    this.stateStore.setSessionDriver(input.sessionId, input.provider);
    if (changed) this.onMutation('register');
    return session;
  }

  unregister(sessionId: string, reason: 'unregister' | 'ttl' = 'unregister'): boolean {
    const session = this.sessions.get(sessionId);
    this.commandQueues.delete(sessionId);
    this.commandWaiters.delete(sessionId);
    this.inFlightCommands.delete(sessionId);
    this.delayedTerminalEvents.delete(sessionId);
    const removed = this.sessions.delete(sessionId);
    if (removed && session) {
      // Preserve the owner until after registry removal so a stale unregister cannot
      // delete a session that has already been reassigned to another driver.
      this.stateStore.removeSession(sessionId, session.provider);
      this.onMutation(reason);
      return true;
    }

    // A Pi shutdown can race a Bridge restart before the session re-registers. The
    // authenticated unregister remains authoritative for that persisted session.
    const removedPersisted = this.stateStore.removeSession(sessionId);
    if (removedPersisted) this.onMutation(reason);
    return removedPersisted;
  }

  hasSession(sessionId: string): boolean {
    return this.sessions.has(sessionId);
  }

  cancelCommandPolls(): void {
    const waiters = [...this.commandWaiters.values()].flat();
    this.commandWaiters.clear();
    for (const waiter of waiters) waiter(null);
  }

  heartbeat(
    sessionId: string,
    status: SessionStatus,
    latestActivityText?: string | null,
    metadata: { openingText?: string | null; projectName?: string; nameText?: string } = {},
  ): RegisteredSession | undefined {
    const session = this.sessions.get(sessionId);
    if (!session) return undefined;

    const before = semanticFingerprint(session);
    const now = this.nowIso();
    session.lastHeartbeatAt = now;
    session.status = status;
    if (latestActivityText !== undefined) session.latestActivityText = latestActivityText ?? undefined;
    if (metadata.openingText !== undefined) session.openingText = metadata.openingText ?? undefined;
    if (metadata.projectName !== undefined) session.projectName = metadata.projectName;
    if (metadata.nameText !== undefined) session.nameText = metadata.nameText;
    if (semanticFingerprint(session) !== before) {
      session.semanticUpdatedAt = now;
      this.onMutation('semantic');
    }
    return session;
  }

  listSessions(): CanonicalSessionState[] {
    const now = this.now().getTime();
    const active: CanonicalSessionState[] = [];

    for (const session of this.sessions.values()) {
      const lastHeartbeat = new Date(session.lastHeartbeatAt).getTime();
      if (now - lastHeartbeat > SESSION_TTL_MS) {
        this.unregister(session.sessionId, 'ttl');
        continue;
      }

      active.push(this.toCanonicalSession(session));
    }

    return active.sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
  }

  /**
   * A freshly restarted in-memory registry cannot authoritatively declare the Pi set
   * empty until every persisted Pi session has either re-registered or exceeded the
   * normal heartbeat TTL. This bounded recovery window prevents a restart race while
   * still allowing shutdown/unregister and TTL expiry to end sessions.
   */
  isAuthoritativeSetReady(persistedSessions: CanonicalSessionState[]): boolean {
    if (persistedSessions.length === 0 || this.now().getTime() > this.recoveryDeadlineMs) return true;
    return persistedSessions.every((persisted) => this.sessions.has(persisted.sessionId));
  }

  pushEvent(sessionId: string, event: Partial<CanonicalEvent>): string {
    const session = this.sessions.get(sessionId);
    if (!session) {
      throw new Error(`Session ${sessionId} is not registered`);
    }

    const now = isoNow();
    const eventType = event.type ?? 'blocked';
    const canonicalEvent: CanonicalEvent = {
      eventId: event.eventId ?? createId('evt'),
      hostId: session.hostId,
      sessionId,
      provider: event.provider ?? session.provider,
      type: eventType,
      status: event.status ?? session.status,
      typeLabel: event.typeLabel ?? deriveEventTypeLabel(eventType),
      assistantText: normalizeEventAssistantText(eventType, event.assistantText, session),
      userMessageText: event.userMessageText,
      contextText: event.contextText ?? buildContextText(session),
      actionablePrompt: event.actionablePrompt,
      correlationId: event.correlationId,
      createdAt: event.createdAt ?? now,
    };

    const before = semanticFingerprint(session);
    if (event.status !== undefined) session.status = event.status;
    const activity = event.assistantText?.trim();
    if (activity) session.latestActivityText = event.assistantText;
    if (semanticFingerprint(session) !== before) {
      session.semanticUpdatedAt = now;
      this.onMutation('semantic');
    }
    if (isTerminalEvent(canonicalEvent) && this.hasPendingCommandWork(sessionId)) {
      this.delayedTerminalEvents.set(sessionId, canonicalEvent);
    } else {
      this.stateStore.queuePendingEvent(canonicalEvent);
    }
    return canonicalEvent.eventId;
  }

  handleSession(sessionId: string, request: HandleSessionRequest): { ok: true; hostId: string; sessionId: string; handledThroughEventId: string } {
    const session = this.sessions.get(sessionId);
    if (!session) {
      throw new Error(`Session ${sessionId} is not registered`);
    }
    if (!request.handledThroughEventId?.trim()) {
      throw new Error('handledThroughEventId is required');
    }
    const handledAt = normalizeHandledAt(request.handledAt, isoNow());
    this.stateStore.queuePendingSessionHandle({
      hostId: session.hostId,
      sessionId,
      handledThroughEventId: request.handledThroughEventId,
      handledThroughEventCreatedAt: request.handledThroughEventCreatedAt,
      handledAt,
      action: request.action === 'bridge_recovery' ? 'bridge_recovery' : 'pi_input',
      updatedAt: isoNow(),
    });
    return {
      ok: true,
      hostId: session.hostId,
      sessionId,
      handledThroughEventId: request.handledThroughEventId,
    };
  }

  handleSessionReadAlias(sessionId: string, request: MarkSessionReadRequest): { ok: true; hostId: string; sessionId: string; handledThroughEventId: string } {
    if (request.source !== 'pi_local_interaction' && request.source !== 'bridge_recovery') {
      throw new Error('legacy read alias requires pi_local_interaction or bridge_recovery source');
    }
    const handledThroughEventId = request.latestReadEventId ?? request.latestSeenEventId;
    if (!handledThroughEventId) {
      throw new Error('latestReadEventId is required');
    }
    return this.handleSession(sessionId, {
      handledThroughEventId,
      handledAt: request.readAt ?? request.seenAt,
      action: request.source === 'bridge_recovery' ? 'bridge_recovery' : 'pi_input',
    });
  }

  enqueueCommand(command: CommandEnvelope): void {
    const sessionId = command.sessionId;
    const waiters = this.commandWaiters.get(sessionId);

    if (waiters && waiters.length > 0) {
      const waiter = waiters.shift();
      if (waiters.length === 0) {
        this.commandWaiters.delete(sessionId);
      }
      this.markCommandInFlight(command);
      waiter?.(command);
      return;
    }

    const queue = this.commandQueues.get(sessionId) ?? [];
    queue.push(command);
    this.commandQueues.set(sessionId, queue);
  }

  async dequeueCommand(sessionId: string, timeoutMs: number): Promise<CommandEnvelope | null> {
    const queue = this.commandQueues.get(sessionId);
    if (queue && queue.length > 0) {
      const command = queue.shift();
      if (queue.length === 0) {
        this.commandQueues.delete(sessionId);
      }
      if (command) {
        this.markCommandInFlight(command);
      }
      return command ?? null;
    }

    if (timeoutMs <= 0) {
      return null;
    }

    return new Promise((resolve) => {
      let settled = false;

      const timer = setTimeout(() => {
        if (settled) return;
        settled = true;
        this.removeCommandWaiter(sessionId, resolver);
        resolve(null);
      }, timeoutMs);

      const resolver = (command: CommandEnvelope | null) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        this.removeCommandWaiter(sessionId, resolver);
        resolve(command);
      };

      const waiters = this.commandWaiters.get(sessionId) ?? [];
      waiters.push(resolver);
      this.commandWaiters.set(sessionId, waiters);
    });
  }

  async waitForResult(commandId: string, options: { timeoutMs: number }): Promise<CommandResult | undefined> {
    const existing = this.results.get(commandId);
    if (existing) {
      return existing;
    }

    return new Promise((resolve) => {
      let settled = false;

      const timer = setTimeout(() => {
        if (settled) return;
        settled = true;
        this.removeResultWaiter(commandId, resolver);
        resolve(undefined);
      }, options.timeoutMs);

      const resolver = (result: CommandResult) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        this.removeResultWaiter(commandId, resolver);
        resolve(result);
      };

      const waiters = this.resultWaiters.get(commandId) ?? [];
      waiters.push(resolver);
      this.resultWaiters.set(commandId, waiters);
    });
  }

  resolveCommand(commandId: string, result: CommandResult): void {
    this.results.set(commandId, result);
    this.clearCommandInFlight(result.sessionId, commandId);
    const waiters = this.resultWaiters.get(commandId);
    this.resultWaiters.delete(commandId);

    if (waiters) {
      for (const waiter of waiters) {
        waiter(result);
      }
    }
  }

  hasPendingCommandWork(sessionId: string): boolean {
    return (this.commandQueues.get(sessionId)?.length ?? 0) > 0 || (this.inFlightCommands.get(sessionId)?.size ?? 0) > 0;
  }

  flushDelayedTerminalEvent(sessionId: string): string | undefined {
    if (this.hasPendingCommandWork(sessionId)) return undefined;
    const event = this.delayedTerminalEvents.get(sessionId);
    if (!event) return undefined;
    this.delayedTerminalEvents.delete(sessionId);
    this.stateStore.queuePendingEvent(event);
    return event.eventId;
  }

  private markCommandInFlight(command: CommandEnvelope): void {
    const current = this.inFlightCommands.get(command.sessionId) ?? new Set<string>();
    current.add(command.commandId);
    this.inFlightCommands.set(command.sessionId, current);
  }

  private clearCommandInFlight(sessionId: string, commandId: string): void {
    const current = this.inFlightCommands.get(sessionId);
    if (!current) {
      this.flushDelayedTerminalEvent(sessionId);
      return;
    }
    current.delete(commandId);
    if (current.size === 0) {
      this.inFlightCommands.delete(sessionId);
    }
    this.flushDelayedTerminalEvent(sessionId);
  }

  private toCanonicalSession(session: RegisteredSession): CanonicalSessionState {
    const updatedAt = session.semanticUpdatedAt;
    return {
      sessionId: session.sessionId,
      hostId: session.hostId,
      provider: session.provider,
      projectName: session.projectName,
      nameText: session.nameText,
      openingText: session.openingText,
      latestActivityText: session.latestActivityText,
      stateLabel: statusToStateLabel(session.status),
      status: session.status,
      updatedAt,
    };
  }

  private nowIso(): string {
    return this.now().toISOString();
  }

  private removeCommandWaiter(sessionId: string, resolver: (command: CommandEnvelope | null) => void): void {
    const waiters = this.commandWaiters.get(sessionId);
    if (!waiters) return;

    const index = waiters.indexOf(resolver);
    if (index >= 0) {
      waiters.splice(index, 1);
    }
    if (waiters.length === 0) {
      this.commandWaiters.delete(sessionId);
    }
  }

  private removeResultWaiter(commandId: string, resolver: (result: CommandResult) => void): void {
    const waiters = this.resultWaiters.get(commandId);
    if (!waiters) return;

    const index = waiters.indexOf(resolver);
    if (index >= 0) {
      waiters.splice(index, 1);
    }
    if (waiters.length === 0) {
      this.resultWaiters.delete(commandId);
    }
  }
}

function buildContextText(session: RegisteredSession): string | undefined {
  const rawName = session.nameText?.trim() ?? '';
  const project = session.projectName?.trim() ?? '';
  if (rawName && project && rawName !== project) {
    return `${rawName} · ${project}`;
  }
  return project || rawName || undefined;
}

function normalizeEventAssistantText(
  type: CanonicalEvent['type'],
  assistantText: string | undefined,
  session: Pick<RegisteredSession, 'latestActivityText' | 'nameText'>,
): string {
  const eventAssistant = assistantText?.trim();
  if (eventAssistant) return eventAssistant;

  const latestActivityText = session.latestActivityText?.trim();
  if (latestActivityText) return latestActivityText;

  switch (type) {
    case 'done': return 'Task complete';
    case 'blocked': return 'Review needed on desktop';
    case 'question_requested': return 'Agent has a question';
    case 'working': return `${session.nameText} is running`;
    default: return 'Agent update';
  }
}

function deriveEventTypeLabel(type: CanonicalEvent['type']): string {
  switch (type) {
    case 'approval_requested': return 'Needs approval';
    case 'question_requested': return 'Agent question';
    case 'blocked': return 'Session blocked';
    case 'done': return 'Task complete';
    case 'working': return 'In progress';
    case 'summary_updated': return 'Summary updated';
    case 'driver_error': return 'Driver error';
    case 'host_unavailable': return 'Host unavailable';
  }
}

function isTerminalEvent(event: CanonicalEvent): boolean {
  return event.type === 'done' || event.type === 'blocked' || event.type === 'question_requested';
}

function normalizeHandledAt(value: string | undefined, fallback: string): string {
  if (!value) return fallback;
  const time = new Date(value).getTime();
  return Number.isFinite(time) ? value : fallback;
}

function semanticFingerprint(session: RegisteredSession): string {
  return JSON.stringify({
    sessionId: session.sessionId, provider: session.provider, projectName: session.projectName,
    cwd: session.cwd, nameText: session.nameText, openingText: session.openingText,
    latestActivityText: session.latestActivityText, pid: session.pid, hostId: session.hostId, status: session.status,
  });
}
