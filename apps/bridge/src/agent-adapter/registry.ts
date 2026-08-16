import type {
  CanonicalSessionState,
  CommandEnvelope,
  CommandResult,
  HandleSessionRequest,
  SessionStatus,
} from '@ariava/protocol';
import { ProtectedContentValidationError } from '@ariava/protocol';
import { createId, isoNow } from '@ariava/shared-utils';
import { asCommandResult, parseAgentAdapterCommandResult } from './result';
import {
  assertCanonicalSessionWithinLimit,
  assertProducerContextMatchesSession,
  immutableCopy,
  normalizeHandledAt,
  parseCanonicalProducerEvent,
  producerEventFingerprint,
  semanticFingerprint,
} from './registry-codec';
import { authorizeRegistration, reduceHeartbeat, reduceRegistration } from './session-transitions';
import { planTerminalEvent, toCanonicalSessionState } from './terminal-event-plan';
import { SESSION_TTL_MS, TERMINAL_RETRY_DELAYS_MS } from './registry-types';
import type {
  PendingTerminal,
  RegisteredSession,
  RegisterSessionInput,
  RegistryMutationCallback,
  RegistryMutationReason,
  RegistryRetryScheduler,
  RegistryStateStore,
} from './registry-types';

export type {
  AgentAdapterEventInput,
  RegisteredSession,
  RegisterSessionInput,
  RegistryMutationCallback,
  RegistryMutationReason,
  RegistryRetryScheduler,
} from './registry-types';

export class AgentAdapterRequestValidationError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'AgentAdapterRequestValidationError';
  }
}

export class SessionIdCollisionError extends Error {
  readonly code = 'session_id_collision' as const;

  constructor(sessionId: string) {
    super(`Session ID ${sessionId} is already owned by a different adapter`);
    this.name = 'SessionIdCollisionError';
  }
}

const DEFAULT_RETRY_SCHEDULER: RegistryRetryScheduler = {
  schedule: (callback, delayMs) => {
    const timer = setTimeout(callback, delayMs);
    timer.unref();
    return timer;
  },
  cancel: (handle) => clearTimeout(handle as ReturnType<typeof setTimeout>),
};
const DEFAULT_RESULT_WAITER_SCHEDULER: RegistryRetryScheduler = {
  schedule: (callback, delayMs) => setTimeout(callback, delayMs),
  cancel: (handle) => clearTimeout(handle as ReturnType<typeof setTimeout>),
};

export class AgentAdapterRegistry {
  private readonly recoveryDeadlineMs: number;
  private sessions = new Map<string, RegisteredSession>();
  private commandQueues = new Map<string, CommandEnvelope[]>();
  private commandWaiters = new Map<string, Array<(command: CommandEnvelope | null) => void>>();
  private results = new Map<string, CommandResult>();
  private resultWaiters = new Map<string, Array<(result: CommandResult | undefined) => void>>();
  private resultWaiterTimers = new Map<(result: CommandResult | undefined) => void, unknown>();
  private commandSessions = new Map<string, { hostId: string; sessionId: string; provider: string }>();
  private inFlightCommands = new Map<string, Set<string>>();
  private delayedTerminalEvents = new Map<string, PendingTerminal>();
  private terminalRetryAttempts = new Map<string, number>();
  private terminalRetryTimers = new Map<string, unknown>();
  private disposed = false;

  constructor(
    private readonly hostId: string,
    private readonly stateStore: RegistryStateStore,
    private readonly onMutation: RegistryMutationCallback = () => {},
    private readonly now: () => Date = () => new Date(),
    private readonly retryScheduler: RegistryRetryScheduler = DEFAULT_RETRY_SCHEDULER,
    private readonly resultWaiterScheduler: RegistryRetryScheduler = DEFAULT_RESULT_WAITER_SCHEDULER,
  ) {
    this.recoveryDeadlineMs = this.now().getTime() + SESSION_TTL_MS;
  }

  register(input: RegisterSessionInput): RegisteredSession {
    const previous = this.sessions.get(input.sessionId);
    const persistedSession = this.stateStore.getSession(input.sessionId);
    const authorization = authorizeRegistration({ previousLive: previous, persistedSession }, input);
    if (authorization.kind === 'collision') throw new SessionIdCollisionError(authorization.sessionId);

    const now = this.nowIso();
    const persistedCancellation = this.stateStore.getTerminalEventCancellation(input.sessionId);
    const transition = reduceRegistration(
      { previousLive: previous, persistedSession, terminalCancellation: persistedCancellation },
      input, this.hostId, now,
    );
    try {
      assertCanonicalSessionWithinLimit(toCanonicalSessionState(transition.nextSession));
    } catch (error) {
      if (error instanceof ProtectedContentValidationError) {
        throw new AgentAdapterRequestValidationError(error.message, { cause: error });
      }
      throw error;
    }
    if (transition.persistence.kind === 'durable-set-session-driver') {
      this.stateStore.setSessionDriver(input.sessionId, input.provider, toCanonicalSessionState(transition.nextSession));
    } else {
      this.cancelTerminalRetry(input.sessionId, {
        nextDriverName: transition.persistence.nextDriverName,
        persistedCancellation: transition.persistence.persistedCancellation,
      });
    }
    this.sessions.set(input.sessionId, transition.nextSession);
    if (transition.semanticChanged) this.onMutation('register');
    return transition.nextSession;
  }

  unregister(sessionId: string, reason: 'unregister' | 'ttl' = 'unregister'): boolean {
    const session = this.sessions.get(sessionId);
    const pending = this.delayedTerminalEvents.get(sessionId);
    const persistedCancellation = this.stateStore.getTerminalEventCancellation(sessionId);
    let removedPersisted = false;
    if (pending || persistedCancellation) {
      this.cancelTerminalRetry(sessionId, { removeSession: true, persistedCancellation });
      removedPersisted = true;
    } else {
      removedPersisted = this.stateStore.removeSession(sessionId, session?.provider);
    }
    if (!session && !removedPersisted) return false;
    this.cancelCommandPolls(sessionId);
    for (const [commandId, binding] of this.commandSessions) {
      if (binding.sessionId === sessionId) this.settleResultWaiters(commandId, undefined);
      if (binding.sessionId === sessionId) this.commandSessions.delete(commandId);
    }
    this.commandQueues.delete(sessionId); this.inFlightCommands.delete(sessionId);
    this.sessions.delete(sessionId);
    this.onMutation(reason);
    return true;
  }

  hasSession(sessionId: string): boolean { return this.sessions.has(sessionId); }
  cancelCommandPolls(sessionId?: string): void {
    const waiters = sessionId === undefined
      ? [...this.commandWaiters.values()].flat()
      : [...(this.commandWaiters.get(sessionId) ?? [])];
    if (sessionId === undefined) this.commandWaiters.clear();
    else this.commandWaiters.delete(sessionId);
    for (const waiter of waiters) waiter(null);
  }
  dispose(): void {
    if (this.disposed) return;
    this.disposed = true;
    for (const handle of this.terminalRetryTimers.values()) this.retryScheduler.cancel(handle);
    this.terminalRetryTimers.clear();
    this.terminalRetryAttempts.clear();
    this.delayedTerminalEvents.clear();
    this.cancelCommandPolls();
    for (const commandId of [...this.resultWaiters.keys()]) this.settleResultWaiters(commandId, undefined);
    this.commandQueues.clear();
    this.inFlightCommands.clear();
    this.results.clear();
    this.commandSessions.clear();
  }

  heartbeat(sessionId: string, status: SessionStatus, latestActivityText?: string | null,
    metadata: { openingText?: string | null; projectName?: string; nameText?: string } = {},
  ): RegisteredSession | undefined {
    const session = this.sessions.get(sessionId); if (!session) return undefined;
    const now = this.nowIso();
    const transition = reduceHeartbeat(session, { status, latestActivityText, metadata }, now);
    try {
      assertCanonicalSessionWithinLimit(toCanonicalSessionState(transition.nextSession));
    } catch (error) {
      if (error instanceof ProtectedContentValidationError) {
        throw new AgentAdapterRequestValidationError(error.message, { cause: error });
      }
      throw error;
    }
    if (transition.contextChanged) this.cancelTerminalRetry(sessionId);
    if (transition.semanticChanged) this.onMutation('semantic');
    this.sessions.set(sessionId, transition.nextSession);
    return transition.nextSession;
  }

  listSessions(): CanonicalSessionState[] {
    const now = this.now().getTime(); const active: CanonicalSessionState[] = [];
    for (const session of this.sessions.values()) {
      if (now - new Date(session.lastHeartbeatAt).getTime() > SESSION_TTL_MS) { this.unregister(session.sessionId, 'ttl'); continue; }
      active.push(toCanonicalSessionState(session));
    }
    return active.sort((left, right) => right.updatedAt.localeCompare(left.updatedAt));
  }

  isAuthoritativeSetReady(persistedSessions: CanonicalSessionState[]): boolean {
    if (persistedSessions.length === 0 || this.now().getTime() > this.recoveryDeadlineMs) return true;
    return persistedSessions.every((persisted) => this.sessions.has(persisted.sessionId));
  }

  pushEvent(sessionId: string, value: unknown): string {
    const session = this.sessions.get(sessionId);
    if (!session) throw new AgentAdapterRequestValidationError(`Session ${sessionId} is not registered`);
    let input: import('./registry-types').AgentAdapterEventInput;
    try {
      input = parseCanonicalProducerEvent(value);
      if (input.sessionId !== sessionId) throw new TypeError('canonical Event sessionId does not match the request path');
      if (input.provider !== session.provider) throw new TypeError('canonical Event provider does not match the registered Session');
      assertProducerContextMatchesSession(input, session);
    } catch (error) {
      if (error instanceof ProtectedContentValidationError || error instanceof TypeError) {
        throw new AgentAdapterRequestValidationError(error.message, { cause: error });
      }
      throw error;
    }

    const fingerprint = producerEventFingerprint(input);
    const existing = this.delayedTerminalEvents.get(sessionId);
    const isLiveDuplicate = existing !== undefined && producerEventFingerprint(existing.event) === fingerprint;
    const persistedReservation = isLiveDuplicate ? undefined : this.stateStore.getProducerEventReservation(sessionId, fingerprint);
    const persistedTuple = persistedReservation
      ? this.stateStore.getProducerEventTuple(persistedReservation.eventId, fingerprint)
      : undefined;
    const eventId = isLiveDuplicate
      ? existing.event.eventId
      : persistedReservation?.eventId ?? createId('evt');
    const plan = planTerminalEvent({
      session, livePending: existing, persistedReservation, persistedTuple,
      hasPendingCommandWork: this.hasPendingCommandWork(sessionId), input, eventId,
    });
    switch (plan.type) {
      case 'reject':
        throw plan.error;
      case 'return-live-duplicate': {
        const duplicate = existing!;
        if (plan.promoteNow) this.promotePendingTerminal(sessionId, duplicate, fingerprint);
        return duplicate.event.eventId;
      }
      case 'return-reservation-without-tuple':
        return plan.eventId;
      case 'stage-reserved-tuple': {
        const pending = Object.freeze({ event: immutableCopy(plan.tuple.event), session: immutableCopy(plan.tuple.session) });
        this.delayedTerminalEvents.set(sessionId, pending);
        if (plan.promoteNow) this.promotePendingTerminal(sessionId, pending, fingerprint);
        return persistedReservation!.eventId;
      }
      case 'cancel-older-and-reserve':
      case 'reserve-new-tuple': {
        if (plan.type === 'cancel-older-and-reserve') this.cancelTerminalRetry(sessionId);
        this.stateStore.reserveProducerEventTuple(plan.tuple.event, plan.tuple.session, fingerprint);
        this.delayedTerminalEvents.set(sessionId, plan.tuple);
        this.stateStore.reserveProducerEvent(plan.reservation);
        if (plan.promoteNow) this.promotePendingTerminal(sessionId, plan.tuple, fingerprint);
        return plan.tuple.event.eventId;
      }
    }
  }

  /** Commit a staged terminal Event now, or arrange a retry when the durable write fails. */
  private promotePendingTerminal(sessionId: string, pending: PendingTerminal, fingerprint: string): void {
    try {
      this.commitPendingTerminal(sessionId, pending, fingerprint);
    } catch (error) {
      this.scheduleTerminalRetry(sessionId);
      throw error;
    }
  }

  handleSession(sessionId: string, request: HandleSessionRequest): { ok: true; hostId: string; sessionId: string; handledThroughEventId: string } {
    const session = this.sessions.get(sessionId);
    if (!session) throw new AgentAdapterRequestValidationError(`Session ${sessionId} is not registered`);
    if (!request.handledThroughEventId?.trim()) throw new AgentAdapterRequestValidationError('handledThroughEventId is required');
    const handledAt = normalizeHandledAt(request.handledAt, isoNow());
    this.stateStore.queuePendingSessionHandle({ hostId: session.hostId, sessionId,
      handledThroughEventId: request.handledThroughEventId, handledThroughEventCreatedAt: request.handledThroughEventCreatedAt,
      handledAt, action: request.action === 'bridge_recovery' ? 'bridge_recovery' : 'pi_input', updatedAt: isoNow() });
    this.onMutation('handle');
    return { ok: true, hostId: session.hostId, sessionId, handledThroughEventId: request.handledThroughEventId };
  }


  assertCommandDispatchReady(command: CommandEnvelope): void {
    if (this.disposed) throw new TypeError('Agent Adapter registry is disposed');
    const session = this.sessions.get(command.sessionId);
    if (command.hostId !== this.hostId || !session || session.hostId !== command.hostId) {
      throw new TypeError('command does not match a registered adapter Session and Host');
    }
  }

  enqueueCommand(command: CommandEnvelope): void {
    this.assertCommandDispatchReady(command);
    const session = this.sessions.get(command.sessionId)!;
    this.commandSessions.set(command.commandId, {
      hostId: command.hostId, sessionId: command.sessionId, provider: session.provider,
    });
    const waiters = this.commandWaiters.get(command.sessionId);
    if (waiters?.length) {
      const waiter = waiters.shift(); if (!waiters.length) this.commandWaiters.delete(command.sessionId);
      this.markCommandInFlight(command); waiter?.(command); return;
    }
    const queue = this.commandQueues.get(command.sessionId) ?? []; queue.push(command); this.commandQueues.set(command.sessionId, queue);
  }

  async dequeueCommand(sessionId: string, timeoutMs: number): Promise<CommandEnvelope | null> {
    if (this.disposed) return null;
    const queue = this.commandQueues.get(sessionId);
    if (queue?.length) {
      const command = queue.shift(); if (!queue.length) this.commandQueues.delete(sessionId);
      if (command) this.markCommandInFlight(command); return command ?? null;
    }
    if (timeoutMs <= 0) return null;
    return new Promise((resolve) => {
      let settled = false;
      const timer = setTimeout(() => { if (settled) return; settled = true; this.removeCommandWaiter(sessionId, resolver); resolve(null); }, timeoutMs);
      const resolver = (command: CommandEnvelope | null) => { if (settled) return; settled = true; clearTimeout(timer); this.removeCommandWaiter(sessionId, resolver); resolve(command); };
      const waiters = this.commandWaiters.get(sessionId) ?? []; waiters.push(resolver); this.commandWaiters.set(sessionId, waiters);
    });
  }

  async waitForResult(commandId: string, options: { timeoutMs: number }): Promise<CommandResult | undefined> {
    if (this.disposed) return undefined;
    const existing = this.results.get(commandId); if (existing) return existing;
    return new Promise((resolve) => {
      let settled = false;
      const resolver = (result: CommandResult | undefined) => {
        if (settled) return;
        settled = true;
        const timer = this.resultWaiterTimers.get(resolver);
        if (timer !== undefined) this.resultWaiterScheduler.cancel(timer);
        this.resultWaiterTimers.delete(resolver);
        this.removeResultWaiter(commandId, resolver);
        resolve(result);
      };
      const waiters = this.resultWaiters.get(commandId) ?? []; waiters.push(resolver); this.resultWaiters.set(commandId, waiters);
      const timer = this.resultWaiterScheduler.schedule(() => resolver(undefined), options.timeoutMs);
      if (!settled) this.resultWaiterTimers.set(resolver, timer);
      else this.resultWaiterScheduler.cancel(timer);
    });
  }

  resolveCommand(commandId: string, value: unknown, submittedSessionId?: string): void {
    const result = parseAgentAdapterCommandResult(value);
    if (this.disposed) throw new TypeError('command result does not match its queued adapter command and registered Session');
    const binding = this.commandSessions.get(commandId);
    const resultSessionId = submittedSessionId ?? result.sessionId;
    const session = this.sessions.get(resultSessionId);
    if (!binding || commandId !== result.commandId || resultSessionId !== result.sessionId
      || binding.hostId !== result.hostId || binding.sessionId !== result.sessionId
      || !session || session.hostId !== binding.hostId || session.provider !== binding.provider) {
      throw new AgentAdapterRequestValidationError('command result does not match its queued adapter command and registered Session');
    }
    const commandResult = asCommandResult(result);
    this.results.set(commandId, commandResult); this.clearCommandInFlight(binding.sessionId, commandId);
    this.settleResultWaiters(commandId, commandResult);
    this.commandSessions.delete(commandId);
  }

  abandonCommand(commandId: string): void {
    const binding = this.commandSessions.get(commandId);
    if (!binding) return;
    this.results.delete(commandId);
    this.clearCommandInFlight(binding.sessionId, commandId);
    this.settleResultWaiters(commandId, undefined);
    this.commandSessions.delete(commandId);
  }

  hasPendingCommandWork(sessionId: string): boolean {
    return (this.commandQueues.get(sessionId)?.length ?? 0) > 0 || (this.inFlightCommands.get(sessionId)?.size ?? 0) > 0;
  }

  flushDelayedTerminalEvent(sessionId: string): string | undefined {
    if (this.hasPendingCommandWork(sessionId)) return undefined;
    const pending = this.delayedTerminalEvents.get(sessionId);
    if (!pending) return undefined;
    if (!this.sessions.has(sessionId)) { this.cancelTerminalRetry(sessionId); return undefined; }
    try {
    this.commitPendingTerminal(sessionId, pending, producerEventFingerprint(pending.event));
      return pending.event.eventId;
    } catch {
      this.scheduleTerminalRetry(sessionId);
      return undefined;
    }
  }

  private commitPendingTerminal(sessionId: string, pending: PendingTerminal, fingerprint: string): void {
    const current = this.sessions.get(sessionId);
    if (!current) throw new Error(`Session ${sessionId} is not registered`);
    this.stateStore.queuePendingEvent(pending.event, pending.session, fingerprint);
    const terminalRegistered = this.fromCanonicalTerminalSession(current, pending.session);
    this.commitTerminalSession(sessionId, current, terminalRegistered);
    this.cancelTerminalRetry(sessionId, { committed: true });
  }

  private scheduleTerminalRetry(sessionId: string): void {
    if (this.disposed || !this.delayedTerminalEvents.has(sessionId) || this.terminalRetryTimers.has(sessionId)) return;
    const attempt = this.terminalRetryAttempts.get(sessionId) ?? 0;
    const delayMs = TERMINAL_RETRY_DELAYS_MS[Math.min(attempt, TERMINAL_RETRY_DELAYS_MS.length - 1)];
    this.terminalRetryAttempts.set(sessionId, attempt + 1);
    const handle = this.retryScheduler.schedule(() => {
      this.terminalRetryTimers.delete(sessionId);
      if (!this.disposed) this.flushDelayedTerminalEvent(sessionId);
    }, delayMs);
    this.terminalRetryTimers.set(sessionId, handle);
  }

  private cancelTerminalRetry(sessionId: string, options: { committed?: boolean; removeSession?: boolean; nextDriverName?: string;
    persistedCancellation?: { eventId: string; fingerprint: string } } = {}): void {
    const pending = this.delayedTerminalEvents.get(sessionId);
    const cancellation = pending ? { eventId: pending.event.eventId, fingerprint: producerEventFingerprint(pending.event) }
      : options.persistedCancellation;
    if (cancellation && !options.committed) {
      this.stateStore.cancelTerminalEvent({
        eventId: cancellation.eventId, sessionId, fingerprint: cancellation.fingerprint,
        removeSession: options.removeSession, nextDriverName: options.nextDriverName, createdAt: this.nowIso(),
      });
    }
    const handle = this.terminalRetryTimers.get(sessionId);
    if (handle !== undefined) this.retryScheduler.cancel(handle);
    this.terminalRetryTimers.delete(sessionId);
    this.terminalRetryAttempts.delete(sessionId);
    this.delayedTerminalEvents.delete(sessionId);
  }

  private commitTerminalSession(sessionId: string, previous: RegisteredSession, terminal: RegisteredSession): void {
    const before = semanticFingerprint(previous);
    this.sessions.set(sessionId, terminal);
    if (semanticFingerprint(terminal) !== before) this.onMutation('semantic');
  }

  private fromCanonicalTerminalSession(
    current: RegisteredSession,
    terminal: CanonicalSessionState,
  ): RegisteredSession {
    return {
      ...current,
      status: terminal.status,
      latestActivityText: terminal.latestActivityText,
      lastEventId: terminal.lastEventId,
      semanticUpdatedAt: terminal.updatedAt,
    };
  }

  private markCommandInFlight(command: CommandEnvelope): void {
    const session = this.sessions.get(command.sessionId);
    if (!session) throw new TypeError('command Session is no longer registered');
    this.commandSessions.set(command.commandId, {
      hostId: command.hostId, sessionId: command.sessionId, provider: session.provider,
    });
    const current = this.inFlightCommands.get(command.sessionId) ?? new Set<string>(); current.add(command.commandId); this.inFlightCommands.set(command.sessionId, current);
  }
  private clearCommandInFlight(sessionId: string, commandId: string): void {
    const current = this.inFlightCommands.get(sessionId); if (!current) { this.flushDelayedTerminalEvent(sessionId); return; }
    current.delete(commandId); if (!current.size) this.inFlightCommands.delete(sessionId); this.flushDelayedTerminalEvent(sessionId);
  }
  private nowIso(): string { return this.now().toISOString(); }
  private removeCommandWaiter(sessionId: string, resolver: (command: CommandEnvelope | null) => void): void {
    const waiters = this.commandWaiters.get(sessionId); if (!waiters) return; const index = waiters.indexOf(resolver);
    if (index >= 0) waiters.splice(index, 1); if (!waiters.length) this.commandWaiters.delete(sessionId);
  }
  private removeResultWaiter(commandId: string, resolver: (result: CommandResult | undefined) => void): void {
    const waiters = this.resultWaiters.get(commandId); if (!waiters) return; const index = waiters.indexOf(resolver);
    if (index >= 0) waiters.splice(index, 1); if (!waiters.length) this.resultWaiters.delete(commandId);
  }
  private settleResultWaiters(commandId: string, result: CommandResult | undefined): void {
    const waiters = [...(this.resultWaiters.get(commandId) ?? [])];
    for (const waiter of waiters) waiter(result);
    this.resultWaiters.delete(commandId);
  }
}
