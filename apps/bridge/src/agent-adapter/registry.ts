import { createHash } from 'node:crypto';
import type {
  CanonicalEvent,
  CanonicalSessionState,
  CommandEnvelope,
  CommandResult,
  HandleSessionRequest,
  SessionStatus,
} from '@ariava/protocol';
import {
  base64UrlEncode,
  buildProtectedEventContentBytes,
  encodeLengthPrefixedFields,
  isCanonicalTimestamp,
  validateCanonicalEventInvariant,
} from '@ariava/protocol';
import { createId, isoNow } from '@ariava/shared-utils';
import type { BridgeStateStore } from '../state-store';
import { asCommandResult, parseAgentAdapterCommandResult } from './result';

export type AgentAdapterEventInput = CanonicalEvent extends infer Event
  ? Event extends CanonicalEvent ? Omit<Event, 'eventId' | 'hostId'> : never
  : never;

export interface RegisteredSession {
  sessionId: string;
  provider: string;
  projectName: string;
  cwd: string;
  nameText: string;
  openingText?: string;
  latestActivityText?: string;
  harnessProvider?: string;
  pid?: number;
  hostId: string;
  registeredAt: string;
  lastHeartbeatAt: string;
  status: SessionStatus;
  semanticUpdatedAt: string;
  lastEventId?: string;
}

export interface RegisterSessionInput {
  sessionId: string;
  provider: string;
  projectName: string;
  cwd: string;
  nameText: string;
  openingText?: string;
  latestActivityText?: string;
  harnessProvider?: string;
  pid?: number;
  status?: SessionStatus;
}

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

const SESSION_TTL_MS = 45_000;
const TERMINAL_RETRY_DELAYS_MS = [100, 500, 2_000, 5_000] as const;
const EVENT_KEYS = [
  'sessionId', 'provider', 'type', 'status', 'agentText', 'humanText', 'projectName',
  'workingDirectory', 'harnessProvider', 'createdAt', 'needHuman',
] as const;
const EVENT_REQUIRED_KEYS = [
  'sessionId', 'provider', 'type', 'status', 'agentText', 'projectName', 'workingDirectory',
  'harnessProvider', 'createdAt',
] as const;

type PendingTerminal = { event: CanonicalEvent; session: CanonicalSessionState };
export type RegistryMutationReason = 'register' | 'semantic' | 'handle' | 'unregister' | 'ttl';
export type RegistryMutationCallback = (reason: RegistryMutationReason) => void;
export interface RegistryRetryScheduler {
  schedule(callback: () => void, delayMs: number): unknown;
  cancel(handle: unknown): void;
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
    private readonly stateStore: BridgeStateStore,
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
    const requestedOwner = normalizedOwner(input);
    const liveOwner = previous ? normalizedOwner(previous) : undefined;
    const persistedOwner = persistedSession ? normalizedOwner(persistedSession) : undefined;
    if ((liveOwner && !sameOwner(liveOwner, requestedOwner))
      || (persistedOwner && !sameOwner(persistedOwner, requestedOwner))) {
      throw new SessionIdCollisionError(input.sessionId);
    }

    const now = this.nowIso();
    const projectName = input.projectName;
    const nameText = input.nameText;
    const session: RegisteredSession = {
      sessionId: input.sessionId, provider: input.provider, projectName, cwd: input.cwd, nameText,
      openingText: input.openingText, latestActivityText: input.latestActivityText,
      harnessProvider: input.harnessProvider, pid: input.pid,
      hostId: this.hostId, registeredAt: previous?.registeredAt ?? now, lastHeartbeatAt: now,
      status: input.status ?? 'idle', semanticUpdatedAt: previous?.semanticUpdatedAt ?? now,
      lastEventId: previous?.lastEventId,
    };
    const changed = !previous || semanticFingerprint(previous) !== semanticFingerprint(session);
    if (changed && previous) session.semanticUpdatedAt = now;
    const contextChanged = previous && producerContextFingerprint(previous) !== producerContextFingerprint(session);
    const persistedContextChanged = !previous && persistedSession
      && canonicalProducerContextFingerprint(persistedSession) !== producerContextFingerprint(session);
    const persistedCancellation = this.stateStore.getTerminalEventCancellation(input.sessionId);
    if (contextChanged || (persistedContextChanged && persistedCancellation)) {
      this.cancelTerminalRetry(input.sessionId, { nextDriverName: input.provider, persistedCancellation });
    } else this.stateStore.setSessionDriver(input.sessionId, input.provider, this.toCanonicalSession(session));
    this.sessions.set(input.sessionId, session);
    if (changed) this.onMutation('register');
    return session;
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
    const before = semanticFingerprint(session); const contextBefore = producerContextFingerprint(session); const now = this.nowIso();
    const next = { ...session, lastHeartbeatAt: now, status };
    if (latestActivityText !== undefined) next.latestActivityText = latestActivityText ?? undefined;
    if (metadata.openingText !== undefined) next.openingText = metadata.openingText ?? undefined;
    if (metadata.projectName !== undefined) next.projectName = metadata.projectName;
    if (metadata.nameText !== undefined) next.nameText = metadata.nameText;
    if (producerContextFingerprint(next) !== contextBefore) this.cancelTerminalRetry(sessionId);
    if (semanticFingerprint(next) !== before) { next.semanticUpdatedAt = now; this.onMutation('semantic'); }
    this.sessions.set(sessionId, next);
    return next;
  }

  listSessions(): CanonicalSessionState[] {
    const now = this.now().getTime(); const active: CanonicalSessionState[] = [];
    for (const session of this.sessions.values()) {
      if (now - new Date(session.lastHeartbeatAt).getTime() > SESSION_TTL_MS) { this.unregister(session.sessionId, 'ttl'); continue; }
      active.push(this.toCanonicalSession(session));
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
    let input: AgentAdapterEventInput;
    try {
      input = parseCanonicalProducerEvent(value);
      if (input.sessionId !== sessionId) throw new TypeError('canonical Event sessionId does not match the request path');
      if (input.provider !== session.provider) throw new TypeError('canonical Event provider does not match the registered Session');
      assertProducerContextMatchesSession(input, session);
    } catch (error) {
      if (error instanceof TypeError) throw new AgentAdapterRequestValidationError(error.message, { cause: error });
      throw error;
    }

    const fingerprint = producerEventFingerprint(input);
    const existing = this.delayedTerminalEvents.get(sessionId);
    if (existing && producerEventFingerprint(existing.event) === fingerprint) {
      if (!this.hasPendingCommandWork(sessionId)) {
        try { this.commitPendingTerminal(sessionId, existing, fingerprint); }
        catch (error) { this.scheduleTerminalRetry(sessionId); throw error; }
      }
      return existing.event.eventId;
    }
    const persisted = this.stateStore.getProducerEventReservation(sessionId, fingerprint);
    if (persisted) {
      const tuple = this.stateStore.getProducerEventTuple(persisted.eventId, fingerprint);
      if (!tuple) return persisted.eventId;
      const pending = Object.freeze({ event: immutableCopy(tuple.event), session: immutableCopy(tuple.session) });
      this.delayedTerminalEvents.set(sessionId, pending);
      if (!this.hasPendingCommandWork(sessionId)) {
        try { this.commitPendingTerminal(sessionId, pending, fingerprint); }
        catch (error) { this.scheduleTerminalRetry(sessionId); throw error; }
      }
      return persisted.eventId;
    }
    if (existing) this.cancelTerminalRetry(sessionId);

    const eventId = createId('evt');
    const event = immutableCopy({ ...input, eventId, hostId: session.hostId } as CanonicalEvent);
    const terminalRegistered = { ...session, status: event.status, latestActivityText: event.agentText,
      lastEventId: eventId, semanticUpdatedAt: event.createdAt };
    const terminalSession = immutableCopy(this.toCanonicalSession(terminalRegistered));
    const pending = Object.freeze({ event, session: terminalSession });
    this.stateStore.reserveProducerEventTuple(event, terminalSession, fingerprint);
    this.delayedTerminalEvents.set(sessionId, pending);
    this.stateStore.reserveProducerEvent({ version: 1, eventId, sessionId, fingerprint, createdAt: event.createdAt });
    if (!this.hasPendingCommandWork(sessionId)) {
      try { this.commitPendingTerminal(sessionId, pending, fingerprint); }
      catch (error) { this.scheduleTerminalRetry(sessionId); throw error; }
    }
    return eventId;
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
  private toCanonicalSession(session: RegisteredSession): CanonicalSessionState {
    return { sessionId: session.sessionId, hostId: session.hostId, provider: session.provider, projectName: session.projectName,
      nameText: session.nameText, openingText: session.openingText, latestActivityText: session.latestActivityText,
      workingDirectory: session.cwd, harnessProvider: session.harnessProvider,
      status: session.status, updatedAt: session.semanticUpdatedAt, lastEventId: session.lastEventId };
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

function parseCanonicalProducerEvent(value: unknown): AgentAdapterEventInput {
  const event = exactRecord(value, EVENT_KEYS, EVENT_REQUIRED_KEYS, 'canonical Event');
  for (const key of ['sessionId', 'provider', 'agentText', 'projectName', 'workingDirectory', 'harnessProvider', 'createdAt'] as const) requireString(event, key);
  optionalString(event, 'humanText');
  if (!isCanonicalTimestamp(event.createdAt)) throw new TypeError('canonical Event createdAt is invalid');
  const invariant = validateCanonicalEventInvariant({ type: event.type, status: event.status, ...(Object.hasOwn(event, 'needHuman') ? { needHuman: event.needHuman } : {}) });
  if (!invariant.success) throw new TypeError(`canonical Event invariant is invalid: ${invariant.issues.join(', ')}`);
  buildProtectedEventContentBytes({
    version: 3,
    agentText: event.agentText as string,
    ...(event.humanText !== undefined ? { humanText: event.humanText as string } : {}),
    projectName: event.projectName as string,
    workingDirectory: event.workingDirectory as string,
    harnessProvider: event.harnessProvider as string,
    ...(event.needHuman !== undefined ? { needHuman: event.needHuman as never } : {}),
  });
  return event as unknown as AgentAdapterEventInput;
}

function exactRecord(value: unknown, allowedKeys: readonly string[], requiredKeys: readonly string[], label: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new TypeError(`${label} must be an object`);
  const allowed = new Set(allowedKeys);
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string' || !allowed.has(key)) throw new TypeError(`${label} contains unsupported fields`);
    const descriptor = Object.getOwnPropertyDescriptor(value, key)!;
    if (!descriptor.enumerable || !('value' in descriptor)) throw new TypeError(`${label}.${key} is invalid`);
  }
  for (const key of requiredKeys) if (!Object.hasOwn(value, key)) throw new TypeError(`${label}.${key} is required`);
  return value as Record<string, unknown>;
}
function immutableCopy<Value>(value: Value): Value {
  const copy = structuredClone(value);
  return deepFreeze(copy);
}

function deepFreeze<Value>(value: Value): Value {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value;
  for (const nested of Object.values(value)) deepFreeze(nested);
  return Object.freeze(value);
}

function requireString(value: Record<string, unknown>, key: string): void { if (typeof value[key] !== 'string') throw new TypeError(`canonical Event.${key} is invalid`); }
function optionalString(value: Record<string, unknown>, key: string): void { if (value[key] !== undefined && typeof value[key] !== 'string') throw new TypeError(`canonical Event.${key} is invalid`); }
function normalizeHandledAt(value: string | undefined, fallback: string): string { if (!value) return fallback; return Number.isFinite(new Date(value).getTime()) ? value : fallback; }

function assertProducerContextMatchesSession(event: AgentAdapterEventInput, session: RegisteredSession): void {
  const expected = {
    projectName: session.projectName,
    workingDirectory: session.cwd,
    harnessProvider: session.harnessProvider ?? session.provider,
  };
  for (const [key, value] of Object.entries(expected)) {
    if ((event as unknown as Record<string, unknown>)[key] !== value) {
      throw new TypeError(`canonical Event ${key} does not match the registered Session`);
    }
  }
}

function producerEventFingerprint(event: AgentAdapterEventInput | CanonicalEvent): string {
  const producer = event as CanonicalEvent;
  const protectedContent = buildProtectedEventContentBytes({
    version: 3,
    agentText: producer.agentText,
    ...(producer.humanText === undefined ? {} : { humanText: producer.humanText }),
    ...(producer.projectName === undefined ? {} : { projectName: producer.projectName }),
    ...(producer.workingDirectory === undefined ? {} : { workingDirectory: producer.workingDirectory }),
    ...(producer.harnessProvider === undefined ? {} : { harnessProvider: producer.harnessProvider }),
    ...(producer.needHuman === undefined ? {} : { needHuman: producer.needHuman }),
  });
  const publicMetadata = JSON.stringify({
    sessionId: producer.sessionId,
    provider: producer.provider,
    type: producer.type,
    status: producer.status,
    createdAt: producer.createdAt,
  });
  const canonical = encodeLengthPrefixedFields([
    'ariava-producer-event-fingerprint-v1',
    publicMetadata,
    base64UrlEncode(protectedContent),
  ]);
  return createHash('sha256').update(canonical).digest('base64url');
}
function producerContextFingerprint(session: Pick<RegisteredSession, 'projectName' | 'cwd' | 'harnessProvider' | 'provider'>): string {
  return JSON.stringify({
    projectName: session.projectName,
    workingDirectory: session.cwd,
    harnessProvider: session.harnessProvider ?? session.provider,
  });
}

function canonicalProducerContextFingerprint(session: CanonicalSessionState): string {
  return JSON.stringify({
    projectName: session.projectName,
    workingDirectory: session.workingDirectory ?? '',
    harnessProvider: session.harnessProvider ?? session.provider,
  });
}

function normalizedOwner(session: Pick<RegisterSessionInput, 'provider' | 'harnessProvider'>): readonly [string, string] {
  return [session.provider, session.harnessProvider ?? session.provider] as const;
}

function sameOwner(left: readonly [string, string], right: readonly [string, string]): boolean {
  return left[0] === right[0] && left[1] === right[1];
}

function semanticFingerprint(session: RegisteredSession): string {
  return JSON.stringify({ sessionId: session.sessionId, provider: session.provider, projectName: session.projectName, cwd: session.cwd,
    nameText: session.nameText, openingText: session.openingText, latestActivityText: session.latestActivityText,
    harnessProvider: session.harnessProvider, pid: session.pid,
    hostId: session.hostId, status: session.status, lastEventId: session.lastEventId });
}
