import { isoNow } from '@ariava/shared-utils';
import type { CanonicalEvent, CanonicalSessionState, CommandResult, HostProjection } from '@ariava/protocol';
import { RelayClientError, RelayTransportError } from '../relay-client';
import type { AgentDriver, BridgeSyncResult } from '../types';
import { snapshotError } from './daemon-errors';

/**
 * §6.2 Session publication outcome taxonomy (spec §6.2). `published`/`unchanged`
 * allow the normal Event drain; `locally-blocked` allows Event drain only under
 * the §6.2 conditions (stable accepted recipient version + no unconverged Session
 * inflight); `deferred`/`fail-closed` keep the existing stop semantics.
 *
 * Declared here so the linear sync orchestration and `BridgeDaemon` share one
 * definition (the daemon imports it; nothing in this module imports the daemon).
 */
export type SessionPublicationOutcome =
  | { type: 'published' | 'unchanged' }
  | { type: 'locally-blocked'; reason: 'protected_content_invalid' | 'session_source_invalid'; blockedSessionCount: number; recipientSetVersion: number }
  | { type: 'deferred'; reason: 'network' | 'recipient-set' }
  | { type: 'fail-closed' };

/**
 * Narrow dependency contract for one linear sync pass (spec §5 `sync-workflow.ts`,
 * spec §9, plan Task 6). Contains only the imperative serial sequence the daemon
 * previously ran inside `performSyncOnce`; every effect behind a dependency stays
 * owned by `BridgeDaemon` (spec §8): the sync single-flight/coalescing flag
 * (`acknowledgeSyncPass`), stop/abort ownership (`stop`), timer scheduling
 * (`recordLocalSnapshotPublicationFailure` schedules the debounced registry
 * reconciliation), the presence/receipt-drain/command flights
 * (`ensureHostPresence`, `reconcileRecipientsAndDrainReceipts`,
 * `pullAndHandleCommands`), mutable policy/lifecycle state (snapshot failure
 * state, `recordLocalSnapshotPublicationFailure`), and the logging/health
 * authorities (driver health, session publication block logger, snapshot
 * failure logger). Dependencies delegate to daemon-owned methods; there is no
 * generic facade or resource container.
 */
export interface SyncWorkflowDependencies {
  /** §9 step 1: reset guard; a rejection stops the daemon and aborts the pass. */
  assertHostDomainResetStartAllowed(): void;
  /** Daemon-owned stop, invoked only on the reset-guard failure path. */
  stop(): void;
  /** §9 step 1: idempotent startup validation/activation. */
  validateStartup(): Promise<void>;
  /** Clears the daemon-owned reconciliationRequested coalescing flag. */
  acknowledgeSyncPass(): void;
  /** §9 step 2: Host presence publication (presence single-flight stays in the daemon). */
  ensureHostPresence(): Promise<void>;
  /** §9 step 3: command authority reconciliation + pending receipt drain (flight stays in the daemon). */
  reconcileRecipientsAndDrainReceipts(): Promise<number>;
  /** §9 step 4: the daemon-owned driver list, read once per pass. */
  drivers(): readonly AgentDriver[];
  hostId: string;
  pollIntervalMs: number;
  listSessions(): CanonicalSessionState[];
  getDriverNameForSession(sessionId: string): string | undefined;
  replaceDriverSessions(driverName: string, sessions: CanonicalSessionState[]): void;
  /** Daemon-owned failure health recording: store transition + runtime-health log. */
  recordDriverReconciliationFailure(driverName: string, observedAt: string, nextRetryAt: string): void;
  /** Daemon-owned success health recording: store transition + runtime-health recovery log. */
  recordDriverReconciliationSuccess(driverName: string): void;
  /** §9 step 5: authoritative current Sessions publication (daemon-owned effect). */
  flushCurrentSessionsSnapshot(currentSessions: CanonicalSessionState[]): Promise<SessionPublicationOutcome>;
  /**
   * §9 step 5, non-Relay local fault branch: shared pure log-throttle decision,
   * snapshot failure state, failure log, and registry-reconciliation scheduling —
   * all daemon-owned.
   */
  recordLocalSnapshotPublicationFailure(error: unknown, activeSessions: CanonicalSessionState[]): void;
  /** §9 step 5, Relay failure branch: daemon-owned escalation/recovery pipeline. */
  handleCurrentSessionsSnapshotFailure(
    error: unknown,
    activeSessions: CanonicalSessionState[],
  ): Promise<{ online: boolean; outcome: SessionPublicationOutcome }>;
  /** §9 step 5 logging authority: daemon-owned Session publication block logger. */
  sessionPublicationRecovered(): void;
  sessionPublicationBlocked(blockedSessionCount: number, reason: 'protected_content_invalid' | 'session_source_invalid'): void;
  /** §6.2 drain gate, evaluated by the daemon-owned method. */
  eventsMayDrain(outcome: SessionPublicationOutcome): boolean;
  /** §9 step 6: pending encrypted Event upload. */
  flushPendingEvents(): Promise<number>;
  /** §9 step 7: pending handles flush. */
  flushPendingHandles(): Promise<number>;
  /** §9 step 8: command pull/dispatch (command single-flight stays in the daemon). */
  pullAndHandleCommands(): Promise<CommandResult[]>;
  /** Result assembly: authoritative Host projection. */
  getHost(): HostProjection | null;
}

/**
 * One linear sync pass (spec §9), moved verbatim out of
 * `BridgeDaemon.performSyncOnce`. The exact serial durable-effect order and
 * every early-return/failure category are preserved: reset/startup validation →
 * Host presence publication → command authority reconciliation + pending
 * receipt drain → serial driver reconciliation → authoritative current Sessions
 * publication → pending encrypted Event upload → pending handles flush →
 * command pull/dispatch → runtime-health recording (via the daemon-owned
 * record* dependencies). Nothing is parallelized, and no termination, timer,
 * or single-flight ownership moved with the orchestration.
 */
export async function performBridgeSyncOnce(
  deps: SyncWorkflowDependencies,
): Promise<BridgeSyncResult> {
  try {
    deps.assertHostDomainResetStartAllowed();
  } catch (error) {
    deps.stop();
    throw error;
  }
  await deps.validateStartup();
  deps.acknowledgeSyncPass();
  let offline = false;
  try {
    await deps.ensureHostPresence();
  } catch {
    offline = true;
  }
  if (!offline) await deps.reconcileRecipientsAndDrainReceipts();

  const newEvents: CanonicalEvent[] = [];
  let authoritativeSetComplete = true;
  for (const driver of deps.drivers()) {
    const observedAt = isoNow();
    const nextRetryAt = new Date(Date.parse(observedAt) + deps.pollIntervalMs).toISOString();
    try {
      const persistedDriverSessions = deps.listSessions()
        .filter((session) => deps.getDriverNameForSession(session.sessionId) === driver.name);
      const sessions = await driver.listSessions(deps.hostId);
      if (driver.isAuthoritativeSetReady?.(persistedDriverSessions) === false) {
        authoritativeSetComplete = false;
        deps.recordDriverReconciliationFailure(driver.name, observedAt, nextRetryAt);
        continue;
      }
      deps.replaceDriverSessions(driver.name, sessions);
      deps.recordDriverReconciliationSuccess(driver.name);
    } catch {
      authoritativeSetComplete = false;
      deps.recordDriverReconciliationFailure(driver.name, observedAt, nextRetryAt);
    }
  }
  // A driver failure must never turn a partial list into an authoritative replacement.
  // Successful drivers have been reconciled above, while failed drivers retain their last
  // complete persisted set. Build the Host snapshot only from that reconciled store.
  const nextSessions = deps.listSessions();
  const activeSessions = nextSessions;
  let sessionPublicationOutcome: SessionPublicationOutcome = { type: 'deferred', reason: 'network' };
  if (authoritativeSetComplete && !offline) {
    try {
      sessionPublicationOutcome = await deps.flushCurrentSessionsSnapshot(activeSessions);
      if (sessionPublicationOutcome.type === 'deferred' && sessionPublicationOutcome.reason === 'network') offline = true;
    }
    catch (error) {
      if (snapshotError(error, 'session_snapshot_conflict')) throw new Error('Relay rejected the persisted E2E lifecycle revision as conflicting', { cause: error });
      if (!(error instanceof RelayClientError) && !(error instanceof RelayTransportError)) {
        // Storage/canonicalization/keyring/crypto/Relay-response-shape faults are
        // local fail-closed conditions, not evidence that the Host is offline.
        // Keep unrelated handles/commands alive while Session/Event publication
        // remains stopped for this pass.
        deps.recordLocalSnapshotPublicationFailure(error, activeSessions);
        sessionPublicationOutcome = { type: 'fail-closed' };
      } else {
        const recovery = await deps.handleCurrentSessionsSnapshotFailure(error, activeSessions);
        offline = !recovery.online;
        sessionPublicationOutcome = recovery.outcome;
      }
    }
  }
  if (sessionPublicationOutcome.type === 'published' || sessionPublicationOutcome.type === 'unchanged') {
    deps.sessionPublicationRecovered();
  } else if (sessionPublicationOutcome.type === 'locally-blocked') {
    deps.sessionPublicationBlocked(sessionPublicationOutcome.blockedSessionCount, sessionPublicationOutcome.reason);
  }
  const eventsMayDrain = !offline && deps.eventsMayDrain(sessionPublicationOutcome);
  const flushedEvents = !eventsMayDrain ? 0 : await deps.flushPendingEvents();
  const flushedReads = offline ? 0 : await deps.flushPendingHandles();
  const handledCommands = offline ? [] : await deps.pullAndHandleCommands();
  return { host: deps.getHost(), sessions: nextSessions, emittedEvents: newEvents, flushedEvents, flushedReads, handledCommands, offline };
}
