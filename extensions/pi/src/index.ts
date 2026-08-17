import type { ExtensionAPI, ExtensionContext } from '@earendil-works/pi-coding-agent';
import type { AgentMessage } from '@earendil-works/pi-agent-core';
import { AgentAdapterClient } from './adapter';
import type { AgentAdapter } from './adapter-interface';
import { executeCommand } from './commands';
import { buildDoneEvent, buildNeedHumanEvent, extractNeedHumanError } from './events';
import { startHeartbeat, stopHeartbeat, type HeartbeatContext } from './heartbeat';
import {
  classifyStoredAssistantText,
  markFingerprintEmitted,
  resetEmittedFingerprints,
  type StoredTerminalCandidate,
} from './question-detector';
import { startCommandPoller, type CommandPollerHandle } from './poller';
import { logExtensionEvent } from './logger';
import {
  clampAssistantText,
  deriveActiveLeafId,
  deriveLatestActivityText,
  deriveMessageTexts,
  deriveSession,
  deriveSessionId,
  normalizeAssistantTextForEvent,
  withSessionStatus,
} from './session';

const REGISTRATION_WARNING_MS = 5_000;
const REGISTRATION_WARNING_MESSAGE =
  'Ariava bridge did not register this pi session within 5s. Check that the selected local bridge profile is running and its Agent Adapter discovery file is available.';
const REGISTRATION_RETRY_MS = 1_000;
const TERMINAL_ALERT_QUIET_WINDOW_MS = 1_500;

type LatestAgentEndResult = {
  assistantFound: boolean;
  stopReason?: string;
  agentText?: string;
  errorMessage?: unknown;
  error?: unknown;
  runGeneration: number;
};

type PendingTerminalAlertBase = {
  agentText: string;
  fingerprint?: string;
  humanText?: string;
  createdAt: string;
  flowRevision: number;
  runGeneration: number;
};

type PendingTerminalAlert = PendingTerminalAlertBase & (
  | { type: 'done'; reason?: never; error?: never }
  | { type: 'need_human'; reason: 'question' | 'blocked'; error?: never }
  | { type: 'need_human'; reason: 'error'; error: ReturnType<typeof extractNeedHumanError> }
);

type PendingHandleCandidate = {
  sessionId: string;
  eventId: string;
  eventCreatedAt: string;
  observedUserInputCursor: number;
  reported: boolean;
};

type PiReducerState = {
  sessionId: string;
  rootSessionActive: boolean;
  loopRunning: boolean;
  terminalEmittedForCurrentLoop: boolean;
  flowRevision: number;
  latestAgentEndResult?: LatestAgentEndResult;
  latestPendingAlert?: PendingTerminalAlert;
  pendingHandleCandidate?: PendingHandleCandidate;
  quietTimer?: ReturnType<typeof setTimeout>;
  terminalDeliveryInFlight?: boolean;
  lastInputAt?: number;
  inputCursor: number;
  activeLeafId?: string;
  lastTreeSwitchAt?: number;
  generationSequence: number;
  currentRunGeneration?: number;
  settledRunGeneration?: number;
};

export default function ariavaPiExtension(pi: ExtensionAPI, testAdapter?: AgentAdapter) {
  let session: ReturnType<typeof deriveSession> | null = null;
  const adapter: AgentAdapter = testAdapter ?? new AgentAdapterClient();
  let commandPoller: CommandPollerHandle | null = null;
  let state: PiReducerState | null = null;
  let registrationWarningTimer: ReturnType<typeof setTimeout> | null = null;
  let registrationRetryTimer: ReturnType<typeof setTimeout> | null = null;
  let deliverySequence = 0;
  let activeSessionManager: ExtensionContext['sessionManager'] | undefined;
  let registrationGeneration = 0;

  const heartbeatContext: HeartbeatContext = {
    sessionId: '',
    client: adapter,
    status: 'idle',
    latestActivityText: undefined,
    getSession: () => session,
  };

  function runAdapterTask(task: () => Promise<unknown>): void {
    void task().catch(() => logExtensionEvent('adapter_task_failed'));
  }

  function reportPendingHandleAfterLocalInput(loopState: PiReducerState): void {
    const candidate = loopState.pendingHandleCandidate;
    if (!candidate || candidate.reported || !loopState.lastInputAt) return;
    if (loopState.inputCursor <= candidate.observedUserInputCursor) return;

    candidate.reported = true;
    reportHandledEvent(loopState, candidate);
  }

  function reportHandledEvent(
    loopState: PiReducerState,
    candidate: PendingHandleCandidate,
  ): void {
    runAdapterTask(async () => {
      try {
        await adapter.handleSession(candidate.sessionId, {
          handledThroughEventId: candidate.eventId,
          handledThroughEventCreatedAt: candidate.eventCreatedAt,
          handledAt: new Date(loopState.lastInputAt ?? Date.now()).toISOString(),
          action: 'local_input',
        });
        if (state?.pendingHandleCandidate === candidate) {
          state.pendingHandleCandidate = undefined;
        }
      } catch (error) {
        candidate.reported = false;
        throw error;
      }
    });
  }

  async function pushWorking(ctx: ExtensionContext, agentText?: string) {
    if (!session || !state?.rootSessionActive) return;
    const latestActivityText = clampAssistantText(agentText ?? deriveLatestActivityText(ctx));
    session = withSessionStatus(session, 'working', latestActivityText);
    heartbeatContext.status = 'working';
    heartbeatContext.latestActivityText = session.latestActivityText;
    const workingSession = session;
    runAdapterTask(() =>
      adapter.heartbeat(workingSession.sessionId, 'working', latestActivityText ?? null, workingSession),
    );
  }

  function runtimeHasNewWork(ctx: ExtensionContext): boolean {
    return ctx.isIdle() === false || ctx.hasPendingMessages() === true;
  }

  function extractLatestAssistantEnd(
    messages: AgentMessage[] | undefined,
    runGeneration: number,
  ): LatestAgentEndResult {
    for (let index = (messages?.length ?? 0) - 1; index >= 0; index -= 1) {
      const message = messages?.[index] as {
        role?: string;
        stopReason?: unknown;
        content?: unknown;
        errorMessage?: unknown;
        error?: unknown;
      } | undefined;
      if (message?.role !== 'assistant') continue;
      return {
        assistantFound: true,
        stopReason: typeof message.stopReason === 'string' ? message.stopReason : undefined,
        agentText: extractTextContent(message.content),
        errorMessage: message.errorMessage,
        error: message.error,
        runGeneration,
      };
    }
    return { assistantFound: false, runGeneration };
  }

  function extractTextContent(content: unknown): string | undefined {
    if (!Array.isArray(content)) return undefined;
    const text = content
      .filter((part): part is { type: string; text: string } =>
        typeof part === 'object' &&
        part !== null &&
        (part as { type?: unknown }).type === 'text' &&
        typeof (part as { text?: unknown }).text === 'string',
      )
      .map((part) => part.text)
      .join('')
      .trim();
    return text || undefined;
  }
  async function settleTerminalLocally(
    loopState: PiReducerState,
    alert: PendingTerminalAlert,
    terminalSession: NonNullable<typeof session>,
    sessionStatus: 'idle' | 'need_human',
  ): Promise<void> {
    if (alert.fingerprint) markFingerprintEmitted(alert.fingerprint);
    session = terminalSession;
    heartbeatContext.status = sessionStatus;
    heartbeatContext.latestActivityText = terminalSession.latestActivityText;
    loopState.terminalEmittedForCurrentLoop = true;
    loopState.latestPendingAlert = undefined;
    loopState.terminalDeliveryInFlight = false;
    loopState.pendingHandleCandidate = undefined;
    try {
      await adapter.heartbeat(
        terminalSession.sessionId, sessionStatus, terminalSession.latestActivityText ?? null, terminalSession,
      );
    } catch {
      logExtensionEvent('heartbeat_failed');
    }
  }

  async function emitTerminalAlert(alert: PendingTerminalAlert) {
    if (
      !session ||
      !state?.rootSessionActive ||
      state.latestPendingAlert !== alert ||
      state.terminalDeliveryInFlight ||
      state.flowRevision !== alert.flowRevision ||
      state.settledRunGeneration !== alert.runGeneration
    ) return;

    const eventType = alert.type;
    const normalizedAgentText = normalizeAssistantTextForEvent(eventType, session, alert.agentText);
    const sessionStatus = alert.type === 'done' ? 'idle' : 'need_human';
    const terminalSession = withSessionStatus(session, sessionStatus, normalizedAgentText);
    if (adapter.eventPublicationEnabled === false) {
      await settleTerminalLocally(state, alert, terminalSession, sessionStatus);
      return;
    }

    const event = alert.type === 'done'
      ? buildDoneEvent(terminalSession, normalizedAgentText, alert.humanText, alert.createdAt)
      : buildNeedHumanEvent(terminalSession, alert.reason === 'error'
          ? {
              reason: alert.reason,
              error: alert.error,
              agentText: normalizedAgentText,
              humanText: alert.humanText,
              createdAt: alert.createdAt,
            }
          : {
              reason: alert.reason,
              agentText: normalizedAgentText,
              humanText: alert.humanText,
              createdAt: alert.createdAt,
            });

    const deliveryToken = deliverySequence;
    const deliveredSessionId = state.sessionId;
    const deliveredLeafId = state.activeLeafId;
    const deliveredFlowRevision = state.flowRevision;
    const deliveredRunGeneration = state.settledRunGeneration;
    const observedUserInputCursor = state.inputCursor;
    state.terminalDeliveryInFlight = true;

    try {
      const pushed = await adapter.pushEvent(event);
      const currentState = state;
      if (
        !currentState ||
        deliveryToken !== deliverySequence ||
        currentState.sessionId !== deliveredSessionId ||
        currentState.activeLeafId !== deliveredLeafId
      ) return;

      if (alert.fingerprint) markFingerprintEmitted(alert.fingerprint);
      const candidate: PendingHandleCandidate = {
        sessionId: event.sessionId,
        eventId: pushed.eventId,
        eventCreatedAt: event.createdAt ?? new Date().toISOString(),
        observedUserInputCursor,
        reported: false,
      };
      if (currentState.inputCursor > observedUserInputCursor) {
        currentState.pendingHandleCandidate = candidate;
        candidate.reported = true;
        reportHandledEvent(currentState, candidate);
        return;
      }
      if (
        currentState.latestPendingAlert !== alert ||
        currentState.flowRevision !== deliveredFlowRevision ||
        currentState.settledRunGeneration !== deliveredRunGeneration
      ) return;
      session = terminalSession;
      heartbeatContext.status = sessionStatus;
      heartbeatContext.latestActivityText = terminalSession.latestActivityText;
      currentState.terminalEmittedForCurrentLoop = true;
      currentState.latestPendingAlert = undefined;
      currentState.pendingHandleCandidate = candidate;
    } catch (error) {
      const currentState = state;
      if (
        currentState &&
        deliveryToken === deliverySequence &&
        currentState.sessionId === deliveredSessionId &&
        currentState.activeLeafId === deliveredLeafId &&
        currentState.latestPendingAlert === alert &&
        currentState.flowRevision === deliveredFlowRevision &&
        currentState.settledRunGeneration === deliveredRunGeneration
      ) {
        await settleTerminalLocally(currentState, alert, terminalSession, sessionStatus);
      }
      logExtensionEvent('terminal_event_push_failed');
    } finally {
      if (state?.latestPendingAlert === alert) state.terminalDeliveryInFlight = false;
    }
  }

  function clearQuietTimer(loopState: PiReducerState | null = state) {
    if (!loopState?.quietTimer) return;
    clearTimeout(loopState.quietTimer);
    loopState.quietTimer = undefined;
  }


  function invalidatePendingTerminal(loopState: PiReducerState): void {
    clearQuietTimer(loopState);
    loopState.latestPendingAlert = undefined;
    loopState.terminalDeliveryInFlight = false;
  }

  function schedulePendingTerminal(ctx: ExtensionContext) {
    if (!state) return;
    clearQuietTimer(state);
    const scheduledSessionId = state.sessionId;
    const scheduledFlowRevision = state.flowRevision;
    state.quietTimer = setTimeout(() => {
      void flushPendingTerminalIfStable(ctx, scheduledSessionId, scheduledFlowRevision);
    }, TERMINAL_ALERT_QUIET_WINDOW_MS);
    state.quietTimer.unref?.();
  }

  async function flushPendingTerminalIfStable(
    ctx: ExtensionContext,
    scheduledSessionId: string,
    scheduledFlowRevision: number,
  ) {
    if (
      !state ||
      state.sessionId !== scheduledSessionId ||
      state.flowRevision !== scheduledFlowRevision ||
      !state.latestPendingAlert ||
      state.settledRunGeneration !== state.latestPendingAlert.runGeneration ||
      state.loopRunning
    ) return;
    if (runtimeHasNewWork(ctx)) {
      invalidatePendingTerminal(state);
      return;
    }
    const alert = state.latestPendingAlert;
    clearQuietTimer(state);
    await emitTerminalAlert(alert);
  }

  function submitTerminalCandidate(
    candidate: StoredTerminalCandidate,
    ctx: ExtensionContext,
    runGeneration: number,
  ) {
    if (!session || !state?.rootSessionActive || state.terminalEmittedForCurrentLoop || state.latestPendingAlert) return;
    const commonAlert = {
      agentText: normalizeAssistantTextForEvent(candidate.type, session, candidate.agentText),
      humanText: deriveMessageTexts(ctx).latestUserText,
      fingerprint: candidate.fingerprint,
      createdAt: new Date().toISOString(),
      flowRevision: state.flowRevision,
      runGeneration,
    };
    state.latestPendingAlert = candidate.type === 'need_human'
      ? { ...commonAlert, type: candidate.type, reason: candidate.reason }
      : { ...commonAlert, type: candidate.type };
    schedulePendingTerminal(ctx);
  }

  function submitErrorCandidate(
    ctx: ExtensionContext,
    result: LatestAgentEndResult,
    runGeneration: number,
  ): void {
    if (!session || !state?.rootSessionActive || state.terminalEmittedForCurrentLoop || state.latestPendingAlert) return;
    const error = extractNeedHumanError(result);
    state.latestPendingAlert = {
      type: 'need_human',
      reason: 'error',
      agentText: error.message,
      error,
      humanText: deriveMessageTexts(ctx).latestUserText,
      createdAt: new Date().toISOString(),
      flowRevision: state.flowRevision,
      runGeneration,
    };
    schedulePendingTerminal(ctx);
  }

  function resetLoopState(nextSessionId: string, activeLeafId?: string): PiReducerState {
    state = {
      sessionId: nextSessionId,
      rootSessionActive: true,
      loopRunning: false,
      terminalEmittedForCurrentLoop: false,
      flowRevision: 0,
      activeLeafId,
      pendingHandleCandidate: undefined,
      generationSequence: 0,
      inputCursor: 0,
    };
    return state;
  }

  function ensureLoopState(nextSessionId: string, activeLeafId?: string): PiReducerState {
    if (!state || state.sessionId !== nextSessionId) return resetLoopState(nextSessionId, activeLeafId);
    state.activeLeafId = activeLeafId ?? state.activeLeafId;
    return state;
  }

  function clearRegistrationWarningTimer() {
    if (!registrationWarningTimer) return;
    clearTimeout(registrationWarningTimer);
    registrationWarningTimer = null;
  }

  function clearRegistrationRetryTimer() {
    if (!registrationRetryTimer) return;
    clearTimeout(registrationRetryTimer);
    registrationRetryTimer = null;
  }

  function registerSessionInBackground(ctx: ExtensionContext, sessionId: string) {
    clearRegistrationWarningTimer();
    clearRegistrationRetryTimer();
    const generation = ++registrationGeneration;
    let settled = false;
    registrationWarningTimer = setTimeout(() => {
      registrationWarningTimer = null;
      if (settled || generation !== registrationGeneration || heartbeatContext.sessionId !== sessionId) return;
      const notify = (ctx as { ui?: { notify?: (message: string, level?: string) => void } }).ui?.notify;
      notify?.(REGISTRATION_WARNING_MESSAGE, 'warning');
    }, REGISTRATION_WARNING_MS);
    registrationWarningTimer.unref?.();

    const attemptRegistration = () => {
      if (settled || generation !== registrationGeneration || heartbeatContext.sessionId !== sessionId) return;
      const currentSession = session;
      if (!currentSession || currentSession.sessionId !== sessionId) return;
      void adapter.registerSession(currentSession)
        .then(() => {
          if (generation !== registrationGeneration || heartbeatContext.sessionId !== sessionId) return;
          settled = true;
          clearRegistrationWarningTimer();
          clearRegistrationRetryTimer();
        })
        .catch((error) => {
          logExtensionEvent('session_register_failed');
          if (generation !== registrationGeneration || heartbeatContext.sessionId !== sessionId || settled) return;
          registrationRetryTimer = setTimeout(attemptRegistration, REGISTRATION_RETRY_MS);
          registrationRetryTimer.unref?.();
        });
    };
    attemptRegistration();
  }

  function clearBranchSensitiveState(loopState: PiReducerState) {
    deliverySequence += 1;
    invalidatePendingTerminal(loopState);
    loopState.latestAgentEndResult = undefined;
    loopState.terminalEmittedForCurrentLoop = false;
    loopState.pendingHandleCandidate = undefined;
    loopState.flowRevision += 1;
    loopState.loopRunning = false;
    loopState.currentRunGeneration = undefined;
    loopState.settledRunGeneration = undefined;
  }

  function beginNewLowLevelRun(loopState: PiReducerState): number {
    invalidatePendingTerminal(loopState);
    loopState.latestAgentEndResult = undefined;
    loopState.terminalEmittedForCurrentLoop = false;
    loopState.flowRevision += 1;
    loopState.generationSequence += 1;
    loopState.currentRunGeneration = loopState.generationSequence;
    loopState.settledRunGeneration = undefined;
    loopState.loopRunning = true;
    return loopState.currentRunGeneration;
  }

  pi.on('session_start', async (_event, ctx) => {
    deliverySequence += 1;
    stopHeartbeat();
    commandPoller?.stop();
    commandPoller = null;

    clearQuietTimer(state);
    const sessionId = deriveSessionId(ctx);
    activeSessionManager = ctx.sessionManager;
    session = deriveSession(ctx, sessionId);
    heartbeatContext.sessionId = sessionId;
    heartbeatContext.latestActivityText = session.latestActivityText;
    heartbeatContext.status = session.status;
    resetLoopState(sessionId, deriveActiveLeafId(ctx));

    startHeartbeat(heartbeatContext);
    commandPoller = startCommandPoller({
      sessionId,
      client: adapter,
      onCommand: (command) => handleCommand(pi, ctx, command),
    });
    registerSessionInBackground(ctx, sessionId);
  });

  pi.on('session_shutdown', async (_event, ctx) => {
    deliverySequence += 1;
    const sessionId = heartbeatContext.sessionId;
    stopHeartbeat();
    clearRegistrationWarningTimer();
    clearRegistrationRetryTimer();
    commandPoller?.stop();
    commandPoller = null;
    clearQuietTimer(state);

    if (session && state?.rootSessionActive) {
      const agentText = clampAssistantText(deriveLatestActivityText(ctx) ?? 'pi session ended');
      session = withSessionStatus(session, session.status, agentText);
      heartbeatContext.latestActivityText = session.latestActivityText;
    }
    if (sessionId) runAdapterTask(() => adapter.unregisterSession(sessionId));

    heartbeatContext.sessionId = '';
    heartbeatContext.status = 'idle';
    heartbeatContext.latestActivityText = undefined;
    session = null;
    activeSessionManager = undefined;
    registrationGeneration += 1;
    state = null;
    resetEmittedFingerprints();
  });

  pi.on('input', async (event, _ctx) => {
    if (!state) return;
    state.lastInputAt = Date.now();
    state.inputCursor += 1;
    reportPendingHandleAfterLocalInput(state);

    if (event.streamingBehavior === 'steer' || event.streamingBehavior === 'followUp') return;

    invalidatePendingTerminal(state);
    state.latestAgentEndResult = undefined;
    state.flowRevision += 1;
    state.loopRunning = false;
    state.currentRunGeneration = undefined;
    state.settledRunGeneration = undefined;
  });

  pi.on('agent_start', async (_event, ctx) => {
    const eventSessionId = heartbeatContext.sessionId;
    if (!eventSessionId || ctx.sessionManager !== activeSessionManager) return;
    session = deriveSession(ctx, eventSessionId);
    const loopState = ensureLoopState(session.sessionId, deriveActiveLeafId(ctx));
    beginNewLowLevelRun(loopState);
    await pushWorking(ctx, deriveLatestActivityText(ctx));
  });

  // Pi exposes no low-level loop identity. Consume at most one agent_end per
  // observed agent_start, but defer all terminal classification to agent_settled.
  pi.on('agent_end', async (event, ctx) => {
    const eventSessionId = heartbeatContext.sessionId;
    if (!eventSessionId || ctx.sessionManager !== activeSessionManager) return;

    session = deriveSession(ctx, eventSessionId);
    const loopState = ensureLoopState(session.sessionId, deriveActiveLeafId(ctx));
    const runGeneration = loopState.currentRunGeneration;
    if (!loopState.loopRunning || runGeneration === undefined) return;

    loopState.loopRunning = false;
    loopState.latestAgentEndResult = extractLatestAssistantEnd(event.messages, runGeneration);
    await pushWorking(ctx, loopState.latestAgentEndResult.agentText);
  });

  pi.on('agent_settled', async (_event, ctx) => {
    const eventSessionId = heartbeatContext.sessionId;
    if (!eventSessionId || ctx.sessionManager !== activeSessionManager || !state || !session) return;
    const loopState = state;
    if (loopState.sessionId !== eventSessionId || loopState.latestPendingAlert) return;
    const runGeneration = loopState.currentRunGeneration;
    if (runGeneration === undefined) return;
    if (loopState.loopRunning) {
      loopState.loopRunning = false;
      loopState.currentRunGeneration = undefined;
      loopState.latestAgentEndResult = undefined;
      return;
    }

    const result = loopState.latestAgentEndResult;
    loopState.latestAgentEndResult = undefined;
    loopState.currentRunGeneration = undefined;
    if (!result || result.runGeneration !== runGeneration) return;
    loopState.settledRunGeneration = runGeneration;
    if (!result.assistantFound || loopState.terminalEmittedForCurrentLoop) return;

    const stopReason = result.stopReason;
    if (stopReason === 'aborted') {
      loopState.terminalEmittedForCurrentLoop = true;
      session = withSessionStatus(
        session,
        'idle',
        session.latestActivityText ?? deriveLatestActivityText(ctx),
      );
      heartbeatContext.status = 'idle';
      heartbeatContext.latestActivityText = session.latestActivityText;
      try {
        await adapter.heartbeat(session.sessionId, 'idle', session.latestActivityText ?? null, session);
      } catch {
        logExtensionEvent('heartbeat_failed');
      }
      return;
    }

    if (stopReason !== undefined && stopReason !== 'stop') {
      submitErrorCandidate(ctx, result, runGeneration);
      return;
    }

    const classification = classifyStoredAssistantText(result.agentText, {
      sessionId: loopState.sessionId,
      activeLeafId: loopState.activeLeafId,
    });
    if (classification.suppressed) return;
    submitTerminalCandidate(classification, ctx, runGeneration);
  });

  pi.on('session_tree', async (event, ctx) => {
    const eventSessionId = heartbeatContext.sessionId;
    if (!eventSessionId || ctx.sessionManager !== activeSessionManager || !state) return;
    const treeEvent = event as { newLeafId?: string };
    const loopState = state;
    loopState.activeLeafId = treeEvent.newLeafId ?? deriveActiveLeafId(ctx) ?? loopState.activeLeafId;
    loopState.lastTreeSwitchAt = Date.now();
    clearBranchSensitiveState(loopState);
    const currentSession = withSessionStatus(
      deriveSession(ctx, eventSessionId), heartbeatContext.status, deriveLatestActivityText(ctx),
    );
    session = currentSession;
    heartbeatContext.latestActivityText = currentSession.latestActivityText;
    runAdapterTask(() =>
      adapter.heartbeat(
        currentSession.sessionId, currentSession.status, currentSession.latestActivityText ?? null, currentSession,
      ),
    );
  });
}

async function handleCommand(
  pi: ExtensionAPI,
  ctx: ExtensionContext,
  command: import('@ariava/protocol').CommandEnvelope,
): ReturnType<typeof executeCommand> {
  return executeCommand({ pi, ctx, command });
}
