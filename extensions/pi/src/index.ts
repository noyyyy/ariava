import type { ExtensionAPI, ExtensionContext } from '@earendil-works/pi-coding-agent';
import { AgentAdapterClient } from './adapter';
import type { AgentAdapter } from './adapter-interface';
import { executeCommand } from './commands';
import { buildBlockedEvent, buildDoneEvent, buildQuestionEvent, buildWorkingEvent } from './events';
import { startHeartbeat, stopHeartbeat, type HeartbeatContext } from './heartbeat';
import {
  classifyAgentEnd,
  extractBlockedReason,
  markFingerprintEmitted,
  resetEmittedFingerprints,
} from './question-detector';
import { startCommandPoller, type CommandPollerHandle } from './poller';
import { logExtensionError } from './logger';
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

function previewInputText(value: string, maxLength = 120): string {
  const normalized = value.replace(/\s+/g, ' ').trim();
  if (normalized.length <= maxLength) return normalized;
  return `${normalized.slice(0, Math.max(1, maxLength - 1)).trimEnd()}…`;
}

function deriveAgentEndActivityText(ctx: ExtensionContext, messages: unknown[] | undefined): string | undefined {
  const latestError = Array.isArray(messages)
    ? [...messages].reverse().find((message): message is { errorMessage: string } =>
      typeof message === 'object' &&
      message !== null &&
      typeof (message as { errorMessage?: unknown }).errorMessage === 'string' &&
      (message as { errorMessage: string }).errorMessage.trim().length > 0,
    )?.errorMessage.trim()
    : undefined;
  return latestError ?? deriveLatestActivityText(ctx, { eventMessages: messages as import('@earendil-works/pi-agent-core').AgentMessage[] | undefined });
}

const DEFAULT_RECOVERY_HOLD_MS = 60_000;
const REGISTRATION_WARNING_MS = 5_000;
const REGISTRATION_WARNING_MESSAGE =
  'Ariava bridge did not register this pi session within 5s. Watch integration may be unavailable; check the local bridge on 127.0.0.1:7272.';
const REGISTRATION_RETRY_MS = 1_000;
const TERMINAL_ALERT_QUIET_WINDOW_MS = 1_500;

type PendingTerminalAlert = {
  type: 'done' | 'blocked' | 'question_requested';
  assistantText: string;
  fingerprint?: string;
  userMessageText?: string;
  createdAt: string;
};

type RecoveryHoldReason = 'agent_error' | 'length' | 'context_overflow' | 'system_abort' | 'auto_compact';

type RecoveryHold = {
  reason: RecoveryHoldReason;
  assistantText: string;
  userMessageText?: string;
  startedAt: number;
  expiresAt: number;
  timer: ReturnType<typeof setTimeout>;
};

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
  retryHoldUntil: number | null;
  retryHoldAssistantText?: string;
  blockedReason?: string;
  latestPendingAlert?: PendingTerminalAlert;
  pendingHandleCandidate?: PendingHandleCandidate;
  quietTimer?: ReturnType<typeof setTimeout>;
  recoveryHold?: RecoveryHold;
  lastInputAt?: number;
  lastAgentLoopEndedAt?: number;
  activeLeafId?: string;
  lastTreeSwitchAt?: number;
};

export default function ariavaPiExtension(pi: ExtensionAPI, testAdapter?: AgentAdapter) {
  let session: ReturnType<typeof deriveSession> | null = null;
  const adapter: AgentAdapter = testAdapter ?? new AgentAdapterClient();
  let commandPoller: CommandPollerHandle | null = null;
  let state: PiReducerState | null = null;
  let registrationWarningTimer: ReturnType<typeof setTimeout> | null = null;
  let registrationRetryTimer: ReturnType<typeof setTimeout> | null = null;

  const heartbeatContext: HeartbeatContext = {
    sessionId: '',
    client: adapter,
    status: 'unknown',
    latestActivityText: undefined,
  };

  function runAdapterTask(label: string, task: () => Promise<unknown>): void {
    void task().catch((error) => logExtensionError(label, error));
  }

  function reportPendingHandleAfterLocalInput(loopState: PiReducerState): void {
    const candidate = loopState.pendingHandleCandidate;
    if (!candidate || candidate.reported || !loopState.lastInputAt) return;
    if (loopState.lastInputAt <= candidate.observedUserInputCursor) return;

    candidate.reported = true;
    runAdapterTask('handle session from local input', async () => {
      try {
        await adapter.handleSession(candidate.sessionId, {
          handledThroughEventId: candidate.eventId,
          handledThroughEventCreatedAt: candidate.eventCreatedAt,
          handledAt: new Date(loopState.lastInputAt ?? Date.now()).toISOString(),
          action: 'pi_input',
        });
        if (state?.pendingHandleCandidate?.eventId === candidate.eventId) {
          state.pendingHandleCandidate = undefined;
        }
      } catch (error) {
        candidate.reported = false;
        throw error;
      }
    });
  }

  async function pushWorking(ctx: ExtensionContext, assistantText?: string) {
    if (!session || !state?.rootSessionActive) return;
    const latestActivityText = normalizeAssistantTextForEvent('working', session, assistantText ?? deriveLatestActivityText(ctx));
    session = withSessionStatus(session, 'working', latestActivityText);
    heartbeatContext.status = 'working';
    heartbeatContext.latestActivityText = session.latestActivityText;
    runAdapterTask('push working event', () => adapter.pushEvent(buildWorkingEvent(session!, latestActivityText)));
  }

  function runtimeHasPendingMessages(ctx: ExtensionContext): boolean {
    const runtime = ctx as ExtensionContext & { isIdle?: () => boolean; hasPendingMessages?: () => boolean };
    return runtime.isIdle?.() === false || runtime.hasPendingMessages?.() === true;
  }


  function extractLatestAssistantEnd(event: { messages?: import('@earendil-works/pi-agent-core').AgentMessage[] }): { stopReason?: string; assistantText?: string; errorText?: string } {
    const messages = event.messages ?? [];
    for (let index = messages.length - 1; index >= 0; index -= 1) {
      const message = messages[index] as { role?: string; stopReason?: unknown; content?: unknown; errorMessage?: unknown; error?: unknown } | undefined;
      if (message?.role !== 'assistant') continue;
      return {
        stopReason: typeof message.stopReason === 'string' ? message.stopReason : undefined,
        assistantText: extractTextContent(message.content),
        errorText: stringifyErrorLike(message.errorMessage) ?? stringifyErrorLike(message.error),
      };
    }
    return {};
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

  function stringifyErrorLike(value: unknown): string | undefined {
    if (typeof value === 'string' && value.trim()) return value.trim();
    if (value instanceof Error && value.message.trim()) return value.message.trim();
    if (typeof value !== 'object' || value === null) return undefined;
    const record = value as { message?: unknown; type?: unknown; code?: unknown; error?: unknown };
    return [record.type, record.code, record.message, record.error]
      .map((part) => typeof part === 'string' ? part.trim() : undefined)
      .filter((part): part is string => Boolean(part))
      .join(': ') || undefined;
  }

  function getRecoveryHoldMs(): number {
    const configured = Number(process.env.ARIAVA_PI_RECOVERY_HOLD_MS);
    return Number.isFinite(configured) && configured > 0 ? configured : DEFAULT_RECOVERY_HOLD_MS;
  }

  async function emitTerminalAlert(alert: PendingTerminalAlert) {
    if (!session || !state?.rootSessionActive) return;

    const normalizedAssistant = normalizeAssistantTextForEvent(alert.type, session, alert.assistantText);
    const sessionStatus = alert.type === 'done' ? 'done' : 'blocked';
    session = withSessionStatus(session, sessionStatus, normalizedAssistant);
    heartbeatContext.status = sessionStatus;
    heartbeatContext.latestActivityText = session.latestActivityText;

    const event = (() => {
      switch (alert.type) {
        case 'done':
          return buildDoneEvent(session!, normalizedAssistant, alert.userMessageText);
        case 'blocked':
          return buildBlockedEvent(session!, normalizedAssistant, alert.userMessageText);
        case 'question_requested':
          return buildQuestionEvent(session!, normalizedAssistant, alert.userMessageText);
      }
    })();

    state.terminalEmittedForCurrentLoop = true;
    state.latestPendingAlert = undefined;
    if (alert.fingerprint) {
      markFingerprintEmitted(alert.fingerprint);
    }

    runAdapterTask(`push ${alert.type} event`, async () => {
      const pushed = await adapter.pushEvent(event);
      if (!state || state.sessionId !== event.sessionId) return;
      state.pendingHandleCandidate = {
        sessionId: event.sessionId,
        eventId: pushed.eventId,
        eventCreatedAt: event.createdAt ?? new Date().toISOString(),
        observedUserInputCursor: state.lastInputAt ?? 0,
        reported: false,
      };
    });
  }

  function clearQuietTimer(loopState: PiReducerState | null = state) {
    if (loopState?.quietTimer) {
      clearTimeout(loopState.quietTimer);
      loopState.quietTimer = undefined;
    }
  }

  function schedulePendingTerminal(ctx: ExtensionContext) {
    if (!state) return;
    clearQuietTimer(state);
    const scheduledSessionId = state.sessionId;
    state.quietTimer = setTimeout(() => {
      void flushPendingTerminalIfStable(ctx, scheduledSessionId);
    }, TERMINAL_ALERT_QUIET_WINDOW_MS);
    state.quietTimer.unref?.();
  }

  async function flushPendingTerminalIfStable(ctx: ExtensionContext, scheduledSessionId: string) {
    if (!state || state.sessionId !== scheduledSessionId || !state.latestPendingAlert || state.loopRunning) return;
    if (runtimeHasPendingMessages(ctx)) {
      schedulePendingTerminal(ctx);
      return;
    }
    const alert = state.latestPendingAlert;
    clearQuietTimer(state);
    await emitTerminalAlert(alert);
  }

  async function pushTerminal(type: 'done' | 'blocked' | 'question_requested', ctx: ExtensionContext, assistantText?: string, fingerprint?: string) {
    if (!session || !state?.rootSessionActive || state.terminalEmittedForCurrentLoop) return;

    const normalizedAssistant = normalizeAssistantTextForEvent(type, session, assistantText ?? deriveLatestActivityText(ctx));
    const sessionStatus = type === 'done' ? 'done' : 'blocked';
    session = withSessionStatus(session, sessionStatus, normalizedAssistant);
    heartbeatContext.status = sessionStatus;
    heartbeatContext.latestActivityText = session.latestActivityText;
    state.latestPendingAlert = {
      type,
      assistantText: normalizedAssistant,
      userMessageText: deriveMessageTexts(ctx).latestUserText,
      fingerprint,
      createdAt: new Date().toISOString(),
    };
    state.lastAgentLoopEndedAt = Date.now();
    schedulePendingTerminal(ctx);
  }

  async function emitBlockedAlertNow(assistantText: string, userMessageText?: string): Promise<void> {
    if (!session || !state?.rootSessionActive || state.terminalEmittedForCurrentLoop) return;
    await emitTerminalAlert({
      type: 'blocked',
      assistantText,
      userMessageText,
      createdAt: new Date().toISOString(),
    });
  }

  function clearRecoveryHold(loopState: PiReducerState | null = state): void {
    if (loopState?.recoveryHold?.timer) {
      clearTimeout(loopState.recoveryHold.timer);
    }
    if (loopState) {
      loopState.recoveryHold = undefined;
    }
  }

  function enterRecoveryHold(reason: RecoveryHoldReason, ctx: ExtensionContext, assistantText: string): void {
    if (!state || !session || !state.rootSessionActive) return;
    clearRecoveryHold(state);
    clearQuietTimer(state);
    state.latestPendingAlert = undefined;
    const startedAt = Date.now();
    const holdMs = getRecoveryHoldMs();
    const scheduledSessionId = state.sessionId;
    const userMessageText = deriveMessageTexts(ctx).latestUserText;
    const normalizedAssistant = normalizeAssistantTextForEvent('working', session, assistantText);
    const timer = setTimeout(() => {
      void emitRecoveryHoldBlockedIfCurrent(scheduledSessionId, startedAt);
    }, holdMs);
    timer.unref?.();
    state.recoveryHold = {
      reason,
      assistantText: normalizedAssistant,
      userMessageText,
      startedAt,
      expiresAt: startedAt + holdMs,
      timer,
    };
    void pushWorking(ctx, normalizedAssistant);
  }

  async function emitRecoveryHoldBlockedIfCurrent(scheduledSessionId: string, startedAt: number): Promise<void> {
    if (!state || state.sessionId !== scheduledSessionId || state.loopRunning || !state.recoveryHold) return;
    if (state.recoveryHold.startedAt !== startedAt) return;
    const { assistantText, userMessageText } = state.recoveryHold;
    clearRecoveryHold(state);
    await emitBlockedAlertNow(assistantText, userMessageText);
  }

  function resetLoopState(nextSessionId: string, activeLeafId?: string): PiReducerState {
    state = {
      sessionId: nextSessionId,
      rootSessionActive: true,
      loopRunning: false,
      terminalEmittedForCurrentLoop: false,
      retryHoldUntil: null,
      retryHoldAssistantText: undefined,
      blockedReason: undefined,
      latestPendingAlert: undefined,
      quietTimer: undefined,
      activeLeafId,
      recoveryHold: undefined,
      pendingHandleCandidate: undefined,
    };
    return state;
  }

  function ensureLoopState(nextSessionId: string, activeLeafId?: string): PiReducerState {
    if (!state || state.sessionId !== nextSessionId) {
      return resetLoopState(nextSessionId, activeLeafId);
    }
    state.activeLeafId = activeLeafId ?? state.activeLeafId;
    return state;
  }

  function clearRegistrationWarningTimer() {
    if (registrationWarningTimer) {
      clearTimeout(registrationWarningTimer);
      registrationWarningTimer = null;
    }
  }

  function clearRegistrationRetryTimer() {
    if (registrationRetryTimer) {
      clearTimeout(registrationRetryTimer);
      registrationRetryTimer = null;
    }
  }

  function registerSessionInBackground(ctx: ExtensionContext, sessionInfo: NonNullable<typeof session>) {
    clearRegistrationWarningTimer();
    clearRegistrationRetryTimer();
    let settled = false;
    registrationWarningTimer = setTimeout(() => {
      registrationWarningTimer = null;
      if (settled || heartbeatContext.sessionId !== sessionInfo.sessionId) return;
      const notify = (ctx as { ui?: { notify?: (message: string, level?: string) => void } }).ui?.notify;
      notify?.(REGISTRATION_WARNING_MESSAGE, 'warning');
    }, REGISTRATION_WARNING_MS);
    registrationWarningTimer.unref?.();

    const attemptRegistration = () => {
      void adapter.registerSession(sessionInfo)
        .then(() => {
          if (heartbeatContext.sessionId !== sessionInfo.sessionId) return;
          settled = true;
          clearRegistrationWarningTimer();
          clearRegistrationRetryTimer();
        })
        .catch((error) => {
          logExtensionError('register session', error);
          if (heartbeatContext.sessionId !== sessionInfo.sessionId || settled) return;
          registrationRetryTimer = setTimeout(attemptRegistration, REGISTRATION_RETRY_MS);
          registrationRetryTimer.unref?.();
        });
    };

    attemptRegistration();
  }

  function clearBranchSensitiveState(loopState: PiReducerState) {
    clearQuietTimer(loopState);
    loopState.terminalEmittedForCurrentLoop = false;
    loopState.latestPendingAlert = undefined;
    loopState.pendingHandleCandidate = undefined;
    loopState.retryHoldUntil = null;
    loopState.retryHoldAssistantText = undefined;
    loopState.blockedReason = undefined;
    clearRecoveryHold(loopState);
  }

  function refreshActiveLeaf(ctx: ExtensionContext): string | undefined {
    const activeLeafId = deriveActiveLeafId(ctx);
    if (state) {
      state.activeLeafId = activeLeafId ?? state.activeLeafId;
    }
    return state?.activeLeafId ?? activeLeafId;
  }

  pi.on('session_start', async (_event, ctx) => {
    stopHeartbeat();
    commandPoller?.stop();
    commandPoller = null;

    session = deriveSession(ctx);
    const sessionId = deriveSessionId(ctx);
    heartbeatContext.sessionId = sessionId;
    heartbeatContext.latestActivityText = session.latestActivityText;
    heartbeatContext.status = 'unknown';
    resetLoopState(sessionId, deriveActiveLeafId(ctx));

    startHeartbeat(heartbeatContext);
    commandPoller = startCommandPoller({
      sessionId,
      client: adapter,
      onCommand: (command) => handleCommand(pi, ctx, command, adapter),
    });
    registerSessionInBackground(ctx, session);
  });

  pi.on('session_shutdown', async (_event, ctx) => {
    const sessionId = heartbeatContext.sessionId;
    stopHeartbeat();
    clearRegistrationWarningTimer();
    clearRegistrationRetryTimer();
    commandPoller?.stop();
    commandPoller = null;
    clearQuietTimer(state);
    clearRecoveryHold(state);

    if (session && state?.rootSessionActive) {
      const assistantText = clampAssistantText(deriveLatestActivityText(ctx) ?? 'pi session ended');
      session = withSessionStatus(session, session.status, assistantText);
      heartbeatContext.latestActivityText = session.latestActivityText;
    }

    if (sessionId) {
      runAdapterTask('unregister session', () => adapter.unregisterSession(sessionId));
    }

    heartbeatContext.sessionId = '';
    heartbeatContext.status = 'unknown';
    heartbeatContext.latestActivityText = undefined;
    session = null;
    state = null;
    resetEmittedFingerprints();
  });

  pi.on('input', async (_event, _ctx) => {
    if (!state) return;
    state.lastInputAt = Date.now();
    clearQuietTimer(state);
    reportPendingHandleAfterLocalInput(state);
  });

  pi.on('agent_start', async (_event, ctx) => {
    session = deriveSession(ctx);
    const loopState = ensureLoopState(session.sessionId, deriveActiveLeafId(ctx));
    loopState.loopRunning = true;
    clearBranchSensitiveState(loopState);
    await pushWorking(ctx, deriveLatestActivityText(ctx));
  });

  pi.on('agent_end', async (event, ctx) => {
    const eventSessionId = deriveSessionId(ctx);
    if (!heartbeatContext.sessionId || eventSessionId !== heartbeatContext.sessionId) {
      return;
    }

    const agentEndEvent = event as { messages?: import('@earendil-works/pi-agent-core').AgentMessage[] };
    session = deriveSession(ctx);
    const loopState = ensureLoopState(session.sessionId, deriveActiveLeafId(ctx));

    loopState.loopRunning = false;
    const activeLeafId = refreshActiveLeaf(ctx);
    const latestActivityText = deriveAgentEndActivityText(ctx, agentEndEvent.messages);
    const latestAssistant = extractLatestAssistantEnd(agentEndEvent);
    const stopReason = latestAssistant.stopReason;
    const stopReasonText = latestAssistant.errorText ?? latestActivityText ?? latestAssistant.assistantText;

    if (stopReason === 'error') {
      enterRecoveryHold('agent_error', ctx, stopReasonText ?? 'Agent error needs attention');
      return;
    }

    if (stopReason === 'length') {
      enterRecoveryHold('length', ctx, stopReasonText ?? 'Agent output was truncated');
      return;
    }

    if (stopReason === 'toolUse') {
      clearRecoveryHold(loopState);
      await pushTerminal('blocked', ctx, stopReasonText ?? 'Agent stopped while waiting to use a tool');
      return;
    }

    if (stopReason === 'aborted') {
      clearRecoveryHold(loopState);
      return;
    }

    const classification = classifyAgentEnd(ctx, {
      sessionId: session.sessionId,
      activeLeafId,
      messages: agentEndEvent.messages,
    });

    if (classification.type === 'suppress_duplicate') {
      return;
    }

    clearRecoveryHold(loopState);

    if (classification.type === 'question_requested') {
      loopState.retryHoldUntil = null;
      loopState.retryHoldAssistantText = undefined;
      loopState.blockedReason = undefined;
      await pushTerminal('question_requested', ctx, classification.assistantText, classification.fingerprint);
      return;
    }

    const explicitBlockedReason = classification.type === 'blocked'
      ? classification.blockedReason
      : extractBlockedReason(latestActivityText ?? '');
    if (explicitBlockedReason) {
      loopState.retryHoldUntil = null;
      loopState.retryHoldAssistantText = undefined;
      loopState.blockedReason = explicitBlockedReason;
      await pushTerminal('blocked', ctx, explicitBlockedReason, classification.fingerprint);
      return;
    }

    loopState.retryHoldUntil = null;
    loopState.retryHoldAssistantText = undefined;
    loopState.blockedReason = undefined;
    await pushTerminal('done', ctx, classification.assistantText || latestActivityText || 'Task complete', classification.fingerprint);
  });

  pi.on('session_tree', async (event, ctx) => {
    const treeEvent = event as { newLeafId?: string };
    const sessionId = session?.sessionId ?? deriveSessionId(ctx);
    const loopState = ensureLoopState(sessionId, treeEvent.newLeafId ?? deriveActiveLeafId(ctx));
    loopState.activeLeafId = treeEvent.newLeafId ?? deriveActiveLeafId(ctx) ?? loopState.activeLeafId;
    loopState.lastTreeSwitchAt = Date.now();
    clearBranchSensitiveState(loopState);
  });
}

async function handleCommand(
  pi: ExtensionAPI,
  ctx: ExtensionContext,
  command: import('@ariava/protocol').CommandEnvelope,
  adapter: AgentAdapter,
): Promise<void> {
  const result = await executeCommand({ pi, ctx, command, adapter });
  void adapter.submitResult(command.commandId, result)
    .catch((error) => logExtensionError('submit command result', error));
}
