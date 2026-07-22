import type { ExtensionAPI, ExtensionContext } from '@earendil-works/pi-coding-agent';
import type { AgentMessage } from '@earendil-works/pi-agent-core';
import { AgentAdapterClient } from './adapter';
import type { AgentAdapter } from './adapter-interface';
import { executeCommand } from './commands';
import { buildBlockedEvent, buildDoneEvent, buildQuestionEvent, buildWorkingEvent } from './events';
import { startHeartbeat, stopHeartbeat, type HeartbeatContext } from './heartbeat';
import {
  classifyStoredAssistantText,
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

const REGISTRATION_WARNING_MS = 5_000;
const REGISTRATION_WARNING_MESSAGE =
  'Ariava bridge did not register this pi session within 5s. Check that the selected local bridge profile is running and its Agent Adapter discovery file is available.';
const REGISTRATION_RETRY_MS = 1_000;
const TERMINAL_ALERT_QUIET_WINDOW_MS = 1_500;
const UNKNOWN_STOP_REASON_MAX_LENGTH = 80;
const ERROR_PREVIEW_MAX_LENGTH = 240;

type LatestAgentEndResult = {
  assistantFound: boolean;
  stopReason?: string;
  assistantText?: string;
  errorText?: string;
};

type PendingTerminalAlert = {
  type: 'done' | 'blocked' | 'question_requested';
  assistantText: string;
  fingerprint?: string;
  userMessageText?: string;
  createdAt: string;
  flowRevision: number;
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
  flowRevision: number;
  latestAgentEndResult?: LatestAgentEndResult;
  latestPendingAlert?: PendingTerminalAlert;
  pendingHandleCandidate?: PendingHandleCandidate;
  quietTimer?: ReturnType<typeof setTimeout>;
  lastInputAt?: number;
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

  function runtimeHasNewWork(ctx: ExtensionContext): boolean {
    return ctx.isIdle() === false || ctx.hasPendingMessages() === true;
  }

  function extractLatestAssistantEnd(messages: AgentMessage[] | undefined): LatestAgentEndResult {
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
        assistantText: extractTextContent(message.content),
        errorText: stringifyErrorLike(message.errorMessage) ?? stringifyErrorLike(message.error),
      };
    }
    return { assistantFound: false };
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

  function sanitizeDisplayText(value: string | undefined, maxLength: number): string | undefined {
    const normalized = value
      ?.replace(/[\u0000-\u001F\u007F-\u009F]/g, ' ')
      .replace(/\p{Cf}/gu, '')
      .replace(/\s+/g, ' ')
      .trim();
    if (!normalized) return undefined;
    if (normalized.length <= maxLength) return normalized;
    return `${normalized.slice(0, Math.max(1, maxLength - 1)).trimEnd()}…`;
  }

  function unsupportedReasonPreview(reason: string): string {
    const sanitized = sanitizeDisplayText(reason, UNKNOWN_STOP_REASON_MAX_LENGTH);
    return sanitized
      ? `Pi stopped for an unsupported reason: ${sanitized}.`
      : 'Pi stopped for an unsupported reason.';
  }

  async function emitTerminalAlert(alert: PendingTerminalAlert) {
    if (!session || !state?.rootSessionActive || state.flowRevision !== alert.flowRevision) return;

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
    if (alert.fingerprint) markFingerprintEmitted(alert.fingerprint);

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
    if (!loopState?.quietTimer) return;
    clearTimeout(loopState.quietTimer);
    loopState.quietTimer = undefined;
  }

  function invalidatePendingTerminal(loopState: PiReducerState): void {
    clearQuietTimer(loopState);
    loopState.latestPendingAlert = undefined;
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
    type: 'done' | 'blocked' | 'question_requested',
    ctx: ExtensionContext,
    assistantText: string,
    fingerprint?: string,
  ) {
    if (!session || !state?.rootSessionActive || state.terminalEmittedForCurrentLoop || state.latestPendingAlert) return;
    state.latestPendingAlert = {
      type,
      assistantText: normalizeAssistantTextForEvent(type, session, assistantText),
      userMessageText: deriveMessageTexts(ctx).latestUserText,
      fingerprint,
      createdAt: new Date().toISOString(),
      flowRevision: state.flowRevision,
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
    invalidatePendingTerminal(loopState);
    loopState.latestAgentEndResult = undefined;
    loopState.terminalEmittedForCurrentLoop = false;
    loopState.pendingHandleCandidate = undefined;
    loopState.flowRevision += 1;
  }

  function beginNewLowLevelRun(loopState: PiReducerState) {
    invalidatePendingTerminal(loopState);
    loopState.latestAgentEndResult = undefined;
    loopState.terminalEmittedForCurrentLoop = false;
    loopState.flowRevision += 1;
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

    if (session && state?.rootSessionActive) {
      const assistantText = clampAssistantText(deriveLatestActivityText(ctx) ?? 'pi session ended');
      session = withSessionStatus(session, session.status, assistantText);
      heartbeatContext.latestActivityText = session.latestActivityText;
    }
    if (sessionId) runAdapterTask('unregister session', () => adapter.unregisterSession(sessionId));

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
    invalidatePendingTerminal(state);
    state.latestAgentEndResult = undefined;
    state.flowRevision += 1;
    reportPendingHandleAfterLocalInput(state);
  });

  pi.on('agent_start', async (_event, ctx) => {
    const eventSessionId = deriveSessionId(ctx);
    if (!heartbeatContext.sessionId || eventSessionId !== heartbeatContext.sessionId) return;
    session = deriveSession(ctx);
    const loopState = ensureLoopState(session.sessionId, deriveActiveLeafId(ctx));
    beginNewLowLevelRun(loopState);
    loopState.loopRunning = true;
    await pushWorking(ctx, deriveLatestActivityText(ctx));
  });

  pi.on('agent_end', async (event, ctx) => {
    const eventSessionId = deriveSessionId(ctx);
    if (!heartbeatContext.sessionId || eventSessionId !== heartbeatContext.sessionId) return;

    session = deriveSession(ctx);
    const loopState = ensureLoopState(session.sessionId, deriveActiveLeafId(ctx));
    loopState.loopRunning = false;
    loopState.latestAgentEndResult = extractLatestAssistantEnd(event.messages);
    await pushWorking(ctx, loopState.latestAgentEndResult.errorText ?? loopState.latestAgentEndResult.assistantText);
  });

  pi.on('agent_settled', async (_event, ctx) => {
    const eventSessionId = deriveSessionId(ctx);
    if (!heartbeatContext.sessionId || eventSessionId !== heartbeatContext.sessionId || !state) return;
    const loopState = state;
    if (loopState.sessionId !== eventSessionId || loopState.loopRunning || loopState.latestPendingAlert) return;

    const result = loopState.latestAgentEndResult;
    loopState.latestAgentEndResult = undefined;
    if (!result?.assistantFound || loopState.terminalEmittedForCurrentLoop) return;

    const stopReason = result.stopReason;
    if (stopReason === 'aborted') return;

    if (stopReason === 'error') {
      submitTerminalCandidate(
        'blocked',
        ctx,
        sanitizeDisplayText(result.errorText, ERROR_PREVIEW_MAX_LENGTH) ?? 'Pi stopped after an unrecovered error.',
      );
      return;
    }
    if (stopReason === 'length') {
      submitTerminalCandidate('blocked', ctx, 'Pi stopped after reaching the response length limit.');
      return;
    }
    if (stopReason === 'toolUse') {
      submitTerminalCandidate('blocked', ctx, 'Pi stopped while waiting to use a tool.');
      return;
    }
    if (stopReason !== undefined && stopReason !== 'stop') {
      submitTerminalCandidate('blocked', ctx, unsupportedReasonPreview(stopReason));
      return;
    }

    const classification = classifyStoredAssistantText(result.assistantText, {
      sessionId: loopState.sessionId,
      activeLeafId: loopState.activeLeafId,
    });
    if (classification.type === 'suppress_duplicate') return;
    submitTerminalCandidate(classification.type, ctx, classification.assistantText, classification.fingerprint);
  });

  pi.on('session_tree', async (event, ctx) => {
    const eventSessionId = deriveSessionId(ctx);
    if (!heartbeatContext.sessionId || eventSessionId !== heartbeatContext.sessionId || !state) return;
    const treeEvent = event as { newLeafId?: string };
    const loopState = state;
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
