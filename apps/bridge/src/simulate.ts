import { statusToStateLabel, type CanonicalEvent, type CanonicalSessionState, type CommandEnvelope } from '@ariava/protocol';
import { createId, isoNow } from '@ariava/shared-utils';

export type SimulationScenario = 'blocked' | 'question' | 'done';

export function buildSimulatedSession(hostId: string, scenario: SimulationScenario): CanonicalSessionState {
  const status = scenario === 'done' ? 'done' : 'blocked';
  const promptType = scenario === 'question' ? 'question' : undefined;
  const openingText = 'Fix deploy script permissions';
  let latestActivityText: string;
  switch (scenario) {
    case 'question':
      latestActivityText = 'Which environment should the rollout target?';
      break;
    case 'done':
      latestActivityText = 'Finished the requested change.';
      break;
    case 'blocked':
      latestActivityText = 'Permission denied while editing package.json.';
      break;
  }

  return {
    sessionId: 'sim-session',
    hostId,
    provider: 'pi',
    projectName: 'deploy-tools',
    nameText: 'deploy-tools',
    openingText,
    latestActivityText,
    stateLabel: statusToStateLabel(status),
    status,
    actionablePrompt: promptType
      ? {
          promptId: 'prompt-simulated',
          type: promptType,
          label: 'Reply to the pending question',
        }
      : undefined,
    updatedAt: isoNow(),
  };
}

export function buildSimulatedEvent(session: CanonicalSessionState, scenario: SimulationScenario): CanonicalEvent {
  let type: CanonicalEvent['type'];
  switch (scenario) {
    case 'question':
      type = 'question_requested';
      break;
    case 'done':
      type = 'done';
      break;
    case 'blocked':
      type = 'blocked';
      break;
  }

  let typeLabel: string;
  switch (type) {
    case 'question_requested':
      typeLabel = 'Agent question';
      break;
    case 'done':
      typeLabel = 'Task complete';
      break;
    default:
      typeLabel = 'Session blocked';
  }

  return {
    eventId: createId('evt'),
    hostId: session.hostId,
    sessionId: session.sessionId,
    provider: session.provider,
    type,
    status: session.status,
    typeLabel,
    assistantText:
      scenario === 'question'
        ? 'Which environment should the rollout target?'
        : session.latestActivityText ?? 'Agent update',
    actionablePrompt: session.actionablePrompt,
    contextText: `${session.nameText} · ${session.projectName}`,
    createdAt: session.updatedAt,
  };
}

export function buildSimulatedCommand(hostId: string, sessionId: string): CommandEnvelope {
  return {
    commandId: createId('cmd'),
    hostId,
    sessionId,
    type: 'reply',
    payload: { text: 'Use staging credentials and continue.' },
    issuedAt: isoNow(),
    expiresAt: new Date(Date.now() + 5 * 60_000).toISOString(),
    nonce: createId('nonce'),
    watchDeviceId: 'watch-simulated',
  };
}
