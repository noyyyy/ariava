import { statusToStateLabel, type CanonicalEvent, type CanonicalSessionState, type CommandEnvelope } from '@ariava/protocol';
import { createId, isoNow } from '@ariava/shared-utils';

export type SimulationScenario = 'done' | 'need_human';

export function buildSimulatedSession(hostId: string, scenario: SimulationScenario): CanonicalSessionState {
  const status = scenario === 'done' ? 'done' : 'blocked';
  const latestActivityText = scenario === 'done'
    ? 'Finished the requested change.'
    : 'Ariava needs your attention before continuing.';

  return {
    sessionId: 'sim-session',
    hostId,
    provider: 'pi',
    projectName: 'deploy-tools',
    nameText: 'deploy-tools',
    openingText: 'Fix deploy script permissions',
    latestActivityText,
    stateLabel: statusToStateLabel(status),
    status,
    updatedAt: isoNow(),
  };
}

export function buildSimulatedEvent(session: CanonicalSessionState, scenario: SimulationScenario): CanonicalEvent {
  return {
    eventId: createId('evt'),
    hostId: session.hostId,
    sessionId: session.sessionId,
    provider: session.provider,
    type: scenario,
    status: scenario === 'done' ? 'done' : 'blocked',
    typeLabel: scenario === 'done' ? 'Task complete' : 'Needs attention',
    agentText: session.latestActivityText ?? (scenario === 'done' ? 'Task complete' : 'Needs attention'),
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
