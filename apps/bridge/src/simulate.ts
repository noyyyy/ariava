import type { CanonicalEvent, CanonicalSessionState, CommandEnvelope, NeedHumanContext } from '@ariava/protocol';
import { createId, isoNow } from '@ariava/shared-utils';

export type SimulationScenario = 'blocked' | 'question' | 'done';

export function buildSimulatedSession(hostId: string, scenario: SimulationScenario): CanonicalSessionState {
  const status = scenario === 'done' ? 'idle' : 'need_human';
  const updatedAt = isoNow();
  const lastEventId = createId('evt');
  const latestActivityText = scenario === 'question'
    ? 'Which environment should the rollout target?'
    : scenario === 'done' ? 'Finished the requested change.' : 'Permission denied while editing package.json.';
  return {
    sessionId: 'sim-session', hostId, provider: 'pi', projectName: 'deploy-tools', nameText: 'deploy-tools',
    openingText: 'Fix deploy script permissions', latestActivityText, workingDirectory: '/tmp/deploy-tools',
    harnessProvider: 'pi', status,
    updatedAt, lastEventId,
  };
}

export function buildSimulatedEvent(session: CanonicalSessionState, scenario: SimulationScenario): CanonicalEvent {
  const base = {
    eventId: session.lastEventId!, hostId: session.hostId, sessionId: session.sessionId, provider: session.provider,
    agentText: scenario === 'question' ? 'Which environment should the rollout target?' : session.latestActivityText ?? 'Agent update',
    projectName: session.projectName, workingDirectory: session.workingDirectory,
    harnessProvider: session.harnessProvider, createdAt: session.updatedAt,
  };
  if (scenario === 'done') return { ...base, type: 'done', status: 'idle' };
  const needHuman: NeedHumanContext = { reason: scenario === 'question' ? 'question' : 'blocked' };
  return { ...base, type: 'need_human', status: 'need_human', needHuman };
}

export function buildSimulatedCommand(hostId: string, sessionId: string): CommandEnvelope {
  return { commandId: createId('cmd'), hostId, sessionId, type: 'reply', payload: { text: 'Use staging credentials and continue.' },
    issuedAt: isoNow(), expiresAt: new Date(Date.now() + 5 * 60_000).toISOString(), nonce: createId('nonce'), watchDeviceId: 'watch-simulated' };
}
