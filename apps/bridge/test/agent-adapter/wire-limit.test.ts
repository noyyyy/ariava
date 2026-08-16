import { describe, expect, test } from 'bun:test';
import {
  buildProtectedEventContentBytes,
  buildProtectedSessionContentBytes,
} from '@ariava/protocol';
import {
  AGENT_ADAPTER_REQUEST_BODY_BYTES,
  PROTECTED_CONTENT_BYTES,
  canonicalSize,
  eventBodyAtEventLimit,
  heartbeatBodyAtSessionLimit,
  registerSessionBodyAtSessionLimit,
} from './wire-limit-fixtures';

function sessionBuilder(latestActivityText: string | undefined, extras: {
  projectName: string; nameText: string; workingDirectory: string | undefined; harnessProvider: string | undefined;
}) {
  return (openingText: string) => buildProtectedSessionContentBytes({
    version: 3 as const,
    projectName: extras.projectName,
    nameText: extras.nameText,
    openingText,
    ...(latestActivityText === undefined ? {} : { latestActivityText }),
    ...(extras.workingDirectory === undefined ? {} : { workingDirectory: extras.workingDirectory }),
    ...(extras.harnessProvider === undefined ? {} : { harnessProvider: extras.harnessProvider }),
  });
}

function eventBuilder(extras: { projectName: string; workingDirectory: string; harnessProvider: string }) {
  return (agentText: string) => buildProtectedEventContentBytes({
    version: 3 as const,
    agentText,
    projectName: extras.projectName,
    workingDirectory: extras.workingDirectory,
    harnessProvider: extras.harnessProvider,
  });
}

describe('Agent Adapter wire body upper bounds (§3.4, shared canonical serializer fixtures)', () => {
  test('register body at the session-canonical upper bound serializes ≤ 256 KiB', () => {
    const body = registerSessionBodyAtSessionLimit();
    const build = sessionBuilder(body.latestActivityText, {
      projectName: body.projectName, nameText: body.nameText,
      workingDirectory: body.cwd, harnessProvider: body.harnessProvider,
    });
    expect(canonicalSize(build, body.openingText)).toBeLessThanOrEqual(PROTECTED_CONTENT_BYTES);
    // Maximal legal: one more ASCII padding byte must exceed the content limit.
    expect(canonicalSize(build, `${body.openingText}a`)).toBeGreaterThan(PROTECTED_CONTENT_BYTES);
    expect(Buffer.byteLength(JSON.stringify(body))).toBeLessThanOrEqual(AGENT_ADAPTER_REQUEST_BODY_BYTES);
  });

  test('heartbeat body at the session-canonical upper bound serializes ≤ 256 KiB', () => {
    const body = heartbeatBodyAtSessionLimit();
    const build = sessionBuilder(body.latestActivityText, {
      projectName: body.projectName, nameText: body.nameText, workingDirectory: undefined, harnessProvider: undefined,
    });
    expect(canonicalSize(build, body.openingText)).toBeLessThanOrEqual(PROTECTED_CONTENT_BYTES);
    expect(Buffer.byteLength(JSON.stringify(body))).toBeLessThanOrEqual(AGENT_ADAPTER_REQUEST_BODY_BYTES);
  });

  test('Event body (`AgentAdapterEventInput`, no bundled Session) at the event-canonical upper bound serializes ≤ 256 KiB', () => {
    const body = eventBodyAtEventLimit();
    const build = eventBuilder({
      projectName: body.projectName, workingDirectory: body.workingDirectory, harnessProvider: body.harnessProvider,
    });
    expect(canonicalSize(build, body.agentText)).toBeLessThanOrEqual(PROTECTED_CONTENT_BYTES);
    expect(canonicalSize(build, `${body.agentText}a`)).toBeGreaterThan(PROTECTED_CONTENT_BYTES);
    // Real wire shape: canonical producer Event without Bridge-generated eventId/hostId.
    expect(body).not.toHaveProperty('eventId');
    expect(body).not.toHaveProperty('hostId');
    expect(Buffer.byteLength(JSON.stringify(body))).toBeLessThanOrEqual(AGENT_ADAPTER_REQUEST_BODY_BYTES);
  });
});
