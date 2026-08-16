import {
  buildProtectedEventContentBytes,
  buildProtectedSessionContentBytes,
  ProtectedContentValidationError,
} from '@ariava/protocol';

/** Agent Adapter v3 request-body cap (§3.4). */
export const AGENT_ADAPTER_REQUEST_BODY_BYTES = 256 * 1024;

/** Session/Event protected-content plaintext cap (§3.1). */
export const PROTECTED_CONTENT_BYTES = 64 * 1024;

/**
 * Canonical protected-content size, or positive infinity when the builder
 * rejects the content as over the limit (builders throw, they never return
 * oversized bytes).
 */
export function canonicalSize(build: (padding: string) => Uint8Array, padding: string): number {
  try {
    return build(padding).byteLength;
  } catch (error) {
    if (error instanceof ProtectedContentValidationError) return Number.POSITIVE_INFINITY;
    throw error;
  }
}

/**
 * Largest ASCII padding such that the canonical protected content stays within
 * the 64 KiB limit. The builders are the real shared exact canonical encoders,
 * so the measured upper bound is the same bound the adapter/E2E preflight uses.
 */
function maxPadding(build: (padding: string) => Uint8Array): string {
  let low = 0;
  let high = PROTECTED_CONTENT_BYTES;
  let best = '';
  while (low <= high) {
    const mid = (low + high) >> 1;
    const candidate = 'a'.repeat(mid);
    if (canonicalSize(build, candidate) <= PROTECTED_CONTENT_BYTES) {
      best = candidate;
      low = mid + 1;
    } else {
      high = mid - 1;
    }
  }
  return best;
}


const IDENTIFIER_256 = 'i'.repeat(256);

function sessionCanonical(openingText: string, latestActivityText: string | undefined, extras: {
  projectName: string; nameText: string; workingDirectory: string; harnessProvider: string;
}): Uint8Array {
  return buildProtectedSessionContentBytes({
    version: 3 as const,
    projectName: extras.projectName,
    nameText: extras.nameText,
    openingText,
    ...(latestActivityText === undefined ? {} : { latestActivityText }),
    workingDirectory: extras.workingDirectory,
    harnessProvider: extras.harnessProvider,
  });
}

/**
 * Real register wire body (`RegisterSessionInput`) at the session-canonical
 * upper bound: identifiers at 256 B and openingText padded so the mapped
 * `ProtectedSessionContentV3` canonical bytes are the maximum legal size.
 */
export function registerSessionBodyAtSessionLimit() {
  const base = {
    sessionId: IDENTIFIER_256,
    provider: IDENTIFIER_256,
    projectName: IDENTIFIER_256,
    cwd: IDENTIFIER_256,
    nameText: IDENTIFIER_256,
    harnessProvider: IDENTIFIER_256,
    pid: 1234,
    status: 'working',
  };
  const openingText = maxPadding((padding) => sessionCanonical(padding, undefined, {
    projectName: base.projectName, nameText: base.nameText,
    workingDirectory: base.cwd, harnessProvider: base.harnessProvider,
  }));
  return { ...base, openingText };
}

/** Real heartbeat wire body at the session-canonical upper bound. */
export function heartbeatBodyAtSessionLimit() {
  const base = { status: 'working', projectName: IDENTIFIER_256, nameText: IDENTIFIER_256 };
  const openingText = maxPadding((padding) => sessionCanonical(padding, undefined, {
    projectName: base.projectName, nameText: base.nameText, workingDirectory: undefined, harnessProvider: undefined,
  }));
  return { status: base.status, openingText, projectName: base.projectName, nameText: base.nameText };
}

/** Real Event wire body (`AgentAdapterEventInput`, no eventId/hostId) at the event-canonical upper bound. */
export function eventBodyAtEventLimit() {
  const base = {
    sessionId: IDENTIFIER_256,
    provider: IDENTIFIER_256,
    type: 'done',
    status: 'idle',
    projectName: IDENTIFIER_256,
    workingDirectory: IDENTIFIER_256,
    harnessProvider: IDENTIFIER_256,
    createdAt: '2026-08-07T00:00:01.000Z',
  };
  const agentText = maxPadding((padding) => buildProtectedEventContentBytes({
    version: 3 as const,
    agentText: padding,
    projectName: base.projectName,
    workingDirectory: base.workingDirectory,
    harnessProvider: base.harnessProvider,
  }));
  return { ...base, agentText };
}
