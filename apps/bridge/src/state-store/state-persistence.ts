import {
  pathHasFilesystemEvidence,
  readSecureFile,
  type SecureFileRemoveHooks,
  type SecureFileWriteHooks,
} from '../host-manager/secure-files';
import { hashBytes, isRecord } from './state-codec';

/** Sentinel used when a reset/migration source member is absent on disk. */
export const ABSENT_HASH = 'absent';

type RuntimeRecoveryPhase = 'after-unreadable-recovery';

export interface RuntimeResetHooks {
  write?: SecureFileWriteHooks;
  remove?: SecureFileRemoveHooks;
  recoveryStep?: (phase: RuntimeRecoveryPhase) => void;
}

export function readOptionalSecureBytes(path: string): Buffer | undefined {
  return pathHasFilesystemEvidence(path) ? readSecureFile(path) : undefined;
}

export function parseRawJson(bytes: Buffer | undefined, label: string): Record<string, unknown> | undefined {
  if (!bytes) return undefined;
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch (error) {
    throw new Error(`${label} JSON is malformed`, { cause: error });
  }
  if (!isRecord(parsed)) throw new Error(`${label} must be a JSON object`);
  return parsed;
}

export function isRuntimeResetHooks(value: SecureFileWriteHooks | RuntimeResetHooks | undefined): value is RuntimeResetHooks {
  return value !== undefined && ('write' in value || 'remove' in value || 'recoveryStep' in value);
}

export function serializeSecureJson(value: unknown): Buffer { return Buffer.from(`${JSON.stringify(value, null, 2)}\n`); }
export function hashOptional(bytes: Uint8Array | undefined): string { return bytes ? hashBytes(bytes) : ABSENT_HASH; }
export function isRuntimeHash(value: unknown): boolean {
  return value === ABSENT_HASH || (typeof value === 'string' && /^[A-Za-z0-9_-]{43}$/u.test(value));
}
