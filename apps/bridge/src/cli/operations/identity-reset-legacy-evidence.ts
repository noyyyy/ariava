import { createHash } from 'node:crypto';
import { base64UrlDecode, base64UrlEncode } from '@ariava/protocol';
import { pathHasFilesystemEvidence, readSecureJson, SecureFileError } from '../../host-manager/secure-files';
import { HostIdentityError } from '../../identity/errors';
import type { HostIdentityStore } from '../../identity/types';
import {
  PREPARE_RESET_ONLY_IDENTITY_CLEANUP,
  RESET_ONLY_IDENTITY_EVIDENCE_SOURCE,
  type ResetOnlyIdentityCleanupPlan,
  type ResetOnlyIdentityEvidenceSource,
} from '../../identity/reset-only-evidence-source';
import { MACOS_IDENTITY_EVIDENCE_ACCOUNTS, MACOS_IDENTITY_KEYCHAIN_SERVICE } from '../../identity/macos-keychain-store';

export interface ResetOnlyLegacyIdentityEvidence {
  classification: 'absent' | 'old-identity-unreadable';
  oldHostId: string | null;
  oldKeyId: string | null;
  source:
    | { kind: 'linux-json'; resourcePath: string }
    | { kind: 'macos-keychain'; resourcePath: string; profile: 'default' | 'dev' };
  cleanup: ResetOnlyIdentityCleanupPlan | null;
}

interface ResetOnlyEvidenceStore extends HostIdentityStore {
  [RESET_ONLY_IDENTITY_EVIDENCE_SOURCE](): ResetOnlyIdentityEvidenceSource;
  [PREPARE_RESET_ONLY_IDENTITY_CLEANUP]?(plan: ResetOnlyIdentityCleanupPlan): void;
}

export function inspectResetOnlyLegacyIdentityEvidence(store: HostIdentityStore): ResetOnlyLegacyIdentityEvidence {
  const sourceProvider = (store as Partial<ResetOnlyEvidenceStore>)[RESET_ONLY_IDENTITY_EVIDENCE_SOURCE];
  if (typeof sourceProvider !== 'function') throw resetRequired('Host identity store does not support reset-only evidence inspection');
  const source = sourceProvider.call(store);
  return source.kind === 'linux-json' ? inspectLinux(source) : inspectMacOS(store as ResetOnlyEvidenceStore, source);
}

function inspectLinux(source: Extract<ResetOnlyIdentityEvidenceSource, { kind: 'linux-json' }>): ResetOnlyLegacyIdentityEvidence {
  const binding = { kind: 'linux-json' as const, resourcePath: source.identityPath };
  if (!pathHasFilesystemEvidence(source.identityPath)) {
    return { classification: 'absent', oldHostId: null, oldKeyId: null, source: binding, cleanup: null };
  }
  try {
    const value = readSecureJson<unknown>(source.identityPath);
    if (!isLinuxCurrent(value) && !isLinuxPending(value)) throw resetRequired('Linux Host identity evidence is malformed or unrecognized; manual cleanup is required');
    return {
      classification: 'old-identity-unreadable', oldHostId: value.hostId, oldKeyId: value.keyId,
      source: binding, cleanup: null,
    };
  } catch (error) {
    if (error instanceof HostIdentityError) throw error;
    if (error instanceof SecureFileError) throw new HostIdentityError('ERR_IDENTITY_PERMISSIONS', 'Linux Host identity evidence is not owner-safe', error);
    throw resetRequired('Linux Host identity evidence is malformed or unrecognized; manual cleanup is required', error);
  }
}

function inspectMacOS(
  store: ResetOnlyEvidenceStore,
  source: Extract<ResetOnlyIdentityEvidenceSource, { kind: 'macos-keychain' }>,
): ResetOnlyLegacyIdentityEvidence {
  const binding = { kind: 'macos-keychain' as const, resourcePath: source.metadataPath, profile: source.profile };
  try {
    const metadataPresent = pathHasFilesystemEvidence(source.metadataPath);
    const creationPath = `${source.metadataPath}.creating`;
    const creationPresent = pathHasFilesystemEvidence(creationPath);
    if (!metadataPresent) {
      const indexPresent = source.itemExists(source.evidenceAccount);
      if (!creationPresent && !indexPresent) {
        return { classification: 'absent', oldHostId: null, oldKeyId: null, source: binding, cleanup: null };
      }
      if (!creationPresent) {
        throw resetRequired('macOS selected-profile identity index has no exact creation evidence; manual cleanup is required');
      }
      const creation = readSecureJson<unknown>(creationPath);
      if (!isCreationSentinel(creation)) throw resetRequired('macOS identity creation evidence is malformed; manual cleanup is required');
      const cleanup = {
        previousAccount: null,
        previousPendingAccount: null,
        interruptedCreationAccount: creation.hostId,
      };
      prepareMacOSCleanup(store, cleanup);
      return {
        classification: 'old-identity-unreadable', oldHostId: creation?.hostId ?? null, oldKeyId: creation?.keyId ?? null,
        source: binding, cleanup,
      };
    }

    const value = readSecureJson<unknown>(source.metadataPath);
    if (!profileMatches(value, source.profile, source.evidenceAccount) || !source.itemExists(source.evidenceAccount)) {
      throw resetRequired('macOS identity metadata is not bound to the selected profile evidence');
    }
    if (!isMacCurrent(value) && !isMacPending(value)) throw resetRequired('macOS Host identity evidence is malformed or unrecognized; manual cleanup is required');
    const creation = creationPresent ? readSecureJson<unknown>(creationPath) : undefined;
    if (creation !== undefined && (!isCreationSentinel(creation)
      || creation.hostId !== value.current.hostId || creation.keyId !== value.current.keyId)) {
      throw resetRequired('macOS identity creation evidence does not match current metadata; manual cleanup is required');
    }
    const cleanup = {
      previousAccount: value.current.privateKeyStorage.account,
      previousPendingAccount: 'pending' in value ? value.pending.identity.privateKeyStorage.account : null,
      interruptedCreationAccount: creation?.hostId ?? null,
    };
    prepareMacOSCleanup(store, cleanup);
    return {
      classification: 'old-identity-unreadable', oldHostId: value.current.hostId, oldKeyId: value.current.keyId,
      source: binding, cleanup,
    };
  } catch (error) {
    if (error instanceof HostIdentityError) throw error;
    if (error instanceof SecureFileError) throw new HostIdentityError('ERR_IDENTITY_PERMISSIONS', 'macOS Host identity evidence is not owner-safe', error);
    throw resetRequired('macOS Host identity evidence is malformed or unrecognized; manual cleanup is required', error);
  }
}

function prepareMacOSCleanup(store: ResetOnlyEvidenceStore, plan: ResetOnlyIdentityCleanupPlan): void {
  const prepare = store[PREPARE_RESET_ONLY_IDENTITY_CLEANUP];
  if (typeof prepare !== 'function') throw resetRequired('macOS Host identity store cannot prepare reset-only cleanup');
  prepare.call(store, plan);
}

function isLinuxCurrent(value: unknown): value is Record<string, unknown> & { hostId: string; keyId: string } {
  const required = ['version', 'entityType', 'hostId', 'keyId', 'algorithm', 'publicKey', 'publicKeyFingerprint', 'createdAt'] as const;
  const recognized = exact(value, [...required, 'privateKeyPkcs8'], ['resetOperationId'])
    || exact(value, required, ['resetOperationId']);
  return recognized && identityScalars(value)
    && (value.privateKeyPkcs8 === undefined || typeof value.privateKeyPkcs8 === 'string')
    && (value.resetOperationId === undefined || validOperationId(value.resetOperationId));
}

function isLinuxPending(value: unknown): value is Record<string, unknown> & { hostId: string; keyId: string } {
  const required = ['version', 'entityType', 'hostId', 'keyId', 'algorithm', 'publicKey', 'publicKeyFingerprint', 'createdAt', 'pendingRotation'] as const;
  const recognized = exact(value, [...required, 'privateKeyPkcs8']) || exact(value, required);
  if (!recognized || !identityScalars(value)
    || (value.privateKeyPkcs8 !== undefined && typeof value.privateKeyPkcs8 !== 'string')
    || !exact(value.pendingRotation, ['operationId', 'issuedAt', 'identity'])) return false;
  const pending = value.pendingRotation;
  return validOperationId(pending.operationId) && typeof pending.issuedAt === 'string' && isLinuxCurrent(pending.identity)
    && pending.identity.resetOperationId === undefined;
}

function identityScalars(value: Record<string, unknown>): boolean {
  if (value.version !== 1 || value.entityType !== 'host' || value.algorithm !== 'Ed25519'
    || !validHostId(value.hostId) || !validKeyId(value.keyId) || !validBase64Url43(value.publicKey)
    || !validBase64Url43(value.publicKeyFingerprint) || typeof value.createdAt !== 'string') return false;
  return hasValidPublicKeyBinding(value) && value.hostId === `host_${value.publicKeyFingerprint}`;
}

function isMacCurrent(value: unknown): value is Record<string, unknown> & { current: MacMetadata } {
  return exact(value, ['current'], ['evidenceAccount']) && isMacMetadata(value.current)
    && value.current.privateKeyStorage.account === value.current.hostId;
}

function isMacPending(value: unknown): value is Record<string, unknown> & { current: MacMetadata; pending: { operationId: string; issuedAt: string; identity: MacMetadata } } {
  if (!exact(value, ['current', 'pending'], ['evidenceAccount']) || !isMacMetadata(value.current)
    || !exact(value.pending, ['operationId', 'issuedAt', 'identity']) || !isMacMetadata(value.pending.identity)) return false;
  return value.current.privateKeyStorage.account === value.current.hostId
    && typeof value.pending.operationId === 'string' && typeof value.pending.issuedAt === 'string'
    && value.pending.identity.hostId === value.current.hostId
    && value.pending.identity.privateKeyStorage.account === `${value.current.hostId}.pending`;
}

interface MacMetadata {
  hostId: string;
  keyId: string;
  privateKeyStorage: { account: string };
}

function isMacMetadata(value: unknown): value is MacMetadata & Record<string, unknown> {
  if (!exact(value, ['identityVersion', 'hostId', 'keyId', 'algorithm', 'publicKey', 'publicKeyFingerprint', 'createdAt', 'privateKeyStorage'])
    || !exact(value.privateKeyStorage, ['type', 'service', 'account'])) return false;
  return value.identityVersion === 2 && value.algorithm === 'Ed25519'
    && validHostId(value.hostId) && validKeyId(value.keyId) && validBase64Url43(value.publicKey)
    && validBase64Url43(value.publicKeyFingerprint) && typeof value.createdAt === 'string'
    && value.privateKeyStorage.type === 'macos-keychain' && value.privateKeyStorage.service === MACOS_IDENTITY_KEYCHAIN_SERVICE
    && typeof value.privateKeyStorage.account === 'string' && hasValidPublicKeyBinding(value)
    && value.hostId === `host_${value.publicKeyFingerprint}`;
}

function hasValidPublicKeyBinding(value: Record<string, unknown>): boolean {
  try {
    const publicKey = base64UrlDecode(value.publicKey as string, 32, 'Ed25519 public key');
    const fingerprint = base64UrlEncode(new Uint8Array(createHash('sha256').update(publicKey).digest()));
    return value.publicKeyFingerprint === fingerprint && value.keyId === `key_${fingerprint}`;
  } catch {
    return false;
  }
}

function isCreationSentinel(value: unknown): value is { hostId: string; keyId: string } {
  return exact(value, ['schema', 'phase', 'hostId', 'keyId']) && value.schema === 'ariava-macos-identity-creation-v1'
    && value.phase === 'creating' && validHostId(value.hostId) && validKeyId(value.keyId)
    && value.hostId.slice('host_'.length) === value.keyId.slice('key_'.length);
}

function profileMatches(value: unknown, profile: 'default' | 'dev', account: string): boolean {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const evidence = (value as Record<string, unknown>).evidenceAccount;
  return evidence === account || (profile === 'default' && evidence === undefined && account === MACOS_IDENTITY_EVIDENCE_ACCOUNTS.default);
}

function exact(value: unknown, required: readonly string[], optional: readonly string[] = []): value is Record<string, any> {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) return false;
  const keys = Object.keys(value);
  return required.every((key) => keys.includes(key)) && keys.every((key) => required.includes(key) || optional.includes(key));
}

function validOperationId(value: unknown): boolean { return typeof value === 'string' && /^[A-Za-z0-9_-]{1,128}$/u.test(value); }
function validHostId(value: unknown): value is string { return typeof value === 'string' && /^host_[A-Za-z0-9_-]{43}$/u.test(value); }
function validKeyId(value: unknown): value is string { return typeof value === 'string' && /^key_[A-Za-z0-9_-]{43}$/u.test(value); }
function validBase64Url43(value: unknown): value is string { return typeof value === 'string' && /^[A-Za-z0-9_-]{43}$/u.test(value); }
function resetRequired(message: string, cause?: unknown): HostIdentityError { return new HostIdentityError('ERR_IDENTITY_RESET_REQUIRED', message, cause); }
