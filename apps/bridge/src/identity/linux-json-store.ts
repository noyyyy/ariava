import { isAbsolute, resolve } from 'node:path';
import { base64UrlEncode } from '@ariava/protocol';
import {
  assertSecureFile,
  pathHasFilesystemEvidence,
  readSecureJson,
  SecureFileError,
  writeSecureJson,
  writeSecureJsonExclusive,
} from '../host-manager/secure-files';
import { HostIdentityError } from './errors';
import {
  decodePkcs8,
  generateHostIdentity,
  getHostIdentityPrivateKey,
  importHostIdentityPrivateKey,
} from './host-identity';
import type {
  HostIdentity,
  HostIdentityInspection,
  HostIdentityStore,
  PendingHostIdentity,
} from './types';

interface LinuxIdentityRecord {
  version: 1;
  entityType: 'host';
  hostId: string;
  keyId: string;
  algorithm: 'Ed25519';
  publicKey: string;
  publicKeyFingerprint: string;
  privateKeyPkcs8: string;
  createdAt: string;
  pendingRotation?: {
    operationId: string;
    issuedAt: string;
    identity: Omit<LinuxIdentityRecord, 'pendingRotation'>;
  };
}

export class LinuxJsonHostIdentityStore implements HostIdentityStore {
  readonly identityPath: string;

  constructor(path: string) {
    if (!isAbsolute(path)) throw new HostIdentityError('ERR_IDENTITY_PERMISSIONS', 'Linux identity path must be absolute');
    this.identityPath = resolve(path);
  }

  async inspect(): Promise<HostIdentityInspection> {
    const base = {
      storageType: 'linux-json' as const,
      storageReference: { type: 'linux-json' as const, path: this.identityPath },
      path: this.identityPath,
      ownerIntegrity: false,
      permissionIntegrity: false,
      metadataIntegrity: false,
      pendingRotation: false,
    };
    if (!this.hasEvidence()) return { ...base, status: 'not-initialized' };
    try {
      assertSecureFile(this.identityPath);
    } catch {
      return { ...base, status: 'invalid' };
    }
    try {
      const record = this.readRecord();
      const identity = await this.importRecord(record);
      return {
        ...base,
        status: record.pendingRotation ? 'rotation-pending' : 'ready',
        ownerIntegrity: true,
        permissionIntegrity: true,
        metadataIntegrity: true,
        pendingRotation: Boolean(record.pendingRotation),
        hostId: identity.hostId,
        keyId: identity.keyId,
        algorithm: identity.algorithm,
        publicKeyFingerprint: identity.publicKeyFingerprint,
        pendingOperationId: record.pendingRotation?.operationId,
      };
    } catch {
      return { ...base, status: 'invalid', ownerIntegrity: true, permissionIntegrity: true };
    }
  }

  async load(): Promise<HostIdentity | null> {
    if (!this.hasEvidence()) return null;
    return this.importRecord(this.readRecord());
  }

  async loadPending(): Promise<PendingHostIdentity | null> {
    if (!this.hasEvidence()) return null;
    const record = this.readRecord();
    if (!record.pendingRotation) return null;
    return {
      operationId: record.pendingRotation.operationId,
      issuedAt: record.pendingRotation.issuedAt,
      identity: await this.importSingleRecord(record.pendingRotation.identity),
    };
  }

  async createFirstRun(): Promise<HostIdentity> {
    if (this.hasEvidence()) {
      throw new HostIdentityError('ERR_IDENTITY_RESET_REQUIRED', 'Host identity evidence already exists; explicit reset is required');
    }
    const material = await generateHostIdentity({ type: 'linux-json', path: this.identityPath });
    this.writeRecord(toRecord(material.identity, material.privateKeyPkcs8), true);
    return material.identity;
  }

  async stageRotation(next: PendingHostIdentity): Promise<void> {
    const current = this.readRecordRequired();
    if (next.identity.hostId !== current.hostId) {
      throw new HostIdentityError('ERR_IDENTITY_INVALID', 'Rotation must preserve the Host entity ID');
    }
    const pendingPrivateKey = getHostIdentityPrivateKey(next.identity);
    const pendingRecord = toRecord(next.identity, pendingPrivateKey);
    // Fully prove and validate the pending payload before touching persisted evidence.
    await this.importSingleRecord(pendingRecord);
    const candidate: LinuxIdentityRecord = {
      ...current,
      pendingRotation: { operationId: next.operationId, issuedAt: next.issuedAt, identity: pendingRecord },
    };
    if (current.pendingRotation) {
      if (current.pendingRotation.operationId !== next.operationId) {
        throw new HostIdentityError('ERR_IDENTITY_RESET_REQUIRED', 'A different Host key rotation is already pending');
      }
      if (!samePending(current.pendingRotation, candidate.pendingRotation!)) {
        throw new HostIdentityError('ERR_IDENTITY_INVALID', 'Rotation retry payload does not match the pending operation');
      }
      return;
    }
    this.writeRecord(candidate);
  }

  async abortRotation(operationId: string): Promise<void> {
    const current = this.readRecordRequired();
    if (!current.pendingRotation || current.pendingRotation.operationId !== operationId) {
      throw new HostIdentityError('ERR_IDENTITY_INVALID', 'Pending Host key rotation does not match operation ID');
    }
    delete current.pendingRotation;
    this.writeRecord(current);
  }

  async promoteRotation(operationId: string): Promise<HostIdentity> {
    const current = this.readRecordRequired();
    if (!current.pendingRotation || current.pendingRotation.operationId !== operationId) {
      throw new HostIdentityError('ERR_IDENTITY_INVALID', 'Pending Host key rotation does not match operation ID');
    }
    const promoted = current.pendingRotation.identity;
    const identity = await this.importSingleRecord(promoted);
    // Validation happens before replacement; atomic write preserves old+pending if promotion fails.
    this.writeRecord(promoted);
    return identity;
  }

  async resetAfterExplicitConfirmation(): Promise<HostIdentity> {
    const material = await generateHostIdentity({ type: 'linux-json', path: this.identityPath });
    this.writeRecord(toRecord(material.identity, material.privateKeyPkcs8));
    return material.identity;
  }

  private hasEvidence(): boolean {
    try {
      return pathHasFilesystemEvidence(this.identityPath);
    } catch (error) {
      throw new HostIdentityError('ERR_IDENTITY_PERMISSIONS', 'Could not inspect Linux Host identity evidence', error);
    }
  }

  private readRecordRequired(): LinuxIdentityRecord {
    if (!this.hasEvidence()) throw new HostIdentityError('ERR_IDENTITY_MISSING', 'Host identity key material is missing');
    return this.readRecord();
  }

  private readRecord(): LinuxIdentityRecord {
    try {
      assertSecureFile(this.identityPath);
      const value = readSecureJson<unknown>(this.identityPath);
      if (!isLinuxIdentityRecord(value)) throw new HostIdentityError('ERR_IDENTITY_INVALID', 'Linux Host identity schema is invalid');
      return value;
    } catch (error) {
      if (error instanceof HostIdentityError) throw error;
      if (error instanceof SecureFileError) throw new HostIdentityError('ERR_IDENTITY_PERMISSIONS', 'Linux Host identity permissions are unsafe', error);
      throw new HostIdentityError('ERR_IDENTITY_INVALID', 'Linux Host identity JSON is invalid', error);
    }
  }

  private writeRecord(record: LinuxIdentityRecord, exclusive = false): void {
    try {
      if (exclusive) writeSecureJsonExclusive(this.identityPath, record);
      else writeSecureJson(this.identityPath, record);
    } catch (error) {
      throw new HostIdentityError(exclusive && this.hasEvidence() ? 'ERR_IDENTITY_RESET_REQUIRED' : 'ERR_IDENTITY_PERMISSIONS', 'Could not securely persist Linux Host identity', error);
    }
  }

  private async importRecord(record: LinuxIdentityRecord): Promise<HostIdentity> {
    const current = await this.importSingleRecord(record);
    if (record.pendingRotation) {
      const pending = await this.importSingleRecord(record.pendingRotation.identity);
      if (pending.hostId !== current.hostId) throw new HostIdentityError('ERR_IDENTITY_INVALID', 'Pending Host identity targets a different Host');
    }
    return current;
  }

  private async importSingleRecord(record: Omit<LinuxIdentityRecord, 'pendingRotation'>): Promise<HostIdentity> {
    return (await importHostIdentityPrivateKey(
      decodePkcs8(record.privateKeyPkcs8),
      { type: 'linux-json', path: this.identityPath },
      record.createdAt,
      { ...record, identityVersion: 2 },
    )).identity;
  }
}

function toRecord(identity: HostIdentity, pkcs8: Uint8Array): LinuxIdentityRecord {
  return {
    version: 1,
    entityType: 'host',
    hostId: identity.hostId,
    keyId: identity.keyId,
    algorithm: 'Ed25519',
    publicKey: identity.publicKey,
    publicKeyFingerprint: identity.publicKeyFingerprint,
    privateKeyPkcs8: base64UrlEncode(pkcs8),
    createdAt: identity.createdAt,
  };
}

function samePending(left: NonNullable<LinuxIdentityRecord['pendingRotation']>, right: NonNullable<LinuxIdentityRecord['pendingRotation']>): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

function isLinuxIdentityRecord(value: unknown): value is LinuxIdentityRecord {
  if (!value || typeof value !== 'object') return false;
  const record = value as Record<string, unknown>;
  const allowed = new Set([
    'version', 'entityType', 'hostId', 'keyId', 'algorithm', 'publicKey',
    'publicKeyFingerprint', 'privateKeyPkcs8', 'createdAt', 'pendingRotation',
  ]);
  const valid = Object.keys(record).every((key) => allowed.has(key))
    && record.version === 1 && record.entityType === 'host' && record.algorithm === 'Ed25519'
    && ['hostId', 'keyId', 'publicKey', 'publicKeyFingerprint', 'privateKeyPkcs8', 'createdAt'].every((key) => typeof record[key] === 'string');
  if (!valid || record.pendingRotation === undefined) return valid;
  const pending = record.pendingRotation as Record<string, unknown>;
  return Object.keys(pending).every((key) => key === 'operationId' || key === 'issuedAt' || key === 'identity')
    && typeof pending.operationId === 'string' && typeof pending.issuedAt === 'string' && isLinuxIdentityRecord(pending.identity)
    && !(pending.identity as LinuxIdentityRecord).pendingRotation;
}
