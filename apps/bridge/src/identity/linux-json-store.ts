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
  importHostIdentityPrivateKey,
} from './host-identity';
import type {
  HostIdentity,
  HostIdentityInspection,
  HostIdentityStore,
} from './types';
import { RESET_ONLY_IDENTITY_EVIDENCE_SOURCE, type ResetOnlyIdentityEvidenceSource } from './reset-only-evidence-source';

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
  resetOperationId?: string;
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
        status: 'ready' as const,
        ownerIntegrity: true,
        permissionIntegrity: true,
        metadataIntegrity: true,
        hostId: identity.hostId,
        keyId: identity.keyId,
        algorithm: identity.algorithm,
        publicKeyFingerprint: identity.publicKeyFingerprint,
      };
    } catch {
      return { ...base, status: 'invalid', ownerIntegrity: true, permissionIntegrity: true };
    }
  }

  async load(): Promise<HostIdentity | null> {
    if (!this.hasEvidence()) return null;
    return this.importRecord(this.readRecord());
  }


  async createFirstRun(): Promise<HostIdentity> {
    if (this.hasEvidence()) {
      throw new HostIdentityError('ERR_IDENTITY_RESET_REQUIRED', 'Host identity evidence already exists; explicit reset is required');
    }
    const material = await generateHostIdentity({ type: 'linux-json', path: this.identityPath });
    this.writeRecord(toRecord(material.identity, material.privateKeyPkcs8), true);
    return material.identity;
  }


  [RESET_ONLY_IDENTITY_EVIDENCE_SOURCE](): ResetOnlyIdentityEvidenceSource {
    return { kind: 'linux-json', identityPath: this.identityPath };
  }

  async resetAfterExplicitConfirmation(operationId?: string): Promise<HostIdentity> {
    const material = await generateHostIdentity({ type: 'linux-json', path: this.identityPath });
    this.writeRecord({ ...toRecord(material.identity, material.privateKeyPkcs8), ...(operationId ? { resetOperationId: operationId } : {}) });
    return material.identity;
  }

  async recoverExplicitReset(operationId: string): Promise<HostIdentity | null> {
    if (!this.hasEvidence()) return null;
    const record = this.readRecord();
    return record.resetOperationId === operationId ? this.importRecord(record) : null;
  }

  completeExplicitReset(operationId: string): void {
    if (!this.hasEvidence()) return;
    const record = this.readRecord();
    if (record.resetOperationId === undefined) return;
    if (record.resetOperationId !== operationId) {
      throw new HostIdentityError('ERR_IDENTITY_RESET_REQUIRED', 'Linux Host identity reset evidence belongs to another operation');
    }
    delete record.resetOperationId;
    this.writeRecord(record);
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


function isLinuxIdentityRecord(value: unknown): value is LinuxIdentityRecord {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) return false;
  const record = value as Record<string, unknown>;
  const allowed = new Set([
    'version', 'entityType', 'hostId', 'keyId', 'algorithm', 'publicKey',
    'publicKeyFingerprint', 'privateKeyPkcs8', 'createdAt', 'resetOperationId',
  ]);
  return Object.keys(record).every((key) => allowed.has(key))
    && record.version === 1 && record.entityType === 'host' && record.algorithm === 'Ed25519'
    && ['hostId', 'keyId', 'publicKey', 'publicKeyFingerprint', 'privateKeyPkcs8', 'createdAt'].every((key) => typeof record[key] === 'string')
    && (record.resetOperationId === undefined || (typeof record.resetOperationId === 'string'
      && /^[A-Za-z0-9_-]{1,128}$/u.test(record.resetOperationId)));
}
