import { isAbsolute, resolve } from 'node:path';
import { base64UrlDecode, base64UrlEncode } from '@ariava/protocol';
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
  generateHostEncryptionIdentity,
  importHostEncryptionPrivateKey,
  type HostEncryptionIdentity,
} from './host-encryption-key';

interface LinuxEncryptionKeyRecord {
  version: 1;
  hostId: string;
  encryptionKeyId: string;
  publicKey: string;
  privateKeyPkcs8: string;
  sequence: number;
  createdAt: string;
}

export class LinuxEncryptionKeyStore {
  readonly path: string;

  constructor(path: string) {
    if (!isAbsolute(path)) throw new HostIdentityError('ERR_IDENTITY_PERMISSIONS', 'Linux encryption key path must be absolute');
    this.path = resolve(path);
  }

  load(): HostEncryptionIdentity | null {
    if (!pathHasFilesystemEvidence(this.path)) return null;
    try {
      assertSecureFile(this.path);
      const record = readSecureJson<unknown>(this.path);
      if (!isRecord(record)) throw new Error('invalid encryption key schema');
      const identity = fromRecord(record);
      importHostEncryptionPrivateKey(identity);
      return identity;
    } catch (error) {
      if (error instanceof HostIdentityError) throw error;
      const code = error instanceof SecureFileError ? 'ERR_IDENTITY_PERMISSIONS' : 'ERR_IDENTITY_INVALID';
      throw new HostIdentityError(code, 'Linux Host encryption key is unavailable or corrupt', error);
    }
  }

  loadOrCreate(hostId: string): HostEncryptionIdentity {
    const existing = this.load();
    if (existing) {
      if (existing.hostId !== hostId) throw new HostIdentityError('ERR_IDENTITY_INVALID', 'Encryption key belongs to another Host');
      return existing;
    }
    const identity = generateHostEncryptionIdentity(hostId);
    try { writeSecureJsonExclusive(this.path, toRecord(identity)); }
    catch (error) { throw new HostIdentityError('ERR_IDENTITY_PERMISSIONS', 'Could not securely persist Linux Host encryption key', error); }
    return this.loadRequired(hostId);
  }

  replaceForReset(hostId: string): HostEncryptionIdentity {
    const identity = generateHostEncryptionIdentity(hostId);
    try { writeSecureJson(this.path, toRecord(identity)); }
    catch (error) { throw new HostIdentityError('ERR_IDENTITY_PERMISSIONS', 'Could not replace Linux Host encryption key', error); }
    return this.loadRequired(hostId);
  }

  private loadRequired(hostId: string): HostEncryptionIdentity {
    const loaded = this.load();
    if (!loaded || loaded.hostId !== hostId) throw new HostIdentityError('ERR_IDENTITY_INVALID', 'Persisted encryption key verification failed');
    return loaded;
  }
}

function toRecord(identity: HostEncryptionIdentity): LinuxEncryptionKeyRecord {
  return { ...identity, privateKeyPkcs8: base64UrlEncode(identity.privateKeyPkcs8) };
}

function fromRecord(value: LinuxEncryptionKeyRecord): HostEncryptionIdentity {
  return { ...value, privateKeyPkcs8: base64UrlDecode(value.privateKeyPkcs8, undefined, 'X25519 PKCS#8') };
}

function isRecord(value: unknown): value is LinuxEncryptionKeyRecord {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  const keys = ['version', 'hostId', 'encryptionKeyId', 'publicKey', 'privateKeyPkcs8', 'sequence', 'createdAt'];
  return Object.keys(record).length === keys.length && keys.every((key) => Object.hasOwn(record, key))
    && record.version === 1 && typeof record.hostId === 'string' && typeof record.encryptionKeyId === 'string'
    && typeof record.publicKey === 'string' && typeof record.privateKeyPkcs8 === 'string'
    && Number.isSafeInteger(record.sequence) && (record.sequence as number) > 0 && typeof record.createdAt === 'string';
}
