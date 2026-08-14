import { isAbsolute, resolve } from 'node:path';
import { base64UrlDecode, base64UrlEncode, isCanonicalTimestamp } from '@ariava/protocol';
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
  assertCanonicalHostId,
  generateHostEncryptionIdentity,
  importHostEncryptionPrivateKey,
  type HostEncryptionIdentity,
} from './host-encryption-key';

interface LinuxEncryptionIdentityRecord {
  version: 1;
  hostId: string;
  encryptionKeyId: string;
  publicKey: string;
  privateKeyPkcs8: string;
  sequence: number;
  createdAt: string;
}

interface LinuxEncryptionKeyRecordV2 {
  version: 2;
  hostId: string;
  currentKeyId: string;
  identities: LinuxEncryptionIdentityRecord[];
}

type LinuxEncryptionKeyRecordV1 = LinuxEncryptionIdentityRecord;

export class LinuxEncryptionKeyStore {
  readonly path: string;

  constructor(path: string) {
    if (!isAbsolute(path)) throw new HostIdentityError('ERR_IDENTITY_PERMISSIONS', 'Linux encryption key path must be absolute');
    this.path = resolve(path);
  }

  load(): HostEncryptionIdentity | null {
    const state = this.loadState();
    if (!state) return null;
    return fromRecord(state.identities.find((identity) => identity.encryptionKeyId === state.currentKeyId)!);
  }

  identity(encryptionKeyId: string): HostEncryptionIdentity | null {
    const state = this.loadState();
    const record = state?.identities.find((identity) => identity.encryptionKeyId === encryptionKeyId);
    return record ? fromRecord(record) : null;
  }

  retainedIdentityIds(): Set<string> {
    return new Set(this.loadState()?.identities.map((identity) => identity.encryptionKeyId) ?? []);
  }

  loadOrCreate(hostId: string): HostEncryptionIdentity {
    assertCanonicalHostId(hostId);
    const existing = this.load();
    if (existing) {
      if (existing.hostId !== hostId) throw new HostIdentityError('ERR_IDENTITY_INVALID', 'Encryption key belongs to another Host');
      return existing;
    }
    const identity = generateHostEncryptionIdentity(hostId);
    try { writeSecureJsonExclusive(this.path, stateFor(identity)); }
    catch (error) { throw new HostIdentityError('ERR_IDENTITY_PERMISSIONS', 'Could not securely persist Linux Host encryption key', error); }
    return this.loadRequired(hostId);
  }

  replaceCurrent(hostId: string): HostEncryptionIdentity {
    assertCanonicalHostId(hostId);
    const state = this.loadState();
    if (!state || state.hostId !== hostId) throw new HostIdentityError('ERR_IDENTITY_INVALID', 'Encryption key belongs to another Host');
    const sequence = Math.max(...state.identities.map((identity) => identity.sequence)) + 1;
    const identity = generateHostEncryptionIdentity(hostId, sequence);
    const next = { ...state, currentKeyId: identity.encryptionKeyId, identities: [...state.identities, toRecord(identity)] } satisfies LinuxEncryptionKeyRecordV2;
    this.persist(next, 'Could not rotate Linux Host encryption key');
    return this.loadRequired(hostId);
  }

  prune(referencedKeyIds: ReadonlySet<string>): string[] {
    const state = this.loadState();
    if (!state) return [];
    const removed = state.identities
      .filter((identity) => identity.encryptionKeyId !== state.currentKeyId && !referencedKeyIds.has(identity.encryptionKeyId))
      .map((identity) => identity.encryptionKeyId);
    if (!removed.length) return [];
    const removedSet = new Set(removed);
    this.persist({ ...state, identities: state.identities.filter((identity) => !removedSet.has(identity.encryptionKeyId)) }, 'Could not prune Linux Host encryption keys');
    return removed;
  }

  replaceForReset(hostId: string): HostEncryptionIdentity {
    assertCanonicalHostId(hostId);
    const identity = generateHostEncryptionIdentity(hostId);
    this.persist(stateFor(identity), 'Could not replace Linux Host encryption key');
    return this.loadRequired(hostId);
  }

  private loadState(): LinuxEncryptionKeyRecordV2 | null {
    if (!pathHasFilesystemEvidence(this.path)) return null;
    try {
      assertSecureFile(this.path);
      const raw = readSecureJson<unknown>(this.path);
      const state = decodeState(raw);
      if (isLegacyRecord(raw)) writeSecureJson(this.path, state);
      return state;
    } catch (error) {
      if (error instanceof HostIdentityError) throw error;
      const code = error instanceof SecureFileError ? 'ERR_IDENTITY_PERMISSIONS' : 'ERR_IDENTITY_INVALID';
      throw new HostIdentityError(code, 'Linux Host encryption key is unavailable or corrupt', error);
    }
  }

  private loadRequired(hostId: string): HostEncryptionIdentity {
    const loaded = this.load();
    if (!loaded || loaded.hostId !== hostId) throw new HostIdentityError('ERR_IDENTITY_INVALID', 'Persisted encryption key verification failed');
    return loaded;
  }

  private persist(state: LinuxEncryptionKeyRecordV2, message: string): void {
    try { writeSecureJson(this.path, state); }
    catch (error) { throw new HostIdentityError('ERR_IDENTITY_PERMISSIONS', message, error); }
  }
}

function stateFor(identity: HostEncryptionIdentity): LinuxEncryptionKeyRecordV2 {
  return { version: 2, hostId: identity.hostId, currentKeyId: identity.encryptionKeyId, identities: [toRecord(identity)] };
}

function toRecord(identity: HostEncryptionIdentity): LinuxEncryptionIdentityRecord {
  return { ...identity, privateKeyPkcs8: base64UrlEncode(identity.privateKeyPkcs8) };
}

function fromRecord(value: LinuxEncryptionIdentityRecord): HostEncryptionIdentity {
  const identity = { ...value, privateKeyPkcs8: base64UrlDecode(value.privateKeyPkcs8, undefined, 'X25519 PKCS#8') };
  importHostEncryptionPrivateKey(identity);
  return identity;
}

function decodeState(value: unknown): LinuxEncryptionKeyRecordV2 {
  if (isLegacyRecord(value)) {
    fromRecord(value);
    return { version: 2, hostId: value.hostId, currentKeyId: value.encryptionKeyId, identities: [value] };
  }
  if (!isPlainRecord(value) || !exactKeys(value, ['version', 'hostId', 'currentKeyId', 'identities'])
    || value.version !== 2 || typeof value.hostId !== 'string' || !isCanonicalHostId(value.hostId)
    || typeof value.currentKeyId !== 'string'
    || !Array.isArray(value.identities) || value.identities.length < 1 || value.identities.some((identity) => !isLegacyRecord(identity))) {
    throw new TypeError('invalid encryption key schema');
  }
  const identities = value.identities as LinuxEncryptionIdentityRecord[];
  const ids = new Set<string>();
  const sequences = new Set<number>();
  for (const record of identities) {
    if (record.hostId !== value.hostId || ids.has(record.encryptionKeyId) || sequences.has(record.sequence)) throw new TypeError('ambiguous encryption key schema');
    fromRecord(record);
    ids.add(record.encryptionKeyId); sequences.add(record.sequence);
  }
  const current = identities.find((identity) => identity.encryptionKeyId === value.currentKeyId);
  if (!current || current.sequence !== Math.max(...identities.map((identity) => identity.sequence))) throw new TypeError('encryption key rollback detected');
  return { version: 2, hostId: value.hostId, currentKeyId: value.currentKeyId, identities };
}

function isLegacyRecord(value: unknown): value is LinuxEncryptionKeyRecordV1 {
  if (!isPlainRecord(value) || !exactKeys(value, ['version', 'hostId', 'encryptionKeyId', 'publicKey', 'privateKeyPkcs8', 'sequence', 'createdAt'])) return false;
  return value.version === 1 && typeof value.hostId === 'string' && isCanonicalHostId(value.hostId)
    && typeof value.encryptionKeyId === 'string'
    && typeof value.publicKey === 'string' && typeof value.privateKeyPkcs8 === 'string'
    && Number.isSafeInteger(value.sequence) && (value.sequence as number) > 0 && typeof value.createdAt === 'string'
    && isCanonicalTimestamp(value.createdAt);
}

function isCanonicalHostId(value: string): boolean { return /^host_[A-Za-z0-9_-]{43}$/u.test(value); }
function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}
function exactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const keys = Object.keys(value);
  return keys.length === expected.length && expected.every((key) => Object.hasOwn(value, key));
}
