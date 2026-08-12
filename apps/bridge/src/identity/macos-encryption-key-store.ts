import { randomUUID } from 'node:crypto';
import { isAbsolute, resolve } from 'node:path';
import { base64UrlDecode, base64UrlEncode } from '@ariava/protocol';
import { pathHasFilesystemEvidence, readSecureJson, removeSecureFile, writeSecureJson, writeSecureJsonExclusive } from '../host-manager/secure-files';
import { HostIdentityError } from './errors';
import {
  isKeychainLocked,
  isKeychainMissing,
  MACOS_SECURITY_PATH,
  SpawnKeychainCommandRunner,
  type KeychainCommandRunner,
} from './macos-keychain-store';
import { generateHostEncryptionIdentity, importHostEncryptionPrivateKey, type HostEncryptionIdentity } from './host-encryption-key';

export const MACOS_ENCRYPTION_KEYCHAIN_SERVICE = 'io.noyx.ariava.host-e2e-key' as const;

interface MacEncryptionMetadata {
  version: 1;
  hostId: string;
  encryptionKeyId: string;
  publicKey: string;
  sequence: number;
  createdAt: string;
  account: string;
}

interface MacEncryptionResetSentinel {
  schema: 'ariava-macos-encryption-reset-v1';
  phase: 'prepared';
  operationId: string;
  candidate: MacEncryptionMetadata;
  previousAccount: string | null;
}

export interface MacOSEncryptionResetHooks {
  afterResetSentinel?(): void;
  afterResetKeyWrite?(): void;
  afterResetMetadataWrite?(): void;
}

export class MacOSEncryptionKeyStore {
  readonly metadataPath: string;
  constructor(
    metadataPath: string,
    private readonly runner: KeychainCommandRunner = new SpawnKeychainCommandRunner(),
    private readonly resetHooks: MacOSEncryptionResetHooks = {},
  ) {
    if (!isAbsolute(metadataPath)) throw new HostIdentityError('ERR_IDENTITY_PERMISSIONS', 'macOS encryption metadata path must be absolute');
    this.metadataPath = resolve(metadataPath);
  }

  load(): HostEncryptionIdentity | null {
    if (!pathHasFilesystemEvidence(this.metadataPath)) return null;
    try {
      const metadata = readSecureJson<MacEncryptionMetadata>(this.metadataPath);
      if (!validMetadata(metadata)) throw new Error('invalid encryption metadata');
      const privateKeyPkcs8 = this.readItem(metadata.account);
      const identity = { ...metadata, privateKeyPkcs8 } satisfies HostEncryptionIdentity;
      importHostEncryptionPrivateKey(identity);
      return identity;
    } catch (error) {
      if (error instanceof HostIdentityError) throw error;
      throw new HostIdentityError('ERR_IDENTITY_INVALID', 'macOS Host encryption key is unavailable or corrupt', error);
    }
  }

  loadOrCreate(hostId: string): HostEncryptionIdentity {
    const existing = this.load();
    if (existing) {
      if (existing.hostId !== hostId) throw new HostIdentityError('ERR_IDENTITY_INVALID', 'Encryption key belongs to another Host');
      return existing;
    }
    const identity = generateHostEncryptionIdentity(hostId);
    const account = keychainAccount(identity);
    this.writeItem(account, identity.privateKeyPkcs8, false);
    try { writeSecureJsonExclusive(this.metadataPath, metadata(identity)); }
    catch (error) { this.deleteItem(account); throw new HostIdentityError('ERR_IDENTITY_PERMISSIONS', 'Could not persist macOS encryption metadata', error); }
    return this.loadRequired(hostId);
  }

  replaceForReset(hostId: string, operationId?: string): HostEncryptionIdentity {
    const resetOperationId = operationId ?? `standalone_${randomUUID().replaceAll('-', '')}`;
    const existing = this.readResetSentinelIfPresent();
    if (existing) {
      if (existing.operationId !== resetOperationId || existing.candidate.hostId !== hostId) {
        throw new HostIdentityError('ERR_IDENTITY_RESET_REQUIRED', 'A different macOS encryption identity reset is pending');
      }
      const recovered = this.finishReset(existing);
      if (!operationId) this.completeReset(resetOperationId);
      return recovered;
    }
    const previous = this.load();
    const identity = generateHostEncryptionIdentity(hostId);
    const candidate = metadata(identity);
    const sentinel = {
      schema: 'ariava-macos-encryption-reset-v1', phase: 'prepared', operationId: resetOperationId,
      candidate, previousAccount: previous ? keychainAccount(previous) : null,
    } satisfies MacEncryptionResetSentinel;
    this.writeResetSentinel(sentinel);
    this.resetHooks.afterResetSentinel?.();
    this.writeItem(candidate.account, identity.privateKeyPkcs8, false);
    this.resetHooks.afterResetKeyWrite?.();
    const recovered = this.finishReset(sentinel);
    if (!operationId) this.completeReset(resetOperationId);
    return recovered;
  }

  recoverReset(hostId: string, operationId: string): HostEncryptionIdentity | null {
    const sentinel = this.readResetSentinelIfPresent();
    if (!sentinel) return null;
    if (sentinel.operationId !== operationId || sentinel.candidate.hostId !== hostId) {
      throw new HostIdentityError('ERR_IDENTITY_RESET_REQUIRED', 'macOS encryption reset evidence belongs to another operation');
    }
    return this.finishReset(sentinel);
  }

  completeReset(operationId: string): void {
    const sentinel = this.readResetSentinelIfPresent();
    if (!sentinel) return;
    if (sentinel.operationId !== operationId) {
      throw new HostIdentityError('ERR_IDENTITY_RESET_REQUIRED', 'macOS encryption reset evidence belongs to another operation');
    }
    try { removeSecureFile(this.resetSentinelPath()); }
    catch (error) { throw new HostIdentityError('ERR_IDENTITY_PERMISSIONS', 'Could not clear macOS encryption reset evidence', error); }
  }

  private finishReset(sentinel: MacEncryptionResetSentinel): HostEncryptionIdentity {
    const privateKeyPkcs8 = this.readItem(sentinel.candidate.account);
    importHostEncryptionPrivateKey({ ...sentinel.candidate, privateKeyPkcs8 });
    try {
      writeSecureJson(this.metadataPath, sentinel.candidate);
      this.resetHooks.afterResetMetadataWrite?.();
      const loaded = this.loadRequired(sentinel.candidate.hostId);
      if (sentinel.previousAccount && sentinel.previousAccount !== sentinel.candidate.account) this.deleteItem(sentinel.previousAccount);
      return loaded;
    } catch (error) {
      throw new HostIdentityError('ERR_IDENTITY_PERMISSIONS', 'Could not replace macOS encryption metadata', error);
    }
  }

  private resetSentinelPath(): string { return `${this.metadataPath}.resetting`; }

  private readResetSentinelIfPresent(): MacEncryptionResetSentinel | undefined {
    try {
      if (!pathHasFilesystemEvidence(this.resetSentinelPath())) return undefined;
      const value = readSecureJson<unknown>(this.resetSentinelPath());
      if (!validResetSentinel(value)) throw new Error('invalid reset sentinel');
      return value;
    } catch (error) {
      throw new HostIdentityError('ERR_IDENTITY_RESET_REQUIRED', 'macOS encryption reset evidence is invalid', error);
    }
  }

  private writeResetSentinel(value: MacEncryptionResetSentinel): void {
    try { writeSecureJsonExclusive(this.resetSentinelPath(), value); }
    catch (error) { throw new HostIdentityError('ERR_IDENTITY_PERMISSIONS', 'Could not durably mark macOS encryption reset', error); }
  }

  deleteAfterHostReplacement(encryptionKeyId: string): void {
    if (!/^ekey_[A-Za-z0-9_-]{43}$/u.test(encryptionKeyId)) {
      throw new HostIdentityError('ERR_IDENTITY_INVALID', 'Invalid old Host encryption Keychain account');
    }
    this.deleteItem(`host-e2e:${encryptionKeyId}`);
  }

  private loadRequired(hostId: string): HostEncryptionIdentity {
    const loaded = this.load();
    if (!loaded || loaded.hostId !== hostId) throw new HostIdentityError('ERR_IDENTITY_INVALID', 'Persisted encryption key verification failed');
    return loaded;
  }

  private writeItem(account: string, value: Uint8Array, update: boolean): void {
    assertSafeKeychainIdentifier(account, 'account');
    const args = ['add-generic-password', ...(update ? ['-U'] : []), '-s', MACOS_ENCRYPTION_KEYCHAIN_SERVICE, '-a', account, '-X', Buffer.from(value).toString('hex')];
    const result = this.runner.run(MACOS_SECURITY_PATH, args);
    if (result.status !== 0 || result.error) throw new HostIdentityError('ERR_IDENTITY_PERMISSIONS', 'macOS encryption Keychain write failed');
  }

  private readItem(account: string): Uint8Array {
    assertSafeKeychainIdentifier(account, 'account');
    const result = this.runner.run(MACOS_SECURITY_PATH, ['find-generic-password', '-s', MACOS_ENCRYPTION_KEYCHAIN_SERVICE, '-a', account, '-w']);
    if (result.status !== 0 || result.error) {
      if (isKeychainLocked(result)) {
        throw new HostIdentityError(
          'ERR_IDENTITY_KEYCHAIN_LOCKED',
          'macOS login Keychain is locked or unavailable in this session.',
        );
      }
      if (isKeychainMissing(result)) {
        throw new HostIdentityError('ERR_IDENTITY_MISSING', 'macOS encryption Keychain item is missing');
      }
      throw new HostIdentityError('ERR_IDENTITY_PERMISSIONS', 'macOS encryption Keychain read failed');
    }
    const encoded = Buffer.from(result.stdout).toString('utf8').trimEnd();
    if (!/^(?:[0-9a-f]{2})+$/iu.test(encoded)) throw new HostIdentityError('ERR_IDENTITY_INVALID', 'macOS encryption Keychain encoding is invalid');
    return base64UrlDecode(base64UrlEncode(Buffer.from(encoded, 'hex')), undefined, 'X25519 PKCS#8');
  }

  private deleteItem(account: string): void {
    assertSafeKeychainIdentifier(account, 'account');
    const result = this.runner.run(
      MACOS_SECURITY_PATH,
      ['delete-generic-password', '-s', MACOS_ENCRYPTION_KEYCHAIN_SERVICE, '-a', account],
    );
    if (result.status === 0 && !result.error) return;
    if (isKeychainMissing(result)) return;
    if (isKeychainLocked(result)) {
      throw new HostIdentityError(
        'ERR_IDENTITY_KEYCHAIN_LOCKED',
        'macOS login Keychain is locked or unavailable in this session.',
      );
    }
    throw new HostIdentityError('ERR_IDENTITY_PERMISSIONS', 'macOS encryption Keychain delete failed');
  }
}

function validResetSentinel(value: unknown): value is MacEncryptionResetSentinel {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  if (Object.keys(record).sort().join(',') !== 'candidate,operationId,phase,previousAccount,schema') return false;
  return record.schema === 'ariava-macos-encryption-reset-v1' && record.phase === 'prepared'
    && typeof record.operationId === 'string' && /^[A-Za-z0-9_-]{1,128}$/u.test(record.operationId)
    && validMetadata(record.candidate as MacEncryptionMetadata)
    && (record.previousAccount === null || (typeof record.previousAccount === 'string'
      && /^host-e2e:ekey_[A-Za-z0-9_-]{43}$/u.test(record.previousAccount)));
}

function metadata(identity: HostEncryptionIdentity): MacEncryptionMetadata {
  const { privateKeyPkcs8: _private, ...publicFields } = identity;
  return { ...publicFields, account: keychainAccount(identity) };
}
function validMetadata(value: MacEncryptionMetadata): boolean {
  return value?.version === 1 && typeof value.hostId === 'string' && value.account === `host-e2e:${value.encryptionKeyId}`
    && typeof value.encryptionKeyId === 'string' && typeof value.publicKey === 'string'
    && Number.isSafeInteger(value.sequence) && value.sequence > 0 && typeof value.createdAt === 'string';
}
function keychainAccount(identity: HostEncryptionIdentity): string { return `host-e2e:${identity.encryptionKeyId}`; }
function assertSafeKeychainIdentifier(value: string, label: string): void {
  if (!/^[A-Za-z0-9_.:-]{1,128}$/u.test(value)) throw new HostIdentityError('ERR_IDENTITY_INVALID', `Unsafe macOS Keychain ${label}`);
}
