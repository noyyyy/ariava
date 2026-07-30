import { isAbsolute, resolve } from 'node:path';
import { base64UrlDecode, base64UrlEncode } from '@ariava/protocol';
import { pathHasFilesystemEvidence, readSecureJson, writeSecureJson, writeSecureJsonExclusive } from '../host-manager/secure-files';
import { HostIdentityError } from './errors';
import { MACOS_SECURITY_PATH, SpawnKeychainCommandRunner, type KeychainCommandRunner } from './macos-keychain-store';
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

export class MacOSEncryptionKeyStore {
  readonly metadataPath: string;
  constructor(metadataPath: string, private readonly runner: KeychainCommandRunner = new SpawnKeychainCommandRunner()) {
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

  replaceForReset(hostId: string): HostEncryptionIdentity {
    const identity = generateHostEncryptionIdentity(hostId);
    const account = keychainAccount(identity);
    const previous = this.load();
    this.writeItem(account, identity.privateKeyPkcs8, false);
    try {
      writeSecureJson(this.metadataPath, metadata(identity));
      const loaded = this.loadRequired(hostId);
      if (previous) this.deleteItem(keychainAccount(previous));
      return loaded;
    } catch (error) {
      this.deleteItem(account);
      if (previous) {
        try { writeSecureJson(this.metadataPath, metadata(previous)); } catch { /* preserve the original failure */ }
      }
      throw new HostIdentityError('ERR_IDENTITY_PERMISSIONS', 'Could not replace macOS encryption metadata', error);
    }
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
    if (result.status !== 0 || result.error) throw new HostIdentityError('ERR_IDENTITY_MISSING', 'macOS encryption Keychain item is missing');
    const encoded = Buffer.from(result.stdout).toString('utf8').trimEnd();
    if (!/^(?:[0-9a-f]{2})+$/iu.test(encoded)) throw new HostIdentityError('ERR_IDENTITY_INVALID', 'macOS encryption Keychain encoding is invalid');
    return base64UrlDecode(base64UrlEncode(Buffer.from(encoded, 'hex')), undefined, 'X25519 PKCS#8');
  }

  private deleteItem(account: string): void {
    assertSafeKeychainIdentifier(account, 'account');
    this.runner.run(MACOS_SECURITY_PATH, ['delete-generic-password', '-s', MACOS_ENCRYPTION_KEYCHAIN_SERVICE, '-a', account]);
  }
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
