import { spawnSync } from 'node:child_process';
import { isAbsolute, resolve } from 'node:path';
import { pathHasFilesystemEvidence, readSecureJson, removeSecureFile, SecureFileError, writeSecureJson, writeSecureJsonExclusive } from '../host-manager/secure-files';
import { HostIdentityError } from './errors';
import {
  generateHostIdentity,
  getHostIdentityPrivateKey,
  importHostIdentityPrivateKey,
  rebindHostIdentity,
} from './host-identity';
import type {
  HostIdentity,
  HostIdentityInspection,
  HostIdentityMetadata,
  HostIdentityStore,
  PendingHostIdentity,
} from './types';

export const MACOS_IDENTITY_KEYCHAIN_SERVICE = 'io.noyx.ariava.host-identity' as const;
export const MACOS_SECURITY_PATH = '/usr/bin/security' as const;
const KEYCHAIN_EVIDENCE_ACCOUNT = '__ariava_identity_index_v1';
const KEYCHAIN_EVIDENCE_VALUE = Buffer.from('ariava-host-identity-evidence-v1');
const CREATION_SENTINEL_SCHEMA = 'ariava-macos-identity-creation-v1' as const;

export interface KeychainCommandResult {
  status: number | null;
  stdout: Uint8Array;
  stderr: string;
  error?: Error;
}

export interface KeychainCommandRunner {
  run(command: string, args: readonly string[], stdin?: Uint8Array): KeychainCommandResult;
}

export class SpawnKeychainCommandRunner implements KeychainCommandRunner {
  run(command: string, args: readonly string[], stdin?: Uint8Array): KeychainCommandResult {
    const result = spawnSync(command, [...args], {
      shell: false,
      input: stdin ? Buffer.from(stdin) : undefined,
      encoding: null,
      maxBuffer: 64 * 1024,
      env: process.env,
    });
    return {
      status: result.status,
      stdout: new Uint8Array(result.stdout ?? []),
      stderr: Buffer.from(result.stderr ?? []).toString('utf8').slice(0, 2_000),
      ...(result.error ? { error: result.error } : {}),
    };
  }
}

interface MacIdentityMetadataFile {
  current: HostIdentityMetadata;
  pending?: { operationId: string; issuedAt: string; identity: HostIdentityMetadata };
}

interface MacIdentityCreationSentinel {
  schema: typeof CREATION_SENTINEL_SCHEMA;
  phase: 'creating';
  hostId: string;
  keyId: string;
}

export interface MacOSIdentityCreationHooks {
  afterSentinel?(): void;
  afterKeyWrite?(): void;
  afterKeyVerification?(): void;
  afterIndexWrite?(): void;
  afterMetadataWrite?(): void;
}

export class MacOSKeychainHostIdentityStore implements HostIdentityStore {
  readonly metadataPath: string;

  constructor(
    metadataPath: string,
    private readonly runner: KeychainCommandRunner = new SpawnKeychainCommandRunner(),
    private readonly creationHooks: MacOSIdentityCreationHooks = {},
  ) {
    if (!isAbsolute(metadataPath)) throw new HostIdentityError('ERR_IDENTITY_PERMISSIONS', 'macOS identity metadata path must be absolute');
    this.metadataPath = resolve(metadataPath);
  }

  async inspect(): Promise<HostIdentityInspection> {
    const reference = (account: string) => ({
      type: 'macos-keychain' as const, service: MACOS_IDENTITY_KEYCHAIN_SERVICE, account,
    });
    const base = {
      storageType: 'macos-keychain' as const,
      storageReference: reference('(not-initialized)'),
      ownerIntegrity: false,
      permissionIntegrity: false,
      metadataIntegrity: false,
      pendingRotation: false,
    };
    if (!this.metadataEvidence()) {
      return this.hasCreationSentinel() || this.hasIndexEvidence()
        ? { ...base, status: 'invalid' }
        : { ...base, status: 'not-initialized' };
    }
    try {
      const metadata = this.readMetadata();
      const identity = await this.loadItem(metadata.current);
      if (metadata.pending) await this.loadItem(metadata.pending.identity);
      return {
        ...base,
        status: metadata.pending ? 'rotation-pending' : 'ready',
        storageReference: metadata.current.privateKeyStorage,
        ownerIntegrity: true,
        permissionIntegrity: true,
        metadataIntegrity: true,
        pendingRotation: Boolean(metadata.pending),
        hostId: identity.hostId,
        keyId: identity.keyId,
        algorithm: identity.algorithm,
        publicKeyFingerprint: identity.publicKeyFingerprint,
        pendingOperationId: metadata.pending?.operationId,
      };
    } catch {
      return { ...base, status: 'invalid' };
    }
  }

  async load(): Promise<HostIdentity | null> {
    const creationInterrupted = this.hasCreationSentinel();
    if (!this.metadataEvidence()) {
      if (creationInterrupted || this.hasIndexEvidence()) {
        throw new HostIdentityError('ERR_IDENTITY_RESET_REQUIRED', 'Incomplete macOS identity creation requires explicit reset');
      }
      return null;
    }
    try {
      const metadata = this.readMetadata();
      const current = await this.loadItem(metadata.current, true);
      if (metadata.pending) await this.loadItem(metadata.pending.identity);
      if (creationInterrupted) this.deleteCreationSentinel();
      return current;
    } catch (error) {
      if (creationInterrupted) {
        throw new HostIdentityError('ERR_IDENTITY_RESET_REQUIRED', 'Incomplete macOS identity creation requires explicit reset', error);
      }
      throw error;
    }
  }

  async loadPending(): Promise<PendingHostIdentity | null> {
    if (!this.metadataEvidence()) return null;
    const metadata = this.readMetadata();
    if (!metadata.pending) return null;
    return {
      operationId: metadata.pending.operationId,
      issuedAt: metadata.pending.issuedAt,
      identity: await this.loadItem(metadata.pending.identity),
    };
  }

  async createFirstRun(): Promise<HostIdentity> {
    if (this.metadataEvidence() || this.hasCreationSentinel() || this.hasIndexEvidence()) {
      throw new HostIdentityError('ERR_IDENTITY_RESET_REQUIRED', 'Host identity evidence already exists; explicit reset is required');
    }
    const generated = await generateHostIdentity({ type: 'macos-keychain', service: MACOS_IDENTITY_KEYCHAIN_SERVICE, account: 'pending-first-run' });
    const metadata = withKeychainStorage(generated.identity, generated.identity.hostId);
    this.writeCreationSentinel(metadata);
    let metadataCreated = false;
    let keyCreated = false;
    let indexCreated = false;
    try {
      this.creationHooks.afterSentinel?.();
      this.writeItem(metadata.hostId, generated.privateKeyPkcs8, false);
      keyCreated = true;
      this.creationHooks.afterKeyWrite?.();
      const verified = await this.loadItem(metadata, true);
      this.creationHooks.afterKeyVerification?.();
      this.writeItem(KEYCHAIN_EVIDENCE_ACCOUNT, KEYCHAIN_EVIDENCE_VALUE, false);
      indexCreated = true;
      this.creationHooks.afterIndexWrite?.();
      this.writeMetadata({ current: publicMetadata(verified) }, true);
      metadataCreated = true;
      this.creationHooks.afterMetadataWrite?.();
      this.deleteCreationSentinel();
      return rebindHostIdentity(verified, metadata);
    } catch (error) {
      if (!metadataCreated) {
        // Roll back only if every created Keychain item can be removed. Otherwise retain the
        // sentinel so restart can never mistake partial identity evidence for a fresh install.
        if (keyCreated) this.tryDeleteItem(metadata.hostId);
        if (indexCreated) this.tryDeleteItem(KEYCHAIN_EVIDENCE_ACCOUNT);
        // Keep the durable marker: restart requires explicit reset rather than replacement.
      }
      // Once metadata is durable, retain the complete transaction. load() validates it and
      // clears the leftover sentinel; createFirstRun() can never silently replace it.
      throw error;
    }
  }

  async stageRotation(next: PendingHostIdentity): Promise<void> {
    const metadata = this.readMetadata();
    if (next.identity.hostId !== metadata.current.hostId) throw new HostIdentityError('ERR_IDENTITY_INVALID', 'Rotation must preserve the Host entity ID');
    const pendingAccount = `${metadata.current.hostId}.pending`;
    const pending = withKeychainStorage(next.identity, pendingAccount);
    if (metadata.pending) {
      if (metadata.pending.operationId !== next.operationId) throw new HostIdentityError('ERR_IDENTITY_RESET_REQUIRED', 'A different Host key rotation is already pending');
      if (!samePending(metadata.pending, { operationId: next.operationId, issuedAt: next.issuedAt, identity: publicMetadata(pending) })) {
        throw new HostIdentityError('ERR_IDENTITY_INVALID', 'Rotation retry payload does not match the pending operation');
      }
      await this.loadItem(metadata.pending.identity);
      return;
    }
    const bytes = getHostIdentityPrivateKey(next.identity);
    // Validate the exact payload before creating or replacing any pending evidence.
    await importHostIdentityPrivateKey(bytes, pending.privateKeyStorage, pending.createdAt, pending);
    if (this.itemExists(pendingAccount)) throw new HostIdentityError('ERR_IDENTITY_RESET_REQUIRED', 'Orphan pending Keychain item requires explicit reset');
    this.writeItem(pendingAccount, bytes, false);
    try {
      await this.loadItem(pending);
      this.writeMetadata({ current: metadata.current, pending: { operationId: next.operationId, issuedAt: next.issuedAt, identity: publicMetadata(pending) } });
    } catch (error) {
      this.tryDeleteItem(pendingAccount);
      throw error;
    }
  }

  async abortRotation(operationId: string): Promise<void> {
    const metadata = this.readMetadata();
    if (!metadata.pending || metadata.pending.operationId !== operationId) throw new HostIdentityError('ERR_IDENTITY_INVALID', 'Pending Host key rotation does not match operation ID');
    this.writeMetadata({ current: metadata.current });
    const storage = metadata.pending.identity.privateKeyStorage;
    if (storage.type !== 'macos-keychain') throw new HostIdentityError('ERR_IDENTITY_INVALID', 'Pending Keychain storage reference is invalid');
    this.deleteItem(storage.account);
  }

  async promoteRotation(operationId: string): Promise<HostIdentity> {
    const metadata = this.readMetadata();
    if (!metadata.pending || metadata.pending.operationId !== operationId) throw new HostIdentityError('ERR_IDENTITY_INVALID', 'Pending Host key rotation does not match operation ID');
    const pendingStorage = metadata.pending.identity.privateKeyStorage;
    if (pendingStorage.type !== 'macos-keychain') throw new HostIdentityError('ERR_IDENTITY_INVALID', 'Pending Keychain storage reference is invalid');
    const pendingKey = this.readItem(pendingStorage.account);
    const promotedMetadata = withKeychainStorage(metadata.pending.identity, metadata.current.hostId);
    await importHostIdentityPrivateKey(pendingKey, promotedMetadata.privateKeyStorage, promotedMetadata.createdAt, promotedMetadata);
    // Preserve metadata+pending if replacing current or metadata persistence fails.
    const oldKey = this.readItem(metadata.current.hostId);
    this.writeItem(metadata.current.hostId, pendingKey, true);
    try {
      const promoted = await this.loadItem(promotedMetadata, true);
      this.writeMetadata({ current: publicMetadata(promoted) });
      this.deleteItem(pendingStorage.account);
      return promoted;
    } catch (error) {
      try { this.writeItem(metadata.current.hostId, oldKey, true); } catch {}
      throw error;
    }
  }

  async resetAfterExplicitConfirmation(): Promise<HostIdentity> {
    const previous = this.metadataEvidence() ? this.readMetadata() : undefined;
    const interrupted = this.readCreationSentinelIfPresent();
    const generated = await generateHostIdentity({ type: 'macos-keychain', service: MACOS_IDENTITY_KEYCHAIN_SERVICE, account: 'pending-reset' });
    const metadata = withKeychainStorage(generated.identity, generated.identity.hostId);
    this.writeItem(metadata.hostId, generated.privateKeyPkcs8, true);
    const verified = await this.loadItem(metadata, true);
    this.writeItem(KEYCHAIN_EVIDENCE_ACCOUNT, KEYCHAIN_EVIDENCE_VALUE, true);
    this.writeMetadata({ current: publicMetadata(verified) }, !this.metadataEvidence());
    if (previous && previous.current.hostId !== metadata.hostId) this.deleteItem(previous.current.hostId);
    if (previous?.pending && previous.pending.identity.privateKeyStorage.type === 'macos-keychain') this.deleteItem(previous.pending.identity.privateKeyStorage.account);
    if (interrupted && interrupted.hostId !== metadata.hostId) this.tryDeleteItem(interrupted.hostId);
    if (interrupted) this.deleteCreationSentinel();
    return verified;
  }

  private async loadItem(metadata: HostIdentityMetadata, current = false): Promise<HostIdentity> {
    if (metadata.privateKeyStorage.type !== 'macos-keychain') throw new HostIdentityError('ERR_IDENTITY_INVALID', 'Host identity storage reference is invalid');
    if (metadata.privateKeyStorage.service !== MACOS_IDENTITY_KEYCHAIN_SERVICE) throw new HostIdentityError('ERR_IDENTITY_INVALID', 'Host identity Keychain service is invalid');
    if (current && metadata.privateKeyStorage.account !== metadata.hostId) throw new HostIdentityError('ERR_IDENTITY_INVALID', 'Current Keychain account must equal hostId');
    const key = this.readItem(metadata.privateKeyStorage.account);
    return (await importHostIdentityPrivateKey(key, metadata.privateKeyStorage, metadata.createdAt, metadata)).identity;
  }

  private writeItem(account: string, value: Uint8Array, update: boolean): void {
    const command = `add-generic-password${update ? ' -U' : ''} -s ${quoteSecurity(MACOS_IDENTITY_KEYCHAIN_SERVICE)} -a ${quoteSecurity(account)} -X ${Buffer.from(value).toString('hex')}\n`;
    const result = this.runner.run(MACOS_SECURITY_PATH, ['-i'], Buffer.from(command, 'utf8'));
    if (result.status !== 0 || result.error) this.failKeychain('write', result);
  }

  private readItem(account: string): Uint8Array {
    const result = this.runner.run(MACOS_SECURITY_PATH, ['find-generic-password', '-s', MACOS_IDENTITY_KEYCHAIN_SERVICE, '-a', account, '-w']);
    if (result.status !== 0 || result.error || result.stdout.byteLength === 0) this.failKeychain('read', result, true);
    return decodeSecurityPassword(result.stdout);
  }

  private itemExists(account: string): boolean {
    const result = this.runner.run(MACOS_SECURITY_PATH, ['find-generic-password', '-s', MACOS_IDENTITY_KEYCHAIN_SERVICE, '-a', account, '-w']);
    if (result.status === 0 && !result.error && result.stdout.byteLength > 0) return true;
    if (isKeychainMissing(result)) return false;
    this.failKeychain('probe', result);
  }

  private hasIndexEvidence(): boolean { return this.itemExists(KEYCHAIN_EVIDENCE_ACCOUNT); }

  private deleteItem(account: string): void {
    const result = this.runner.run(MACOS_SECURITY_PATH, ['delete-generic-password', '-s', MACOS_IDENTITY_KEYCHAIN_SERVICE, '-a', account]);
    if (result.status !== 0 && !isKeychainMissing(result)) this.failKeychain('delete', result);
  }

  private tryDeleteItem(account: string): boolean {
    try { this.deleteItem(account); return true; } catch { return false; }
  }

  private failKeychain(action: string, result: KeychainCommandResult, missing = false): never {
    const code = missing && isKeychainMissing(result) ? 'ERR_IDENTITY_MISSING' : 'ERR_IDENTITY_PERMISSIONS';
    throw new HostIdentityError(code, `macOS Keychain Host identity ${action} failed`);
  }

  private metadataEvidence(): boolean {
    try { return pathHasFilesystemEvidence(this.metadataPath); }
    catch (error) { throw new HostIdentityError('ERR_IDENTITY_PERMISSIONS', 'Could not inspect macOS identity metadata', error); }
  }

  private creationSentinelPath(): string {
    return `${this.metadataPath}.creating`;
  }

  private hasCreationSentinel(): boolean {
    return this.readCreationSentinelIfPresent() !== undefined;
  }

  private readCreationSentinelIfPresent(): MacIdentityCreationSentinel | undefined {
    try {
      if (!pathHasFilesystemEvidence(this.creationSentinelPath())) return undefined;
      const value = readSecureJson<MacIdentityCreationSentinel>(this.creationSentinelPath());
      if (value?.schema !== CREATION_SENTINEL_SCHEMA || value.phase !== 'creating'
        || typeof value.hostId !== 'string' || typeof value.keyId !== 'string') {
        throw new Error('invalid creation sentinel');
      }
      return value;
    } catch (error) {
      throw new HostIdentityError('ERR_IDENTITY_RESET_REQUIRED', 'macOS identity creation sentinel requires explicit reset', error);
    }
  }

  private writeCreationSentinel(metadata: HostIdentityMetadata): void {
    try {
      writeSecureJsonExclusive(this.creationSentinelPath(), {
        schema: CREATION_SENTINEL_SCHEMA, phase: 'creating', hostId: metadata.hostId, keyId: metadata.keyId,
      });
    } catch (error) {
      throw new HostIdentityError('ERR_IDENTITY_PERMISSIONS', 'Could not durably mark macOS identity creation', error);
    }
  }

  private deleteCreationSentinel(): void {
    try {
      const path = this.creationSentinelPath();
      if (pathHasFilesystemEvidence(path)) removeSecureFile(path);
    } catch (error) {
      throw new HostIdentityError('ERR_IDENTITY_PERMISSIONS', 'Could not clear macOS identity creation marker', error);
    }
  }

  private readMetadata(): MacIdentityMetadataFile {
    try {
      const value = readSecureJson<MacIdentityMetadataFile>(this.metadataPath);
      if (!isMetadata(value)) throw new Error('invalid schema');
      return value;
    } catch (error) {
      if (error instanceof HostIdentityError) throw error;
      const code = error instanceof SecureFileError ? 'ERR_IDENTITY_PERMISSIONS' : 'ERR_IDENTITY_INVALID';
      throw new HostIdentityError(code, 'macOS Host identity metadata is invalid', error);
    }
  }

  private writeMetadata(metadata: MacIdentityMetadataFile, exclusive = false): void {
    try {
      if (exclusive) writeSecureJsonExclusive(this.metadataPath, metadata);
      else writeSecureJson(this.metadataPath, metadata);
    } catch (error) {
      throw new HostIdentityError('ERR_IDENTITY_PERMISSIONS', 'Could not securely persist Host identity metadata', error);
    }
  }
}

function withKeychainStorage(identity: HostIdentityMetadata, account: string): HostIdentityMetadata {
  return { ...publicMetadata(identity), privateKeyStorage: { type: 'macos-keychain', service: MACOS_IDENTITY_KEYCHAIN_SERVICE, account } };
}

function publicMetadata(identity: HostIdentityMetadata): HostIdentityMetadata {
  return {
    identityVersion: identity.identityVersion, hostId: identity.hostId, keyId: identity.keyId,
    algorithm: identity.algorithm, publicKey: identity.publicKey, publicKeyFingerprint: identity.publicKeyFingerprint,
    createdAt: identity.createdAt, privateKeyStorage: identity.privateKeyStorage,
  };
}

function isMetadata(value: MacIdentityMetadataFile): boolean {
  if (!value || typeof value !== 'object' || !isPublicIdentityMetadata(value.current)) return false;
  if (value.current.privateKeyStorage.account !== value.current.hostId) return false;
  if (!value.pending) return true;
  return typeof value.pending.operationId === 'string' && typeof value.pending.issuedAt === 'string'
    && isPublicIdentityMetadata(value.pending.identity) && value.pending.identity.hostId === value.current.hostId
    && value.pending.identity.privateKeyStorage.account === `${value.current.hostId}.pending`;
}

function isPublicIdentityMetadata(value: HostIdentityMetadata): boolean {
  return Boolean(value && value.identityVersion === 2 && value.algorithm === 'Ed25519'
    && typeof value.hostId === 'string' && typeof value.keyId === 'string' && typeof value.publicKey === 'string'
    && typeof value.publicKeyFingerprint === 'string' && typeof value.createdAt === 'string'
    && value.privateKeyStorage?.type === 'macos-keychain' && value.privateKeyStorage.service === MACOS_IDENTITY_KEYCHAIN_SERVICE);
}

function samePending(left: MacIdentityMetadataFile['pending'], right: NonNullable<MacIdentityMetadataFile['pending']>): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

function decodeSecurityPassword(stdout: Uint8Array): Uint8Array {
  const encoded = Buffer.from(stdout).toString('utf8').trimEnd();
  if (!/^(?:[0-9a-f]{2})+$/iu.test(encoded)) {
    throw new HostIdentityError('ERR_IDENTITY_INVALID', 'macOS Keychain Host identity encoding is invalid');
  }
  return new Uint8Array(Buffer.from(encoded, 'hex'));
}

function isKeychainMissing(result: KeychainCommandResult): boolean {
  return result.status === 44 || /could not be found/iu.test(result.stderr);
}

function quoteSecurity(value: string): string {
  if (!/^[A-Za-z0-9._-]+$/u.test(value)) throw new HostIdentityError('ERR_IDENTITY_INVALID', 'Invalid Keychain item identifier');
  return `\"${value}\"`;
}
