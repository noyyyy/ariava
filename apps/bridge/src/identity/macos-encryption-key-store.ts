import { randomUUID } from 'node:crypto';
import { isAbsolute, resolve } from 'node:path';
import { base64UrlDecode, base64UrlEncode, isCanonicalTimestamp } from '@ariava/protocol';
import { pathHasFilesystemEvidence, readSecureJson, removeSecureFile, writeSecureJson, writeSecureJsonExclusive } from '../host-manager/secure-files';
import { HostIdentityError } from './errors';
import {
  isKeychainLocked,
  isKeychainMissing,
  MACOS_SECURITY_PATH,
  SpawnKeychainCommandRunner,
  type KeychainCommandRunner,
} from './macos-keychain-store';
import {
  assertCanonicalHostId,
  generateHostEncryptionIdentity,
  importHostEncryptionPrivateKey,
  type HostEncryptionIdentity,
} from './host-encryption-key';

export const MACOS_ENCRYPTION_KEYCHAIN_SERVICE = 'io.noyx.ariava.host-e2e-key' as const;

interface MacEncryptionIdentityMetadata {
  version: 1;
  hostId: string;
  encryptionKeyId: string;
  publicKey: string;
  sequence: number;
  createdAt: string;
  account: string;
}
interface MacEncryptionMetadataV2 {
  version: 2;
  hostId: string;
  currentKeyId: string;
  identities: MacEncryptionIdentityMetadata[];
}
interface MacEncryptionResetSentinelV2 {
  schema: 'ariava-macos-encryption-reset-v2';
  phase: 'prepared';
  operationId: string;
  candidate: MacEncryptionIdentityMetadata;
  previousAccounts: string[];
}
interface MacEncryptionResetSentinelV1 {
  schema: 'ariava-macos-encryption-reset-v1';
  phase: 'prepared';
  operationId: string;
  candidate: MacEncryptionIdentityMetadata;
  previousAccount: string | null;
}

interface MacEncryptionPruneJournalV1 {
  schema: 'ariava-macos-encryption-prune-v1';
  phase: 'prepared';
  hostId: string;
  currentKeyId: string;
  identities: MacEncryptionIdentityMetadata[];
}

export interface MacOSEncryptionResetHooks {
  afterResetSentinel?(): void;
  afterResetKeyWrite?(): void;
  afterResetMetadataWrite?(): void;
  afterPruneJournal?(): void;
  afterPruneDelete?(account: string): void;
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
    const state = this.loadState();
    if (!state) return null;
    return this.loadIdentity(state.identities.find((identity) => identity.encryptionKeyId === state.currentKeyId)!);
  }

  identity(encryptionKeyId: string): HostEncryptionIdentity | null {
    const state = this.loadState();
    const metadata = state?.identities.find((identity) => identity.encryptionKeyId === encryptionKeyId);
    return metadata ? this.loadIdentity(metadata) : null;
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
    const candidate = metadata(identity);
    this.writeItem(candidate.account, identity.privateKeyPkcs8, false);
    try { writeSecureJsonExclusive(this.metadataPath, stateFor(candidate)); }
    catch (error) { this.deleteItem(candidate.account); throw new HostIdentityError('ERR_IDENTITY_PERMISSIONS', 'Could not persist macOS encryption metadata', error); }
    return this.loadRequired(hostId);
  }

  replaceCurrent(hostId: string): HostEncryptionIdentity {
    assertCanonicalHostId(hostId);
    const state = this.loadState();
    if (!state || state.hostId !== hostId) throw new HostIdentityError('ERR_IDENTITY_INVALID', 'Encryption key belongs to another Host');
    const sequence = Math.max(...state.identities.map((identity) => identity.sequence)) + 1;
    const identity = generateHostEncryptionIdentity(hostId, sequence);
    const candidate = metadata(identity);
    this.writeItem(candidate.account, identity.privateKeyPkcs8, false);
    try {
      writeSecureJson(this.metadataPath, { ...state, currentKeyId: candidate.encryptionKeyId, identities: [...state.identities, candidate] } satisfies MacEncryptionMetadataV2);
      return this.loadRequired(hostId);
    } catch (error) {
      this.deleteItem(candidate.account);
      throw new HostIdentityError('ERR_IDENTITY_PERMISSIONS', 'Could not rotate macOS Host encryption key', error);
    }
  }

  prune(referencedKeyIds: ReadonlySet<string>): string[] {
    const state = this.loadState();
    if (!state) return [];
    const removable = state.identities.filter((identity) => identity.encryptionKeyId !== state.currentKeyId && !referencedKeyIds.has(identity.encryptionKeyId));
    if (!removable.length) return [];
    const journal = {
      schema: 'ariava-macos-encryption-prune-v1', phase: 'prepared', hostId: state.hostId,
      currentKeyId: state.currentKeyId, identities: removable,
    } satisfies MacEncryptionPruneJournalV1;
    this.writePruneJournal(journal);
    this.resetHooks.afterPruneJournal?.();
    this.finishPrune(state, journal);
    return removable.map((identity) => identity.encryptionKeyId);
  }

  replaceForReset(hostId: string, operationId?: string): HostEncryptionIdentity {
    assertCanonicalHostId(hostId);
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
    const previous = this.loadState();
    const identity = generateHostEncryptionIdentity(hostId);
    const candidate = metadata(identity);
    const sentinel = {
      schema: 'ariava-macos-encryption-reset-v2', phase: 'prepared', operationId: resetOperationId,
      candidate, previousAccounts: previous?.identities.map((item) => item.account) ?? [],
    } satisfies MacEncryptionResetSentinelV2;
    this.writeResetSentinel(sentinel);
    this.resetHooks.afterResetSentinel?.();
    this.writeItem(candidate.account, identity.privateKeyPkcs8, false);
    this.resetHooks.afterResetKeyWrite?.();
    const recovered = this.finishReset(sentinel);
    if (!operationId) this.completeReset(resetOperationId);
    return recovered;
  }

  recoverReset(hostId: string, operationId: string): HostEncryptionIdentity | null {
    assertCanonicalHostId(hostId);
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
    if (sentinel.operationId !== operationId) throw new HostIdentityError('ERR_IDENTITY_RESET_REQUIRED', 'macOS encryption reset evidence belongs to another operation');
    try { removeSecureFile(this.resetSentinelPath()); }
    catch (error) { throw new HostIdentityError('ERR_IDENTITY_PERMISSIONS', 'Could not clear macOS encryption reset evidence', error); }
  }

  deleteAfterHostReplacement(encryptionKeyId: string): void {
    assertEncryptionKeyId(encryptionKeyId);
    this.deleteItem(`host-e2e:${encryptionKeyId}`);
  }

  private finishReset(sentinel: MacEncryptionResetSentinelV2): HostEncryptionIdentity {
    let effective = sentinel;
    let privateKeyPkcs8: Uint8Array;
    try {
      privateKeyPkcs8 = this.readItem(effective.candidate.account);
    } catch (error) {
      if (!(error instanceof HostIdentityError) || error.code !== 'ERR_IDENTITY_MISSING') throw error;
      const replacement = generateHostEncryptionIdentity(effective.candidate.hostId, effective.candidate.sequence);
      effective = { ...effective, candidate: metadata(replacement) };
      this.rewriteResetSentinel(effective);
      this.resetHooks.afterResetSentinel?.();
      this.writeItem(effective.candidate.account, replacement.privateKeyPkcs8, false);
      this.resetHooks.afterResetKeyWrite?.();
      privateKeyPkcs8 = replacement.privateKeyPkcs8;
    }
    importHostEncryptionPrivateKey({ ...effective.candidate, privateKeyPkcs8 });
    try {
      writeSecureJson(this.metadataPath, stateFor(effective.candidate));
      this.resetHooks.afterResetMetadataWrite?.();
      const loaded = this.loadRequired(effective.candidate.hostId);
      for (const account of effective.previousAccounts) if (account !== effective.candidate.account) this.deleteItem(account);
      return loaded;
    } catch (error) {
      if (error instanceof HostIdentityError) throw error;
      throw new HostIdentityError('ERR_IDENTITY_PERMISSIONS', 'Could not replace macOS encryption metadata', error);
    }
  }

  private loadState(): MacEncryptionMetadataV2 | null {
    this.recoverPendingPrune();
    if (!pathHasFilesystemEvidence(this.metadataPath)) return null;
    try {
      const raw = readSecureJson<unknown>(this.metadataPath);
      const state = decodeState(raw);
      for (const item of state.identities) this.loadIdentity(item);
      if (isIdentityMetadata(raw)) writeSecureJson(this.metadataPath, state);
      return state;
    } catch (error) {
      if (error instanceof HostIdentityError) throw error;
      throw new HostIdentityError('ERR_IDENTITY_INVALID', 'macOS Host encryption key is unavailable or corrupt', error);
    }
  }

  private loadIdentity(value: MacEncryptionIdentityMetadata): HostEncryptionIdentity {
    const privateKeyPkcs8 = this.readItem(value.account);
    const identity = { ...value, privateKeyPkcs8 } satisfies HostEncryptionIdentity;
    importHostEncryptionPrivateKey(identity);
    return identity;
  }
  private loadRequired(hostId: string): HostEncryptionIdentity {
    const loaded = this.load();
    if (!loaded || loaded.hostId !== hostId) throw new HostIdentityError('ERR_IDENTITY_INVALID', 'Persisted encryption key verification failed');
    return loaded;
  }
  private resetSentinelPath(): string { return `${this.metadataPath}.resetting`; }
  private pruneJournalPath(): string { return `${this.metadataPath}.pruning`; }
  private readResetSentinelIfPresent(): MacEncryptionResetSentinelV2 | undefined {
    try {
      if (!pathHasFilesystemEvidence(this.resetSentinelPath())) return undefined;
      const value = readSecureJson<unknown>(this.resetSentinelPath());
      if (validResetSentinel(value)) return value;
      if (validLegacyResetSentinel(value)) {
        return {
          schema: 'ariava-macos-encryption-reset-v2', phase: 'prepared', operationId: value.operationId,
          candidate: value.candidate, previousAccounts: value.previousAccount ? [value.previousAccount] : [],
        };
      }
      throw new Error('invalid reset sentinel');
    } catch (error) { throw new HostIdentityError('ERR_IDENTITY_RESET_REQUIRED', 'macOS encryption reset evidence is invalid', error); }
  }
  private writeResetSentinel(value: MacEncryptionResetSentinelV2): void {
    try { writeSecureJsonExclusive(this.resetSentinelPath(), value); }
    catch (error) { throw new HostIdentityError('ERR_IDENTITY_PERMISSIONS', 'Could not durably mark macOS encryption reset', error); }
  }
  private rewriteResetSentinel(value: MacEncryptionResetSentinelV2): void {
    try { writeSecureJson(this.resetSentinelPath(), value); }
    catch (error) { throw new HostIdentityError('ERR_IDENTITY_PERMISSIONS', 'Could not rewrite macOS encryption reset candidate', error); }
  }
  private writePruneJournal(value: MacEncryptionPruneJournalV1): void {
    try { writeSecureJsonExclusive(this.pruneJournalPath(), value); }
    catch (error) { throw new HostIdentityError('ERR_IDENTITY_PERMISSIONS', 'Could not durably schedule macOS encryption key pruning', error); }
  }
  private recoverPendingPrune(): void {
    if (!pathHasFilesystemEvidence(this.pruneJournalPath())) return;
    try {
      const journal = readSecureJson<unknown>(this.pruneJournalPath());
      if (!validPruneJournal(journal) || !pathHasFilesystemEvidence(this.metadataPath)) throw new TypeError('invalid prune journal');
      const state = decodeState(readSecureJson<unknown>(this.metadataPath));
      if (journal.hostId !== state.hostId || journal.currentKeyId !== state.currentKeyId) {
        throw new TypeError('prune journal does not match metadata');
      }
      const scheduledPresent = journal.identities.filter((scheduled) =>
        state.identities.some((identity) => sameIdentityMetadata(identity, scheduled)),
      ).length;
      if (scheduledPresent === 0) {
        removeSecureFile(this.pruneJournalPath());
        return;
      }
      if (scheduledPresent !== journal.identities.length) throw new TypeError('prune journal metadata is partially committed');
      this.finishPrune(state, journal);
    } catch (error) {
      if (error instanceof HostIdentityError) throw error;
      throw new HostIdentityError('ERR_IDENTITY_RESET_REQUIRED', 'macOS encryption prune evidence is invalid', error);
    }
  }
  private finishPrune(state: MacEncryptionMetadataV2, journal: MacEncryptionPruneJournalV1): void {
    const removed = new Set(journal.identities.map((identity) => identity.encryptionKeyId));
    for (const identity of journal.identities) {
      this.deleteItem(identity.account);
      this.resetHooks.afterPruneDelete?.(identity.account);
    }
    try {
      writeSecureJson(this.metadataPath, { ...state, identities: state.identities.filter((identity) => !removed.has(identity.encryptionKeyId)) });
      removeSecureFile(this.pruneJournalPath());
    } catch (error) {
      throw new HostIdentityError('ERR_IDENTITY_PERMISSIONS', 'Could not commit macOS encryption key pruning', error);
    }
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
      if (isKeychainLocked(result)) throw new HostIdentityError('ERR_IDENTITY_KEYCHAIN_LOCKED', 'macOS login Keychain is locked or unavailable in this session.');
      if (isKeychainMissing(result)) throw new HostIdentityError('ERR_IDENTITY_MISSING', 'macOS encryption Keychain item is missing');
      throw new HostIdentityError('ERR_IDENTITY_PERMISSIONS', 'macOS encryption Keychain read failed');
    }
    const encoded = Buffer.from(result.stdout).toString('utf8').trimEnd();
    if (!/^(?:[0-9a-f]{2})+$/iu.test(encoded)) throw new HostIdentityError('ERR_IDENTITY_INVALID', 'macOS encryption Keychain encoding is invalid');
    return base64UrlDecode(base64UrlEncode(Buffer.from(encoded, 'hex')), undefined, 'X25519 PKCS#8');
  }
  private deleteItem(account: string): void {
    assertSafeKeychainIdentifier(account, 'account');
    const result = this.runner.run(MACOS_SECURITY_PATH, ['delete-generic-password', '-s', MACOS_ENCRYPTION_KEYCHAIN_SERVICE, '-a', account]);
    if (result.status === 0 && !result.error) return;
    if (isKeychainMissing(result)) return;
    if (isKeychainLocked(result)) throw new HostIdentityError('ERR_IDENTITY_KEYCHAIN_LOCKED', 'macOS login Keychain is locked or unavailable in this session.');
    throw new HostIdentityError('ERR_IDENTITY_PERMISSIONS', 'macOS encryption Keychain delete failed');
  }
}

function stateFor(identity: MacEncryptionIdentityMetadata): MacEncryptionMetadataV2 {
  return { version: 2, hostId: identity.hostId, currentKeyId: identity.encryptionKeyId, identities: [identity] };
}
function metadata(identity: HostEncryptionIdentity): MacEncryptionIdentityMetadata {
  const { privateKeyPkcs8: _private, ...publicFields } = identity;
  return { ...publicFields, account: keychainAccount(identity) };
}
function decodeState(value: unknown): MacEncryptionMetadataV2 {
  if (isIdentityMetadata(value)) return stateFor(value);
  if (!isPlainRecord(value) || !exactKeys(value, ['version', 'hostId', 'currentKeyId', 'identities']) || value.version !== 2
    || typeof value.hostId !== 'string' || !isCanonicalHostId(value.hostId) || typeof value.currentKeyId !== 'string' || !Array.isArray(value.identities)
    || value.identities.length < 1 || value.identities.some((identity) => !isIdentityMetadata(identity))) throw new TypeError('invalid encryption metadata');
  const identities = value.identities as MacEncryptionIdentityMetadata[];
  const ids = new Set<string>(); const sequences = new Set<number>();
  for (const item of identities) {
    if (item.hostId !== value.hostId || ids.has(item.encryptionKeyId) || sequences.has(item.sequence)) throw new TypeError('ambiguous encryption metadata');
    ids.add(item.encryptionKeyId); sequences.add(item.sequence);
  }
  const current = identities.find((identity) => identity.encryptionKeyId === value.currentKeyId);
  if (!current || current.sequence !== Math.max(...identities.map((identity) => identity.sequence))) throw new TypeError('encryption metadata rollback detected');
  return { version: 2, hostId: value.hostId, currentKeyId: value.currentKeyId, identities };
}
function isIdentityMetadata(value: unknown): value is MacEncryptionIdentityMetadata {
  if (!isPlainRecord(value) || !exactKeys(value, ['version', 'hostId', 'encryptionKeyId', 'publicKey', 'sequence', 'createdAt', 'account'])) return false;
  return value.version === 1 && typeof value.hostId === 'string' && isCanonicalHostId(value.hostId)
    && typeof value.encryptionKeyId === 'string'
    && value.account === `host-e2e:${value.encryptionKeyId}` && /^ekey_[A-Za-z0-9_-]{43}$/u.test(value.encryptionKeyId)
    && typeof value.publicKey === 'string' && Number.isSafeInteger(value.sequence) && (value.sequence as number) > 0
    && typeof value.createdAt === 'string' && isCanonicalTimestamp(value.createdAt);
}
function validResetSentinel(value: unknown): value is MacEncryptionResetSentinelV2 {
  if (!isPlainRecord(value) || !exactKeys(value, ['schema', 'phase', 'operationId', 'candidate', 'previousAccounts'])) return false;
  return value.schema === 'ariava-macos-encryption-reset-v2' && value.phase === 'prepared'
    && typeof value.operationId === 'string' && /^[A-Za-z0-9_-]{1,128}$/u.test(value.operationId)
    && isIdentityMetadata(value.candidate) && Array.isArray(value.previousAccounts)
    && new Set(value.previousAccounts).size === value.previousAccounts.length
    && value.previousAccounts.every((account) => typeof account === 'string' && /^host-e2e:ekey_[A-Za-z0-9_-]{43}$/u.test(account));
}
function validLegacyResetSentinel(value: unknown): value is MacEncryptionResetSentinelV1 {
  if (!isPlainRecord(value) || !exactKeys(value, ['schema', 'phase', 'operationId', 'candidate', 'previousAccount'])) return false;
  return value.schema === 'ariava-macos-encryption-reset-v1' && value.phase === 'prepared'
    && typeof value.operationId === 'string' && /^[A-Za-z0-9_-]{1,128}$/u.test(value.operationId)
    && isIdentityMetadata(value.candidate)
    && (value.previousAccount === null || (typeof value.previousAccount === 'string' && /^host-e2e:ekey_[A-Za-z0-9_-]{43}$/u.test(value.previousAccount)));
}
function validPruneJournal(value: unknown): value is MacEncryptionPruneJournalV1 {
  return isPlainRecord(value) && exactKeys(value, ['schema', 'phase', 'hostId', 'currentKeyId', 'identities'])
    && value.schema === 'ariava-macos-encryption-prune-v1' && value.phase === 'prepared'
    && typeof value.hostId === 'string' && isCanonicalHostId(value.hostId) && typeof value.currentKeyId === 'string'
    && Array.isArray(value.identities) && value.identities.length > 0
    && value.identities.every(isIdentityMetadata)
    && new Set(value.identities.map((identity) => identity.encryptionKeyId)).size === value.identities.length
    && value.identities.every((identity) => identity.hostId === value.hostId && identity.encryptionKeyId !== value.currentKeyId);
}
function sameIdentityMetadata(left: MacEncryptionIdentityMetadata, right: MacEncryptionIdentityMetadata): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}
function isCanonicalHostId(value: string): boolean { return /^host_[A-Za-z0-9_-]{43}$/u.test(value); }
function keychainAccount(identity: Pick<HostEncryptionIdentity, 'encryptionKeyId'>): string { return `host-e2e:${identity.encryptionKeyId}`; }
function assertEncryptionKeyId(value: string): void {
  if (!/^ekey_[A-Za-z0-9_-]{43}$/u.test(value)) throw new HostIdentityError('ERR_IDENTITY_INVALID', 'Invalid old Host encryption Keychain account');
}
function assertSafeKeychainIdentifier(value: string, label: string): void {
  if (!/^[A-Za-z0-9_.:-]{1,128}$/u.test(value)) throw new HostIdentityError('ERR_IDENTITY_INVALID', `Unsafe macOS Keychain ${label}`);
}
function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}
function exactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const keys = Object.keys(value);
  return keys.length === expected.length && expected.every((key) => Object.hasOwn(value, key));
}
