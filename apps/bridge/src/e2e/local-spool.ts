import { createHash, randomBytes } from 'node:crypto';
import { base64UrlDecode, base64UrlEncode, encodeLengthPrefixedFields } from '@ariava/protocol';
import {
  pathHasFilesystemEvidence,
  readSecureJson,
  writeSecureJson,
  writeSecureJsonExclusive,
  type SecureFileWriteHooks,
} from '../host-manager/secure-files';
import { MACOS_SECURITY_PATH, SpawnKeychainCommandRunner, type KeychainCommandRunner } from '../identity/macos-keychain-store';
import { ChaChaPolyAuthenticationError, chachaPolyOpen, chachaPolySeal } from './node-crypto';

const LOCAL_SPOOL_PAYLOAD_KINDS = [
  'event-source-v2',
  'event-reservation-v2',
  'event-dead-letter-v2',
  'session-source-v2',
  'event-upload-v2',
  'session-upload-v2',
  'terminal-cancellation-v2',
] as const;
export type LocalSpoolPayloadKind = typeof LOCAL_SPOOL_PAYLOAD_KINDS[number];
export interface LocalEncryptedPendingPayloadV1 {
  version: 1;
  spoolItemId: string;
  hostId: string;
  sessionId: string;
  eventId?: string;
  payloadKind: LocalSpoolPayloadKind;
  nonce: string;
  ciphertext: string;
  aadVersion: 1;
  createdAt: string;
}
export interface LocalSpoolFileV2 {
  version: 2;
  runtimeStateSchemaVersion: number;
  runtimeResetEpoch: string;
  hostId: string;
  keyId: string;
  items: LocalEncryptedPendingPayloadV1[];
}
interface LinuxSpoolKeyV1 { version: 1; hostId: string; key: string }
interface LinuxSpoolKeyV2 { version: 2; hostId: string; keyId: string; key: string }
interface MacOSSpoolKeyEvidenceV1 { version: 1; hostId: string; account: string }
interface MacOSSpoolKeyEvidenceV2 { version: 2; hostId: string; account: string; keyId: string }
const SERVICE = 'io.noyx.ariava.local-spool-v1';
const encoder = new TextEncoder();

export interface SpoolKeyStore { loadOrCreate(hostId: string, options?: { allowCreate?: boolean }): Uint8Array; }
export interface SpoolRecoveryReport { droppedUnreadableItems: number }

export class LocalSpoolRecoveryRequiredError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'LocalSpoolRecoveryRequiredError';
  }
}

export class LinuxSpoolKeyStore implements SpoolKeyStore {
  constructor(private readonly path: string) {}
  loadOrCreate(hostId: string, options: { allowCreate?: boolean } = {}): Uint8Array {
    if (!pathHasFilesystemEvidence(this.path)) {
      if (options.allowCreate === false) throw new LocalSpoolRecoveryRequiredError('local spool key is missing; recovery is required');
      const key = new Uint8Array(randomBytes(32));
      try {
        writeSecureJsonExclusive(this.path,
          { version: 2, hostId, keyId: spoolKeyIdForKey(key), key: base64UrlEncode(key) } satisfies LinuxSpoolKeyV2);
      } finally { key.fill(0); }
    }
    const record = readSecureJson<LinuxSpoolKeyV1 | LinuxSpoolKeyV2>(this.path);
    if (!record || (record.version !== 1 && record.version !== 2) || record.hostId !== hostId) {
      throw new LocalSpoolRecoveryRequiredError('local spool key metadata is invalid; recovery is required');
    }
    const key = base64UrlDecode(record.key, 32, 'local spool key');
    if (record.version === 2 && record.keyId !== spoolKeyIdForKey(key)) {
      key.fill(0);
      throw new LocalSpoolRecoveryRequiredError('local spool key verifier is invalid; recovery is required');
    }
    return key;
  }
}

export class MacOSSpoolKeyStore implements SpoolKeyStore {
  constructor(
    private readonly evidencePath: string,
    private readonly runner: KeychainCommandRunner = new SpawnKeychainCommandRunner(),
    private readonly evidenceWriteHooks: SecureFileWriteHooks = {},
  ) {}
  loadOrCreate(hostId: string, options: { allowCreate?: boolean } = {}): Uint8Array {
    const account = `host-spool:${hostId}`;
    const existing = this.runner.run(MACOS_SECURITY_PATH, ['find-generic-password', '-s', SERVICE, '-a', account, '-w']);
    if (existing.status === 0 && !existing.error) {
      const key = decodeHex(existing.stdout);
      const keyId = spoolKeyIdForKey(key);
      if (!pathHasFilesystemEvidence(this.evidencePath)) {
        if (options.allowCreate === false) {
          key.fill(0);
          throw new LocalSpoolRecoveryRequiredError('local spool Keychain metadata is missing; recovery is required');
        }
        try {
          writeSecureJsonExclusive(this.evidencePath, { version: 2, hostId, account, keyId } satisfies MacOSSpoolKeyEvidenceV2, undefined, this.evidenceWriteHooks);
        } catch (error) {
          key.fill(0);
          throw new LocalSpoolRecoveryRequiredError('local spool Keychain metadata recovery failed; recovery is required', { cause: error });
        }
        return key;
      }
      const evidence = readSecureJson<MacOSSpoolKeyEvidenceV1 | MacOSSpoolKeyEvidenceV2>(this.evidencePath);
      if (!evidence || (evidence.version !== 1 && evidence.version !== 2) || evidence.hostId !== hostId
        || evidence.account !== account || (evidence.version === 2 && evidence.keyId !== keyId)) {
        key.fill(0);
        throw new LocalSpoolRecoveryRequiredError('local spool Keychain metadata is invalid; recovery is required');
      }
      return key;
    }
    if (options.allowCreate === false || pathHasFilesystemEvidence(this.evidencePath)) {
      throw new LocalSpoolRecoveryRequiredError('local spool Keychain item is missing; recovery is required');
    }
    const key = randomBytes(32);
    const command = `add-generic-password -s '${SERVICE}' -a '${account}' -X ${key.toString('hex')}\n`;
    const result = this.runner.run(MACOS_SECURITY_PATH, ['-i'], encoder.encode(command));
    if (result.status !== 0 || result.error) { key.fill(0); throw new TypeError('local spool Keychain write failed'); }
    writeSecureJsonExclusive(this.evidencePath, {
      version: 2, hostId, account, keyId: spoolKeyIdForKey(key),
    } satisfies MacOSSpoolKeyEvidenceV2, undefined, this.evidenceWriteHooks);
    return new Uint8Array(key);
  }
}

export function createRuntimeSpoolKeyStore(identityPath: string, platform: NodeJS.Platform | string): SpoolKeyStore {
  return platform === 'darwin' ? new MacOSSpoolKeyStore(`${identityPath}.spool.json`)
    : new LinuxSpoolKeyStore(`${identityPath}.spool-key.json`);
}

export class LocalEncryptedSpool {
  private items: LocalEncryptedPendingPayloadV1[];
  private keyId?: string;
  private hasPersistedItems: boolean;
  constructor(
    private readonly path: string,
    private readonly hostId: string,
    private readonly keyStore: SpoolKeyStore,
    private readonly runtimeStateSchemaVersion = 2,
    private readonly runtimeResetEpoch = 'standalone',
    private readonly assertAccess: () => void = () => {},
  ) {
    this.assertAccess();
    const loaded = this.load();
    this.items = loaded.items;
    this.keyId = loaded.keyId;
    this.hasPersistedItems = loaded.keyId !== undefined;
  }

  enqueue(input: { spoolItemId: string; sessionId: string; eventId?: string; payloadKind: LocalSpoolPayloadKind;
    createdAt: string; plaintext: Uint8Array }): LocalEncryptedPendingPayloadV1 {
    this.assertAccess();
    const existing = this.items.find((item) => item.spoolItemId === input.spoolItemId);
    if (existing) {
      if (existing.sessionId !== input.sessionId || existing.eventId !== input.eventId || existing.payloadKind !== input.payloadKind) {
        input.plaintext.fill(0); throw new TypeError('local spool item ID conflict');
      }
      input.plaintext.fill(0);
      return structuredClone(existing);
    }
    const metadata = { version: 1 as const, spoolItemId: input.spoolItemId, hostId: this.hostId,
      sessionId: input.sessionId, ...(input.eventId ? { eventId: input.eventId } : {}), payloadKind: input.payloadKind,
      nonce: '', ciphertext: '', aadVersion: 1 as const, createdAt: input.createdAt };
    const key = this.loadVerifiedKey();
    try {
      const sealed = chachaPolySeal(key, input.plaintext, spoolAAD(metadata));
      const item = { ...metadata, nonce: base64UrlEncode(sealed.nonce), ciphertext: base64UrlEncode(sealed.ciphertext) };
      const nextItems = [...this.items, item];
      this.persist(nextItems);
      this.items = nextItems;
      this.hasPersistedItems = true;
      return structuredClone(item);
    } finally { key.fill(0); input.plaintext.fill(0); }
  }

  list(kind?: LocalSpoolPayloadKind): LocalEncryptedPendingPayloadV1[] {
    this.assertAccess();
    return this.items.filter((item) => !kind || item.payloadKind === kind).map((item) => structuredClone(item));
  }
  get(spoolItemId: string): LocalEncryptedPendingPayloadV1 | undefined {
    this.assertAccess();
    const item = this.items.find((candidate) => candidate.spoolItemId === spoolItemId); return item && structuredClone(item);
  }
  open(item: LocalEncryptedPendingPayloadV1): Uint8Array {
    this.assertAccess();
    const stored = this.items.find((candidate) => candidate.spoolItemId === item.spoolItemId);
    if (!stored || JSON.stringify(stored) !== JSON.stringify(item) || !validItem(item, this.hostId)) throw new TypeError('local spool item is invalid');
    const key = this.loadVerifiedKey();
    try { return chachaPolyOpen(key, base64UrlDecode(item.nonce, 12, 'spool nonce'),
      base64UrlDecode(item.ciphertext, undefined, 'spool ciphertext'), spoolAAD(item)); }
    finally { key.fill(0); }
  }
  replace(removeIds: readonly string[], additions: Array<{ spoolItemId: string; sessionId: string; eventId?: string;
    payloadKind: LocalSpoolPayloadKind; createdAt: string; plaintext: Uint8Array }>): void {
    this.assertAccess();
    const remove = new Set(removeIds);
    let next = this.items.filter((item) => !remove.has(item.spoolItemId));
    const key = this.loadVerifiedKey();
    try {
      for (const input of additions) {
        if (next.some((item) => item.spoolItemId === input.spoolItemId)) throw new TypeError('local spool item ID conflict');
        const metadata = { version: 1 as const, spoolItemId: input.spoolItemId, hostId: this.hostId,
          sessionId: input.sessionId, ...(input.eventId ? { eventId: input.eventId } : {}), payloadKind: input.payloadKind,
          nonce: '', ciphertext: '', aadVersion: 1 as const, createdAt: input.createdAt };
        const sealed = chachaPolySeal(key, input.plaintext, spoolAAD(metadata));
        next = [...next, { ...metadata, nonce: base64UrlEncode(sealed.nonce), ciphertext: base64UrlEncode(sealed.ciphertext) }];
      }
      this.persist(next); this.items = next;
      if (next.length > 0) this.hasPersistedItems = true;
    } finally { key.fill(0); additions.forEach((item) => item.plaintext.fill(0)); }
  }
  remove(spoolItemId: string): void { this.replace([spoolItemId], []); }
  removeMany(spoolItemIds: readonly string[]): void { this.replace(spoolItemIds, []); }
  recoverUnreadable(): SpoolRecoveryReport {
    this.assertAccess();
    const key = this.loadVerifiedKey();
    const readable: LocalEncryptedPendingPayloadV1[] = [];
    let droppedUnreadableItems = 0;
    try {
      for (const item of this.items) {
        try {
          const value = this.openWithKey(item, key);
          value.fill(0);
          readable.push(item);
        } catch (error) {
          if (!(error instanceof ChaChaPolyAuthenticationError)) throw error;
          droppedUnreadableItems += 1;
        }
      }
    } finally {
      key.fill(0);
    }
    if (droppedUnreadableItems) { this.persist(readable); this.items = readable; }
    return { droppedUnreadableItems };
  }

  private openWithKey(item: LocalEncryptedPendingPayloadV1, key: Uint8Array): Uint8Array {
    return chachaPolyOpen(key, base64UrlDecode(item.nonce, 12, 'spool nonce'),
      base64UrlDecode(item.ciphertext, undefined, 'spool ciphertext'), spoolAAD(item));
  }
  private load(): { items: LocalEncryptedPendingPayloadV1[]; keyId?: string } {
    this.assertAccess();
    if (!pathHasFilesystemEvidence(this.path)) return { items: [] };
    const file = readSecureJson<LocalSpoolFileV2>(this.path);
    if (file?.version !== 2 || file.runtimeStateSchemaVersion !== this.runtimeStateSchemaVersion
      || file.runtimeResetEpoch !== this.runtimeResetEpoch || file.hostId !== this.hostId || typeof file.keyId !== 'string'
      || !Array.isArray(file.items) || file.items.some((item) => !validItem(item, this.hostId))) {
      throw new LocalSpoolRecoveryRequiredError('local spool metadata is invalid; recovery is required');
    }
    return { items: file.items, keyId: file.keyId };
  }
  private loadVerifiedKey(): Uint8Array {
    this.assertAccess();
    let key: Uint8Array;
    try {
      key = this.keyStore.loadOrCreate(this.hostId, { allowCreate: !this.hasPersistedItems });
    } catch (error) {
      if (error instanceof LocalSpoolRecoveryRequiredError) throw error;
      throw new LocalSpoolRecoveryRequiredError('local spool key is unavailable; recovery is required', { cause: error });
    }
    const keyId = spoolKeyIdForKey(key);
    if (this.keyId !== undefined && this.keyId !== keyId) {
      key.fill(0);
      throw new LocalSpoolRecoveryRequiredError('local spool key does not match; recovery is required');
    }
    this.keyId = keyId;
    return key;
  }
  private persist(items: LocalEncryptedPendingPayloadV1[]): void {
    this.assertAccess();
    if (!this.keyId) throw new LocalSpoolRecoveryRequiredError('local spool key identity is unavailable; recovery is required');
    writeSecureJson(this.path, {
      version: 2, runtimeStateSchemaVersion: this.runtimeStateSchemaVersion, runtimeResetEpoch: this.runtimeResetEpoch,
      hostId: this.hostId, keyId: this.keyId, items,
    } satisfies LocalSpoolFileV2);
  }
}

export function spoolPathForState(statePath: string): string { return `${statePath}.spool.json`; }
export function isRecognizedLocalSpoolPayloadKind(value: unknown): value is LocalSpoolPayloadKind {
  return typeof value === 'string' && (LOCAL_SPOOL_PAYLOAD_KINDS as readonly string[]).includes(value);
}
function spoolAAD(item: Omit<LocalEncryptedPendingPayloadV1, 'nonce' | 'ciphertext'> | LocalEncryptedPendingPayloadV1): Uint8Array {
  return encodeLengthPrefixedFields(['ariava-local-spool-v1', item.spoolItemId, item.hostId, item.sessionId,
    item.eventId ?? '', item.payloadKind, String(item.aadVersion), item.createdAt]);
}
function validItem(item: LocalEncryptedPendingPayloadV1, hostId: string): boolean {
  if (item?.version !== 1 || item.hostId !== hostId || !LOCAL_SPOOL_PAYLOAD_KINDS.includes(item.payloadKind)
    || item.aadVersion !== 1 || typeof item.spoolItemId !== 'string' || typeof item.sessionId !== 'string' || typeof item.createdAt !== 'string') return false;
  try { base64UrlDecode(item.nonce, 12); return base64UrlDecode(item.ciphertext).length >= 16; } catch { return false; }
}
function decodeHex(value: Uint8Array): Uint8Array {
  const text = Buffer.from(value).toString('utf8').trim();
  if (!/^[0-9a-f]{64}$/iu.test(text)) throw new TypeError('local spool Keychain encoding is invalid');
  return new Uint8Array(Buffer.from(text, 'hex'));
}
export function spoolKeyIdForKey(key: Uint8Array): string {
  return createHash('sha256').update('ariava-local-spool-key-v2\0').update(key).digest('base64url');
}
