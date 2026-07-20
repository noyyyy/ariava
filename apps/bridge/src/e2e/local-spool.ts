import { randomBytes } from 'node:crypto';
import { base64UrlDecode, base64UrlEncode, encodeLengthPrefixedFields } from '@ariava/protocol';
import { pathHasFilesystemEvidence, readSecureJson, writeSecureJson, writeSecureJsonExclusive } from '../host-manager/secure-files';
import { MACOS_SECURITY_PATH, SpawnKeychainCommandRunner, type KeychainCommandRunner } from '../identity/macos-keychain-store';
import { chachaPolyOpen, chachaPolySeal } from './node-crypto';

export type LocalSpoolPayloadKind = 'event-source-v1' | 'session-source-v1' | 'event-upload-v1' | 'session-upload-v1';
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
interface LocalSpoolFileV1 { version: 1; items: LocalEncryptedPendingPayloadV1[] }
interface LinuxSpoolKeyV1 { version: 1; hostId: string; key: string }
const SERVICE = 'io.noyx.ariava.local-spool-v1';
const encoder = new TextEncoder();

export interface SpoolKeyStore { loadOrCreate(hostId: string): Uint8Array; }
export interface SpoolRecoveryReport { droppedUnreadableItems: number }

export class LinuxSpoolKeyStore implements SpoolKeyStore {
  constructor(private readonly path: string) {}
  loadOrCreate(hostId: string): Uint8Array {
    if (!pathHasFilesystemEvidence(this.path)) writeSecureJsonExclusive(this.path,
      { version: 1, hostId, key: base64UrlEncode(randomBytes(32)) } satisfies LinuxSpoolKeyV1);
    const record = readSecureJson<LinuxSpoolKeyV1>(this.path);
    if (record?.version !== 1 || record.hostId !== hostId) throw new TypeError('local spool key metadata is invalid');
    return base64UrlDecode(record.key, 32, 'local spool key');
  }
}

export class MacOSSpoolKeyStore implements SpoolKeyStore {
  constructor(private readonly evidencePath: string, private readonly runner: KeychainCommandRunner = new SpawnKeychainCommandRunner()) {}
  loadOrCreate(hostId: string): Uint8Array {
    const account = `host-spool:${hostId}`;
    const existing = this.runner.run(MACOS_SECURITY_PATH, ['find-generic-password', '-s', SERVICE, '-a', account, '-w']);
    if (existing.status === 0 && !existing.error) return decodeHex(existing.stdout);
    if (pathHasFilesystemEvidence(this.evidencePath)) throw new TypeError('local spool Keychain item is missing');
    const key = randomBytes(32);
    const command = `add-generic-password -s '${SERVICE}' -a '${account}' -X ${key.toString('hex')}\n`;
    const result = this.runner.run(MACOS_SECURITY_PATH, ['-i'], encoder.encode(command));
    if (result.status !== 0 || result.error) { key.fill(0); throw new TypeError('local spool Keychain write failed'); }
    writeSecureJsonExclusive(this.evidencePath, { version: 1, hostId, account });
    return new Uint8Array(key);
  }
}

export function createRuntimeSpoolKeyStore(identityPath: string, platform: NodeJS.Platform | string): SpoolKeyStore {
  return platform === 'darwin' ? new MacOSSpoolKeyStore(`${identityPath}.spool.json`)
    : new LinuxSpoolKeyStore(`${identityPath}.spool-key.json`);
}

export class LocalEncryptedSpool {
  private items: LocalEncryptedPendingPayloadV1[];
  constructor(private readonly path: string, private readonly hostId: string, private readonly keyStore: SpoolKeyStore) {
    this.items = this.load();
  }

  enqueue(input: { spoolItemId: string; sessionId: string; eventId?: string; payloadKind: LocalSpoolPayloadKind;
    createdAt: string; plaintext: Uint8Array }): LocalEncryptedPendingPayloadV1 {
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
    const key = this.keyStore.loadOrCreate(this.hostId);
    try {
      const sealed = chachaPolySeal(key, input.plaintext, spoolAAD(metadata));
      const item = { ...metadata, nonce: base64UrlEncode(sealed.nonce), ciphertext: base64UrlEncode(sealed.ciphertext) };
      const nextItems = [...this.items, item];
      this.persist(nextItems);
      this.items = nextItems;
      return structuredClone(item);
    } finally { key.fill(0); input.plaintext.fill(0); }
  }

  list(kind?: LocalSpoolPayloadKind): LocalEncryptedPendingPayloadV1[] {
    return this.items.filter((item) => !kind || item.payloadKind === kind).map((item) => structuredClone(item));
  }
  get(spoolItemId: string): LocalEncryptedPendingPayloadV1 | undefined {
    const item = this.items.find((candidate) => candidate.spoolItemId === spoolItemId); return item && structuredClone(item);
  }
  open(item: LocalEncryptedPendingPayloadV1): Uint8Array {
    const stored = this.items.find((candidate) => candidate.spoolItemId === item.spoolItemId);
    if (!stored || JSON.stringify(stored) !== JSON.stringify(item) || !validItem(item, this.hostId)) throw new TypeError('local spool item is invalid');
    const key = this.keyStore.loadOrCreate(this.hostId);
    try { return chachaPolyOpen(key, base64UrlDecode(item.nonce, 12, 'spool nonce'),
      base64UrlDecode(item.ciphertext, undefined, 'spool ciphertext'), spoolAAD(item)); }
    finally { key.fill(0); }
  }
  replace(removeIds: readonly string[], additions: Array<{ spoolItemId: string; sessionId: string; eventId?: string;
    payloadKind: LocalSpoolPayloadKind; createdAt: string; plaintext: Uint8Array }>): void {
    const remove = new Set(removeIds);
    let next = this.items.filter((item) => !remove.has(item.spoolItemId));
    const key = this.keyStore.loadOrCreate(this.hostId);
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
    } finally { key.fill(0); additions.forEach((item) => item.plaintext.fill(0)); }
  }
  remove(spoolItemId: string): void { this.replace([spoolItemId], []); }
  recoverUnreadable(): SpoolRecoveryReport {
    const readable: LocalEncryptedPendingPayloadV1[] = [];
    let droppedUnreadableItems = 0;
    for (const item of this.items) {
      try { const value = this.open(item); value.fill(0); readable.push(item); } catch { droppedUnreadableItems += 1; }
    }
    if (droppedUnreadableItems) { this.persist(readable); this.items = readable; }
    return { droppedUnreadableItems };
  }

  private load(): LocalEncryptedPendingPayloadV1[] {
    if (!pathHasFilesystemEvidence(this.path)) return [];
    const file = readSecureJson<LocalSpoolFileV1>(this.path);
    if (file?.version !== 1 || !Array.isArray(file.items) || file.items.some((item) => !validItem(item, this.hostId))) throw new TypeError('local spool file is invalid');
    return file.items;
  }
  private persist(items: LocalEncryptedPendingPayloadV1[]): void { writeSecureJson(this.path, { version: 1, items } satisfies LocalSpoolFileV1); }
}

export function spoolPathForState(statePath: string): string { return `${statePath}.spool.json`; }
function spoolAAD(item: Omit<LocalEncryptedPendingPayloadV1, 'nonce' | 'ciphertext'> | LocalEncryptedPendingPayloadV1): Uint8Array {
  return encodeLengthPrefixedFields(['ariava-local-spool-v1', item.spoolItemId, item.hostId, item.sessionId,
    item.eventId ?? '', item.payloadKind, String(item.aadVersion), item.createdAt]);
}
function validItem(item: LocalEncryptedPendingPayloadV1, hostId: string): boolean {
  if (item?.version !== 1 || item.hostId !== hostId || !['event-source-v1', 'session-source-v1', 'event-upload-v1', 'session-upload-v1'].includes(item.payloadKind)
    || item.aadVersion !== 1 || typeof item.spoolItemId !== 'string' || typeof item.sessionId !== 'string' || typeof item.createdAt !== 'string') return false;
  try { base64UrlDecode(item.nonce, 12); return base64UrlDecode(item.ciphertext).length >= 16; } catch { return false; }
}
function decodeHex(value: Uint8Array): Uint8Array {
  const text = Buffer.from(value).toString('utf8').trim();
  if (!/^[0-9a-f]{64}$/iu.test(text)) throw new TypeError('local spool Keychain encoding is invalid');
  return new Uint8Array(Buffer.from(text, 'hex'));
}
