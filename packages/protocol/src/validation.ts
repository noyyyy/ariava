import {
  EVENT_TYPES,
  NEED_HUMAN_ERROR_KINDS,
  NEED_HUMAN_REASONS,
  type EventType,
  type NeedHumanContext,
  type NeedHumanError,
} from './events.js';
import {
  BRIDGE_STATUSES,
  HOST_PLATFORMS,
  type HostEnrollmentRequest,
  type HostMetadataUpdateRequest,
} from './hosts.js';
import {
  ENTITY_TYPES,
  IDENTITY_ALGORITHM,
  IDENTITY_STATUSES,
  KEY_STATUSES,
  deriveEntityIdentity,
  type EntityType,
} from './identity.js';
import { LINK_REVOKE_REASONS } from './pairing.js';
import {
  SIGNED_REQUEST_HEADER_NAMES,
  SIGNED_REQUEST_LIMITS,
  base64UrlDecode,
  type SignedRequestHeaders,
} from './request-signing.js';

export interface ValidationResult<T> {
  success: boolean;
  value?: T;
  issues: string[];
}

export interface CanonicalEventInvariant {
  type: EventType;
  status: 'idle' | 'need_human';
  needHuman?: NeedHumanContext;
}

const EVENT_INVARIANT_KEYS = ['type', 'status', 'needHuman'] as const;
const NEED_HUMAN_KEYS = ['reason', 'error'] as const;
const NEED_HUMAN_ERROR_KEYS = ['kind', 'message', 'providerCode', 'retryExhausted'] as const;
const NEED_HUMAN_ERROR_MESSAGE_BYTES = 2_000;
const NEED_HUMAN_PROVIDER_CODE_BYTES = 128;
const validationEncoder = new TextEncoder();
const NEED_HUMAN_PROTECTED_MESSAGE_PATTERNS = [
  /(?:^|[^\p{L}\p{N}_])["']?authorization["']?(?:\s*[:=]|\s+(?:basic|bearer)\s+)/iu,
  /\b(?:basic|bearer)\s+[^\s,;]+/iu,
  /(?:^|[^\p{L}\p{N}_])["']?(?:api[\s_-]*(?:k[\s_-]*e[\s_-]*y|token)|private[\s_-]*key|client[\s_-]*secret|(?:access|refresh|id|auth|bearer|session)[\s_-]*token|token|secret|password)["']?\s*[:=]/iu,
  /\bsk-[A-Za-z0-9_-]{16,}\b/u,
  /\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/u,
  /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/u,
  /-----BEGIN [^-\r\n]*PRIVATE KEY-----/iu,
  /\b(?:request|response)[\s_-]+(?:body|payload)\s*[:=]/iu,
] as const;
const NEED_HUMAN_PROVIDER_CODE_CREDENTIAL_PATTERNS = [
  /\bsk-[A-Za-z0-9_-]{16,}\b/u,
  /\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/u,
  /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/u,
  /^(?:basic|bearer)[._:/-]/iu,
  /^(?:api[._:/-]?key|(?:access|refresh|id|auth|bearer|session)[._:/-]?token|client[._:/-]?secret|token|secret|password|authorization)[._:/-]/iu,
] as const;

/** Shared exact validator for the canonical Relay metadata ↔ protected-content invariant. */
export function validateCanonicalEventInvariant(value: unknown): ValidationResult<CanonicalEventInvariant> {
  const issues: string[] = [];
  const event = exactOptionalRecord(value, EVENT_INVARIANT_KEYS, ['type', 'status'], 'event invariant', issues);
  if (!event) return { success: false, issues };
  if (typeof event.type !== 'string' || !(EVENT_TYPES as readonly string[]).includes(event.type)) issues.push('type is invalid');
  if (event.status !== 'idle' && event.status !== 'need_human') issues.push('status is invalid');

  if (event.type === 'done') {
    if (event.status !== 'idle') issues.push('done requires idle status');
    if (Object.hasOwn(event, 'needHuman')) issues.push('done must not contain needHuman');
  } else if (event.type === 'need_human') {
    if (event.status !== 'need_human') issues.push('need_human requires need_human status');
    validateNeedHumanContext(event.needHuman, issues);
  }

  return issues.length ? { success: false, issues } : { success: true, value: value as CanonicalEventInvariant, issues };
}

function validateNeedHumanContext(value: unknown, issues: string[]): void {
  const context = exactOptionalRecord(value, NEED_HUMAN_KEYS, ['reason'], 'needHuman', issues);
  if (!context) return;
  if (typeof context.reason !== 'string' || !(NEED_HUMAN_REASONS as readonly string[]).includes(context.reason)) {
    issues.push('needHuman.reason is invalid');
    return;
  }
  if (context.reason === 'error') {
    validateNeedHumanErrorValue(context.error, issues);
  } else if (Object.hasOwn(context, 'error')) {
    issues.push('needHuman.error is only allowed for error reason');
  }
}

export function validateNeedHumanError(value: unknown): ValidationResult<NeedHumanError> {
  const issues: string[] = [];
  validateNeedHumanErrorValue(value, issues);
  return issues.length ? { success: false, issues } : { success: true, value: value as NeedHumanError, issues };
}

function validateNeedHumanErrorValue(value: unknown, issues: string[]): void {
  const error = exactOptionalRecord(
    value, NEED_HUMAN_ERROR_KEYS, ['kind', 'message', 'retryExhausted'], 'needHuman.error', issues,
  );
  if (!error) return;
  if (typeof error.kind !== 'string' || !(NEED_HUMAN_ERROR_KINDS as readonly string[]).includes(error.kind)) {
    issues.push('needHuman.error.kind is invalid');
  }
  if (!isCanonicalNeedHumanErrorMessage(error.message)) {
    issues.push('needHuman.error.message is not canonical bounded text');
  }
  const providerCode = error.providerCode;
  if (providerCode !== undefined && (typeof providerCode !== 'string'
    || !/^[A-Za-z0-9][A-Za-z0-9._:/-]*$/u.test(providerCode)
    || validationEncoder.encode(providerCode).byteLength > NEED_HUMAN_PROVIDER_CODE_BYTES
    || NEED_HUMAN_PROVIDER_CODE_CREDENTIAL_PATTERNS.some((pattern) => pattern.test(providerCode)))) {
    issues.push('needHuman.error.providerCode is invalid');
  }
  if (error.retryExhausted !== true) issues.push('needHuman.error.retryExhausted must be true');
}

export function isCanonicalNeedHumanErrorMessage(value: unknown): value is string {
  if (typeof value !== 'string' || value.length === 0 || value !== value.trim()
    || value.normalize('NFC') !== value
    || validationEncoder.encode(value).byteLength > NEED_HUMAN_ERROR_MESSAGE_BYTES
    || /[\u0000-\u001F\u007F-\u009F]/u.test(value) || /\p{Cf}/u.test(value)
    || /[^\S ]/u.test(value) || / {2,}/u.test(value)
    || NEED_HUMAN_PROTECTED_MESSAGE_PATTERNS.some((pattern) => pattern.test(value))) return false;
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) return false;
  }
  return true;
}

function exactOptionalRecord(
  value: unknown,
  allowedKeys: readonly string[],
  requiredKeys: readonly string[],
  label: string,
  issues: string[],
): Record<string, unknown> | undefined {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    issues.push(`${label} must be an object`);
    return undefined;
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const allowed = new Set(allowedKeys);
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string') {
      issues.push(`${label} contains an unsupported symbol key`);
      continue;
    }
    const descriptor = descriptors[key]!;
    if (!descriptor.enumerable || !('value' in descriptor)) {
      issues.push(`${label}.${key} must be an enumerable own data property`);
    }
    if (!allowed.has(key)) issues.push(`${label}.${key} is unsupported`);
  }
  for (const key of requiredKeys) if (!Object.hasOwn(value, key)) issues.push(`${label}.${key} is required`);
  for (const key of allowedKeys) {
    if (!Object.hasOwn(value, key) && key in value) issues.push(`${label}.${key} must be an own data property`);
  }
  return Object.fromEntries(
    Object.entries(descriptors)
      .filter(([, descriptor]) => descriptor.enumerable && 'value' in descriptor)
      .map(([key, descriptor]) => [key, descriptor.value]),
  );
}

export function isHostPlatform(value: unknown): value is 'macos' | 'linux' {
  return typeof value === 'string' && (HOST_PLATFORMS as readonly string[]).includes(value);
}

export function isEntityType(value: unknown): value is EntityType {
  return typeof value === 'string' && (ENTITY_TYPES as readonly string[]).includes(value);
}

export function isCanonicalTimestamp(value: unknown): value is string {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value)) return false;
  const parsed = new Date(value);
  return !Number.isNaN(parsed.getTime()) && parsed.toISOString() === value;
}

export function isRotationOperationId(value: unknown): value is string {
  return typeof value === 'string' && /^op_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(value);
}

export function validateSignedRequestHeaders(headers: Headers | SignedRequestHeaders | Record<string, string | undefined>): ValidationResult<SignedRequestHeaders> {
  const get = (name: string): string | undefined => {
    if (headers instanceof Headers) return headers.get(name) ?? undefined;
    const descriptor = Object.getOwnPropertyDescriptor(headers, name);
    return descriptor && 'value' in descriptor && typeof descriptor.value === 'string' ? descriptor.value : undefined;
  };
  const issues: string[] = [];
  const entityId = get(SIGNED_REQUEST_HEADER_NAMES.entityId);
  const keyId = get(SIGNED_REQUEST_HEADER_NAMES.keyId);
  const timestamp = get(SIGNED_REQUEST_HEADER_NAMES.timestamp);
  const nonce = get(SIGNED_REQUEST_HEADER_NAMES.nonce);
  const contentHash = get(SIGNED_REQUEST_HEADER_NAMES.contentSha256);
  const signature = get(SIGNED_REQUEST_HEADER_NAMES.signature);
  for (const [name, value] of Object.entries({ entityId, keyId, timestamp, nonce, contentHash, signature })) {
    if (!value) issues.push(`${name} is required`);
    else if (value.length > SIGNED_REQUEST_LIMITS.headerCharacters) issues.push(`${name} exceeds the header limit`);
  }
  if (entityId && !isEntityId(entityId)) issues.push('entityId is invalid');
  if (keyId && !/^key_[A-Za-z0-9_-]{43}$/u.test(keyId)) issues.push('keyId is invalid');
  if (timestamp && !isCanonicalTimestamp(timestamp)) issues.push('timestamp is not canonical RFC3339');
  validateEncodedLength(nonce, SIGNED_REQUEST_LIMITS.nonceBytes, 'nonce', issues);
  validateEncodedLength(contentHash, SIGNED_REQUEST_LIMITS.sha256Bytes, 'contentSha256', issues);
  validateEncodedLength(signature, SIGNED_REQUEST_LIMITS.signatureBytes, 'signature', issues);
  return issues.length ? { success: false, issues } : {
    success: true,
    issues,
    value: {
      [SIGNED_REQUEST_HEADER_NAMES.entityId]: entityId!,
      [SIGNED_REQUEST_HEADER_NAMES.keyId]: keyId!,
      [SIGNED_REQUEST_HEADER_NAMES.timestamp]: timestamp!,
      [SIGNED_REQUEST_HEADER_NAMES.nonce]: nonce!,
      [SIGNED_REQUEST_HEADER_NAMES.contentSha256]: contentHash!,
      [SIGNED_REQUEST_HEADER_NAMES.signature]: signature!,
    },
  };
}

export function validateHostEnrollmentRequestSyntax(value: unknown): ValidationResult<HostEnrollmentRequest> {
  const issues: string[] = [];
  const object = asRecord(value, issues);
  if (!object) return { success: false, issues };
  validateIdentityEnrollment(object, 'host', issues);
  requireNonEmptyString(object.hostName, 'hostName', issues);
  requireNonEmptyString(object.bridgeVersion, 'bridgeVersion', issues);
  if (!isHostPlatform(object.platform)) issues.push('platform must be macos or linux');
  if (object.encryptionBinding !== undefined) {
    const binding = object.encryptionBinding as { entityType?: unknown; entityId?: unknown; identityKeyId?: unknown };
    if (!binding || binding.entityType !== 'host' || binding.entityId !== object.hostId || binding.identityKeyId !== object.keyId) {
      issues.push('encryptionBinding does not match Host identity');
    }
  }
  return result(value as HostEnrollmentRequest, issues);
}

export async function validateHostEnrollmentRequest(value: unknown): Promise<ValidationResult<HostEnrollmentRequest>> {
  return validateEnrollmentIdentityBinding(value, 'host', validateHostEnrollmentRequestSyntax);
}

export function validateHostMetadataUpdateRequest(value: unknown): ValidationResult<HostMetadataUpdateRequest> {
  const issues: string[] = [];
  const object = asRecord(value, issues);
  if (!object) return { success: false, issues };
  requireExactKeys(object, ['hostName', 'platform', 'bridgeVersion'], issues);
  requireNonEmptyString(object.hostName, 'hostName', issues);
  requireNonEmptyString(object.bridgeVersion, 'bridgeVersion', issues);
  if (!isHostPlatform(object.platform)) issues.push('platform must be macos or linux');
  return result(value as HostMetadataUpdateRequest, issues);
}

export function validateIdentityRevokeRequest(value: unknown): ValidationResult<Record<string, never>> {
  const issues: string[] = [];
  const object = asRecord(value, issues);
  if (!object) return { success: false, issues };
  requireExactKeys(object, [], issues);
  return result(object as Record<string, never>, issues);
}

export function isIdentityStatus(value: unknown): boolean {
  return typeof value === 'string' && (IDENTITY_STATUSES as readonly string[]).includes(value);
}

export function isKeyStatus(value: unknown): boolean {
  return typeof value === 'string' && (KEY_STATUSES as readonly string[]).includes(value);
}

export function isBridgeStatus(value: unknown): boolean {
  return typeof value === 'string' && (BRIDGE_STATUSES as readonly string[]).includes(value);
}

export function isLinkRevokeReason(value: unknown): boolean {
  return typeof value === 'string' && (LINK_REVOKE_REASONS as readonly string[]).includes(value);
}

async function validateEnrollmentIdentityBinding<T extends HostEnrollmentRequest>(
  value: unknown,
  type: Extract<EntityType, 'host'>,
  syntaxValidator: (candidate: unknown) => ValidationResult<T>,
): Promise<ValidationResult<T>> {
  const syntax = syntaxValidator(value);
  if (!syntax.success || !syntax.value) return syntax;
  const entityField = 'hostId';
  const expected = await deriveEntityIdentity(type, syntax.value.publicKey);
  const issues = [...syntax.issues];
  const submittedEntityId = syntax.value.hostId;
  if (submittedEntityId !== expected.entityId) issues.push(`${entityField} does not match publicKey fingerprint`);
  if (syntax.value.keyId !== expected.keyId) issues.push('keyId does not match publicKey fingerprint');
  return issues.length ? { success: false, issues } : { success: true, value: syntax.value, issues };
}

function validateIdentityEnrollment(object: Record<string, unknown>, type: EntityType, issues: string[]): void {
  const entityField = 'hostId';
  const expectedKeys = [entityField, 'keyId', 'algorithm', 'publicKey', 'hostName', 'platform', 'bridgeVersion'];
  const acceptedKeys = object.encryptionBinding === undefined ? expectedKeys : [...expectedKeys, 'encryptionBinding'];
  requireExactKeys(object, acceptedKeys, issues);
  const entityId = object[entityField];
  if (typeof entityId !== 'string' || !isEntityId(entityId, type)) issues.push(`${entityField} is invalid`);
  if (typeof object.keyId !== 'string' || !/^key_[A-Za-z0-9_-]{43}$/u.test(object.keyId)) issues.push('keyId is invalid');
  if (object.algorithm !== IDENTITY_ALGORITHM) issues.push('algorithm must be Ed25519');
  validateEncodedLength(object.publicKey, SIGNED_REQUEST_LIMITS.publicKeyBytes, 'publicKey', issues);
}

function isEntityId(value: string, expected?: EntityType): boolean {
  if (expected === 'host') return /^host_[A-Za-z0-9_-]{43}$/u.test(value);
  if (expected === 'watch') return /^watch_[A-Za-z0-9_-]{43}$/u.test(value);
  return /^(?:host|watch)_[A-Za-z0-9_-]{43}$/u.test(value);
}

function validateEncodedLength(value: unknown, bytes: number, name: string, issues: string[]): void {
  if (typeof value !== 'string') {
    issues.push(`${name} is required`);
    return;
  }
  try {
    base64UrlDecode(value, bytes, name);
  } catch (error) {
    issues.push(error instanceof Error ? error.message : `${name} is invalid`);
  }
}

function asRecord(value: unknown, issues: string[]): Record<string, unknown> | undefined {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    issues.push('body must be an object');
    return undefined;
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  for (const [key, descriptor] of Object.entries(descriptors)) {
    if (!('value' in descriptor)) issues.push(`${key} must be an own data property`);
  }
  return Object.fromEntries(
    Object.entries(descriptors)
      .filter(([, descriptor]) => 'value' in descriptor)
      .map(([key, descriptor]) => [key, descriptor.value]),
  );
}

function requireExactKeys(object: Record<string, unknown>, expected: readonly string[], issues: string[]): void {
  const supported = new Set(expected);
  for (const key of Object.keys(object)) if (!supported.has(key)) issues.push(`${key} is unsupported`);
  for (const key of expected) if (!Object.prototype.hasOwnProperty.call(object, key)) issues.push(`${key} is required`);
}

function requireNonEmptyString(value: unknown, name: string, issues: string[]): void {
  if (typeof value !== 'string' || !value.trim()) issues.push(`${name} must be a non-empty string`);
}

function result<T>(value: T, issues: string[]): ValidationResult<T> {
  return issues.length ? { success: false, issues } : { success: true, value, issues };
}
