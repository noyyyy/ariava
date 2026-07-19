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
