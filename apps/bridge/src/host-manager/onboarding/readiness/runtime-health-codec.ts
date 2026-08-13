import { isCanonicalTimestamp } from '@ariava/protocol';
import type { BridgeRuntimeHealth } from '../../../types';

export function parseAgentAdapterHealth(value: unknown, hostId: string): BridgeRuntimeHealth | undefined {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  const record = value as Record<string, unknown>;
  if (Object.keys(record).sort().join(',') !== 'health,hostId,ok' || record.ok !== true || record.hostId !== hostId
    || !isBridgeRuntimeHealth(record.health)) return undefined;
  return record.health as BridgeRuntimeHealth;
}

function isBridgeRuntimeHealth(value: unknown): boolean {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const health = value as Record<string, unknown>;
  if (!hasExactOptionalKeys(health, ['status', 'drivers'], ['relayPresence']) || !Array.isArray(health.drivers)) return false;
  const drivers = health.drivers as unknown[];
  if (drivers.length > 32 || !drivers.every(isDriverHealth)) return false;
  const driverIds = drivers.map((item) => (item as { driver: string }).driver);
  if (new Set(driverIds).size !== driverIds.length || driverIds.some((driver, index) => index > 0 && driverIds[index - 1]! > driver)) return false;
  const degraded = drivers.length > 0 || health.relayPresence !== undefined;
  return health.status === (degraded ? 'degraded' : 'healthy')
    && (health.relayPresence === undefined || isRelayPresenceHealth(health.relayPresence));
}

function isDriverHealth(value: unknown): boolean {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const item = value as Record<string, unknown>;
  return hasExactOptionalKeys(item, ['driver', 'code', 'count', 'firstSeenAt', 'lastSeenAt', 'nextRetryAt'], ['lastSuccessAt'])
    && typeof item.driver === 'string' && /^[A-Za-z0-9._-]{1,64}$/u.test(item.driver)
    && item.code === 'driver_reconciliation_failed'
    && isPositiveSafeInteger(item.count) && healthTimesAreCanonical(item);
}

function isRelayPresenceHealth(value: unknown): boolean {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const item = value as Record<string, unknown>;
  return hasExactOptionalKeys(item, ['code', 'count', 'firstSeenAt', 'lastSeenAt', 'nextRetryAt'], ['lastSuccessAt'])
    && item.code === 'relay_presence_refresh_failed' && isPositiveSafeInteger(item.count) && healthTimesAreCanonical(item);
}

function healthTimesAreCanonical(value: Record<string, unknown>): boolean {
  return ['firstSeenAt', 'lastSeenAt', 'nextRetryAt'].every((key) => isCanonicalTimestamp(value[key]))
    && (value.lastSuccessAt === undefined || isCanonicalTimestamp(value.lastSuccessAt));
}

function isPositiveSafeInteger(value: unknown): boolean {
  return Number.isSafeInteger(value) && (value as number) > 0;
}

function hasExactOptionalKeys(value: Record<string, unknown>, required: string[], optional: string[]): boolean {
  return required.every((key) => key in value) && Object.keys(value).every((key) => required.includes(key) || optional.includes(key));
}
