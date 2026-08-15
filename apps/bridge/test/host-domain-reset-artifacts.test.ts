import { describe, expect, test } from 'bun:test';
import {
  assertArtifactCleanupBoundary,
  HOST_DOMAIN_RESET_CLEANUP_TARGETS,
  HOST_DOMAIN_RESET_PRESERVED_RESOURCES,
} from '../src/cli/operations/host-domain-reset-artifacts';
import { HOST_DOMAIN_RESET_BINDING_INPUTS } from '../src/cli/operations/host-domain-reset-journal-policy';

describe('Host-domain reset fixed artifact cleanup plan', () => {
  test('cleanup targets are exactly the five fixed categories', () => {
    expect([...HOST_DOMAIN_RESET_CLEANUP_TARGETS]).toEqual([
      'linkKeyringPath',
      'statePath',
      'encryptedSpoolPath',
      'runtimeResetIntentPath',
    ]);
    expect([...HOST_DOMAIN_RESET_CLEANUP_TARGETS]).toHaveLength(4);
  });

  test('every generic cleanup target is a journal binding input', () => {
    const bindingInputs = new Set<string>(HOST_DOMAIN_RESET_BINDING_INPUTS);
    for (const target of HOST_DOMAIN_RESET_CLEANUP_TARGETS) {
      expect(bindingInputs.has(target)).toBe(true);
    }
  });

  test('preserved resources are never cleanup targets', () => {
    const cleanupTargets = new Set<string>(HOST_DOMAIN_RESET_CLEANUP_TARGETS);
    for (const preserved of HOST_DOMAIN_RESET_PRESERVED_RESOURCES) {
      expect(cleanupTargets.has(preserved)).toBe(false);
    }
  });

  test('preserved resources include exactly the non-destructive set', () => {
    expect([...HOST_DOMAIN_RESET_PRESERVED_RESOURCES]).toEqual([
      'root',
      'configPath',
      'agentAdapterConfigPath',
      'piExtensionLogPath',
      'installMetadataPath',
    ]);
  });

  test('boundary assertion passes for the frozen constants', () => {
    expect(assertArtifactCleanupBoundary()).toBeUndefined();
  });
});
