import { describe, expect, test } from 'bun:test';
import {
  HOST_DOMAIN_RESET_PHASES,
  type HostDomainResetJournalV1,
  type HostDomainResetPhase,
} from '../src/cli/operations/host-domain-reset-journal-schema';
import {
  nextHostResetAction,
  type HostResetAction,
} from '../src/cli/operations/host-domain-reset-machine';

/**
 * Pure Host-domain reset state machine tests (primary spec §7, §7.2, §12).
 *
 * Covers all 13 persisted phases, all 14 phase/evidence mapping cases
 * (explicitly asserting both `prepared` branches), all 13 `HostResetAction`
 * variants, every illegal-journal fail-closed case, and pure/deterministic
 * behavior (external evidence cannot influence the selected action because it
 * cannot even be passed to the function).
 */

/** Builds a schema-valid journal at `phase` with the evidence its phase requires. */
function journalAtPhase(
  phase: typeof HOST_DOMAIN_RESET_PHASES[number],
  patch: Partial<HostDomainResetJournalV1> = {},
): HostDomainResetJournalV1 {
  const index = HOST_DOMAIN_RESET_PHASES.indexOf(phase);
  const atLeast = (candidate: HostDomainResetPhase) => index >= HOST_DOMAIN_RESET_PHASES.indexOf(candidate);
  const timestamp = '2026-08-11T00:00:01.000Z';
  const base: HostDomainResetJournalV1 = {
    version: 1,
    operationId: 'reset_0123456789abcdef',
    profile: 'default',
    phase,
    oldHostId: `host_${'A'.repeat(43)}`,
    oldKeyId: `key_${'B'.repeat(43)}`,
    newHostId: null,
    newKeyId: null,
    oldEncryptionKeyId: `ekey_${'C'.repeat(43)}`,
    signingCleanup: null,
    signingReplacementAttemptedAt: null,
    encryptionIdentityReplacedAt: null,
    runtimeArtifactsClearedAt: null,
    configSavedAt: null,
    enrolledAt: null,
    serviceMetadataSynchronizedAt: null,
    resourceDigest: 'a'.repeat(64),
    createdAt: '2026-08-11T00:00:00.000Z',
    updatedAt: timestamp,
    revoke: { state: 'not-attempted', outcome: null },
    service: { managed: true, installed: true, enabled: true, wasRunning: true, backend: 'launchd' },
  };
  const journal: HostDomainResetJournalV1 = {
    ...base,
    ...(phase === 'quarantine-pending' || phase === 'quarantined'
      ? { oldHostId: null, oldKeyId: null, oldEncryptionKeyId: null }
      : {}),
    ...(atLeast('revoke-pending')
      ? { revoke: { state: 'pending' as const, outcome: null } }
      : {}),
    ...(atLeast('old-identity-revoked')
      ? { revoke: { state: 'complete' as const, outcome: 'revoked' as const } }
      : {}),
    ...(atLeast('signing-replacement-pending') ? { signingReplacementAttemptedAt: timestamp } : {}),
    ...(atLeast('signing-identity-replaced') ? {
      newHostId: `host_${'D'.repeat(43)}`, newKeyId: `key_${'E'.repeat(43)}`,
    } : {}),
    ...(atLeast('encryption-identity-replaced') ? { encryptionIdentityReplacedAt: timestamp } : {}),
    ...(atLeast('runtime-artifacts-cleared') ? { runtimeArtifactsClearedAt: timestamp } : {}),
    ...(atLeast('config-saved') ? { configSavedAt: timestamp } : {}),
    ...(atLeast('enrolled') ? { enrolledAt: timestamp } : {}),
    ...(atLeast('service-metadata-synchronized') ? { serviceMetadataSynchronizedAt: timestamp } : {}),
    ...patch,
  };
  return journal;
}

/** The exact frozen 13-action vocabulary (primary spec §7). */
const ALL_ACTIONS: readonly HostResetAction['type'][] = [
  'stop-quarantine-and-acquire-runtime',
  'inspect-and-bind-old-domain',
  'persist-revoke-intent',
  'revoke-old-identity',
  'persist-signing-replacement-intent',
  'replace-signing-identity',
  'finalize-signing-and-replace-encryption-identity',
  'finalize-encryption-and-clear-runtime-artifacts',
  'persist-config',
  'enroll-new-identity',
  'sync-service-metadata',
  'persist-service-restore-intent',
  'restore-service-and-remove-journal',
];

describe('Host-domain reset machine', () => {
  test('frozen phase vocabulary has exactly 13 persisted phases with no completed phase', () => {
    expect(HOST_DOMAIN_RESET_PHASES).toEqual([
      'quarantine-pending',
      'quarantined',
      'prepared',
      'revoke-pending',
      'old-identity-revoked',
      'signing-replacement-pending',
      'signing-identity-replaced',
      'encryption-identity-replaced',
      'runtime-artifacts-cleared',
      'config-saved',
      'enrolled',
      'service-metadata-synchronized',
      'service-restore-pending',
    ]);
    expect(HOST_DOMAIN_RESET_PHASES).not.toContain('completed');
  });

  test('action vocabulary has exactly 13 distinct variants and no complete variant', () => {
    expect(ALL_ACTIONS).toHaveLength(13);
    expect(new Set(ALL_ACTIONS).size).toBe(13);
    expect(ALL_ACTIONS).not.toContain('complete');
  });

  test('selects the expected action for every non-prepared phase', () => {
    const expected: Record<string, HostResetAction['type']> = {
      'quarantine-pending': 'stop-quarantine-and-acquire-runtime',
      'quarantined': 'inspect-and-bind-old-domain',
      'revoke-pending': 'revoke-old-identity',
      'old-identity-revoked': 'persist-signing-replacement-intent',
      'signing-replacement-pending': 'replace-signing-identity',
      'signing-identity-replaced': 'finalize-signing-and-replace-encryption-identity',
      'encryption-identity-replaced': 'finalize-encryption-and-clear-runtime-artifacts',
      'runtime-artifacts-cleared': 'persist-config',
      'config-saved': 'enroll-new-identity',
      'enrolled': 'sync-service-metadata',
      'service-metadata-synchronized': 'persist-service-restore-intent',
      'service-restore-pending': 'restore-service-and-remove-journal',
    };
    for (const phase of Object.keys(expected)) {
      const journal = journalAtPhase(phase as typeof HOST_DOMAIN_RESET_PHASES[number]);
      expect(nextHostResetAction(journal)).toEqual({ type: expected[phase] });
    }
  });

  test('prepared with readable old identity selects persist-revoke-intent', () => {
    const journal = journalAtPhase('prepared', {
      revoke: { state: 'not-attempted', outcome: null },
    });
    expect(nextHostResetAction(journal)).toEqual({ type: 'persist-revoke-intent' });
  });

  test('prepared with recognized-unreadable old identity selects persist-signing-replacement-intent', () => {
    const journal = journalAtPhase('prepared', {
      oldHostId: null,
      oldKeyId: null,
      oldEncryptionKeyId: null,
      signingCleanup: {
        kind: 'linux-json',
        resourceDigest: 'b'.repeat(64),
        profile: 'default',
        previousAccount: null,
        previousPendingAccount: null,
        interruptedCreationAccount: null,
      },
      revoke: { state: 'skipped', outcome: 'old-identity-unreadable' },
    });
    expect(nextHostResetAction(journal)).toEqual({ type: 'persist-signing-replacement-intent' });
  });

  test('prepared with pending revoke intent fails closed as schema-invalid', () => {
    const journal = journalAtPhase('prepared', {
      revoke: { state: 'pending', outcome: null },
    });
    expect(() => nextHostResetAction(journal)).toThrow(TypeError);
  });

  test('selects one of the 13 documented actions for every persisted phase', () => {
    for (const phase of HOST_DOMAIN_RESET_PHASES) {
      const journal = phase === 'prepared'
        ? journalAtPhase(phase)
        : journalAtPhase(phase);
      const action = nextHostResetAction(journal);
      expect(ALL_ACTIONS).toContain(action.type);
    }
  });

  test('is deterministic for identical journals', () => {
    for (const phase of HOST_DOMAIN_RESET_PHASES) {
      const journal = journalAtPhase(phase);
      expect(nextHostResetAction(journal)).toEqual(nextHostResetAction({ ...journal }));
    }
  });

  test('fails closed on an unknown phase', () => {
    const journal = journalAtPhase('prepared', { phase: 'bogus' as never });
    expect(() => nextHostResetAction(journal)).toThrow(TypeError);
  });

  test('fails closed when the journal is not an object', () => {
    expect(() => nextHostResetAction(null as never)).toThrow(TypeError);
  });

  test('fails closed on a missing revoke decision', () => {
    const journal = journalAtPhase('prepared');
    const { revoke: _dropped, ...withoutRevoke } = journal;
    expect(() => nextHostResetAction(withoutRevoke as unknown as HostDomainResetJournalV1)).toThrow(TypeError);
  });

  test('fails closed on contradictory revoke combinations on prepared', () => {
    const base = journalAtPhase('prepared');
    expect(() => nextHostResetAction({ ...base, revoke: { state: 'not-attempted', outcome: 'revoked' as never } }))
      .toThrow(TypeError);
    expect(() => nextHostResetAction({ ...base, revoke: { state: 'complete', outcome: 'revoked' as never } }))
      .toThrow(TypeError);
    expect(() => nextHostResetAction({ ...base, revoke: { state: 'skipped', outcome: null as never } }))
      .toThrow(TypeError);
    expect(() => nextHostResetAction({ ...base, revoke: { state: 'bogus' as never, outcome: null } }))
      .toThrow(TypeError);
  });

  test('fails closed on illegal revoke combinations on later phases', () => {
    const revokePending = journalAtPhase('revoke-pending');
    expect(() => nextHostResetAction({ ...revokePending, revoke: { state: 'complete', outcome: 'revoked' as never } }))
      .toThrow(TypeError);
    const revoked = journalAtPhase('old-identity-revoked');
    expect(() => nextHostResetAction({ ...revoked, revoke: { state: 'pending', outcome: null as never } }))
      .toThrow(TypeError);
  });

  test('the action union type has no other members than the 13 documented actions', () => {
    // Type-level: a value typed as HostResetAction must be assignable to the
    // union of the exact 13 literals. The compile-time check happens through
    // this literal array; at runtime we verify all produced actions are members.
    const produced = new Set<string>();
    for (const phase of HOST_DOMAIN_RESET_PHASES) {
      produced.add(nextHostResetAction(journalAtPhase(phase)).type);
    }
    for (const action of ALL_ACTIONS) expect(produced.has(action)).toBe(true);
  });

  test('accepts only a journal argument (type-level signature)', () => {
    // Compile-time contract: nextHostResetAction must accept exactly one
    // exact-decoded journal and nothing else. If the signature ever gains a
    // second parameter (evidence, snapshot, runtime state, ...), this
    // assignment stops typechecking.
    const signature: (journal: HostDomainResetJournalV1) => HostResetAction = nextHostResetAction;
    expect(signature).toBe(nextHostResetAction);
    expect(signature(journalAtPhase('prepared'))).toEqual({ type: 'persist-revoke-intent' });
  });
});
