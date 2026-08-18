/**
 * Canonical case registry for the Codex Exact-Release Capability PoC (spec §7.2).
 *
 * The registry is versioned, strict, and reviewed. Entries use the exact keys:
 *   caseId, capabilityId, surfaces, operatingSystems, architectures,
 *   requiredForGo, fixtureClass, requiresRealAccount, requiresSynchronousObserver,
 *   expectedOutcomeClass
 *
 * Rules enforced here:
 * - `caseId` and `capabilityId` are globally unique and stable;
 * - filtering by tuple produces the run's unique required case set;
 * - CLI profiles may only select the full canonical set (all required cases) or
 *   extra diagnostic cases; they can never exclude `requiredForGo=true` cases;
 * - the registry digest is SHA-256 of RFC 8785 JCS canonical registry bytes,
 *   computed at run start and written into the evidence artifact;
 * - missing/duplicate/unknown/not-run/UNAVAILABLE required cases all block `GO`
 *   (enforced by the verdict module, which consumes this registry).
 *
 * This is research-only harness code. It never imports Bridge production
 * modules and is never part of the production import graph.
 */

import { createHash } from 'node:crypto';
import {
  ARCHITECTURES,
  CODEX_POC_REGISTRY_VERSION,
  EXPECTED_OUTCOME_CLASSES,
  FIXTURE_CLASSES,
  OPERATING_SYSTEMS,
  SURFACES,
  type Architecture,
  type ExpectedOutcomeClass,
  type FixtureClass,
  type OperatingSystem,
  type Surface,
} from './constants';
import { jcs } from './jcs';

export interface CanonicalCase {
  caseId: string;
  capabilityId: string;
  surfaces: Surface[];
  operatingSystems: OperatingSystem[];
  architectures: Architecture[];
  requiredForGo: boolean;
  fixtureClass: FixtureClass;
  requiresRealAccount: boolean;
  requiresSynchronousObserver: boolean;
  expectedOutcomeClass: ExpectedOutcomeClass;
}

export interface CaseProfile {
  /** Stable profile id. */
  id: string;
  /** Diagnostic-only case ids that the profile may ADD (never remove required). */
  extraCaseIds?: string[];
  /** When true, the profile selects the full canonical set plus extras. */
  fullCanonicalSet: boolean;
}

export interface RegistryDigest {
  version: number;
  digest: string;
  /** The exact canonical JCS bytes the digest covers. */
  canonicalBytes: string;
}

/** All reviewed canonical cases. */
export const CANONICAL_CASES: readonly CanonicalCase[] = Object.freeze([
  {
    caseId: 'case-schema-initialize',
    capabilityId: 'cap-schema-transport',
    surfaces: ['standalone_tui', 'macos_desktop'],
    operatingSystems: ['macos', 'linux', 'wsl'],
    architectures: ['arm64', 'x86_64'],
    requiredForGo: true,
    fixtureClass: 'public-deterministic',
    requiresRealAccount: false,
    requiresSynchronousObserver: false,
    expectedOutcomeClass: 'pass',
  },
  {
    caseId: 'case-schema-framing-correlation',
    capabilityId: 'cap-schema-transport',
    surfaces: ['standalone_tui', 'macos_desktop'],
    operatingSystems: ['macos', 'linux', 'wsl'],
    architectures: ['arm64', 'x86_64'],
    requiredForGo: true,
    fixtureClass: 'public-deterministic',
    requiresRealAccount: false,
    requiresSynchronousObserver: false,
    expectedOutcomeClass: 'pass',
  },
  {
    caseId: 'case-schema-thread-list-read',
    capabilityId: 'cap-schema-transport',
    surfaces: ['standalone_tui', 'macos_desktop'],
    operatingSystems: ['macos', 'linux', 'wsl'],
    architectures: ['arm64', 'x86_64'],
    requiredForGo: true,
    fixtureClass: 'public-deterministic',
    requiresRealAccount: false,
    requiresSynchronousObserver: false,
    expectedOutcomeClass: 'pass',
  },
  {
    caseId: 'case-schema-loaded-unloaded',
    capabilityId: 'cap-schema-transport',
    surfaces: ['standalone_tui', 'macos_desktop'],
    operatingSystems: ['macos', 'linux', 'wsl'],
    architectures: ['arm64', 'x86_64'],
    requiredForGo: true,
    fixtureClass: 'public-deterministic',
    requiresRealAccount: false,
    requiresSynchronousObserver: false,
    expectedOutcomeClass: 'pass',
  },
  {
    caseId: 'case-schema-turn-start-steer-interrupt',
    capabilityId: 'cap-schema-transport',
    surfaces: ['standalone_tui', 'macos_desktop'],
    operatingSystems: ['macos', 'linux', 'wsl'],
    architectures: ['arm64', 'x86_64'],
    requiredForGo: true,
    fixtureClass: 'public-deterministic',
    requiresRealAccount: false,
    requiresSynchronousObserver: false,
    expectedOutcomeClass: 'pass',
  },
  {
    caseId: 'case-schema-turn-item-completion-error',
    capabilityId: 'cap-schema-transport',
    surfaces: ['standalone_tui', 'macos_desktop'],
    operatingSystems: ['macos', 'linux', 'wsl'],
    architectures: ['arm64', 'x86_64'],
    requiredForGo: true,
    fixtureClass: 'public-deterministic',
    requiresRealAccount: false,
    requiresSynchronousObserver: false,
    expectedOutcomeClass: 'pass',
  },
  {
    caseId: 'case-schema-approval-blocking',
    capabilityId: 'cap-schema-transport',
    surfaces: ['standalone_tui', 'macos_desktop'],
    operatingSystems: ['macos', 'linux', 'wsl'],
    architectures: ['arm64', 'x86_64'],
    requiredForGo: true,
    fixtureClass: 'public-deterministic',
    requiresRealAccount: false,
    requiresSynchronousObserver: false,
    expectedOutcomeClass: 'pass',
  },
  {
    caseId: 'case-schema-daemon-version-status',
    capabilityId: 'cap-schema-transport',
    surfaces: ['standalone_tui', 'macos_desktop'],
    operatingSystems: ['macos', 'linux', 'wsl'],
    architectures: ['arm64', 'x86_64'],
    requiredForGo: true,
    fixtureClass: 'public-deterministic',
    requiresRealAccount: false,
    requiresSynchronousObserver: false,
    expectedOutcomeClass: 'pass',
  },
  {
    caseId: 'case-schema-malformed-oversized-duplicate-unknown',
    capabilityId: 'cap-schema-transport',
    surfaces: ['standalone_tui', 'macos_desktop'],
    operatingSystems: ['macos', 'linux', 'wsl'],
    architectures: ['arm64', 'x86_64'],
    requiredForGo: true,
    fixtureClass: 'public-deterministic',
    requiresRealAccount: false,
    requiresSynchronousObserver: false,
    expectedOutcomeClass: 'pass',
  },
  {
    caseId: 'case-schema-bounded-frame-depth-queue-rate',
    capabilityId: 'cap-schema-transport',
    surfaces: ['standalone_tui', 'macos_desktop'],
    operatingSystems: ['macos', 'linux', 'wsl'],
    architectures: ['arm64', 'x86_64'],
    requiredForGo: true,
    fixtureClass: 'public-deterministic',
    requiresRealAccount: false,
    requiresSynchronousObserver: false,
    expectedOutcomeClass: 'pass',
  },
  {
    caseId: 'case-identity-wellformed-stable',
    capabilityId: 'cap-thread-identity',
    surfaces: ['standalone_tui', 'macos_desktop'],
    operatingSystems: ['macos', 'linux', 'wsl'],
    architectures: ['arm64', 'x86_64'],
    requiredForGo: true,
    fixtureClass: 'public-deterministic',
    requiresRealAccount: false,
    requiresSynchronousObserver: false,
    expectedOutcomeClass: 'pass',
  },
  {
    caseId: 'case-identity-distinct-thread-ids',
    capabilityId: 'cap-thread-identity',
    surfaces: ['standalone_tui', 'macos_desktop'],
    operatingSystems: ['macos', 'linux', 'wsl'],
    architectures: ['arm64', 'x86_64'],
    requiredForGo: true,
    fixtureClass: 'public-deterministic',
    requiresRealAccount: false,
    requiresSynchronousObserver: false,
    expectedOutcomeClass: 'pass',
  },
  {
    caseId: 'case-identity-survives-app-server-restart',
    capabilityId: 'cap-thread-identity',
    surfaces: ['standalone_tui', 'macos_desktop'],
    operatingSystems: ['macos', 'linux', 'wsl'],
    architectures: ['arm64', 'x86_64'],
    requiredForGo: true,
    fixtureClass: 'public-deterministic',
    requiresRealAccount: false,
    requiresSynchronousObserver: false,
    expectedOutcomeClass: 'pass',
  },
  {
    caseId: 'case-identity-authoritative-client-observer-same',
    capabilityId: 'cap-thread-identity',
    surfaces: ['standalone_tui', 'macos_desktop'],
    operatingSystems: ['macos', 'linux', 'wsl'],
    architectures: ['arm64', 'x86_64'],
    requiredForGo: true,
    fixtureClass: 'public-deterministic',
    requiresRealAccount: false,
    requiresSynchronousObserver: false,
    expectedOutcomeClass: 'pass',
  },
  {
    caseId: 'case-identity-no-raw-id-in-artifact',
    capabilityId: 'cap-thread-identity',
    surfaces: ['standalone_tui', 'macos_desktop'],
    operatingSystems: ['macos', 'linux', 'wsl'],
    architectures: ['arm64', 'x86_64'],
    requiredForGo: true,
    fixtureClass: 'public-deterministic',
    requiresRealAccount: false,
    requiresSynchronousObserver: false,
    expectedOutcomeClass: 'pass',
  },
  {
    caseId: 'case-order-source-tuple-stable',
    capabilityId: 'cap-event-order',
    surfaces: ['standalone_tui', 'macos_desktop'],
    operatingSystems: ['macos', 'linux', 'wsl'],
    architectures: ['arm64', 'x86_64'],
    requiredForGo: true,
    fixtureClass: 'public-deterministic',
    requiresRealAccount: false,
    requiresSynchronousObserver: false,
    expectedOutcomeClass: 'pass',
  },
  {
    caseId: 'case-order-authoritative-comparable-gap-detectable',
    capabilityId: 'cap-event-order',
    surfaces: ['standalone_tui', 'macos_desktop'],
    operatingSystems: ['macos', 'linux', 'wsl'],
    architectures: ['arm64', 'x86_64'],
    requiredForGo: true,
    fixtureClass: 'public-deterministic',
    requiresRealAccount: false,
    requiresSynchronousObserver: false,
    expectedOutcomeClass: 'pass',
  },
  {
    caseId: 'case-order-duplicate-identifiable',
    capabilityId: 'cap-event-order',
    surfaces: ['standalone_tui', 'macos_desktop'],
    operatingSystems: ['macos', 'linux', 'wsl'],
    architectures: ['arm64', 'x86_64'],
    requiredForGo: true,
    fixtureClass: 'public-deterministic',
    requiresRealAccount: false,
    requiresSynchronousObserver: false,
    expectedOutcomeClass: 'pass',
  },
  {
    caseId: 'case-order-reconnect-replay-repair',
    capabilityId: 'cap-event-order',
    surfaces: ['standalone_tui', 'macos_desktop'],
    operatingSystems: ['macos', 'linux', 'wsl'],
    architectures: ['arm64', 'x86_64'],
    requiredForGo: true,
    fixtureClass: 'public-deterministic',
    requiresRealAccount: false,
    requiresSynchronousObserver: false,
    expectedOutcomeClass: 'pass',
  },
  {
    caseId: 'case-order-arrival-time-not-only-order',
    capabilityId: 'cap-event-order',
    surfaces: ['standalone_tui', 'macos_desktop'],
    operatingSystems: ['macos', 'linux', 'wsl'],
    architectures: ['arm64', 'x86_64'],
    requiredForGo: true,
    fixtureClass: 'public-deterministic',
    requiresRealAccount: false,
    requiresSynchronousObserver: false,
    expectedOutcomeClass: 'pass',
  },
  {
    caseId: 'case-order-complete-set-authority',
    capabilityId: 'cap-event-order',
    surfaces: ['standalone_tui', 'macos_desktop'],
    operatingSystems: ['macos', 'linux', 'wsl'],
    architectures: ['arm64', 'x86_64'],
    requiredForGo: true,
    fixtureClass: 'public-deterministic',
    requiresRealAccount: false,
    requiresSynchronousObserver: false,
    expectedOutcomeClass: 'pass',
  },
  {
    caseId: 'case-order-no-duplicate-mapping-fanout',
    capabilityId: 'cap-event-order',
    surfaces: ['standalone_tui', 'macos_desktop'],
    operatingSystems: ['macos', 'linux', 'wsl'],
    architectures: ['arm64', 'x86_64'],
    requiredForGo: true,
    fixtureClass: 'public-deterministic',
    requiresRealAccount: false,
    requiresSynchronousObserver: false,
    expectedOutcomeClass: 'pass',
  },
  {
    caseId: 'case-commit-reply-steer-predicate',
    capabilityId: 'cap-command-commit',
    surfaces: ['standalone_tui', 'macos_desktop'],
    operatingSystems: ['macos', 'linux', 'wsl'],
    architectures: ['arm64', 'x86_64'],
    requiredForGo: false,
    fixtureClass: 'public-deterministic',
    requiresRealAccount: false,
    requiresSynchronousObserver: false,
    expectedOutcomeClass: 'pass',
  },
  {
    caseId: 'case-commit-reply-live-turn-rejected',
    capabilityId: 'cap-command-commit',
    surfaces: ['standalone_tui', 'macos_desktop'],
    operatingSystems: ['macos', 'linux', 'wsl'],
    architectures: ['arm64', 'x86_64'],
    requiredForGo: true,
    fixtureClass: 'public-deterministic',
    requiresRealAccount: false,
    requiresSynchronousObserver: false,
    expectedOutcomeClass: 'pass',
  },
  {
    caseId: 'case-commit-done-start-predicate',
    capabilityId: 'cap-command-commit',
    surfaces: ['standalone_tui', 'macos_desktop'],
    operatingSystems: ['macos', 'linux', 'wsl'],
    architectures: ['arm64', 'x86_64'],
    requiredForGo: true,
    fixtureClass: 'public-deterministic',
    requiresRealAccount: false,
    requiresSynchronousObserver: false,
    expectedOutcomeClass: 'pass',
  },
  {
    caseId: 'case-commit-interrupt-predicate',
    capabilityId: 'cap-command-commit',
    surfaces: ['standalone_tui', 'macos_desktop'],
    operatingSystems: ['macos', 'linux', 'wsl'],
    architectures: ['arm64', 'x86_64'],
    requiredForGo: true,
    fixtureClass: 'public-deterministic',
    requiresRealAccount: false,
    requiresSynchronousObserver: false,
    expectedOutcomeClass: 'pass',
  },
  {
    caseId: 'case-approval-authoritative-local-ui',
    capabilityId: 'cap-approval-authority',
    surfaces: ['standalone_tui', 'macos_desktop'],
    operatingSystems: ['macos', 'linux', 'wsl'],
    architectures: ['arm64', 'x86_64'],
    requiredForGo: true,
    fixtureClass: 'public-deterministic',
    requiresRealAccount: false,
    requiresSynchronousObserver: true,
    expectedOutcomeClass: 'pass',
  },
  {
    caseId: 'case-approval-observer-no-response',
    capabilityId: 'cap-approval-authority',
    surfaces: ['standalone_tui', 'macos_desktop'],
    operatingSystems: ['macos', 'linux', 'wsl'],
    architectures: ['arm64', 'x86_64'],
    requiredForGo: true,
    fixtureClass: 'public-deterministic',
    requiresRealAccount: false,
    requiresSynchronousObserver: true,
    expectedOutcomeClass: 'pass',
  },
  {
    caseId: 'case-approval-not-watch-reply-target',
    capabilityId: 'cap-approval-authority',
    surfaces: ['standalone_tui', 'macos_desktop'],
    operatingSystems: ['macos', 'linux', 'wsl'],
    architectures: ['arm64', 'x86_64'],
    requiredForGo: true,
    fixtureClass: 'public-deterministic',
    requiresRealAccount: false,
    requiresSynchronousObserver: false,
    expectedOutcomeClass: 'pass',
  },
  {
    caseId: 'case-approval-unknown-blocking-fails-closed',
    capabilityId: 'cap-approval-authority',
    surfaces: ['standalone_tui', 'macos_desktop'],
    operatingSystems: ['macos', 'linux', 'wsl'],
    architectures: ['arm64', 'x86_64'],
    requiredForGo: true,
    fixtureClass: 'public-deterministic',
    requiresRealAccount: false,
    requiresSynchronousObserver: false,
    expectedOutcomeClass: 'pass',
  },
  {
    caseId: 'case-approval-multiclient-ownership-stable',
    capabilityId: 'cap-approval-authority',
    surfaces: ['standalone_tui', 'macos_desktop'],
    operatingSystems: ['macos', 'linux', 'wsl'],
    architectures: ['arm64', 'x86_64'],
    requiredForGo: true,
    fixtureClass: 'public-deterministic',
    requiresRealAccount: false,
    requiresSynchronousObserver: false,
    expectedOutcomeClass: 'pass',
  },
  {
    caseId: 'case-fanout-observer-authoritative-concurrent',
    capabilityId: 'cap-multi-client-fanout',
    surfaces: ['standalone_tui', 'macos_desktop'],
    operatingSystems: ['macos', 'linux', 'wsl'],
    architectures: ['arm64', 'x86_64'],
    requiredForGo: true,
    fixtureClass: 'public-deterministic',
    requiresRealAccount: false,
    requiresSynchronousObserver: false,
    expectedOutcomeClass: 'pass',
  },
  {
    caseId: 'case-fanout-loaded-live-consistent',
    capabilityId: 'cap-multi-client-fanout',
    surfaces: ['standalone_tui', 'macos_desktop'],
    operatingSystems: ['macos', 'linux', 'wsl'],
    architectures: ['arm64', 'x86_64'],
    requiredForGo: true,
    fixtureClass: 'public-deterministic',
    requiresRealAccount: false,
    requiresSynchronousObserver: false,
    expectedOutcomeClass: 'pass',
  },
  {
    caseId: 'case-fanout-observer-connect-disconnect-no-change',
    capabilityId: 'cap-multi-client-fanout',
    surfaces: ['standalone_tui', 'macos_desktop'],
    operatingSystems: ['macos', 'linux', 'wsl'],
    architectures: ['arm64', 'x86_64'],
    requiredForGo: true,
    fixtureClass: 'public-deterministic',
    requiresRealAccount: false,
    requiresSynchronousObserver: false,
    expectedOutcomeClass: 'pass',
  },
  {
    caseId: 'case-fanout-correlation-no-cross-client',
    capabilityId: 'cap-multi-client-fanout',
    surfaces: ['standalone_tui', 'macos_desktop'],
    operatingSystems: ['macos', 'linux', 'wsl'],
    architectures: ['arm64', 'x86_64'],
    requiredForGo: true,
    fixtureClass: 'public-deterministic',
    requiresRealAccount: false,
    requiresSynchronousObserver: false,
    expectedOutcomeClass: 'pass',
  },
  {
    caseId: 'case-fanout-slow-observer-no-block',
    capabilityId: 'cap-multi-client-fanout',
    surfaces: ['standalone_tui', 'macos_desktop'],
    operatingSystems: ['macos', 'linux', 'wsl'],
    architectures: ['arm64', 'x86_64'],
    requiredForGo: true,
    fixtureClass: 'public-deterministic',
    requiresRealAccount: false,
    requiresSynchronousObserver: false,
    expectedOutcomeClass: 'pass',
  },
  {
    caseId: 'case-fanout-reconnect-no-duplicate-side-effect',
    capabilityId: 'cap-multi-client-fanout',
    surfaces: ['standalone_tui', 'macos_desktop'],
    operatingSystems: ['macos', 'linux', 'wsl'],
    architectures: ['arm64', 'x86_64'],
    requiredForGo: true,
    fixtureClass: 'public-deterministic',
    requiresRealAccount: false,
    requiresSynchronousObserver: false,
    expectedOutcomeClass: 'pass',
  },
  {
    caseId: 'case-tui-help-subcommand-tree',
    capabilityId: 'cap-tui-attachment',
    surfaces: ['standalone_tui'],
    operatingSystems: ['macos', 'linux', 'wsl'],
    architectures: ['arm64', 'x86_64'],
    requiredForGo: true,
    fixtureClass: 'public-deterministic',
    requiresRealAccount: false,
    requiresSynchronousObserver: false,
    expectedOutcomeClass: 'pass',
  },
  {
    caseId: 'case-tui-attachable-classification',
    capabilityId: 'cap-tui-attachment',
    surfaces: ['standalone_tui'],
    operatingSystems: ['macos', 'linux', 'wsl'],
    architectures: ['arm64', 'x86_64'],
    requiredForGo: true,
    fixtureClass: 'public-deterministic',
    requiresRealAccount: false,
    requiresSynchronousObserver: false,
    expectedOutcomeClass: 'pass',
  },
  {
    caseId: 'case-tui-internal-argv-no-collision',
    capabilityId: 'cap-tui-attachment',
    surfaces: ['standalone_tui'],
    operatingSystems: ['macos', 'linux', 'wsl'],
    architectures: ['arm64', 'x86_64'],
    requiredForGo: true,
    fixtureClass: 'public-deterministic',
    requiresRealAccount: false,
    requiresSynchronousObserver: false,
    expectedOutcomeClass: 'pass',
  },
  {
    caseId: 'case-tui-wrapper-argv-tty-stdio-signal-exit',
    capabilityId: 'cap-tui-attachment',
    surfaces: ['standalone_tui'],
    operatingSystems: ['macos', 'linux', 'wsl'],
    architectures: ['arm64', 'x86_64'],
    requiredForGo: true,
    fixtureClass: 'public-deterministic',
    requiresRealAccount: false,
    requiresSynchronousObserver: false,
    expectedOutcomeClass: 'pass',
  },
  {
    caseId: 'case-tui-actual-child-executable-identity',
    capabilityId: 'cap-tui-attachment',
    surfaces: ['standalone_tui'],
    operatingSystems: ['macos', 'linux', 'wsl'],
    architectures: ['arm64', 'x86_64'],
    requiredForGo: true,
    fixtureClass: 'public-deterministic',
    requiresRealAccount: false,
    requiresSynchronousObserver: false,
    expectedOutcomeClass: 'pass',
  },
  {
    caseId: 'case-tui-app-server-tui-observer-topology',
    capabilityId: 'cap-tui-attachment',
    surfaces: ['standalone_tui'],
    operatingSystems: ['macos', 'linux', 'wsl'],
    architectures: ['arm64', 'x86_64'],
    requiredForGo: true,
    fixtureClass: 'public-deterministic',
    requiresRealAccount: false,
    requiresSynchronousObserver: false,
    expectedOutcomeClass: 'pass',
  },
  {
    caseId: 'case-tui-no-owned-orphan',
    capabilityId: 'cap-tui-attachment',
    surfaces: ['standalone_tui'],
    operatingSystems: ['macos', 'linux', 'wsl'],
    architectures: ['arm64', 'x86_64'],
    requiredForGo: true,
    fixtureClass: 'public-deterministic',
    requiresRealAccount: false,
    requiresSynchronousObserver: false,
    expectedOutcomeClass: 'pass',
  },
  {
    caseId: 'case-desktop-app-identity',
    capabilityId: 'cap-desktop-attachment',
    surfaces: ['macos_desktop'],
    operatingSystems: ['macos'],
    architectures: ['arm64', 'x86_64'],
    requiredForGo: true,
    fixtureClass: 'public-deterministic',
    requiresRealAccount: false,
    requiresSynchronousObserver: false,
    expectedOutcomeClass: 'pass',
  },
  {
    caseId: 'case-desktop-local-daemon-env-scoped',
    capabilityId: 'cap-desktop-attachment',
    surfaces: ['macos_desktop'],
    operatingSystems: ['macos'],
    architectures: ['arm64', 'x86_64'],
    requiredForGo: true,
    fixtureClass: 'public-deterministic',
    requiresRealAccount: false,
    requiresSynchronousObserver: false,
    expectedOutcomeClass: 'pass',
  },
  {
    caseId: 'case-desktop-fixed-socket-audit',
    capabilityId: 'cap-desktop-attachment',
    surfaces: ['macos_desktop'],
    operatingSystems: ['macos'],
    architectures: ['arm64', 'x86_64'],
    requiredForGo: true,
    fixtureClass: 'public-deterministic',
    requiresRealAccount: false,
    requiresSynchronousObserver: false,
    expectedOutcomeClass: 'pass',
  },
  {
    caseId: 'case-desktop-listener-pid-start-identity',
    capabilityId: 'cap-desktop-attachment',
    surfaces: ['macos_desktop'],
    operatingSystems: ['macos'],
    architectures: ['arm64', 'x86_64'],
    requiredForGo: true,
    fixtureClass: 'public-deterministic',
    requiresRealAccount: false,
    requiresSynchronousObserver: false,
    expectedOutcomeClass: 'pass',
  },
  {
    caseId: 'case-desktop-shared-app-server-concurrency',
    capabilityId: 'cap-desktop-attachment',
    surfaces: ['macos_desktop'],
    operatingSystems: ['macos'],
    architectures: ['arm64', 'x86_64'],
    requiredForGo: true,
    fixtureClass: 'public-deterministic',
    requiresRealAccount: false,
    requiresSynchronousObserver: false,
    expectedOutcomeClass: 'pass',
  },
  {
    caseId: 'case-desktop-actual-pid-code-object-attachment',
    capabilityId: 'cap-desktop-attachment',
    surfaces: ['macos_desktop'],
    operatingSystems: ['macos'],
    architectures: ['arm64', 'x86_64'],
    requiredForGo: true,
    fixtureClass: 'public-deterministic',
    requiresRealAccount: false,
    requiresSynchronousObserver: false,
    expectedOutcomeClass: 'pass',
  },
  {
    caseId: 'case-desktop-preexisting-external-listener-not-taken-over',
    capabilityId: 'cap-desktop-attachment',
    surfaces: ['macos_desktop'],
    operatingSystems: ['macos'],
    architectures: ['arm64', 'x86_64'],
    requiredForGo: true,
    fixtureClass: 'public-deterministic',
    requiresRealAccount: false,
    requiresSynchronousObserver: false,
    expectedOutcomeClass: 'pass',
  },
  {
    caseId: 'case-desktop-launcher-exit-keeps-runtime',
    capabilityId: 'cap-desktop-attachment',
    surfaces: ['macos_desktop'],
    operatingSystems: ['macos'],
    architectures: ['arm64', 'x86_64'],
    requiredForGo: true,
    fixtureClass: 'public-deterministic',
    requiresRealAccount: false,
    requiresSynchronousObserver: false,
    expectedOutcomeClass: 'pass',
  },
  {
    caseId: 'case-desktop-graceful-restart-boundary',
    capabilityId: 'cap-desktop-attachment',
    surfaces: ['macos_desktop'],
    operatingSystems: ['macos'],
    architectures: ['arm64', 'x86_64'],
    requiredForGo: true,
    fixtureClass: 'public-deterministic',
    requiresRealAccount: false,
    requiresSynchronousObserver: false,
    expectedOutcomeClass: 'pass',
  },
  {
    caseId: 'case-desktop-remote-control-coexistence',
    capabilityId: 'cap-desktop-attachment',
    surfaces: ['macos_desktop'],
    operatingSystems: ['macos'],
    architectures: ['arm64', 'x86_64'],
    requiredForGo: true,
    fixtureClass: 'public-deterministic',
    requiresRealAccount: false,
    requiresSynchronousObserver: false,
    expectedOutcomeClass: 'pass',
  },
  {
    caseId: 'case-desktop-cleanup-only-owned-child',
    capabilityId: 'cap-desktop-attachment',
    surfaces: ['macos_desktop'],
    operatingSystems: ['macos'],
    architectures: ['arm64', 'x86_64'],
    requiredForGo: true,
    fixtureClass: 'public-deterministic',
    requiresRealAccount: false,
    requiresSynchronousObserver: false,
    expectedOutcomeClass: 'pass',
  },
  {
    caseId: 'case-platform-parent-death-containment',
    capabilityId: 'cap-platform-containment',
    surfaces: ['standalone_tui', 'macos_desktop'],
    operatingSystems: ['macos', 'linux', 'wsl'],
    architectures: ['arm64', 'x86_64'],
    requiredForGo: true,
    fixtureClass: 'public-deterministic',
    requiresRealAccount: false,
    requiresSynchronousObserver: false,
    expectedOutcomeClass: 'pass',
  },
  {
    caseId: 'case-platform-normal-exit-signal-crash-cleanup',
    capabilityId: 'cap-platform-containment',
    surfaces: ['standalone_tui', 'macos_desktop'],
    operatingSystems: ['macos', 'linux', 'wsl'],
    architectures: ['arm64', 'x86_64'],
    requiredForGo: true,
    fixtureClass: 'public-deterministic',
    requiresRealAccount: false,
    requiresSynchronousObserver: false,
    expectedOutcomeClass: 'pass',
  },
  {
    caseId: 'case-platform-sigkill-durable-ownership-record',
    capabilityId: 'cap-platform-containment',
    surfaces: ['standalone_tui', 'macos_desktop'],
    operatingSystems: ['macos', 'linux', 'wsl'],
    architectures: ['arm64', 'x86_64'],
    requiredForGo: true,
    fixtureClass: 'public-deterministic',
    requiresRealAccount: false,
    requiresSynchronousObserver: false,
    expectedOutcomeClass: 'pass',
  },
  {
    caseId: 'case-platform-macos-signature-or-linux-proc-identity',
    capabilityId: 'cap-platform-containment',
    surfaces: ['standalone_tui', 'macos_desktop'],
    operatingSystems: ['macos', 'linux', 'wsl'],
    architectures: ['arm64', 'x86_64'],
    requiredForGo: true,
    fixtureClass: 'public-deterministic',
    requiresRealAccount: false,
    requiresSynchronousObserver: false,
    expectedOutcomeClass: 'pass',
  },
  {
    caseId: 'case-platform-wsl-systemd-user-capability',
    capabilityId: 'cap-platform-containment',
    surfaces: ['standalone_tui'],
    operatingSystems: ['wsl'],
    architectures: ['arm64', 'x86_64'],
    requiredForGo: true,
    fixtureClass: 'public-deterministic',
    requiresRealAccount: false,
    requiresSynchronousObserver: false,
    expectedOutcomeClass: 'pass',
  },
  {
    caseId: 'case-platform-docker-only-container-tuple',
    capabilityId: 'cap-platform-containment',
    surfaces: ['standalone_tui'],
    operatingSystems: ['linux'],
    architectures: ['arm64', 'x86_64'],
    requiredForGo: false,
    fixtureClass: 'public-deterministic',
    requiresRealAccount: false,
    requiresSynchronousObserver: false,
    expectedOutcomeClass: 'pass',
  },
]);

/** Capability ids referenced by the registry (stable, reviewed). */
export const CANONICAL_CAPABILITIES: readonly string[] = Object.freeze([
  'cap-schema-transport',
  'cap-thread-identity',
  'cap-event-order',
  'cap-command-commit',
  'cap-approval-authority',
  'cap-multi-client-fanout',
  'cap-tui-attachment',
  'cap-desktop-attachment',
  'cap-platform-containment',
]);

/**
 * Named profiles. A profile may only select the full canonical set
 * (`fullCanonicalSet: true`) plus optional diagnostic-only extra cases.
 * No profile can exclude a `requiredForGo=true` case.
 */
export const CANONICAL_PROFILES: readonly CaseProfile[] = Object.freeze([
  { id: 'full', fullCanonicalSet: true },
  { id: 'diagnostics', fullCanonicalSet: true, extraCaseIds: ['case-platform-docker-only-container-tuple'] },
]);

function assertCanonicalRegistry(cases: readonly CanonicalCase[]): void {
  const caseIds = new Set<string>();
  const capabilityIds = new Set<string>();
  for (const entry of cases) {
    if (!entry.caseId || typeof entry.caseId !== 'string') throw new Error('case registry: caseId must be a non-empty string');
    if (caseIds.has(entry.caseId)) throw new Error(`case registry: duplicate caseId ${entry.caseId}`);
    caseIds.add(entry.caseId);
    if (!entry.capabilityId || typeof entry.capabilityId !== 'string') throw new Error(`case ${entry.caseId}: capabilityId must be a non-empty string`);
    capabilityIds.add(entry.capabilityId);
    if (!entry.surfaces.length || entry.surfaces.some((surface) => !SURFACES.includes(surface))) {
      throw new Error(`case ${entry.caseId}: surfaces must be non-empty and reviewed`);
    }
    if (!entry.operatingSystems.length || entry.operatingSystems.some((os) => !OPERATING_SYSTEMS.includes(os))) {
      throw new Error(`case ${entry.caseId}: operatingSystems must be non-empty and reviewed`);
    }
    if (!entry.architectures.length || entry.architectures.some((arch) => !ARCHITECTURES.includes(arch))) {
      throw new Error(`case ${entry.caseId}: architectures must be non-empty and reviewed`);
    }
    if (!FIXTURE_CLASSES.includes(entry.fixtureClass)) throw new Error(`case ${entry.caseId}: unknown fixtureClass`);
    if (!EXPECTED_OUTCOME_CLASSES.includes(entry.expectedOutcomeClass)) throw new Error(`case ${entry.caseId}: unknown expectedOutcomeClass`);
  }
  for (const capabilityId of CANONICAL_CAPABILITIES) {
    if (!capabilityIds.has(capabilityId)) throw new Error(`case registry: capability ${capabilityId} has no cases`);
  }
}

assertCanonicalRegistry(CANONICAL_CASES);

/** Compute the registry digest over JCS-canonical bytes. */
export function registryDigest(): RegistryDigest {
  const canonicalBytes = jcs(CANONICAL_CASES.map((entry) => ({
    caseId: entry.caseId,
    capabilityId: entry.capabilityId,
    surfaces: entry.surfaces,
    operatingSystems: entry.operatingSystems,
    architectures: entry.architectures,
    requiredForGo: entry.requiredForGo,
    fixtureClass: entry.fixtureClass,
    requiresRealAccount: entry.requiresRealAccount,
    requiresSynchronousObserver: entry.requiresSynchronousObserver,
    expectedOutcomeClass: entry.expectedOutcomeClass,
  })) as unknown as Parameters<typeof jcs>[0]);
  return {
    version: CODEX_POC_REGISTRY_VERSION,
    digest: createHash('sha256').update(canonicalBytes).digest('hex'),
    canonicalBytes,
  };
}

export interface TupleFilter {
  surface: Surface;
  os: OperatingSystem;
  architecture: Architecture;
}

/** Filter the canonical registry by tuple to obtain the run's required case set. */
export function selectCasesForTuple(filter: TupleFilter, options: { profile?: CaseProfile } = {}): {
  requiredCaseIds: string[];
  diagnosticCaseIds: string[];
} {
  const matches = CANONICAL_CASES.filter((entry) =>
    entry.surfaces.includes(filter.surface) &&
    entry.operatingSystems.includes(filter.os) &&
    entry.architectures.includes(filter.architecture));
  const required = matches.filter((entry) => entry.requiredForGo).map((entry) => entry.caseId);
  const diagnostic = matches.filter((entry) => !entry.requiredForGo).map((entry) => entry.caseId);

  const profile = options.profile;
  if (profile) {
    if (!profile.fullCanonicalSet) throw new Error(`profile ${profile.id}: only full-canonical-set profiles are allowed`);
    const known = new Set(CANONICAL_CASES.map((entry) => entry.caseId));
    for (const extra of profile.extraCaseIds ?? []) {
      if (!known.has(extra)) throw new Error(`profile ${profile.id}: unknown extra case ${extra}`);
      const entry = CANONICAL_CASES.find((candidate) => candidate.caseId === extra);
      if (entry && entry.requiredForGo) throw new Error(`profile ${profile.id}: extra case ${extra} is requiredForGo and cannot be re-selected as diagnostic`);
    }
  }

  return {
    requiredCaseIds: [...required].sort(),
    diagnosticCaseIds: [...diagnostic].sort(),
  };
}

/** Validate a set of case ids against the canonical registry. */
export function validateCaseIds(caseIds: string[]): { unknown: string[]; duplicates: string[]; missing: string[] } {
  const known = new Set(CANONICAL_CASES.map((entry) => entry.caseId));
  const seen = new Set<string>();
  const duplicates: string[] = [];
  const unknown: string[] = [];
  for (const caseId of caseIds) {
    if (!known.has(caseId)) unknown.push(caseId);
    if (seen.has(caseId)) duplicates.push(caseId);
    seen.add(caseId);
  }
  const missing = CANONICAL_CASES.filter((entry) => entry.requiredForGo && !seen.has(entry.caseId)).map((entry) => entry.caseId);
  return { unknown: [...unknown].sort(), duplicates: [...duplicates].sort(), missing: [...missing].sort() };
}
