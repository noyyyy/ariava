/**
 * Shared constants for the Codex Exact-Release Capability PoC harness.
 *
 * These are normative harness inputs: changing any reviewed constant here makes
 * prior evidence artifacts stale (spec §5.4) and changes the
 * `normativeInputDigest` computed for a run (spec §7.3).
 *
 * Scope: research PoC only. This module is never imported by Bridge production
 * code, Relay, or watchOS. It implements no production adapter, manifest entry,
 * or service wiring (spec §4).
 */

export const CODEX_POC_SCHEMA_VERSION = 1 as const;

export const CODEX_POC_REGISTRY_VERSION = 1 as const;

/** Stable identity of the evidence schema; part of normative inputs. */
export const EVIDENCE_SCHEMA_ID = 'codex-exact-release-poc-evidence-v1' as const;

/** Reviewed bounded outcome codes (spec §7.3): never raw exception text. */
export const OUTCOME_CODES = [
  'pass',
  'fail-missing-seam',
  'fail-no-stable-identity',
  'fail-no-stable-order',
  'fail-no-commit-predicate',
  'fail-approval-preemption',
  'fail-unsafe-multiclient',
  'fail-ownership-indistinguishable',
  'fail-wrapper-breaks-semantics',
  'fail-forbidden-env-override',
  'fail-unbounded-parser-risk',
  'fail-provider-outside-allowlist-write',
  'unavailable-environment',
  'unavailable-account',
  'unavailable-platform',
  'unavailable-tty',
  'unavailable-desktop',
  'unavailable-binary',
  'unavailable-observer-attestation',
  'interrupted-external-failure',
  'inconclusive-evidence-incomplete',
  'inconclusive-harness-vs-provider',
  'inconclusive-identity-drift',
  'inconclusive-unreviewable',
  'unknown',
] as const;

export type OutcomeCode = (typeof OUTCOME_CODES)[number];

/** Reviewed bounded verdict reasons (spec §9, §7.3). */
export const VERDICT_REASONS = [
  'release-identity-complete',
  'schema-complete',
  'all-required-cases-pass',
  'thread-identity-stable',
  'event-identity-order-gap-repair',
  'three-command-commit-predicates',
  'approval-authority',
  'multi-client-fanout',
  'surface-attachment-lifecycle',
  'platform-containment',
  'privacy-workspace-cleanup-audits-pass',
  'no-unknown-authority-changing-request',
  'independent-review-accepted',
  'required-case-missing',
  'required-case-duplicate',
  'required-case-unknown',
  'required-case-not-run',
  'required-case-unavailable',
  'release-identity-incomplete',
  'schema-incomplete',
  'missing-seam',
  'event-no-stable-identity-order',
  'command-no-positive-commit-predicate',
  'approval-preemption',
  'unsafe-multiclient',
  'ownership-indistinguishable',
  'wrapper-breaks-semantics',
  'forbidden-env-override',
  'unbounded-parser-risk',
  'provider-outside-allowlist-write',
  'privacy-audit-failed',
  'workspace-audit-failed',
  'cleanup-audit-failed',
  'unknown-authority-changing-request',
  'review-missing',
  'environment-unavailable',
  'account-unavailable',
  'platform-unavailable',
  'tty-unavailable',
  'desktop-unavailable',
  'interrupted',
  'evidence-incomplete',
  'harness-vs-provider-indistinguishable',
  'identity-drift',
  'unreviewable',
  'diagnostic-only',
] as const;

export type VerdictReason = (typeof VERDICT_REASONS)[number];

/** Bounded exit classes (spec §7.3). */
export const EXIT_CLASSES = ['zero', 'nonzero', 'signal', 'none'] as const;
export type ExitClass = (typeof EXIT_CLASSES)[number];

/** Bounded duration buckets (spec §7.3). */
export const DURATION_BUCKETS = ['lt1s', '1s-10s', '10s-60s', 'gt60s'] as const;
export type DurationBucket = (typeof DURATION_BUCKETS)[number];

/** Surface dimension of the tuple (spec §5.1). */
export const SURFACES = ['standalone_tui', 'macos_desktop'] as const;
export type Surface = (typeof SURFACES)[number];

/** OS dimension of the tuple (spec §5.1). */
export const OPERATING_SYSTEMS = ['macos', 'linux', 'wsl'] as const;
export type OperatingSystem = (typeof OPERATING_SYSTEMS)[number];

/** Architecture dimension of the tuple (spec §5.1). */
export const ARCHITECTURES = ['arm64', 'x86_64'] as const;
export type Architecture = (typeof ARCHITECTURES)[number];

/** Capability status values (spec §7.3). */
export const CAPABILITY_STATUSES = ['PASS', 'FAIL', 'UNAVAILABLE'] as const;
export type CapabilityStatus = (typeof CAPABILITY_STATUSES)[number];

/** Verdict values (spec §7.3, §9). */
export const VERDICTS = ['GO', 'NO-GO', 'INCONCLUSIVE'] as const;
export type Verdict = (typeof VERDICTS)[number];

/**
 * Attachment strategy IDs (reviewed stable IDs; spec §5.1). Values are
 * placeholders pending real-release inventory (Task 8); changing the reviewed
 * set makes evidence stale.
 */
export const ATTACHMENT_STRATEGIES = [
  'reviewed-tui-app-server-argv',
  'reviewed-macos-desktop-local-daemon-socket',
] as const;
export type AttachmentStrategy = (typeof ATTACHMENT_STRATEGIES)[number];

/** Fixture classes (spec §7.1). */
export const FIXTURE_CLASSES = ['public-deterministic', 'real-interaction'] as const;
export type FixtureClass = (typeof FIXTURE_CLASSES)[number];

/** Expected outcome classes for canonical cases. */
export const EXPECTED_OUTCOME_CLASSES = [
  'pass',
  'fail',
  'unsupported',
  'unavailable',
] as const;
export type ExpectedOutcomeClass = (typeof EXPECTED_OUTCOME_CLASSES)[number];
