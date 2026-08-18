/**
 * CODEX-POC requirement registry (spec §10 Phase 0, §7.2).
 *
 * Every normative requirement carries a stable `CODEX-POC-<DOMAIN>-NNN` id and
 * maps to at least one canonical case id. The mapping is enforced by tests:
 * every requirement must map to ≥1 case, and every canonical case must be
 * reachable from at least one requirement (full coverage both ways).
 *
 * This is research-only harness code, never part of the production import graph.
 */

export interface RequirementEntry {
  /** Stable requirement id, e.g. `CODEX-POC-IDENTITY-001`. */
  id: string;
  /** Short normative statement. */
  requirement: string;
  /** Canonical case ids that evidence this requirement. */
  caseIds: string[];
  /** Spec section that defines the requirement. */
  specSection: string;
}

export const REQUIREMENT_REGISTRY: readonly RequirementEntry[] = Object.freeze([
  {
    id: 'CODEX-POC-BASELINE-001',
    requirement: 'Formal verdict runs execute only from a clean committed harness checkout; dirty harness is debug-only and can never produce GO.',
    caseIds: ['case-schema-initialize'],
    specSection: '§10 Phase 0',
  },
  {
    id: 'CODEX-POC-BASELINE-002',
    requirement: 'PoC allowed paths are frozen and forbidden production paths are guarded.',
    caseIds: ['case-schema-initialize'],
    specSection: '§10 Phase 0, §11.3',
  },
  {
    id: 'CODEX-POC-SCHEMA-001',
    requirement: 'Evidence exact schema rejects unknown/missing keys; arrays sorted by stable id and reject duplicates.',
    caseIds: ['case-schema-initialize'],
    specSection: '§7.3',
  },
  {
    id: 'CODEX-POC-SCHEMA-005',
    requirement: 'App-server schema surface covers initialize/initialized, framing/correlation/notification parsing, thread list/read, loaded/unloaded.',
    caseIds: ['case-schema-initialize', 'case-schema-framing-correlation', 'case-schema-thread-list-read', 'case-schema-loaded-unloaded'],
    specSection: '§8.1',
  },
  {
    id: 'CODEX-POC-SCHEMA-006',
    requirement: 'App-server schema surface covers turn start/steer/interrupt, turn/item completion and error notifications, approval/blocking server requests, daemon version/status.',
    caseIds: ['case-schema-turn-start-steer-interrupt', 'case-schema-turn-item-completion-error', 'case-schema-approval-blocking', 'case-schema-daemon-version-status'],
    specSection: '§8.1',
  },
  {
    id: 'CODEX-POC-SCHEMA-007',
    requirement: 'Malformed, oversized, duplicate ID, unknown response/request, out-of-order and disconnect handling; bounded frame/depth/collection/pending/queue/per-thread buffer/rate.',
    caseIds: ['case-schema-malformed-oversized-duplicate-unknown', 'case-schema-bounded-frame-depth-queue-rate'],
    specSection: '§8.1',
  },
  {
    id: 'CODEX-POC-SCHEMA-002',
    requirement: 'Evidence digest is SHA-256(RFC 8785 JCS(artifact with review=null)); review record stored separately.',
    caseIds: ['case-schema-framing-correlation'],
    specSection: '§7.3',
  },
  {
    id: 'CODEX-POC-SCHEMA-003',
    requirement: 'Registry digest computed at run start and written into the artifact.',
    caseIds: ['case-schema-initialize'],
    specSection: '§7.2',
  },
  {
    id: 'CODEX-POC-SCHEMA-004',
    requirement: 'Bounded error codes only; no raw exception text or raw sensitive content in evidence.',
    caseIds: ['case-schema-framing-correlation'],
    specSection: '§7.3',
  },
  {
    id: 'CODEX-POC-IDENTITY-001',
    requirement: 'Raw thread identity is well-formed stable UTF-8; distinct threads have distinct ids; survives app-server restart.',
    caseIds: ['case-identity-wellformed-stable', 'case-identity-distinct-thread-ids', 'case-identity-survives-app-server-restart'],
    specSection: '§8.2',
  },
  {
    id: 'CODEX-POC-IDENTITY-002',
    requirement: 'Authoritative surface client and observer see the same thread identity.',
    caseIds: ['case-identity-authoritative-client-observer-same'],
    specSection: '§8.2',
  },
  {
    id: 'CODEX-POC-IDENTITY-003',
    requirement: 'Raw thread id never enters artifacts, ordinary logs, or Ariava payloads.',
    caseIds: ['case-identity-no-raw-id-in-artifact'],
    specSection: '§8.2',
  },
  {
    id: 'CODEX-POC-ORDER-001',
    requirement: 'Every mapped canonical event has a provider-native source tuple: rawThreadId + providerGeneration + authoritativeOrder + sourceEventId/type.',
    caseIds: ['case-order-source-tuple-stable'],
    specSection: '§8.3',
  },
  {
    id: 'CODEX-POC-ORDER-002',
    requirement: 'Authoritative order is strict, comparable, and gap-detectable; duplicates identifiable.',
    caseIds: ['case-order-authoritative-comparable-gap-detectable', 'case-order-duplicate-identifiable'],
    specSection: '§8.3',
  },
  {
    id: 'CODEX-POC-ORDER-003',
    requirement: 'Reconnect/replay can repair from authoritative read; arrival time is not the only order; complete-set authority exists.',
    caseIds: ['case-order-reconnect-replay-repair', 'case-order-arrival-time-not-only-order', 'case-order-complete-set-authority'],
    specSection: '§8.3',
  },
  {
    id: 'CODEX-POC-ORDER-004',
    requirement: 'Approval and ordinary question/error/completion are not duplicated by fanout mapping.',
    caseIds: ['case-order-no-duplicate-mapping-fanout'],
    specSection: '§8.3',
  },
  {
    id: 'CODEX-POC-COMMIT-001',
    requirement: 'Watch reply on a live/working turn is rejected before any provider RPC and is never implemented as turn/steer.',
    caseIds: ['case-commit-reply-live-turn-rejected'],
    specSection: '§8.4',
  },
  {
    id: 'CODEX-POC-COMMIT-002',
    requirement: 'Watch reply on an idle thread maps to turn/start with an operation-specific positive commit predicate.',
    caseIds: ['case-commit-done-start-predicate'],
    specSection: '§8.4',
  },
  {
    id: 'CODEX-POC-COMMIT-003',
    requirement: 'Working interrupt maps to turn/interrupt with an operation-specific positive commit predicate.',
    caseIds: ['case-commit-interrupt-predicate'],
    specSection: '§8.4',
  },
  {
    id: 'CODEX-POC-COMMIT-004',
    requirement: 'Codex turn/steer may exist on the reviewed schema, but it is diagnostic-only and is not a Watch command.',
    caseIds: ['case-commit-reply-steer-predicate'],
    specSection: '§8.4',
  },
  {
    id: 'CODEX-POC-APPROVAL-001',
    requirement: 'Approval requests reach only the authoritative local TUI/Desktop client; the observer never responds, preempts, or alters approval.',
    caseIds: ['case-approval-authoritative-local-ui', 'case-approval-observer-no-response'],
    specSection: '§8.5',
  },
  {
    id: 'CODEX-POC-APPROVAL-002',
    requirement: 'Approval never maps to a Watch reply target; unknown blocking requests fail closed; multi-client ownership stable.',
    caseIds: ['case-approval-not-watch-reply-target', 'case-approval-unknown-blocking-fails-closed', 'case-approval-multiclient-ownership-stable'],
    specSection: '§8.5',
  },
  {
    id: 'CODEX-POC-FANOUT-001',
    requirement: 'Reviewed app-server supports observer + authoritative client concurrency with consistent loaded/read and live notifications.',
    caseIds: ['case-fanout-observer-authoritative-concurrent', 'case-fanout-loaded-live-consistent'],
    specSection: '§8.6',
  },
  {
    id: 'CODEX-POC-FANOUT-002',
    requirement: 'Observer connect/disconnect does not alter authoritative UI; correlation never crosses clients; slow observer never blocks; reconnect has no duplicate side effects.',
    caseIds: ['case-fanout-observer-connect-disconnect-no-change', 'case-fanout-correlation-no-cross-client', 'case-fanout-slow-observer-no-block', 'case-fanout-reconnect-no-duplicate-side-effect'],
    specSection: '§8.6',
  },
  {
    id: 'CODEX-POC-TUI-001',
    requirement: 'TUI public help/subcommand tree and option arity are fingerprinted; attachability classified.',
    caseIds: ['case-tui-help-subcommand-tree', 'case-tui-attachable-classification'],
    specSection: '§8.7',
  },
  {
    id: 'CODEX-POC-TUI-002',
    requirement: 'Internal app-server/attachment params never collide with user argv; direct vs wrapper argv/cwd/TTY/stdio/signal/exit equivalence proven.',
    caseIds: ['case-tui-internal-argv-no-collision', 'case-tui-wrapper-argv-tty-stdio-signal-exit'],
    specSection: '§8.7',
  },
  {
    id: 'CODEX-POC-TUI-003',
    requirement: 'Actual TUI child executable identity; one reviewed app-server + real TUI + observer topology; no owned orphan after exit/signal/crash/termination.',
    caseIds: ['case-tui-actual-child-executable-identity', 'case-tui-app-server-tui-observer-topology', 'case-tui-no-owned-orphan'],
    specSection: '§8.7',
  },
  {
    id: 'CODEX-POC-DESKTOP-001',
    requirement: 'Desktop identity from explicit absolute .app path: bundle id/version/build, relative executable, realpath/ancestor/owner/mode, binary SHA-256/arch, signing fields, schema fingerprint, socket + attachment strategy.',
    caseIds: ['case-desktop-app-identity', 'case-desktop-local-daemon-env-scoped'],
    specSection: '§5.3, §8.8',
  },
  {
    id: 'CODEX-POC-DESKTOP-002',
    requirement: 'Fixed socket audit and listener PID/start identity; shared app-server concurrency; actual Desktop PID/code object attachment proof.',
    caseIds: ['case-desktop-fixed-socket-audit', 'case-desktop-listener-pid-start-identity', 'case-desktop-shared-app-server-concurrency', 'case-desktop-actual-pid-code-object-attachment'],
    specSection: '§8.8',
  },
  {
    id: 'CODEX-POC-DESKTOP-003',
    requirement: 'Preexisting external listener/Desktop never taken over; launcher exit keeps runtime; graceful restart boundary; Remote Control coexistence; cleanup only exact owned child.',
    caseIds: ['case-desktop-preexisting-external-listener-not-taken-over', 'case-desktop-launcher-exit-keeps-runtime', 'case-desktop-graceful-restart-boundary', 'case-desktop-remote-control-coexistence', 'case-desktop-cleanup-only-owned-child'],
    specSection: '§8.8',
  },
  {
    id: 'CODEX-POC-PLATFORM-001',
    requirement: 'Parent-death containment; normal exit/SIGINT/SIGTERM/crash cleanup; SIGKILL aftermath distinguished via durable ownership record.',
    caseIds: ['case-platform-parent-death-containment', 'case-platform-normal-exit-signal-crash-cleanup', 'case-platform-sigkill-durable-ownership-record'],
    specSection: '§8.9',
  },
  {
    id: 'CODEX-POC-PLATFORM-002',
    requirement: 'macOS process/signature or Linux /proc identity is sufficient; WSL systemd-user capability is real, no fallback; Docker results only label container tuples.',
    caseIds: ['case-platform-macos-signature-or-linux-proc-identity', 'case-platform-wsl-systemd-user-capability', 'case-platform-docker-only-container-tuple'],
    specSection: '§8.9',
  },
]);

/** Validate that every requirement maps to ≥1 canonical case, and every canonical
 * case is reachable from at least one requirement (full coverage both ways).
 * Returns the list of violations: missing requirement ids, dangling case refs,
 * and unreachable canonical cases.
 */
export function assertRequirementCoverage(caseIds: ReadonlySet<string>): string[] {
  const missing: string[] = [];
  const reachable = new Set<string>();
  for (const entry of REQUIREMENT_REGISTRY) {
    if (entry.caseIds.length === 0) missing.push(entry.id);
    for (const caseId of entry.caseIds) {
      if (!caseIds.has(caseId)) missing.push(`${entry.id} -> ${caseId}`);
      reachable.add(caseId);
    }
  }
  for (const caseId of caseIds) {
    if (!reachable.has(caseId)) missing.push(`unreachable case ${caseId}`);
  }
  return missing;
}
