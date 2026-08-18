/**
 * TUI attachment model for the Codex Exact-Release Capability PoC
 * (spec §8.7).
 *
 * Models the TUI attachment/lifecycle invariants the harness must prove:
 *   - attachability classification (tui_attachable | provider_utility |
 *     reserved_internal);
 *   - internal-argv collision checks;
 *   - topology (reviewed app-server + real TUI + observer);
 *   - owned-orphan detection.
 *
 * Research-only harness code; never part of the production import graph.
 */

import { createHash } from 'node:crypto';
import {
  assertReviewedTopology,
  checkInternalArgCollision,
  classifyAttachability,
  detectOwnedOrphans,
  type OwnedProcessRecord,
  type TopologyState,
} from './cli-equivalence';
import { jcs } from './jcs';

/** TUI attachment strategy identity (reviewed stable id; spec §5.1). */
export const TUI_ATTACHMENT_STRATEGY_ID = 'reviewed-tui-app-server-argv';

export interface TuiAttachmentAssessment {
  attachable: boolean;
  classification: 'tui_attachable' | 'provider_utility' | 'reserved_internal';
  internalArgCollision: boolean;
  topologyComplete: boolean;
  ownedOrphans: number[];
  /** Bounded reason when not attachable. */
  reason?: string;
}

/** Assess whether the TUI can be attached per the reviewed strategy. */
export function assessTuiAttachment(input: {
  hasAppServerFlag: boolean;
  hasAttachmentFlag: boolean;
  isReservedInternal: boolean;
  userArgv: string[];
  topology: TopologyState;
  ownedRecords: OwnedProcessRecord[];
}): TuiAttachmentAssessment {
  const classification = classifyAttachability({
    hasAppServerFlag: input.hasAppServerFlag,
    hasAttachmentFlag: input.hasAttachmentFlag,
    isReservedInternal: input.isReservedInternal,
  });
  const internal = ['--app-server', '--attachment', '--daemon-socket', '--control'];
  const collision = checkInternalArgCollision(input.userArgv, internal);
  const topology = assertReviewedTopology(input.topology);
  const orphans = detectOwnedOrphans(input.ownedRecords);

  const reasons: string[] = [];
  if (classification !== 'tui_attachable') reasons.push('classification-not-attachable');
  if (collision.collision) reasons.push('internal-argv-collision');
  if (!topology.ok) reasons.push('topology-incomplete');
  if (!orphans.clean) reasons.push('owned-orphans');

  return {
    attachable: reasons.length === 0,
    classification,
    internalArgCollision: collision.collision,
    topologyComplete: topology.ok ?? false,
    ownedOrphans: orphans.orphanPids,
    reason: reasons.length > 0 ? reasons.join(';') : undefined,
  };
}

/** TUI argv fingerprint (public deterministic fixture only). */
export function tuiArgvFingerprint(argv: string[]): string {
  const canonical = jcs({ argv: [...argv].sort() } as Parameters<typeof jcs>[0]);
  return createHash('sha256').update(canonical).digest('hex');
}
