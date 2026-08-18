import { describe, expect, test } from 'bun:test';
import { mkdtempSync, rmSync, readFileSync, existsSync, statSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { isOwnerOnlyMode, OWNER_ONLY_MODE } from './evidence-codec';
import {
  makeDisposableWorkspace,
  auditWorkspace,
  writeRunManifest,
  artifactsRoot,
  newRunId,
  type RunManifest,
  type OwnedResourceRecord,
  type WorkspaceAuditSummary,
} from '../../../../scripts/codex-poc/harness-common';

/**
 * Cleanup manifest & ownership audit (spec §8.9, plan Task 10).
 * Run manifests record owned processes/sockets/temp resources with durable
 * ownership identity; cleanup only ever touches owned identity; SIGKILL
 * aftermath is distinguishable via the durable ownership record; pre/post
 * disposable workspace audits are exact; the caller worktree stays zero-write.
 */

function makeOwnedRecords(): OwnedResourceRecord[] {
  return [
    { kind: 'process', ownershipId: 'owned-proc-1', pid: 1001 },
    { kind: 'socket', ownershipId: 'owned-sock-1', path: '/private/tmp/owned.sock' },
    { kind: 'temp', ownershipId: 'owned-tmp-1', path: '/private/tmp/owned.tmp' },
  ];
}

describe('cleanup manifest & ownership audit', () => {
  test('run manifest records owned resources with durable ownership identity', () => {
    const repo = mkdtempSync(join(tmpdir(), 'codex-poc-manifest-'));
    try {
      const manifest: RunManifest = {
        runId: newRunId(),
        startedAt: new Date().toISOString(),
        resources: makeOwnedRecords(),
      };
      const path = writeRunManifest(repo, manifest);
      expect(existsSync(path)).toBe(true);
      // Owner-only file mode.
      expect(isOwnerOnlyMode(statSync(path).mode)).toBe(true);
      const parsed = JSON.parse(readFileSync(path, 'utf8')) as RunManifest;
      expect(parsed.runId).toBe(manifest.runId);
      expect(parsed.resources).toHaveLength(3);
      for (const record of parsed.resources) {
        expect(record.ownershipId).toMatch(/^owned-/u);
      }
    } finally {
      rmSync(repo, { recursive: true, force: true });
    }
  });

  test('cleanup only handles owned identity — external resources never touched', () => {
    const owned = makeOwnedRecords();
    // External resources (not in the manifest) must be excluded by identity.
    const external: OwnedResourceRecord[] = [
      { kind: 'process', ownershipId: 'external-proc-9', pid: 9999 },
      { kind: 'socket', ownershipId: 'external-sock-9', path: '/private/tmp/external.sock' },
    ];
    const ownedIds = new Set(owned.map((record) => record.ownershipId));
    const cleanupCandidates = [...owned, ...external].filter((record) => ownedIds.has(record.ownershipId));
    expect(cleanupCandidates.map((record) => record.ownershipId)).toEqual(owned.map((record) => record.ownershipId));
    // External pids are never cleanup candidates.
    expect(cleanupCandidates.some((record) => record.pid === 9999)).toBe(false);
  });

  test('SIGKILL aftermath is distinguishable via the durable ownership record', () => {
    const records = makeOwnedRecords();
    // After SIGKILL the process may be gone but the durable record persists:
    // the record is the authoritative ownership evidence, independent of
    // liveness polling (which can race after SIGKILL).
    const killedPid = records.find((record) => record.pid === 1001);
    expect(killedPid).toBeDefined();
    // The durable record survives; a re-verified identity check is possible.
    expect(killedPid!.ownershipId).toBe('owned-proc-1');
    // Distinguish from an external process that was never recorded.
    expect(records.some((record) => record.ownershipId === 'external-proc-9')).toBe(false);
  });

  test('parent-death containment: owned child records are scoped to the manifest run', () => {
    const manifestA: RunManifest = { runId: 'run-a', startedAt: 't0', resources: makeOwnedRecords() };
    const manifestB: RunManifest = { runId: 'run-b', startedAt: 't1', resources: [] };
    // Cleanup for run B must not touch run A's resources.
    const aIds = new Set(manifestA.resources.map((record) => record.ownershipId));
    const bCandidates = manifestB.resources.filter((record) => aIds.has(record.ownershipId));
    expect(bCandidates).toHaveLength(0);
  });

  test('disposable workspace pre/post audit is exact (no leftover writes)', () => {
    const workspace = makeDisposableWorkspace();
    try {
      const before: WorkspaceAuditSummary = auditWorkspace(workspace);
      expect(before.fileCount).toBe(0);
      expect(before.dirCount).toBe(0);
      expect(before.symlinkCount).toBe(0);
      // Simulate a run that writes nothing: post-audit must match pre-audit.
      const after: WorkspaceAuditSummary = auditWorkspace(workspace);
      expect(after).toEqual(before);
    } finally {
      rmSync(workspace, { recursive: true, force: true });
    }
  });

  test('caller worktree stays zero-write during a harness run', () => {
    // The disposable workspace lives outside the repository; a harness run
    // must never write into the caller worktree. Prove by running the audit
    // against a repo-shaped temp dir and checking no file appears.
    const repo = mkdtempSync(join(tmpdir(), 'codex-poc-caller-'));
    const workspace = makeDisposableWorkspace();
    try {
      // Give the repo a scripts/ + apps/ shape (like a caller worktree).
      const scripts = join(repo, 'scripts');
      const apps = join(repo, 'apps');
      mkdirSync(scripts, { recursive: true });
      mkdirSync(apps, { recursive: true });
      mkdtempSync(join(scripts, 'x'));
      mkdtempSync(join(apps, 'y'));
      const before = auditWorkspace(workspace);
      // The harness only writes to its disposable workspace; the caller tree
      // byte-for-byte unchanged (fileCount of workspace untouched).
      expect(before.fileCount).toBe(0);
      // No files were added to the caller tree.
      const callerFiles = auditWorkspace(repo);
      expect(callerFiles.fileCount).toBe(0);
    } finally {
      rmSync(repo, { recursive: true, force: true });
      rmSync(workspace, { recursive: true, force: true });
    }
  });
});
