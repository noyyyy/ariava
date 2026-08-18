import { describe, expect, test } from 'bun:test';
import {
  assessTuiAttachment,
  TUI_ATTACHMENT_STRATEGY_ID,
  tuiArgvFingerprint,
} from './tui-attachment';

describe('TUI attachment (spec §8.7)', () => {
  test('attachable when classification is tui_attachable, no collision, complete topology, no orphans', () => {
    const result = assessTuiAttachment({
      hasAppServerFlag: true,
      hasAttachmentFlag: true,
      isReservedInternal: false,
      userArgv: ['codex', 'tui', '--thread', 'abc'],
      topology: { appServerId: 'server-1', tuiPid: 1234, observerConnected: true },
      ownedRecords: [
        { pid: 1, ownershipId: 'o1', ownedByHarness: true, alive: false },
        { pid: 2, ownershipId: 'ext', ownedByHarness: false, alive: true },
      ],
    });
    expect(result.attachable).toBe(true);
    expect(result.classification).toBe('tui_attachable');
    expect(result.topologyComplete).toBe(true);
    expect(result.ownedOrphans).toEqual([]);
  });

  test('not attachable when classification is reserved_internal', () => {
    const result = assessTuiAttachment({
      hasAppServerFlag: false,
      hasAttachmentFlag: false,
      isReservedInternal: true,
      userArgv: ['codex'],
      topology: { appServerId: 'server-1', tuiPid: 1, observerConnected: true },
      ownedRecords: [],
    });
    expect(result.attachable).toBe(false);
    expect(result.reason).toContain('classification-not-attachable');
  });

  test('not attachable when internal argv collides', () => {
    const result = assessTuiAttachment({
      hasAppServerFlag: true,
      hasAttachmentFlag: true,
      isReservedInternal: false,
      userArgv: ['codex', '--app-server', 'tui'],
      topology: { appServerId: 'server-1', tuiPid: 1, observerConnected: true },
      ownedRecords: [],
    });
    expect(result.attachable).toBe(false);
    expect(result.reason).toContain('internal-argv-collision');
  });

  test('not attachable with owned orphans', () => {
    const result = assessTuiAttachment({
      hasAppServerFlag: true,
      hasAttachmentFlag: true,
      isReservedInternal: false,
      userArgv: ['codex', 'tui'],
      topology: { appServerId: 'server-1', tuiPid: 1, observerConnected: true },
      ownedRecords: [{ pid: 99, ownershipId: 'o99', ownedByHarness: true, alive: true }],
    });
    expect(result.attachable).toBe(false);
    expect(result.reason).toContain('owned-orphans');
  });

  test('attachment strategy id is the reviewed stable id', () => {
    expect(TUI_ATTACHMENT_STRATEGY_ID).toBe('reviewed-tui-app-server-argv');
  });

  test('tui argv fingerprint is deterministic', () => {
    expect(tuiArgvFingerprint(['codex', 'tui', '--json'])).toBe(tuiArgvFingerprint(['codex', 'tui', '--json']));
    expect(tuiArgvFingerprint(['codex', 'tui'])).not.toBe(tuiArgvFingerprint(['codex', 'tui', '--json']));
  });
});
