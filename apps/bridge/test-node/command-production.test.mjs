import { spawnSync } from 'node:child_process';
import test from 'node:test';
import assert from 'node:assert/strict';

function runFixture(relativePath) {
  const result = spawnSync(process.execPath, [relativePath], {
    cwd: process.cwd(),
    env: process.env,
    encoding: 'utf8',
  });
  assert.equal(result.signal, null, result.stderr || `${relativePath} terminated by ${result.signal}`);
  assert.equal(result.status, 0, result.stderr || `${relativePath} exited ${result.status}`);
  assert.equal(result.stderr, '');
  return JSON.parse(result.stdout);
}

test('strict production preparation accepts reply and interrupt on active and historical pins', () => {
  const output = runFixture('./apps/bridge/test/fixtures/command-execution-vector-runner.mjs');
  assert.deepEqual(output.accepted, {
    reply: { active: true, retiringBeforeBoundary: true, historicalHostKey: true },
    interrupt: { active: true, retiringBeforeBoundary: true, historicalHostKey: true },
  });
  assert.equal(output.invalidCasesPerCommand, 15);
  assert.equal(output.totalInvalidPreparations, 30);
  assert.equal(output.rejectedWithoutEffects.length, 30);
  for (const commandType of ['reply', 'interrupt']) {
    for (const invalidCase of [
      'issuance-after-retiring', 'host-key-substitution', 'wrong-host-private-identity',
      'watch-binding-substitution', 'watch-public-key-substitution', 'transcript-substitution',
      'global-current-key-substitution', 'aead-content-mutation', 'aead-wrap-mutation',
      'expired', 'ttl-invalid', 'missing-pin', 'revoked-pin',
      'sender-key-id-mismatch', 'recipient-key-id-mismatch',
    ]) assert.ok(output.rejectedWithoutEffects.includes(`${commandType}-${invalidCase}`));
  }
  assert.equal(output.terminalBoundary, 'terminal-pending-receipt');
});

test('production receipt helper fixes bytes, key IDs, statuses, and active or historical pins', () => {
  const output = runFixture('./apps/bridge/test/fixtures/command-receipt-vector-runner.mjs');
  assert.equal(output.deterministicVector, true);
  assert.equal(output.canonicalBody, true);
  assert.equal(output.historicalHostKey, true);
  assert.equal(output.activePin, true);
  assert.equal(output.allowedRetiringPin, true);
  assert.deepEqual(output.ciphertextLengths, {
    interrupt: [144, 144, 144, 144],
    reply: [144, 144, 144, 144],
  });
  assert.deepEqual(output.statuses, ['executed', 'expired', 'rejected', 'failed']);
  assert.deepEqual(output.validCommandTypes, ['interrupt', 'reply']);
  assert.equal(output.replyTargetBound, true);
  assert.equal(output.postUnlinkTerminalCommitRefused, true);
  assert.equal(output.noRetarget, true);
  assert.equal(output.rejected.length, 45);
  assert.equal(output.zeroizedInjectedDeks, 46);
  for (const rejected of [
    'command-commandId', 'command-hostId', 'command-watchDeviceId', 'command-sessionId',
    'command-issuedAt', 'command-expiresAt', 'command-nonce', 'command-linkId',
    'command-linkGeneration', 'command-epoch', 'command-contentId', 'command-contentNonce',
    'command-contentCiphertext', 'command-wrapSenderKey', 'command-wrapRecipientKey',
    'command-wrapNonce', 'command-wrapCiphertext', 'stored-commandDigest', 'pin-transcript',
    'result-status-combination', 'terminal-state', 'unknown-state', 'missing-pin', 'revoked-pin',
    'unlinked-watch', 'missing-historical-key', 'wrong-historical-private-key',
    'host-binding-substitution', 'watch-public-substitution', 'transcript-substitution',
    'retiring-boundary', 'command-reply-type', 'command-reply-targetAlertEventId',
    'post-unlink-terminal-commit',
  ]) assert.ok(output.rejected.includes(rejected));
});
