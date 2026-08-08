import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { acquireRuntimeLock } from '../../src/runtime-lock';

const [root, statePath, claimantName, mode = 'claim', gatePath = ''] = process.argv.slice(2);
if (!root || !statePath || !claimantName) throw new Error('runtime-lock claimant arguments are required');

const pid = process.pid;
const processStart = `${claimantName}-${pid}`;
const tokenPrefix = claimantName === 'first' ? 'a' : claimantName === 'second' ? 'b' : 'd';
const marker = (name: string): string => `${root}/${name}-${claimantName}`;
const waitFor = (path: string): void => {
  while (!existsSync(path)) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 5);
};

writeFileSync(`${root}/alive-${pid}`, processStart, { mode: 0o600 });
try {
  const lock = acquireRuntimeLock(statePath, {
    uid: process.getuid!(),
    pid,
    now: () => new Date('2026-08-08T00:00:00.000Z'),
    ownerToken: () => tokenPrefix.repeat(48),
    currentProcessStart: () => processStart,
    inspector: {
      inspect(candidatePid) {
        const alivePath = `${root}/alive-${candidatePid}`;
        if (!existsSync(alivePath)) return { status: 'absent' };
        return { status: 'alive', processStart: readFileSync(alivePath, 'utf8') };
      },
    },
    hooks: {
      beforeTakeoverMutexAcquire() {
        writeFileSync(marker('ready'), '', { mode: 0o600 });
        if (gatePath) waitFor(gatePath);
        if (mode === 'ordered-race' && claimantName === 'second') waitFor(`${root}/winner-first`);
      },
      afterTakeoverMutexAcquired() {
        if (mode === 'crash-mutex') process.exit(81);
      },
      afterStaleMainLockValidated() {
        if (mode === 'crash-validation') process.exit(82);
      },
      afterMainLockRemoved() {
        if (mode === 'crash-removal') process.exit(83);
      },
      afterMainLockCreated() {
        if (mode === 'crash-creation') process.exit(84);
      },
      beforeTakeoverMutexCleanup() {
        if (mode === 'crash-cleanup') process.exit(85);
      },
    },
  });
  writeFileSync(`${root}/winner-${claimantName}`, JSON.stringify(lock.record), { mode: 0o600 });
  if (mode === 'ordered-race' && claimantName === 'first') waitFor(`${root}/release-first`);
  lock.release();
  process.exitCode = 0;
} catch (error) {
  writeFileSync(`${root}/loser-${claimantName}`, String(error), { mode: 0o600 });
  process.exitCode = 2;
}
