import { spawnSync } from 'node:child_process';
import type { CommandResult, CommandRunner, RunOptions } from './types';

export class SpawnSyncCommandRunner implements CommandRunner {
  run(command: string, args: string[], options: RunOptions = {}): CommandResult {
    const result = spawnSync(command, args, {
      encoding: 'utf8',
      shell: false,
      ...options,
    });

    return {
      status: result.status ?? null,
      stdout: result.stdout ?? '',
      stderr: result.stderr ?? '',
      ...(result.error ? { error: result.error } : {}),
    };
  }
}
