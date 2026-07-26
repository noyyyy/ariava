#!/usr/bin/env bun
import { spawnSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { resolveBunExecutable } from './bun-executable.mjs';

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');

export function runHostVerification(options = {}) {
  const platform = options.platform ?? process.platform;
  if (platform !== 'darwin') {
    const logError = options.consoleError ?? console.error;
    logError(`verify:host is the local Darwin host gate; current platform is ${platform}. Linux verification is owned by the Public Core CI lane.`);
    return 1;
  }

  const env = options.env ?? process.env;
  const bunPath = resolveBunExecutable({ bunPath: options.bunPath, env });
  const spawn = options.spawnSync ?? spawnSync;
  const result = spawn(bunPath, ['run', 'verify:macos'], {
    cwd: resolve(options.repositoryRoot ?? repositoryRoot),
    env,
    stdio: options.stdio ?? 'inherit',
    shell: false,
  });
  if (result.error) throw result.error;
  return result.status ?? 1;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = runHostVerification();
}
