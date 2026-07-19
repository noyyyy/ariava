import { realpathSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import type { CommandRunner } from '../host-manager/service/types';

export const MINIMUM_NODE_MAJOR = 22;
export const NODE_RUNTIME_ERROR = 'Ariava requires Node.js 22 or newer for its production Bridge runtime.';

export interface NodeRuntimeInspection {
  runtimeName: string;
  runtimeVersion: string;
  runtimePath: string;
  runtimeNameIsNode: boolean;
  runtimeVersionSupported: boolean;
}

export function inspectCurrentNodeRuntime(): NodeRuntimeInspection {
  const bunRuntime = 'bun' in process.versions;
  const sourceDevelopmentRuntime = bunRuntime && import.meta.url.endsWith('/src/runtime/node-runtime.ts');
  const runtimeNameIsNode = (process.release?.name ?? 'unknown') === 'node' && (!bunRuntime || sourceDevelopmentRuntime);
  const runtimeName = runtimeNameIsNode ? 'node' : bunRuntime ? 'bun' : process.release?.name ?? 'unknown';
  const runtimeVersion = bunRuntime && !sourceDevelopmentRuntime ? String(process.versions.bun) : process.version ?? 'unknown';
  return {
    runtimeName,
    runtimeVersion,
    runtimePath: safeRealpath(process.execPath),
    runtimeNameIsNode,
    runtimeVersionSupported: isSupportedNodeVersion(runtimeVersion),
  };
}

export function assertProductionNodeRuntime(): NodeRuntimeInspection {
  const inspection = inspectCurrentNodeRuntime();
  if (!inspection.runtimeNameIsNode || !inspection.runtimeVersionSupported) {
    throw new Error(`${NODE_RUNTIME_ERROR}\nCurrent runtime: ${inspection.runtimeName} ${inspection.runtimeVersion}`);
  }
  return inspection;
}

export function probeNodeRuntimePath(runtimePath: string): NodeRuntimeInspection {
  return probeNodeRuntime(runtimePath, {
    run(command, args) {
      const result = spawnSync(command, args, { shell: false, encoding: 'utf8' });
      return { status: result.status, stdout: result.stdout ?? '', stderr: result.stderr ?? '', ...(result.error ? { error: result.error } : {}) };
    },
  });
}

export function probeNodeRuntime(runtimePath: string, runner: CommandRunner): NodeRuntimeInspection {
  const canonicalPath = safeRealpath(runtimePath);
  const result = runner.run(canonicalPath, ['--version']);
  const runtimeVersion = result.stdout.trim();
  const runtimeNameIsNode = result.status === 0 && /^v\d+(?:\.|$)/u.test(runtimeVersion);
  const supported = runtimeNameIsNode && isSupportedNodeVersion(runtimeVersion);
  if (!supported) {
    throw new Error(`${NODE_RUNTIME_ERROR}\nCurrent runtime: unknown ${runtimeVersion || 'unavailable'}`);
  }
  return {
    runtimeName: 'node', runtimeVersion, runtimePath: canonicalPath,
    runtimeNameIsNode: true, runtimeVersionSupported: true,
  };
}

export function isSupportedNodeVersion(version: string): boolean {
  const match = /^v?(\d+)(?:\.|$)/u.exec(version.trim());
  return Boolean(match && Number(match[1]) >= MINIMUM_NODE_MAJOR);
}

function safeRealpath(path: string): string {
  try { return realpathSync(path); } catch { return path; }
}
