import type { AriavaCliCommandSuccess } from '../context';
import type { ProfileProbeDependencies, ProfileProbeEvidence } from '../probes/profile';
import { probeProfile } from '../probes/profile';

export interface DoctorLifecycleEvidence {
  buildChecks(shared: ProfileProbeEvidence): Record<string, unknown>;
  healthy(checks: Record<string, unknown>, shared: ProfileProbeEvidence): boolean;
  formatDoctor(checks: Record<string, unknown>): string;
}

export interface DoctorCommandDependencies extends ProfileProbeDependencies {
  lifecycle: DoctorLifecycleEvidence;
}

export async function runDoctorCommand(
  argv: string[],
  dependencies: DoctorCommandDependencies,
): Promise<AriavaCliCommandSuccess> {
  if (argv.length !== 0) throw new Error('Usage: ariava doctor');
  const shared = await probeProfile(dependencies);
  const checks = dependencies.lifecycle.buildChecks(shared);
  if (shared.hostDomainReset.pending) checks.hostDomainReset = shared.hostDomainReset;
  const healthy = dependencies.lifecycle.healthy(checks, shared);
  const human = dependencies.lifecycle.formatDoctor(checks);
  return {
    envelope: {
      ok: healthy,
      code: healthy ? 'ok' : 'ERR_DOCTOR',
      message: healthy ? 'Ariava doctor completed.' : 'Ariava doctor found issues.',
      data: checks,
    } as AriavaCliCommandSuccess['envelope'],
    human: shared.hostDomainReset.pending
      ? `${human}\nHost reset: pending (${shared.hostDomainReset.phase})\nRemediation: ${shared.hostDomainReset.remediation}`
      : human,
    exitCode: healthy ? 0 : 1,
  };
}

export function formatDoctorChecks(checks: Record<string, unknown>): string {
  return Object.entries(checks)
    .map(([key, value]) => `${key}: ${Array.isArray(value) ? value.join(', ') : typeof value === 'object' && value !== null ? JSON.stringify(value) : String(value)}`)
    .join('\n');
}
