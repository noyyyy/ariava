import type { AriavaCliCommandSuccess } from '../context';
import type { ProfileProbeDependencies, ProfileProbeEvidence } from '../probes/profile';
import { probeProfile } from '../probes/profile';

export interface StatusLifecycleEvidence {
  buildStatus(shared: ProfileProbeEvidence): unknown;
  formatStatus(status: unknown): string;
}

export interface StatusCommandDependencies extends ProfileProbeDependencies {
  lifecycle: StatusLifecycleEvidence;
  runPiStatus?(): AriavaCliCommandSuccess;
}

export async function runStatusCommand(
  argv: string[],
  dependencies: StatusCommandDependencies,
): Promise<AriavaCliCommandSuccess> {
  if (argv[0] === 'pi') {
    if (argv.length !== 1 || !dependencies.runPiStatus) throw new Error('Usage: ariava status [pi]');
    return dependencies.runPiStatus();
  }
  if (argv.length !== 0) throw new Error('Usage: ariava status [pi]');
  const shared = await probeProfile(dependencies);
  const status = dependencies.lifecycle.buildStatus(shared);
  if (shared.hostDomainReset.pending && status && typeof status === 'object') {
    Object.assign(status, { hostDomainReset: shared.hostDomainReset });
  }
  const profileId = dependencies.context().profile.id;
  const human = dependencies.lifecycle.formatStatus(status);
  return {
    envelope: { ok: true, code: 'ok', message: profileId === 'dev' ? 'Ariava dev host status.' : 'Ariava host status.', data: status },
    human: shared.hostDomainReset.pending
      ? `${human}\nHost reset: pending (${shared.hostDomainReset.phase})\nRemediation: ${shared.hostDomainReset.remediation}`
      : human,
  };
}
