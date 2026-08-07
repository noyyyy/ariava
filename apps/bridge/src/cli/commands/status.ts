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
  const status = dependencies.lifecycle.buildStatus(await probeProfile(dependencies));
  return {
    envelope: { ok: true, code: 'ok', message: 'Ariava host status.', data: status },
    human: dependencies.lifecycle.formatStatus(status),
  };
}
