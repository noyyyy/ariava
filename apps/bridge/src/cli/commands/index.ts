import type { AriavaCliCommandSuccess, AriavaProfileCliContext } from '../context';
import type { ProfileIdentityResetDependencies } from '../operations/identity';
import type { PairProfileDependencies } from '../operations/pair';
import type { WatchesProfileDependencies } from '../operations/watches';
import { runHostCommand, runIdentityCommand } from './identity';
import { runPairCommand } from './pair';
import { runWatchesCommand } from './watches';
import { initializeProfile } from '../operations/initialize';
import { runConfigCommand } from './config';
import type { StatusCommandDependencies } from './status';
import type { DoctorCommandDependencies } from './doctor';
import { runStatusCommand } from './status';
import { runDoctorCommand } from './doctor';

export interface SharedHostCommandDependencies {
  context(): AriavaProfileCliContext;
  profileId: AriavaProfileCliContext['profile']['id'];
  reset: ProfileIdentityResetDependencies;
  pair: PairProfileDependencies;
  watches: WatchesProfileDependencies;
  status: StatusCommandDependencies;
  doctor: DoctorCommandDependencies;
  stdin: NodeJS.ReadableStream;
  stdout: NodeJS.WritableStream;
  interactive: boolean;
  environment: NodeJS.ProcessEnv;
  confirmSafetyCodeMatch?(): Promise<boolean>;
  sleep?(ms: number): Promise<void>;
}

export async function runSharedHostCommand(
  argv: string[],
  options: { json: boolean },
  dependencies: SharedHostCommandDependencies,
): Promise<AriavaCliCommandSuccess> {
  switch (argv[0]) {
    case 'init': {
      if (argv.length !== 1) throw new Error('Usage: ariava init');
      const result = await initializeProfile(dependencies.context());
      const hostId = result.inspection.hostId;
      if (!hostId) throw new Error('Host identity was not initialized');
      const profile = dependencies.profileId === 'dev' ? 'dev ' : '';
      return {
        envelope: {
          ok: true,
          code: 'ok',
          message: result.identityCreated ? 'Ariava identity initialized.' : 'Ariava identity already initialized.',
          data: {
            configPath: result.resolved.configPath,
            config: redactInitializedConfig(result.config),
            identity: result.inspection,
            created: result.identityCreated,
          },
        },
        human: `${result.identityCreated ? 'Initialized' : 'Reused'} ${profile}Host identity ${hostId}`,
      };
    }
    case 'config': return runConfigCommand(argv.slice(1), dependencies.context());
    case 'status': return runStatusCommand(argv.slice(1), dependencies.status);
    case 'doctor': return runDoctorCommand(argv.slice(1), dependencies.doctor);
    case 'identity': return runIdentityCommand(argv.slice(1), dependencies);
    case 'host': return runHostCommand(argv.slice(1), dependencies);
    case 'pair': return runPairCommand(argv.slice(1), options.json, dependencies);
    case 'watches': return runWatchesCommand(argv.slice(1), dependencies);
    default: throw new Error(`Unknown shared command: ${argv[0] ?? ''}`);
  }
}

function redactInitializedConfig(config: import('../../host-manager/config').AriavaUserConfig) {
  const { agentAdapterSecret: _agentAdapterSecret, ...rest } = config;
  return rest;
}
