import { AriavaCliError } from '../../host-manager/service/errors';
import {
  inspectProfileIdentity,
  resetProfileIdentity,
  type ProfileIdentityResetDependencies,
} from '../operations/identity';
import type { AriavaCliCommandSuccess, AriavaProfileCliContext } from '../context';

export interface IdentityCommandDependencies {
  context(): AriavaProfileCliContext;
  reset: ProfileIdentityResetDependencies;
  profileId: AriavaProfileCliContext['profile']['id'];
}

export async function runIdentityCommand(
  argv: string[],
  dependencies: IdentityCommandDependencies,
): Promise<AriavaCliCommandSuccess> {
  const action = argv[0];
  if (action === 'reset' && !argv.includes('--confirm')) {
    throw new AriavaCliError('ERR_CONFIRMATION_REQUIRED', resetUsage(dependencies.profileId));
  }
  if (action === 'status' && argv.length === 1) {
    const context = dependencies.context();
    const inspection = await inspectProfileIdentity(context);
    const data = context.profile.id === 'dev' ? { profile: 'dev', ...inspection } : inspection;
    return {
      envelope: {
        ok: true,
        code: 'ok',
        message: context.profile.id === 'dev' ? 'Dev Host identity status.' : 'Host identity status.',
        data,
      },
      human: JSON.stringify(data, null, 2),
    };
  }
  if (action === 'reset' && argv.length === 2 && argv[1] === '--confirm') {
    const context = dependencies.context();
    const result = await resetProfileIdentity(context, dependencies.reset);
    const dev = context.profile.id === 'dev';
    return {
      envelope: {
        ok: true,
        code: 'ok',
        message: dev ? 'Dev Host identity reset.' : 'Host identity reset.',
        data: result,
      },
      human: `Reset ${dev ? 'dev ' : ''}Host identity to ${result.hostId}; links: 0; pair Watches again${result.warning ? `; warning: ${result.warning}` : ''}`,
    };
  }
  throw new Error(identityUsage(dependencies.profileId));
}

function identityUsage(profileId: AriavaProfileCliContext['profile']['id']): string {
  return profileId === 'dev'
    ? 'Usage: dev-profile-cli identity status | dev-profile-cli identity reset --confirm'
    : 'Usage: ariava identity status | ariava identity reset --confirm';
}

function resetUsage(profileId: AriavaProfileCliContext['profile']['id']): string {
  return profileId === 'dev'
    ? 'Usage: dev-profile-cli identity reset --confirm'
    : 'Usage: ariava identity reset --confirm';
}
