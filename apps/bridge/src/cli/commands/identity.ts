import { AriavaCliError } from '../../host-manager/service/errors';
import {
  inspectProfileIdentity,
  resetProfileIdentity,
  rotateProfileIdentity,
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
  if ((argv[0] ?? 'status') !== 'status' || argv.length > 1) {
    throw new Error(dependencies.profileId === 'dev'
      ? 'Usage: dev-profile-cli identity status'
      : 'Usage: ariava identity status');
  }
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

export async function runHostCommand(
  argv: string[],
  dependencies: IdentityCommandDependencies,
): Promise<AriavaCliCommandSuccess> {
  const action = argv[0];
  if (action === 'reset' && !argv.includes('--confirm')) {
    const usage = dependencies.profileId === 'dev'
      ? 'Usage: dev-profile-cli host reset --confirm'
      : 'Usage: ariava host reset --confirm';
    throw new AriavaCliError('ERR_CONFIRMATION_REQUIRED', usage);
  }
  const context = dependencies.context();
  if (action === 'rotate-key' && argv.length === 1) {
    const result = await rotateProfileIdentity(context);
    const dev = context.profile.id === 'dev';
    return {
      envelope: {
        ok: true,
        code: 'ok',
        message: dev ? 'Dev Host key rotated.' : 'Host key rotated.',
        data: result,
      },
      human: `Rotated ${dev ? 'dev ' : ''}Host key to ${result.newKeyId}`,
    };
  }
  if (action === 'reset' && argv.length === 2 && argv[1] === '--confirm') {
    const result = await resetProfileIdentity(context, dependencies.reset);
    const dev = context.profile.id === 'dev';
    return {
      envelope: {
        ok: true,
        code: 'ok',
        message: dev ? 'Dev Host identity reset.' : 'Host identity reset.',
        data: result,
      },
      human: `Reset ${dev ? 'dev ' : ''}Host identity to ${result.hostId}; links: 0${result.warning ? `; warning: ${result.warning}` : ''}`,
    };
  }
  throw new Error(context.profile.id === 'dev'
    ? 'Usage: dev-profile-cli host rotate-key | dev-profile-cli host reset --confirm'
    : 'Usage: ariava host rotate-key | ariava host reset --confirm');
}
