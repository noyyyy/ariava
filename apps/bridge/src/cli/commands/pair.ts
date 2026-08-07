import { promptSafetyCodeMatch } from '../../e2e/host-safety-code-activation';
import { pairCancelledFailure, sanitizePairFailure } from '../failure';
import { pairProfile, type PairProfileDependencies } from '../operations/pair';
import type { AriavaCliCommandSuccess, AriavaProfileCliContext } from '../context';

export interface PairCommandDependencies {
  context(): AriavaProfileCliContext;
  pair: PairProfileDependencies;
  profileId: AriavaProfileCliContext['profile']['id'];
  stdin: NodeJS.ReadableStream;
  stdout: NodeJS.WritableStream;
  interactive: boolean;
  environment: NodeJS.ProcessEnv;
  confirmSafetyCodeMatch?(): Promise<boolean>;
  sleep?(ms: number): Promise<void>;
}

export async function runPairCommand(
  argv: string[],
  json: boolean,
  dependencies: PairCommandDependencies,
): Promise<AriavaCliCommandSuccess> {
  const { pairingCode, codesMatch } = parsePairArgs(argv, dependencies.profileId);
  const context = dependencies.context();
  const interactive = !json && dependencies.interactive
    && dependencies.environment.CI === undefined
    && dependencies.environment.TERM !== 'dumb';
  let result: Awaited<ReturnType<typeof pairProfile>>;
  try {
    result = await pairProfile(
      context,
      {
        pairingCode,
        ...(json ? {} : { write: (line: string) => dependencies.stdout.write(`${line}\n`) }),
        ...(json ? {} : {
          presentAccepted: (pairing: Awaited<ReturnType<typeof pairProfile>>['pairing']) => {
            if (context.profile.id === 'dev') {
              dependencies.stdout.write(
                `Pairing code accepted for watch ${pairing.watchDevice.watchDeviceId} with host ${pairing.host.hostName} (${pairing.host.hostId}).\n`,
              );
              dependencies.stdout.write('Pairing is not complete until both sides confirm the Safety Code.\n');
            } else {
              dependencies.stdout.write(
                `Pairing code accepted for watch ${pairing.watchDevice.watchDeviceId} with host ${pairing.host.hostName} (${pairing.host.hostId}). Pairing completes after Safety Code confirmation.\n`,
              );
            }
          },
        }),
        ...(dependencies.sleep ? { sleep: dependencies.sleep } : {}),
        confirmMatch: () => dependencies.confirmSafetyCodeMatch
          ? dependencies.confirmSafetyCodeMatch()
          : promptSafetyCodeMatch({
            stdin: dependencies.stdin,
            stdout: dependencies.stdout,
            interactive,
            codesMatchFlag: codesMatch,
          }),
      },
      dependencies.pair,
    );
  } catch (error) {
    throw sanitizePairFailure(error, [pairingCode, pairingCode.toUpperCase()]);
  }
  if (result.status === 'cancelled') throw pairCancelledFailure();
  return {
    envelope: {
      ok: true,
      code: 'ok',
      message: 'Watch paired successfully.',
      data: {
        ...result.pairing,
        safetyCodeActivation: result.safetyCodeActivation,
        messages: result.messages,
      },
    },
  };
}

function parsePairArgs(
  args: string[],
  profile: AriavaProfileCliContext['profile']['id'],
): { pairingCode: string; codesMatch: boolean } {
  let pairingCode: string | undefined;
  let codesMatch = false;
  const usage = profile === 'dev'
    ? 'Usage: dev-profile-cli pair <PAIRING_CODE> [--codes-match]'
    : 'Usage: ariava pair <PAIRING_CODE> [--codes-match]';
  for (const arg of args) {
    if (arg === '--codes-match') {
      codesMatch = true;
      continue;
    }
    if (arg.startsWith('-')) throw new Error(`Unknown pair option: ${arg}`);
    if (pairingCode) throw new Error(usage);
    pairingCode = arg;
  }
  if (!pairingCode) throw new Error(usage);
  return { pairingCode, codesMatch };
}
