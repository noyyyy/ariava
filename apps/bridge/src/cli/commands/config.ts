import {
  resolveProfileUserConfig,
  type AriavaUserConfig,
  type ResolvedAriavaConfig,
} from '../../host-manager/config';
import {
  loadResolvedProfileConfig,
  type AriavaCliCommandSuccess,
  type AriavaProfileCliContext,
} from '../context';

export async function runConfigCommand(
  argv: string[],
  context: AriavaProfileCliContext,
): Promise<AriavaCliCommandSuccess> {
  context.validation.descriptor();
  const subcommand = argv[0] ?? 'show';
  const loaded = loadResolvedProfileConfig(context);

  switch (subcommand) {
    case 'path':
      requireExactArguments(argv, 1, 'Usage: ariava config path');
      return success(
        'Resolved Ariava config path.',
        { configPath: loaded.resolved.configPath },
        loaded.resolved.configPath,
      );
    case 'show': {
      requireExactArguments(argv, 1, 'Usage: ariava config show');
      const data = {
        config: redactUserConfig(loaded.fileConfig),
        resolved: redactResolvedConfig(context.resolveForDisplay?.(loaded.fileConfig) ?? loaded.resolved),
      };
      return success('Loaded Ariava config.', data, JSON.stringify(data, null, 2));
    }
    case 'get': {
      requireExactArguments(argv, 2, 'Usage: ariava config get <key>');
      const key = argv[1]!;
      const value = loaded.fileConfig[key as keyof AriavaUserConfig];
      const displayValue = key === 'agentAdapterSecret' && value ? '<redacted>' : value;
      return success(
        `Read config key ${key}.`,
        { key, value: displayValue },
        displayValue == null ? '' : String(displayValue),
      );
    }
    case 'set': {
      requireExactArguments(argv, 3, 'Usage: ariava config set <key> <value>');
      const key = argv[1]!;
      const value = argv[2]!;
      context.configMutation.assertSetAllowed(key);
      const candidate = { ...loaded.fileConfig, [key]: parseConfigValue(value) };
      const next = normalizeMutationCandidate(context, candidate);
      saveConfig(context, next);
      const displayValue = key === 'agentAdapterSecret' ? '<redacted>' : next[key];
      return success(`Updated config key ${key}.`, { key, value: displayValue }, `Updated ${key}`);
    }
    case 'agent-secret':
      return runAgentSecretConfig(argv.slice(1), context, loaded.fileConfig);
    default:
      throw new Error(`Unknown config command: ${subcommand}`);
  }
}

function runAgentSecretConfig(
  argv: string[],
  context: AriavaProfileCliContext,
  fileConfig: AriavaUserConfig,
): AriavaCliCommandSuccess {
  requireExactArguments(argv, 1, 'Usage: ariava config agent-secret ensure|rotate');
  const action = argv[0]!;
  const current = fileConfig.agentAdapterSecret?.trim();

  if (action === 'ensure') {
    const generated = !current;
    if (generated) {
      const next = { ...fileConfig, agentAdapterSecret: context.generateSecret() };
      validateMutationCandidate(context, next);
      saveConfig(context, next);
    }
    const message = generated
      ? 'Generated Agent Adapter secret.'
      : 'Agent Adapter secret already configured.';
    return success(message, { generated, rotated: false }, message);
  }

  if (action === 'rotate') {
    const next = { ...fileConfig, agentAdapterSecret: context.generateSecret() };
    validateMutationCandidate(context, next);
    saveConfig(context, next);
    const message = 'Rotated Agent Adapter secret. Restart the Ariava service and reload pi sessions.';
    return success(message, { generated: true, rotated: true }, message);
  }

  throw new Error('Usage: ariava config agent-secret ensure|rotate');
}

function validateMutationCandidate(context: AriavaProfileCliContext, config: AriavaUserConfig): void {
  normalizeMutationCandidate(context, config);
}

function normalizeMutationCandidate(
  context: AriavaProfileCliContext,
  config: AriavaUserConfig,
): AriavaUserConfig {
  const resolved = resolveProfileUserConfig(context.profile, config);
  const resources = context.validation.resolved(resolved);
  if (context.profile.id !== 'default') return config;
  return {
    ...config,
    ...(config.statePath === undefined ? {} : { statePath: resources.statePath }),
    ...(config.agentAdapterConfigPath === undefined
      ? {}
      : { agentAdapterConfigPath: resources.agentAdapterConfigPath }),
  };
}

function saveConfig(context: AriavaProfileCliContext, config: AriavaUserConfig): void {
  context.access?.('filesystemWrites', context.profile.resources.configPath);
  context.config.save(config, context.profile.resources.configPath);
}

function requireExactArguments(argv: readonly string[], count: number, usage: string): void {
  if (argv.length !== count) throw new Error(usage);
}

function parseConfigValue(value: string): string | number | boolean {
  if (value === 'true') return true;
  if (value === 'false') return false;
  const asNumber = Number(value);
  return Number.isFinite(asNumber) && value.trim() !== '' ? asNumber : value;
}

function redactUserConfig(config: AriavaUserConfig): AriavaUserConfig {
  const { agentAdapterSecret: _agentAdapterSecret, ...rest } = config;
  return rest;
}

function redactResolvedConfig(config: ResolvedAriavaConfig): ResolvedAriavaConfig {
  if (!config.agentAdapterSecret) return config;
  return { ...config, agentAdapterSecret: '<redacted>' };
}

function success(
  message: string,
  data: unknown,
  human: string,
): AriavaCliCommandSuccess {
  return { envelope: { ok: true, code: 'ok', message, data }, human };
}
