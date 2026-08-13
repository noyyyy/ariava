import type { AriavaUserConfig, ResolvedAriavaConfig } from '../host-manager/config';

export function redactUserConfig(config: AriavaUserConfig): AriavaUserConfig {
  const { agentAdapterSecret: _agentAdapterSecret, ...rest } = config;
  return rest;
}

export function redactResolvedConfig(config: ResolvedAriavaConfig): ResolvedAriavaConfig {
  if (!config.agentAdapterSecret) return config;
  return { ...config, agentAdapterSecret: '<redacted>' };
}
