import { AriavaCliError } from '../service/errors';
import type { OnboardingAdapterDefinition, OnboardingAdapterId } from './types';

export const PRODUCTION_ADAPTER_CATALOG = [{
  id: 'pi',
  displayName: 'Pi',
  availability: 'production',
  detect: { commands: ['pi'] },
  installer: {
    kind: 'pi-package',
    package: 'npm:@ariava/pi-extension',
    versionPolicy: 'exact-cli-version',
  },
  readiness: { requiresReload: true },
}] as const satisfies readonly OnboardingAdapterDefinition[];

export function getProductionAdapter(id: string): OnboardingAdapterDefinition {
  const adapter = PRODUCTION_ADAPTER_CATALOG.find((entry) => entry.id === id as OnboardingAdapterId);
  if (!adapter) {
    throw new AriavaCliError('ERR_ADAPTER_UNKNOWN', `Unknown onboarding adapter: ${id}`, {
      step: 'adapter-detect',
      retryable: false,
      remediation: { message: 'Choose Pi or set up the Bridge only.' },
    });
  }
  return adapter;
}
