import { runAriavaCli } from './cli/app';
import {
  createDefaultCliApplicationContext,
  type PublicCliDependencies,
  type PublicCliOnboardingDependencies,
} from './cli/lifecycle/default';

export type { PublicCliDependencies, PublicCliOnboardingDependencies } from './cli/lifecycle/default';
export { detectPackageManager } from './cli/lifecycle/default';
export { formatHumanCliFailure, normalizeCliFailure } from './cli/failure';

export function runPublicCli(
  argv: string[],
  overrides: Partial<PublicCliDependencies> = {},
  onboardingOverrides: Partial<PublicCliOnboardingDependencies> = {},
): Promise<number> {
  return runAriavaCli(argv, createDefaultCliApplicationContext(overrides, onboardingOverrides));
}
