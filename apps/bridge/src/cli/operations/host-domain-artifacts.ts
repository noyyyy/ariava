import type { HostReplacementSpoolKeyStore } from '../../e2e/local-spool';
import { removeSecureFileIfPresent } from '../../host-manager/secure-files';
import {
  assertRuntimeCoordinatorPaths,
  assertRuntimeWriterAllowed,
  type RuntimeCoordinator,
} from '../../runtime-lock';
import type { ResolvedProfileResources } from '../context';

export function clearHostDomainArtifacts(
  resources: ResolvedProfileResources,
  coordinator: RuntimeCoordinator,
  spoolKeyStore: HostReplacementSpoolKeyStore,
  expectedOldHostId?: string,
): void {
  assertRuntimeCoordinatorPaths(coordinator, resources.statePath, resources.encryptedSpoolPath);
  assertRuntimeWriterAllowed(coordinator);
  for (const path of [
    resources.linkKeyringPath,
    resources.statePath,
    resources.encryptedSpoolPath,
    resources.runtimeResetIntentPath,
  ]) {
    assertRuntimeWriterAllowed(coordinator);
    removeSecureFileIfPresent(path);
  }
  assertRuntimeWriterAllowed(coordinator);
  spoolKeyStore.removeForHostReplacement(expectedOldHostId);
}
