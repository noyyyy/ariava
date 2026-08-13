import { resolveCliVersion } from '../app';
import { findAriavaPackageAuthority } from '../package-authority';

const PACKAGE_AUTHORITY = findAriavaPackageAuthority(import.meta.url);

export const DEFAULT_PACKAGE_ROOT = PACKAGE_AUTHORITY.packageRoot;
export const DEFAULT_CLI_VERSION = resolveCliVersion('default', () => PACKAGE_AUTHORITY.manifest);
export const DEFAULT_RELEASE_PI_VERSION = DEFAULT_CLI_VERSION;
