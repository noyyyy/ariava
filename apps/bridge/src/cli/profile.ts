import { lstatSync, realpathSync } from 'node:fs';
import { homedir } from 'node:os';
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import type { ResolvedAriavaConfig } from '../host-manager/config';
import { pathHasFilesystemEvidence } from '../host-manager/secure-files';
import { resolveAriavaDefaultProfilePaths } from '../host-manager/paths';
import { ARIAVA_DEV_RELAY_BASE_URL, resolveAriavaDevProfilePaths } from '../host-manager/dev-profile';
import { hostEncryptionIdentityPath, hostLinkKeyringPath } from '../identity/runtime-store';
import {
  MACOS_IDENTITY_EVIDENCE_ACCOUNTS,
  type MacOSIdentityProfile,
} from '../identity/macos-keychain-store';

export type AriavaProfileId = 'default' | 'dev';
export type ProfileFilesystemProbeObserver = (path: string) => void;

export interface ProfileResourceSet {
  readonly root: string;
  readonly configPath: string;
  readonly identityMetadataPath: string;
  readonly identityProfile: MacOSIdentityProfile;
  readonly identityEvidenceAccount: (typeof MACOS_IDENTITY_EVIDENCE_ACCOUNTS)[MacOSIdentityProfile];
  readonly encryptionIdentityPath: string;
  readonly linkKeyringPath: string;
  readonly statePath: string;
  readonly agentAdapterConfigPath: string;
  readonly agentAdapterPort: number;
  readonly piExtensionLogPath: string;
}

export interface AriavaProfileDescriptor {
  readonly id: AriavaProfileId;
  readonly displayName: string;
  readonly resources: ProfileResourceSet;
  readonly defaultRelayBaseUrl: string;
  readonly defaultHostName: (hostname: string) => string;
  readonly assertDescriptor: () => void;
  readonly resolveResources: (
    config: ResolvedAriavaConfig,
    observeFilesystemProbe?: ProfileFilesystemProbeObserver,
  ) => ProfileResourceSet;
  readonly assertResolvedResources: (
    config: ResolvedAriavaConfig,
    observeFilesystemProbe?: ProfileFilesystemProbeObserver,
  ) => void;
}

interface ProfileDescriptorDefinition {
  readonly id: AriavaProfileId;
  readonly displayName: string;
  readonly resources: ProfileResourceSet;
  readonly defaultRelayBaseUrl: string;
  readonly defaultHostName: (hostname: string) => string;
  readonly counterpartResources: ProfileResourceSet;
}

interface ProfileDescriptorPolicy {
  readonly counterpartResources: ProfileResourceSet;
}

const descriptorPolicies = new WeakMap<AriavaProfileDescriptor, ProfileDescriptorPolicy>();

export function createDefaultProfile(): AriavaProfileDescriptor {
  const homeDirectory = currentHomeDirectory();
  const paths = resolveAriavaDefaultProfilePaths({
    homeDirectory,
    xdgConfigHome: process.env.XDG_CONFIG_HOME,
  });
  const devPaths = resolveAriavaDevProfilePaths(homeDirectory);
  return createProfileDescriptor({
    id: 'default',
    displayName: 'Default',
    resources: resourceSet('default', paths),
    defaultRelayBaseUrl: 'https://ariava-relay.noyx.io',
    defaultHostName: (hostname: string) => hostname,
    counterpartResources: resourceSet('dev', devPaths),
  });
}

export function createDevProfile(): AriavaProfileDescriptor {
  const homeDirectory = currentHomeDirectory();
  const paths = resolveAriavaDevProfilePaths(homeDirectory);
  const defaultPaths = resolveAriavaDefaultProfilePaths({
    homeDirectory,
    xdgConfigHome: process.env.XDG_CONFIG_HOME,
  });
  return createProfileDescriptor({
    id: 'dev',
    displayName: 'Development',
    resources: resourceSet('dev', paths),
    defaultRelayBaseUrl: ARIAVA_DEV_RELAY_BASE_URL,
    defaultHostName: (hostname: string) => `${hostname} (Dev)`,
    counterpartResources: resourceSet('default', defaultPaths),
  });
}

function createProfileDescriptor(definition: ProfileDescriptorDefinition): AriavaProfileDescriptor {
  const resources = Object.freeze({ ...definition.resources });
  const counterpartResources = Object.freeze({ ...definition.counterpartResources });
  let descriptor: AriavaProfileDescriptor;
  descriptor = Object.freeze({
    id: definition.id,
    displayName: definition.displayName,
    resources,
    defaultRelayBaseUrl: definition.defaultRelayBaseUrl,
    defaultHostName: definition.defaultHostName,
    assertDescriptor: () => assertAuthenticProfileDescriptor(descriptor),
    resolveResources: (config, observeFilesystemProbe) => (
      resolveProfileResources(descriptor, config, observeFilesystemProbe)
    ),
    assertResolvedResources: (config, observeFilesystemProbe) => (
      assertResolvedProfileResources(descriptor, config, observeFilesystemProbe)
    ),
  });
  assertProfileDescriptor(descriptor);
  assertResourceSetShape(counterpartResources);
  assertResourceSetsDoNotOverlap(resources, counterpartResources);
  descriptorPolicies.set(descriptor, { counterpartResources });
  return descriptor;
}

export function assertAuthenticProfileDescriptor(descriptor: AriavaProfileDescriptor): void {
  if (!descriptorPolicies.has(descriptor)) {
    throw new TypeError('Ariava profile descriptor is not authentic; use a trusted profile factory');
  }
  assertProfileDescriptor(descriptor);
}

export function assertProfileDescriptorForEffects(descriptor: AriavaProfileDescriptor): void {
  const policy = requireDescriptorPolicy(descriptor);
  assertResourceSetsDoNotOverlap(descriptor.resources, policy.counterpartResources);
}

export function assertSelectedProfileResourcesForEffects(
  descriptor: AriavaProfileDescriptor,
  observeFilesystemProbe?: ProfileFilesystemProbeObserver,
): void {
  const policy = requireDescriptorPolicy(descriptor);
  assertCanonicalSelectedResourcesDoNotOverlap(
    descriptor.resources,
    policy.counterpartResources,
    observeFilesystemProbe,
  );
}

export function assertProfileDescriptor(descriptor: AriavaProfileDescriptor): void {
  const { resources } = descriptor;
  const expected = descriptor.id === 'default'
    ? { port: 7272 as const, profile: 'default' as const, rootName: 'ariava' }
    : descriptor.id === 'dev'
      ? { port: 7273 as const, profile: 'dev' as const, rootName: 'ariava-dev' }
      : undefined;
  if (!expected) throw new TypeError('Ariava profile ID is invalid');
  if (resources.agentAdapterPort !== expected.port) throw new TypeError('Ariava profile Adapter port is invalid');
  if (resources.identityProfile !== expected.profile) throw new TypeError('Ariava profile identity profile is invalid');
  if (resources.identityEvidenceAccount !== MACOS_IDENTITY_EVIDENCE_ACCOUNTS[expected.profile]) {
    throw new TypeError('Ariava profile identity evidence account is invalid');
  }
  if (basename(resources.root) !== expected.rootName) throw new TypeError('Ariava profile root is invalid');

  assertResourceSetShape(resources);

  const expectedPaths = {
    configPath: join(resources.root, 'config.json'),
    identityMetadataPath: join(resources.root, 'host-identity.json'),
    encryptionIdentityPath: hostEncryptionIdentityPath(resources.identityMetadataPath),
    linkKeyringPath: hostLinkKeyringPath(resources.identityMetadataPath),
    statePath: join(resources.root, 'state', 'bridge-state.json'),
    agentAdapterConfigPath: join(resources.root, 'agent-adapter.json'),
    piExtensionLogPath: join(resources.root, 'pi-extension.log'),
  };
  const paths = resourcePaths(resources);
  for (const [name, expectedPath] of Object.entries(expectedPaths)) {
    if (paths[name as keyof typeof paths] !== expectedPath) {
      throw new TypeError(`Ariava profile ${name} is inconsistent with the profile root`);
    }
  }
  assertResourcePathsUnique(resources);
}

export function assertProfilesDoNotOverlap(left: AriavaProfileDescriptor, right: AriavaProfileDescriptor): void {
  assertProfileDescriptor(left);
  assertProfileDescriptor(right);
  assertResourceSetsDoNotOverlap(left.resources, right.resources);
}

export function resolveProfileResources(
  descriptor: AriavaProfileDescriptor,
  config: ResolvedAriavaConfig,
  observeFilesystemProbe?: ProfileFilesystemProbeObserver,
): ProfileResourceSet {
  const policy = requireDescriptorPolicy(descriptor);
  const expected = descriptor.resources;
  const fixedMismatches = [
    config.configPath === expected.configPath ? undefined : 'configPath',
    descriptor.id === 'dev' && config.statePath !== expected.statePath ? 'statePath' : undefined,
    descriptor.id === 'dev' && config.agentAdapterConfigPath !== expected.agentAdapterConfigPath
      ? 'agentAdapterConfigPath'
      : undefined,
    descriptor.id === 'dev' && config.agentAdapterPort !== expected.agentAdapterPort ? 'agentAdapterPort' : undefined,
  ].filter((value): value is string => value !== undefined);
  if (fixedMismatches.length > 0) {
    throw new TypeError(`Ariava ${descriptor.id} profile config uses invalid fixed resources: ${fixedMismatches.join(', ')}`);
  }

  const selectedIdentityPath = config.identityPath;
  if (!isCanonicalAbsolute(selectedIdentityPath)) {
    throw new TypeError('Ariava profile identityPath must be a normalized absolute path');
  }
  if (descriptor.id === 'dev' && selectedIdentityPath !== expected.identityMetadataPath) {
    throw new TypeError('Ariava dev profile config uses invalid fixed resources: identityPath');
  }
  if (descriptor.id === 'default') {
    assertValidDefaultAdapterPort(config.agentAdapterPort, policy.counterpartResources.agentAdapterPort);
    for (const path of Object.values(resourcePaths(policy.counterpartResources))) {
      if (pathsOverlapLexically(path, selectedIdentityPath)) {
        throw new TypeError('Ariava default profile identityPath overlaps the dev profile');
      }
    }
  }

  const resources = Object.freeze({
    ...expected,
    identityMetadataPath: selectedIdentityPath,
    encryptionIdentityPath: hostEncryptionIdentityPath(selectedIdentityPath),
    linkKeyringPath: hostLinkKeyringPath(selectedIdentityPath),
    statePath: config.statePath,
    agentAdapterConfigPath: config.agentAdapterConfigPath,
    agentAdapterPort: config.agentAdapterPort,
  });
  assertResourcePathsUnique(resources);
  assertCanonicalSelectedResourcesDoNotOverlap(resources, policy.counterpartResources, observeFilesystemProbe);
  for (const path of Object.values(resourcePaths(resources))) {
    if (descriptor.id === 'default' && !isWithin(expected.root, path)) {
      assertCanonicalStandaloneResourcePath(expected.root, path, observeFilesystemProbe);
    } else {
      assertCanonicalResourcePath(expected.root, path, observeFilesystemProbe);
    }
  }
  return resources;
}

export function assertResolvedProfileResources(
  descriptor: AriavaProfileDescriptor,
  config: ResolvedAriavaConfig,
  observeFilesystemProbe?: ProfileFilesystemProbeObserver,
): void {
  resolveProfileResources(descriptor, config, observeFilesystemProbe);
}

function assertValidDefaultAdapterPort(port: number, devPort: number): void {
  if (!Number.isInteger(port) || port < 1 || port > 65_535) {
    throw new TypeError('Ariava default profile agentAdapterPort must be an integer from 1 through 65535');
  }
  if (port === devPort) {
    throw new TypeError('Ariava default profile agentAdapterPort overlaps the dev profile');
  }
}

function requireDescriptorPolicy(descriptor: AriavaProfileDescriptor): ProfileDescriptorPolicy {
  const policy = descriptorPolicies.get(descriptor);
  if (!policy) {
    throw new TypeError('Ariava profile descriptor is not authentic; use a trusted profile factory');
  }
  assertProfileDescriptor(descriptor);
  return policy;
}

function assertResourceSetShape(resources: ProfileResourceSet): void {
  const paths = resourcePaths(resources);
  for (const [name, path] of Object.entries(paths)) {
    if (!isCanonicalAbsolute(path)) throw new TypeError(`Ariava profile ${name} must be a normalized absolute path`);
    if (name !== 'root' && !isWithin(resources.root, path)) {
      throw new TypeError(`Ariava profile ${name} must remain within the profile root`);
    }
  }
}

function assertResourcePathsUnique(resources: ProfileResourceSet): void {
  const paths = Object.values(resourcePaths(resources));
  if (new Set(paths).size !== paths.length) {
    throw new TypeError('Ariava profile resource collision is not allowed');
  }
  const nonRootPaths = paths.filter((path) => path !== resources.root);
  for (const [index, path] of nonRootPaths.entries()) {
    for (const otherPath of nonRootPaths.slice(index + 1)) {
      if (pathsOverlapLexically(path, otherPath)) {
        throw new TypeError('Ariava profile resource collision is not allowed');
      }
    }
  }
}

function assertResourceSetsDoNotOverlap(left: ProfileResourceSet, right: ProfileResourceSet): void {
  if (isWithin(left.root, right.root) || isWithin(right.root, left.root)) {
    throw new TypeError('Ariava default and dev profile resources overlap');
  }
}

function assertCanonicalSelectedResourcesDoNotOverlap(
  selected: ProfileResourceSet,
  counterpart: ProfileResourceSet,
  observeFilesystemProbe?: ProfileFilesystemProbeObserver,
): void {
  const counterpartPaths = Object.values(resourcePaths(counterpart));
  for (const selectedPath of Object.values(resourcePaths(selected))) {
    for (const counterpartPath of counterpartPaths) {
      if (pathsOverlapLexically(selectedPath, counterpartPath)) {
        throw new TypeError('Ariava default and dev profile resources overlap');
      }
    }
    const canonicalSelectedPath = canonicalizeExistingAncestor(selectedPath, observeFilesystemProbe);
    for (const counterpartPath of counterpartPaths) {
      if (pathsOverlapCanonicalSelectedWithLexicalCounterpart(canonicalSelectedPath, counterpartPath)) {
        throw new TypeError('Ariava default and dev profile resources overlap canonically');
      }
    }
  }
}

function resourcePaths(resources: ProfileResourceSet) {
  return {
    root: resources.root,
    configPath: resources.configPath,
    identityMetadataPath: resources.identityMetadataPath,
    encryptionIdentityPath: resources.encryptionIdentityPath,
    linkKeyringPath: resources.linkKeyringPath,
    statePath: resources.statePath,
    agentAdapterConfigPath: resources.agentAdapterConfigPath,
    piExtensionLogPath: resources.piExtensionLogPath,
  };
}

function assertCanonicalResourcePath(
  root: string,
  path: string,
  observeFilesystemProbe?: ProfileFilesystemProbeObserver,
): void {
  if (!isCanonicalAbsolute(root) || !isCanonicalAbsolute(path) || !isWithin(root, path)) {
    throw new TypeError(`Ariava profile resource escapes its root: ${path}`);
  }

  const canonicalRoot = canonicalizeExistingAncestor(root, observeFilesystemProbe);
  const canonicalPath = canonicalizeExistingAncestor(path, observeFilesystemProbe);
  if (!isWithin(canonicalRoot, canonicalPath)) {
    throw new TypeError(`Ariava profile resource escapes its canonical root: ${path}`);
  }

  if (!hasFilesystemEvidence(root, observeFilesystemProbe)) return;
  let cursor = root;
  assertNotSymlink(cursor, observeFilesystemProbe);
  const remainder = relative(root, path);
  for (const component of remainder.split(sep).filter(Boolean)) {
    cursor = join(cursor, component);
    if (!hasFilesystemEvidence(cursor, observeFilesystemProbe)) break;
    assertNotSymlink(cursor, observeFilesystemProbe);
  }
}

function identityResource(resources: ProfileResourceSet, path: string): boolean {
  return path === resources.identityMetadataPath
    || path === resources.encryptionIdentityPath
    || path === resources.linkKeyringPath;
}

function assertCanonicalStandaloneResourcePath(
  profileRoot: string,
  path: string,
  observeFilesystemProbe?: ProfileFilesystemProbeObserver,
): void {
  if (!isCanonicalAbsolute(path)) throw new TypeError(`Ariava profile resource must be absolute: ${path}`);
  const trustBoundary = commonPathAncestor(profileRoot, path);
  let cursor = trustBoundary;
  if (hasFilesystemEvidence(cursor, observeFilesystemProbe)) {
    assertNotSymlink(cursor, observeFilesystemProbe);
  }
  const remainder = relative(trustBoundary, path);
  for (const component of remainder.split(sep).filter(Boolean)) {
    cursor = join(cursor, component);
    if (!hasFilesystemEvidence(cursor, observeFilesystemProbe)) break;
    assertNotSymlink(cursor, observeFilesystemProbe);
  }
}

function commonPathAncestor(left: string, right: string): string {
  let cursor = left;
  while (!isWithin(cursor, right)) {
    const parent = dirname(cursor);
    if (parent === cursor) return cursor;
    cursor = parent;
  }
  return cursor;
}

function pathsOverlapLexically(left: string, right: string): boolean {
  return isWithin(left, right) || isWithin(right, left);
}

function pathsOverlapCanonicalSelectedWithLexicalCounterpart(
  canonicalSelectedPath: string,
  lexicalCounterpartPath: string,
): boolean {
  if (pathsOverlapLexically(canonicalSelectedPath, lexicalCounterpartPath)) return true;
  if (canonicalSelectedPath.startsWith('/private/')) {
    return pathsOverlapLexically(canonicalSelectedPath.slice('/private'.length), lexicalCounterpartPath);
  }
  return false;
}

function canonicalizeExistingAncestor(
  path: string,
  observeFilesystemProbe?: ProfileFilesystemProbeObserver,
): string {
  const missing: string[] = [];
  let cursor = path;
  while (!hasFilesystemEvidence(cursor, observeFilesystemProbe)) {
    const parent = dirname(cursor);
    if (parent === cursor) return resolve(path);
    missing.unshift(basename(cursor));
    cursor = parent;
  }
  let symlink: boolean;
  try {
    symlink = lstatSync(cursor).isSymbolicLink();
  } catch (error) {
    throw new TypeError(`Ariava profile resource could not be canonicalized: ${path}`, { cause: error });
  }
  if (symlink) {
    throw new TypeError(`Ariava profile resource symlink traversal is not allowed: ${path}`);
  }
  try {
    return resolve(realpathSync(cursor), ...missing);
  } catch (error) {
    throw new TypeError(`Ariava profile resource could not be canonicalized: ${path}`, { cause: error });
  }
}

function hasFilesystemEvidence(path: string, observeFilesystemProbe?: ProfileFilesystemProbeObserver): boolean {
  observeFilesystemProbe?.(path);
  return pathHasFilesystemEvidence(path);
}

function assertNotSymlink(path: string, observeFilesystemProbe?: ProfileFilesystemProbeObserver): void {
  observeFilesystemProbe?.(path);
  if (lstatSync(path).isSymbolicLink()) {
    throw new TypeError(`Ariava profile resource symlink traversal is not allowed: ${path}`);
  }
}

function resourceSet(
  profile: AriavaProfileId,
  paths: ReturnType<typeof resolveAriavaDefaultProfilePaths> | ReturnType<typeof resolveAriavaDevProfilePaths>,
): ProfileResourceSet {
  return {
    root: paths.root,
    configPath: paths.configPath,
    identityMetadataPath: paths.identityPath,
    identityProfile: profile,
    identityEvidenceAccount: MACOS_IDENTITY_EVIDENCE_ACCOUNTS[profile],
    encryptionIdentityPath: hostEncryptionIdentityPath(paths.identityPath),
    linkKeyringPath: hostLinkKeyringPath(paths.identityPath),
    statePath: paths.statePath,
    agentAdapterConfigPath: paths.agentAdapterConfigPath,
    agentAdapterPort: paths.agentAdapterPort,
    piExtensionLogPath: paths.piExtensionLogPath,
  };
}

function currentHomeDirectory(): string {
  const environmentHome = process.env.HOME?.trim();
  return environmentHome && isAbsolute(environmentHome) ? environmentHome : homedir();
}


function isCanonicalAbsolute(path: string): boolean {
  return isAbsolute(path) && resolve(path) === path;
}

function isWithin(root: string, path: string): boolean {
  const remainder = relative(root, path);
  return remainder === '' || (!remainder.startsWith(`..${sep}`) && remainder !== '..' && !isAbsolute(remainder));
}
