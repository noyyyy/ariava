import { afterEach, describe, expect, test } from 'bun:test';
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

const repositoryRoot = join(import.meta.dir, '..');
const dockerfilePath = join(repositoryRoot, 'scripts', 'docker', 'Dockerfile.verify-linux');
const entrypointPath = join(repositoryRoot, 'scripts', 'docker', 'verify-linux-entrypoint.sh');
const wrapperPath = join(repositoryRoot, 'scripts', 'verify-linux-docker.sh');
const dockerignorePath = join(repositoryRoot, '.dockerignore');
const packageJson = JSON.parse(readFileSync(join(repositoryRoot, 'package.json'), 'utf8')) as {
  scripts: Record<string, string>;
};
const roots: string[] = [];

const BASE_IMAGE = 'docker.io/library/node:24.18.0-bookworm-slim@sha256:6f7b03f7c2c8e2e784dcf9295400527b9b1270fd37b7e9a7285cf83b6951452d';
const REQUIRED_CONTEXT_EXCLUSIONS = ['.git', 'node_modules', '**/dist', 'extensions/pi/bundle', '.env', '.env.*'];
const REQUIRED_CREDENTIAL_EXCLUSIONS = [
  '.npmrc', '**/.npmrc',
  '.netrc', '**/.netrc',
  '.ssh', '**/.ssh',
  '.docker/config.json', '**/.docker/config.json',
  '.git-credentials', '**/.git-credentials',
  '*.p8', '**/*.p8',
  '*.pem', '**/*.pem',
  '*.key', '**/*.key',
  '*.p12', '**/*.p12',
  '*.pfx', '**/*.pfx',
];
const REVIEWED_CONTEXT_ROOTS = ['.github', 'apps', 'docs', 'extensions', 'packages', 'scripts'];

function validateDockerPolicy(dockerfile: string, entrypoint: string, wrapper: string, dockerignore: string) {
  const failures: string[] = [];
  const require = (condition: boolean, message: string) => {
    if (!condition) failures.push(message);
  };

  const dockerignorePatterns = dockerignore
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith('#'));
  require(!/^\s*#\s*syntax\s*=/imu.test(dockerfile), 'Dockerfile frontend syntax directive must be omitted');
  require(dockerfile.includes(`FROM node:24.18.0-bookworm-slim@${BASE_IMAGE.split('@')[1]}`), 'base image must use the reviewed digest');
  require(/sha256:[0-9a-f]{64}/u.test(dockerfile), 'base image digest must be a complete sha256');
  require(dockerfile.includes('ARG NODE_VERSION=24.18.0'), 'Node must be pinned to 24.18.0');
  require(dockerfile.includes('ARG NPM_VERSION=11.18.0'), 'npm must be pinned to 11.18.0');
  require(dockerfile.includes('ARG BUN_VERSION=1.3.14'), 'Bun must be pinned to 1.3.14');
  require(dockerfile.includes('USER node:node'), 'verification image must run as non-root node user');
  require(!/^USER\s+root\b/mu.test(dockerfile), 'verification image must not switch back to root');
  require(dockerfile.includes('COPY --chown=node:node . /opt/ariava-source'), 'source must be copied into the image with container ownership');
  require(dockerfile.includes('CMD ["bun", "run", "verify:linux"]'), 'image command must be verify:linux');

  require(entrypoint.includes("[ \"$#\" -ne 3 ]"), 'entrypoint must reject extra commands');
  require(entrypoint.includes('[ "$3" != "verify:linux" ]'), 'entrypoint must allow only verify:linux');
  require(entrypoint.includes('cp -a /opt/ariava-source/. /workspace/'), 'entrypoint must copy source into disposable workspace');
  require(entrypoint.includes('bun install --frozen-lockfile'), 'container install must be frozen');
  require(entrypoint.includes('exec "$@"'), 'entrypoint must execute the reviewed command array');

  require(wrapper.includes(`BASE_IMAGE="${BASE_IMAGE}"`), 'wrapper must log the reviewed image digest');
  require(wrapper.includes('--read-only'), 'container root filesystem must be read-only');
  require(wrapper.includes('--cap-drop ALL'), 'container capabilities must be dropped');
  require(wrapper.includes('--security-opt no-new-privileges'), 'container must disable privilege escalation');
  require(wrapper.includes('--tmpfs /workspace:'), 'workspace must be disposable tmpfs');
  require(wrapper.includes('--tmpfs /tmp:'), 'home and caches must be disposable tmpfs');
  require(wrapper.includes('bun run verify:linux'), 'wrapper must execute verify:linux');
  require(!wrapper.includes('--privileged'), 'privileged containers are forbidden');
  require(!wrapper.includes('/var/run/docker.sock'), 'Docker socket mounts are forbidden');
  require(!/(?:^|\s)(?:-v|--volume)(?:\s|=)/mu.test(wrapper.replace('command -v', 'command')), 'host volume mounts are forbidden');
  require(!/--user\s+(?:0|root)\b/u.test(wrapper), 'root execution is forbidden');
  require(!/NPM_TOKEN|NODE_AUTH_TOKEN|secrets\.|\.npmrc:\/|\.ssh:\//iu.test(wrapper), 'credential forwarding is forbidden');

  for (const ignored of [...REQUIRED_CONTEXT_EXCLUSIONS, ...REQUIRED_CREDENTIAL_EXCLUSIONS]) {
    require(dockerignorePatterns.includes(ignored), `.dockerignore must exclude ${ignored}`);
  }
  for (const reviewedRoot of REVIEWED_CONTEXT_ROOTS) {
    const forbidden = [reviewedRoot, `${reviewedRoot}/`, `${reviewedRoot}/*`, `${reviewedRoot}/**`, `${reviewedRoot}/**/*`, `**/${reviewedRoot}`, `**/${reviewedRoot}/**`];
    require(!forbidden.some((pattern) => dockerignorePatterns.includes(pattern)), `${reviewedRoot} must remain in the Docker build context`);
  }
  require(!dockerignorePatterns.some((pattern) => ['*', '**', '**/*'].includes(pattern)), 'the reviewed source tree must remain in the Docker build context');

  if (failures.length > 0) throw new Error(failures.join('\n'));
}

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe('Docker Linux pre-acceptance policy', () => {
  test('pins the reviewed image/toolchain and keeps verification non-root and disposable', () => {
    validateDockerPolicy(
      readFileSync(dockerfilePath, 'utf8'),
      readFileSync(entrypointPath, 'utf8'),
      readFileSync(wrapperPath, 'utf8'),
      readFileSync(dockerignorePath, 'utf8'),
    );
    expect(packageJson.scripts['verify:linux:docker']).toBe('./scripts/verify-linux-docker.sh');
    for (const ordinaryGate of ['verify', 'verify:shared', 'verify:macos', 'verify:host']) {
      expect(packageJson.scripts[ordinaryGate], ordinaryGate).not.toMatch(/verify:linux:docker|docker/iu);
    }
  });

  test('fake Docker receives a digest-pinned build and a safe exact verify:linux run', () => {
    const root = mkdtempSync(join(tmpdir(), 'ariava-fake-docker-'));
    roots.push(root);
    const logPath = join(root, 'docker.log');
    const fakeDocker = join(root, 'docker');
    writeFileSync(fakeDocker, `#!/bin/sh\nprintf 'CALL' >> "$ARIAVA_FAKE_DOCKER_LOG"\nfor arg in "$@"; do printf '\\t%s' "$arg" >> "$ARIAVA_FAKE_DOCKER_LOG"; done\nprintf '\\n' >> "$ARIAVA_FAKE_DOCKER_LOG"\n`);
    chmodSync(fakeDocker, 0o755);

    const result = spawnSync('/bin/bash', [wrapperPath], {
      cwd: repositoryRoot,
      encoding: 'utf8',
      env: {
        ...process.env,
        ARIAVA_DOCKER_BIN: fakeDocker,
        ARIAVA_DOCKER_PLATFORM: 'linux/arm64',
        ARIAVA_DOCKER_KEEP_IMAGE: '1',
        ARIAVA_FAKE_DOCKER_LOG: logPath,
      },
    });
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain(`base image: ${BASE_IMAGE}`);
    expect(result.stdout).toContain('evidence: Docker Linux arm64');
    expect(result.stdout).toContain('Node 24.18.0, npm 11.18.0, Bun 1.3.14');
    expect(result.stdout).toContain('exit status: 0');

    const calls = readFileSync(logPath, 'utf8').trim().split('\n');
    expect(calls).toHaveLength(2);
    expect(calls[0]).toContain(`\tbuild\t--pull\t--platform\tlinux/arm64`);
    expect(calls[0]).toContain('/scripts/docker/Dockerfile.verify-linux');
    expect(calls[1]).toContain('\trun\t--rm\t--read-only\t--platform\tlinux/arm64');
    expect(calls[1]).toContain('\t--cap-drop\tALL');
    expect(calls[1]).toContain('\t--security-opt\tno-new-privileges');
    expect(calls[1]).toMatch(/\tariava-verify-linux:[^\t]+\tbun\trun\tverify:linux$/u);
    expect(calls[1]).not.toMatch(/--privileged|docker\.sock|\t-v\t|\t--volume\t|\t--user\t(?:0|root)/u);
  });

  test('policy rejects unsafe or weaker mutations', () => {
    const dockerfile = readFileSync(dockerfilePath, 'utf8');
    const entrypoint = readFileSync(entrypointPath, 'utf8');
    const wrapper = readFileSync(wrapperPath, 'utf8');
    const dockerignore = readFileSync(dockerignorePath, 'utf8');

    for (const mutation of [
      { dockerfile: dockerfile.replace(/@sha256:[0-9a-f]{64}/u, ''), entrypoint, wrapper, dockerignore },
      { dockerfile: dockerfile.replace('USER node:node', 'USER root'), entrypoint, wrapper, dockerignore },
      { dockerfile: `# syntax=docker/dockerfile:1\n${dockerfile}`, entrypoint, wrapper, dockerignore },
      { dockerfile, entrypoint, wrapper: wrapper.replace('--cap-drop ALL', '--privileged'), dockerignore },
      { dockerfile, entrypoint, wrapper: `${wrapper}\n# --volume /var/run/docker.sock:/var/run/docker.sock\n`, dockerignore },
      { dockerfile, entrypoint: entrypoint.replace('verify:linux', 'verify:shared'), wrapper: wrapper.replace('bun run verify:linux', 'bun run verify:shared'), dockerignore },
      { dockerfile, entrypoint, wrapper, dockerignore: `${dockerignore}\ndocs\n` },
    ]) {
      expect(() => validateDockerPolicy(mutation.dockerfile, mutation.entrypoint, mutation.wrapper, mutation.dockerignore)).toThrow();
    }

    for (const exclusion of REQUIRED_CREDENTIAL_EXCLUSIONS) {
      const weakenedDockerignore = dockerignore
        .split('\n')
        .filter((line) => line !== exclusion)
        .join('\n');
      expect(() => validateDockerPolicy(dockerfile, entrypoint, wrapper, weakenedDockerignore), exclusion).toThrow();
    }
  });
});
