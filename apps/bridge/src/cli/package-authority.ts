import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, parse } from 'node:path';
import { fileURLToPath } from 'node:url';

export interface AriavaPackageAuthority {
  packageRoot: string;
  manifest: { name?: unknown; version?: unknown };
}

export function findAriavaPackageAuthority(moduleUrl: string | URL): AriavaPackageAuthority {
  const artifactPath = fileURLToPath(moduleUrl);
  let candidateRoot = dirname(artifactPath);

  while (true) {
    const manifestPath = join(candidateRoot, 'package.json');
    if (existsSync(manifestPath)) {
      const manifest = JSON.parse(readFileSync(manifestPath, 'utf8')) as {
        name?: unknown;
        version?: unknown;
      };
      if (manifest.name === 'ariava') return { packageRoot: candidateRoot, manifest };
    }

    const parent = dirname(candidateRoot);
    if (parent === candidateRoot || candidateRoot === parse(candidateRoot).root) break;
    candidateRoot = parent;
  }

  throw new Error(`Unable to locate the ariava package.json from artifact ${artifactPath}`);
}
