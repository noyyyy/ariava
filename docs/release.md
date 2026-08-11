# Public Repo npm release

This document is the source of truth for releasing the two stable Public Repo npm packages, in this fixed order:

1. `ariava`
2. `@ariava/pi-extension`

The normal path uses GitHub Actions Trusted Publishing and short-lived OIDC credentials. It does not require or permit a long-lived npm publication token.

## Release boundaries

A Public Repo tag in `noyyyy/ariava` is the sole npm release trigger. A similarly named tag in a private product repository does **not** publish these packages. Updating a private product's `open-source/ariava` gitlink is a separate, later integration step.

The workflows do not deploy Relay, publish Homebrew, create a GitHub Release, or build or upload watchOS/TestFlight artifacts. They do not bump versions, commit, create tags, or update another repository.

## Verification evidence

The authoritative release-compatible command remains:

```bash
bun install --frozen-lockfile
bun run verify
```

`bun run verify` retains the complete shared build, generated pi bundle, extension test/typecheck, reviewed Public Repo test, tarball/package smoke, and package assertion closure. The tag workflow's Ubuntu prepare job continues to invoke this exact command before packing artifacts; publication does not depend on a macOS runner or on another repository.

Direct pushes to `main` run two additive Public Repo host checks:

- **Linux**: `ubuntu-latest` runs `bun run verify:linux`;
- **macOS**: `macos-latest` runs `bun run verify:macos`.

Both use frozen installs and exact Node 24.18.0, npm 11.18.0, and Bun 1.3.14. `bun run release:tag` requires the exact pushed commit's `Public Repo CI` run and both named jobs to succeed before it creates a tag.

A Mac maintainer may run the explicit Docker pre-acceptance lane before pushing:

```bash
bun run verify:linux:docker
```

It uses `node:24.18.0-bookworm-slim@sha256:6f7b03f7c2c8e2e784dcf9295400527b9b1270fd37b7e9a7285cf83b6951452d` and runs the full `bun run verify:linux` closure as a non-root user in disposable paths. Record the reported architecture: Apple Silicon defaults to Docker Linux arm64. Docker is not a substitute for the GitHub Ubuntu check, a real systemd user manager, journald lifecycle, VM restart, physical Linux login/logout, or WSL.

Stateful integration evidence remains separate and opt-in:

```bash
ARIAVA_RUN_REAL_MACOS_KEYCHAIN_LAUNCHD_TEST=1 ./scripts/test-macos-keychain-launchd.sh
./scripts/test-linux-systemd.sh
```

These commands can touch a real user Keychain/launchd domain or manage a disposable Linux VM. They are not ordinary CI and do not alter the npm publication trigger or artifact boundary.

## Normal Trusted Publishing release

1. Start from a synchronized `main` branch. Commit unrelated feature or test changes separately, then change every common release version through the existing bump tool:

   ```bash
   bun run version:bump patch
   # or: node scripts/bump-version.mjs X.Y.Z
   ```

2. Review the version and lockfile changes, then run:

   ```bash
   bun run release:push
   ```

   This command requires exactly the common version files and `bun.lock` to be modified. It fetches and confirms `HEAD == origin/main`, rejects an existing release tag, runs `bun install --frozen-lockfile` and authoritative `bun run verify`, revalidates the release state, creates `release: bump to X.Y.Z`, and pushes directly to the origin default branch. It never creates a tag.
3. The direct push starts `.github/workflows/ci.yml`. After GitHub has created the run, execute:

   ```bash
   bun run release:tag
   ```

   The command requires a clean synchronized default branch and authenticated `gh`. It finds the exact commit's `Public Repo CI` push run, waits for completion, requires successful **Linux** and **macOS** jobs, revalidates the remote branch and release state, then creates and pushes annotated tag `vX.Y.Z`. Missing, ambiguous, incomplete, failed, or cancelled CI evidence fails closed before tag creation.
4. Never move, delete, or recreate a public release tag to replace published content.
5. Observe `publish-npm.yml`. Its read-only prepare job validates the strict tag, peeled commit, common versions, and default-branch ancestry; performs the frozen install and complete Public Repo verification; packs, inspects, and smoke-tests the exact artifacts; then uploads only two tarballs and `release-manifest.json`.
6. If the `npm-production` GitHub Environment requires approval, inspect the tag, commit, versions, filenames, and SHA-256 values before approving.
7. The dependent publish job downloads those exact artifacts, verifies their manifest and digests, and publishes through npm Trusted Publishing. Only this job has `id-token: write`.
8. Confirm the sanitized job summary and the npm registry pages show both `X.Y.Z` versions and `latest` dist-tags. Check npm provenance where npm exposes it.
9. Update a private product gitlink only in an independent reviewed change after the Public Repo release is accepted.

The GitHub tag glob is only a coarse trigger. The shared release implementation accepts only canonical stable tags matching `vX.Y.Z` and fails before an npm write if the release context is invalid.

## External administrator configuration

Repository code cannot configure the trust relationship. Before the first production run, an administrator must separately:

- configure a GitHub Actions Trusted Publisher for **each** npm package (`ariava` and `@ariava/pi-extension`), with owner `noyyyy`, repository `ariava`, workflow filename `publish-npm.yml`, and environment `npm-production`;
- retain npm account 2FA;
- create the `npm-production` GitHub Environment, preferably with required reviewers and protected tag deployment rules;
- keep publication environment/repository secrets empty—do not add an npm token, password, OTP, or TOTP seed;
- protect the default branch and stable version tags.

Trusted Publishing currently requires npm 11.5.1 or later and Node.js 22.14.0 or later. The reviewed workflow pins newer exact versions and logs them. Update pins and policy tests together when official requirements change.

## Partial success and reruns

npm cannot publish two packages atomically. Rerun the **same tagged workflow** when one package published but the other failed, or when final registry visibility timed out. The publisher revalidates artifact digests and registry metadata, skips an immutable version only when it matches the exact prepared tarball, and publishes only a missing package in the same root-then-scoped order.

Registry visibility checks use bounded retries. A network failure, malformed result, digest mismatch, identity mismatch, or wrong `latest` value fails closed. Do not unpublish, deprecate, move a tag, or rebuild/overwrite an existing version automatically. A mismatched immutable version requires human incident handling and a new patch release.

Approval must occur before the workflow artifact's seven-day retention expires. If an artifact expires before publication, do not assemble replacement files by hand; investigate and create a reviewed new release attempt/version as appropriate.

## Manual OTP break-glass

Use the manual path only when GitHub Actions or OIDC is unavailable, from a clean checkout of the unchanged annotated release tag. The command resolves origin's advertised default branch with `git ls-remote --symref`, freshly fetches that branch into its matching `refs/remotes/origin/*` ref, and verifies ancestry before any registry access or write. A supplied `--default-branch-ref` is accepted only when it is a valid origin remote-tracking ref and exactly matches the advertised default; a tag or local branch ref is rejected. Record why automation was bypassed.

The compatibility command prepares and immediately publishes the same-attempt artifacts through the shared implementation. Read the OTP without echoing it and pass it on standard input; do not put it in shell argv, an exported environment variable, or command logs:

```bash
read -rsp 'npm OTP: ' ARIAVA_OTP; printf '\n' >&2
printf '%s\n' "${ARIAVA_OTP}" | ./scripts/publish-npm-safe.sh \
  --publish \
  --otp-stdin \
  --tag vX.Y.Z
unset ARIAVA_OTP
```

For explicit inspection between stages, prepare into a new empty directory and then publish that unchanged directory:

```bash
./scripts/publish-npm-safe.sh \
  --prepare \
  --output-dir /secure/path/ariava-X.Y.Z \
  --tag vX.Y.Z

read -rsp 'npm OTP: ' ARIAVA_OTP; printf '\n' >&2
printf '%s\n' "${ARIAVA_OTP}" | ./scripts/publish-npm-safe.sh \
  --publish-prepared /secure/path/ariava-X.Y.Z \
  --manual \
  --otp-stdin \
  --tag vX.Y.Z
unset ARIAVA_OTP
```

Manual mode uses `npm whoami`, optional OTP input from stdin or an already-open file descriptor (`--otp-fd`), the official registry, exact artifact validation, partial-success handling, and the same package order and final checks. OTP is passed to the npm subprocess through its environment rather than its argv and is redacted from errors. The legacy `--otp <code>` alias remains only for compatibility and prints a deprecation warning because command arguments may be exposed in shell history and process listings. Preparation alone performs no registry writes and needs neither npm login nor OIDC. Never edit or replace a prepared tarball or manifest.

Run `./scripts/publish-npm-safe.sh --help` for the authoritative command synopsis.
