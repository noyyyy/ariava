# Two-Stage Release Command Design

## Goal

Add a safe, direct-to-main release workflow that keeps commit publication and npm-triggering tag publication as separate commands.

## Commands

### `bun run release:push`

The command prepares and pushes the already-bumped release change. It:

1. Resolves the repository root, current branch, and origin default branch.
2. Requires the current branch to be the origin default branch (`main` today).
3. Fetches `origin/main` and requires local `HEAD` to equal `origin/main` before release changes are committed.
4. Validates one common stable `X.Y.Z` version across every release package and the Bun lockfile.
5. Requires the only uncommitted paths to be the reviewed release version files and `bun.lock`; every required release path must be modified.
6. Rejects an existing local or remote `vX.Y.Z` tag.
7. Runs `bun install --frozen-lockfile` and `bun run verify`.
8. Revalidates the branch, base commit, version, tag absence, and exact changed-path set after verification.
9. Creates `release: bump to X.Y.Z` and pushes `HEAD:main` to `origin`.

The command never creates or pushes a tag. A failed install, verification, commit, or push leaves no npm publication trigger.

### `bun run release:tag`

The command publishes the tag only after direct-push CI succeeds. It:

1. Requires a clean working tree on the origin default branch.
2. Fetches that branch and tags without mutating them.
3. Requires `HEAD` to equal `origin/main`.
4. Validates the common stable version and requires `HEAD` subject to equal `release: bump to X.Y.Z`.
5. Rejects an existing local or remote `vX.Y.Z` tag.
6. Requires an authenticated `gh` CLI and identifies the `Public Core CI` workflow run for the exact `HEAD` commit and push event.
7. Watches the run to completion, then verifies that its conclusion is `success` and that both `Linux` and `macOS` jobs completed successfully.
8. Re-fetches and revalidates `HEAD`, `origin/main`, version, cleanliness, and tag absence after waiting.
9. Creates annotated tag `vX.Y.Z` with message `Release vX.Y.Z` and pushes only that tag.

Missing `gh`, missing authentication, absent/ambiguous CI runs, incomplete jobs, failures, cancellations, or a changed remote branch all fail closed before tag creation.

## Structure

- `scripts/release-flow-lib.mjs` owns parsing, Git/GitHub validation, and the two orchestration functions with an injected command runner.
- `scripts/release-flow.mjs` is the thin CLI entrypoint.
- `scripts/release-flow.test.ts` uses fake command execution and temporary release fixtures; it never contacts GitHub or mutates a real Git repository.
- `package.json` exposes `release:push` and `release:tag`.
- `docs/release.md` documents the direct-push two-stage workflow and keeps Trusted Publishing as the only normal npm writer.

## Safety Boundaries

- The script does not bump versions; `bun run version:bump patch` remains separate.
- The release commit contains only common version manifests and `bun.lock`.
- The script does not open or merge a pull request.
- The script does not push directly to npm, approve the GitHub Environment, move tags, or update the private product repository.
- Existing non-version work must be committed separately before `release:push`.

## Testing

Tests cover argument parsing, allowed-path enforcement, version consistency, direct push command order, verification failure, CI run selection, Linux/macOS job enforcement, remote drift, tag conflicts, and successful annotated tag push. The implementation then runs the targeted test plus the authoritative `bun run verify` release-compatible closure.
