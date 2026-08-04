# Two-Stage Release Command Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add direct-main release commit and CI-gated annotated tag commands without combining the two publication stages.

**Architecture:** A testable Node library performs fail-closed Git and GitHub validation through an injected argument-array command runner. A thin CLI maps `push` and `tag` subcommands to that library, while package scripts and release documentation expose the supported workflow.

**Tech Stack:** Node.js ES modules, Bun test, Git, GitHub CLI, GitHub Actions

---

### Task 1: Release Flow Contract Tests

**Files:**
- Create: `scripts/release-flow.test.ts`
- Reference: `scripts/bump-version.test.ts`
- Reference: `scripts/npm-release.test.ts`

- [ ] **Step 1: Write failing parsing and validation tests**

Add tests that import `parseArgs`, `validateCommonReleaseVersion`, and `validateReleaseChanges` from the missing release library. Assert that only `push` and `tag` are accepted, all release package versions and lockfile workspace versions must match stable SemVer, and release changes must exactly cover the version files plus `bun.lock`.

- [ ] **Step 2: Run tests to verify RED**

Run: `bun test ./scripts/release-flow.test.ts`
Expected: FAIL because `scripts/release-flow-lib.mjs` does not exist.

- [ ] **Step 3: Write failing orchestration tests**

Use an injected fake runner to assert `pushRelease` runs fetch, frozen install, verify, exact-path staging, commit message `release: bump to 1.2.3`, and `git push origin HEAD:main`. Assert `tagRelease` selects the exact push CI run, watches it, verifies successful Linux/macOS jobs, creates an annotated tag, and pushes only the tag. Add negative tests for verification failure, dirty paths, existing tags, missing or failed CI jobs, and remote drift.

- [ ] **Step 4: Run tests to confirm orchestration remains RED**

Run: `bun test ./scripts/release-flow.test.ts`
Expected: FAIL on missing exported orchestration functions.

### Task 2: Release Flow Implementation

**Files:**
- Create: `scripts/release-flow-lib.mjs`
- Create: `scripts/release-flow.mjs`

- [ ] **Step 1: Implement stable parsing and release version validation**

Export the canonical release file lists, `parseArgs`, `validateCommonReleaseVersion`, and `validateReleaseChanges`. Parse `bun.lock` as JSONC using the existing comment/trailing-comma-compatible approach and reject noncanonical versions.

- [ ] **Step 2: Run focused validation tests**

Run: `bun test ./scripts/release-flow.test.ts`
Expected: Validation tests PASS; orchestration tests still FAIL.

- [ ] **Step 3: Implement injected command execution and push orchestration**

Add an argument-array runner, repository/default-branch resolution, exact changed-path validation, local/remote tag absence checks, frozen install and verification, post-verification revalidation, exact-path staging, commit creation, and direct branch push.

- [ ] **Step 4: Run push orchestration tests**

Run: `bun test ./scripts/release-flow.test.ts`
Expected: Push tests PASS; tag tests still FAIL.

- [ ] **Step 5: Implement CI-gated tag orchestration**

Query `gh run list --workflow "Public Core CI" --commit <sha> --event push --json databaseId,headSha,status,conclusion`, require one exact run, invoke `gh run watch <id> --exit-status`, query `gh run view <id> --json headSha,status,conclusion,jobs`, require successful `Linux` and `macOS`, revalidate repository state, then create and push the annotated tag.

- [ ] **Step 6: Run complete focused tests**

Run: `bun test ./scripts/release-flow.test.ts`
Expected: PASS with no real Git or GitHub writes.

### Task 3: Public Command and Documentation Integration

**Files:**
- Modify: `package.json`
- Modify: `scripts/bump-version.mjs`
- Modify: `scripts/bump-version.test.ts`
- Modify: `docs/release.md`

- [ ] **Step 1: Add package scripts**

Add `"release:push": "node ./scripts/release-flow.mjs push"` and `"release:tag": "node ./scripts/release-flow.mjs tag"` without changing the existing Trusted Publishing scripts.

- [ ] **Step 2: Update bump output and its test**

Make bump output direct users to `bun run release:push`, then `bun run release:tag` after CI. Update the existing assertion to require those commands and the commit message convention without mentioning Public Core in the commit subject.

- [ ] **Step 3: Update release documentation**

Replace the PR-specific normal-flow steps with direct-main release preparation, `release:push`, automatic Linux/macOS CI, and `release:tag`. Preserve the tag-triggered Trusted Publishing, environment approval, registry confirmation, rerun, and break-glass guidance.

- [ ] **Step 4: Run release script tests**

Run: `bun test ./scripts/release-flow.test.ts ./scripts/bump-version.test.ts ./scripts/workflow-policy.test.ts ./scripts/npm-release.test.ts`
Expected: PASS.

### Task 4: Verification

**Files:**
- Verify only

- [ ] **Step 1: Run authoritative release-compatible verification**

Run: `bun install --frozen-lockfile && bun run verify`
Expected: PASS.

- [ ] **Step 2: Inspect final diff and working tree**

Run: `git diff --check && git status --short`
Expected: No whitespace errors; only the pre-existing version/test changes plus the approved release-flow files and docs are modified.

- [ ] **Step 3: Report operational caveat**

State that the current unrelated `apps/bridge/test/dev-profile-cli.test.ts` change must be committed separately before `bun run release:push` can succeed, and list every verification command and outcome.
