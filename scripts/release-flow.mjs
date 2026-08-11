#!/usr/bin/env node
import { parseArgs, pushRelease, tagRelease } from './release-flow-lib.mjs';

async function main() {
  const { command } = parseArgs(process.argv.slice(2));
  if (command === 'help') {
    console.log(`Usage: node scripts/release-flow.mjs <push|tag>

Commands:
  push  Verify, commit, and push the already-bumped release to the default branch
  tag   Require successful Linux/macOS CI, then create and push the release tag`);
    return;
  }
  if (command === 'push') {
    const result = await pushRelease();
    console.log(`Pushed release commit ${result.commit} for Ariava ${result.version} to origin/${result.branch}.`);
    console.log('Wait for the Public Repo CI Linux and macOS jobs, then run: bun run release:tag');
    return;
  }

  const result = await tagRelease();
  console.log(`Pushed ${result.tag} at ${result.commit} after CI run ${result.workflowRunId} succeeded.`);
  console.log('Observe and, if configured, approve publish-npm.yml in npm-production.');
}

main().catch((error) => {
  console.error(`error: ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 1;
});
