#!/usr/bin/env bun
import { runDevProfileCommand } from './dev-profile-app';

try {
  const exitCode = await runDevProfileCommand(process.argv.slice(2));
  process.exitCode = exitCode;
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  console.error(message);
  process.exitCode = 1;
}
