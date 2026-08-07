#!/usr/bin/env node
import { runAriavaCli } from './cli/app';
import { createDefaultCliApplicationContext } from './cli/lifecycle/default';

process.exitCode = await runAriavaCli(process.argv.slice(2), createDefaultCliApplicationContext());
