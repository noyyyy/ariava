#!/usr/bin/env node
import { runAriavaCli } from './cli/app';
import { createDevCliApplicationContext } from './cli/lifecycle/dev';

process.exitCode = await runAriavaCli(process.argv.slice(2), createDevCliApplicationContext());
