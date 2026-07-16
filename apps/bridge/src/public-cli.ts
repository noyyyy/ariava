#!/usr/bin/env node
import { runPublicCli } from './public-cli-app';

process.exitCode = await runPublicCli(process.argv.slice(2));
