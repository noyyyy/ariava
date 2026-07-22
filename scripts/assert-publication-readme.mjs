#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

export const PRIVATE_README_MARKER = 'ARIAVA_PRIVATE_PRODUCT_README: DO_NOT_PUBLISH';
export const PUBLIC_README_MARKER = 'ARIAVA_PUBLIC_CORE_README: PUBLISHABLE';

const args = process.argv.slice(2);
let root = process.cwd();
for (let index = 0; index < args.length; index += 1) {
  if (args[index] === '--root' && args[index + 1]) {
    root = resolve(args[index + 1]);
    index += 1;
  } else {
    console.error('usage: assert-publication-readme.mjs [--root <path>]');
    process.exit(2);
  }
}

const readme = readFileSync(resolve(root, 'README.md'), 'utf8');
if (readme.includes(PRIVATE_README_MARKER)) {
  console.error('publication README check failed: this is the private Product README; generate the reviewed Public Core candidate before publishing');
  process.exit(1);
}
if (!readme.includes(PUBLIC_README_MARKER)) {
  console.error(`publication README check failed: expected generated Public Core marker ${PUBLIC_README_MARKER}`);
  process.exit(1);
}

export const REQUIRED_PUBLICATION_TEXT = [
  { label: 'recommended npx onboarding command', text: 'npx --yes ariava@latest setup' },
  { label: 'canonical production Relay', text: 'https://ariava-relay.noyx.io' },
  { label: 'Pi reload instruction', text: '/reload' },
  { label: 'explicit Watch pairing command', text: 'ariava pair <PAIRING_CODE>' },
  { label: 'retained manual init command', text: 'ariava init' },
  { label: 'retained manual service command', text: 'ariava service install' },
  { label: 'retained manual Pi install command', text: 'ariava install pi' },
  { label: 'retained doctor command', text: 'ariava doctor' },
];

const missing = REQUIRED_PUBLICATION_TEXT.filter(({ text }) => !readme.includes(text));
if (missing.length > 0) {
  console.error(`publication README check failed: missing ${missing.map(({ label, text }) => `${label} (${text})`).join(', ')}`);
  process.exit(1);
}
console.log('publication README check passed: marker and required onboarding/manual text present');
