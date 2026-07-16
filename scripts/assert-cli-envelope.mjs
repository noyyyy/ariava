#!/usr/bin/env node
import { readFileSync } from 'node:fs';

const [inputPath, kind, commandExitText] = process.argv.slice(2);

function fail(message) {
  console.error(`CLI envelope assertion failed: ${message}`);
  process.exit(1);
}

if (!inputPath || !['status', 'doctor'].includes(kind) || !/^\d+$/.test(commandExitText ?? '')) {
  fail('usage: assert-cli-envelope.mjs <json-file> <status|doctor> <command-exit>');
}

const commandExit = Number(commandExitText);
let envelope;
try {
  envelope = JSON.parse(readFileSync(inputPath, 'utf8'));
} catch {
  fail(`${inputPath} must contain valid JSON`);
}

if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope)) {
  fail('envelope must be a JSON object');
}
if (typeof envelope.ok !== 'boolean' || typeof envelope.code !== 'string'
  || typeof envelope.message !== 'string' || !envelope.data
  || typeof envelope.data !== 'object' || Array.isArray(envelope.data)) {
  fail('envelope requires boolean ok, string code/message, and object data');
}

if (kind === 'status') {
  if (commandExit !== 0 || envelope.ok !== true || envelope.code !== 'ok') {
    fail('status requires command exit 0 with ok=true and code="ok"');
  }
} else {
  const healthy = commandExit === 0 && envelope.ok === true && envelope.code === 'ok';
  const unhealthy = commandExit === 1 && envelope.ok === false && envelope.code === 'ERR_DOCTOR';
  if (!healthy && !unhealthy) {
    fail('doctor requires exit 0/ok=true/code="ok" or exit 1/ok=false/code="ERR_DOCTOR"');
  }
}

const serviceFields = kind === 'status'
  ? {
      object: envelope.data.service,
      required: {
        backend: 'string',
        supported: 'boolean',
        supportReason: 'string',
        installed: 'boolean',
        enabled: 'boolean',
        loaded: 'boolean',
        processRunning: 'boolean',
      },
    }
  : {
      object: envelope.data,
      required: {
        platform: 'string',
        isWsl: 'boolean',
        serviceBackend: 'string',
        serviceSupported: 'boolean',
        serviceSupportReason: 'string',
        serviceInstalled: 'boolean',
        serviceEnabled: 'boolean',
        serviceLoaded: 'boolean',
        serviceRunning: 'boolean',
        servicePathCurrent: 'boolean',
      },
    };

if (!serviceFields.object || typeof serviceFields.object !== 'object' || Array.isArray(serviceFields.object)) {
  fail(`missing or invalid neutral service diagnostic ${kind === 'status' ? 'service' : 'data'}`);
}
for (const [field, expectedType] of Object.entries(serviceFields.required)) {
  if (typeof serviceFields.object[field] !== expectedType || (expectedType === 'string' && serviceFields.object[field].length === 0)) {
    fail(`missing or invalid neutral service diagnostic ${field}`);
  }
}
