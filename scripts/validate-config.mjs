#!/usr/bin/env node
// Validates config/*.json against what apps-root/fleet-generator.yaml actually
// substitutes. The ApplicationSet's git generator reads every file matching
// config/*.json and templates these four keys straight into an Argo CD
// Application. A missing or empty key does not fail loudly at generation time —
// it produces an Application pointing at an empty repoURL, path or namespace,
// which is a broken deployment rather than a broken pipeline.
//
// It also validates secrets/*.json, the provisioner declarations (#7). Those
// are a separate directory on purpose — the generator must never see them — but
// they are checked from here rather than from their own CI step, because
// .github/workflows/ci.yml already runs this file and a workflow edit is
// James's call under his #83 rule. The name undersells the file; renaming it
// would itself be a workflow change, so the name stays.
//
// Run locally with: node scripts/validate-config.mjs
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { validateSecrets } from './validate-secrets.mjs';

// Keep in step with the `{{...}}` placeholders in apps-root/fleet-generator.yaml.
const REQUIRED = ['appName', 'repoURL', 'chartPath', 'targetNamespace'];

const dir = process.argv[2] ?? 'config';
const secretsDir = process.argv[3] ?? 'secrets';
const errors = [];
const seen = new Map();

const files = readdirSync(dir).filter((f) => f.endsWith('.json')).sort();
if (files.length === 0) errors.push(`${dir}/: no .json files found — the generator would produce no Applications`);

for (const file of files) {
  const path = join(dir, file);
  let config;

  try {
    config = JSON.parse(readFileSync(path, 'utf8'));
  } catch (e) {
    errors.push(`${path}: not valid JSON — ${e.message}`);
    continue;
  }

  if (config === null || typeof config !== 'object' || Array.isArray(config)) {
    errors.push(`${path}: must be a JSON object`);
    continue;
  }

  for (const key of REQUIRED) {
    const value = config[key];
    if (typeof value !== 'string' || value.trim() === '') {
      errors.push(`${path}: "${key}" must be a non-empty string (got ${JSON.stringify(value)})`);
    }
  }

  // Argo CD names the Application after appName, so a duplicate means one
  // config silently overwrites another.
  const name = config.appName;
  if (typeof name === 'string' && name.trim() !== '') {
    if (seen.has(name)) errors.push(`${path}: duplicate appName "${name}" — also in ${seen.get(name)}`);
    else seen.set(name, path);
  }

  const unknown = Object.keys(config).filter((k) => !REQUIRED.includes(k));
  if (unknown.length) console.log(`note: ${path} has keys the generator ignores: ${unknown.join(', ')}`);
}

const secrets = validateSecrets(secretsDir, dir);
for (const n of secrets.notes) console.log(`note: ${n}`);
errors.push(...secrets.errors);

if (errors.length) {
  console.error(`\n${errors.length} problem(s):`);
  for (const e of errors) console.error(`  ✗ ${e}`);
  process.exit(1);
}

const declaredKeys = secrets.declarations.reduce((n, d) => n + d.keys.length, 0);
console.log(`✓ ${files.length} fleet config(s) valid: ${[...seen.keys()].join(', ')}`);
console.log(`✓ ${secrets.declarations.length} secret declaration(s) valid, ${declaredKeys} key(s)`);
