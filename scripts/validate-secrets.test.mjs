// Unit tests for the declaration schema (#7).
//
// Run with: node --test scripts/validate-secrets.test.mjs
//
// ⚠️ Name the FILE, not the directory. `node --test scripts/` fails here with
// "Cannot find module .../scripts" — this repo has no package.json, so Node
// resolves the argument as a module to execute rather than a tree to walk. The
// failure looks like a broken test suite and is not one.
//
// ⚠️ These are NOT gated in CI yet. .github/workflows/ci.yml runs
// `node scripts/validate-config.mjs` and nothing else, so a broken test here
// would not fail a pull request. Adding the step is a workflow change and
// therefore James's under his #83 rule; it is offered as its own one-line PR.
// Until that merges, treat a green run here as something a human saw, not as a
// gate — a passing test that no workflow runs proves nothing about the next
// pull request.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { validateSecrets } from './validate-secrets.mjs';

// Builds a throwaway pair of directories and returns the validator's findings.
// `secrets` is a map of file basename -> object (or a raw string, so a malformed
// JSON case can be expressed).
function run(secrets, fleet = { 'demo.json': { appName: 'demo', repoURL: 'r', chartPath: 'helm', targetNamespace: 'balenthiran' } }) {
  const root = mkdtempSync(join(tmpdir(), 'fleet-secrets-'));
  const secretsDir = join(root, 'secrets');
  const configDir = join(root, 'config');
  mkdirSync(configDir);

  for (const [name, body] of Object.entries(fleet)) {
    writeFileSync(join(configDir, name), JSON.stringify(body));
  }

  if (secrets !== null) {
    mkdirSync(secretsDir);
    for (const [name, body] of Object.entries(secrets)) {
      writeFileSync(join(secretsDir, name), typeof body === 'string' ? body : JSON.stringify(body));
    }
  }

  try {
    return validateSecrets(secretsDir, configDir);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

// A declaration that mirrors what this estate actually looks like.
const demo = () => ({
  app: 'demo',
  namespace: 'balenthiran',
  secretName: 'demo-secrets',
  keys: [
    { key: 'ConnectionStrings__DefaultConnection', type: 'postgres-db', database: 'demo', role: 'demo' },
    { key: 'Jwt__Secret', type: 'random', bytes: 32 },
    { key: 'PhotoStorage__AccessKeyId', type: 'external' },
  ],
});

test('a declaration describing this estate validates clean', () => {
  const { errors, notes } = run({ 'demo.json': demo() });
  assert.deepEqual(errors, []);
  assert.deepEqual(notes, []);
});

test('a secret KEY may contain underscores and capitals', () => {
  // Guards against applying the Secret's own naming rule to the keys inside it.
  // `ConnectionStrings__DefaultConnection` is a real key in this estate, and a
  // DNS-label check would reject every app we have.
  const decl = demo();
  decl.keys = [{ key: 'ConnectionStrings__DefaultConnection', type: 'external' }];
  assert.deepEqual(run({ 'demo.json': decl }).errors, []);
});

test('a missing secrets/ directory is a note, not a failure', () => {
  const { errors, notes, declarations } = run(null);
  assert.deepEqual(errors, []);
  assert.deepEqual(declarations, []);
  assert.match(notes.join('\n'), /no declarations directory/);
});

test('an app with no fleet entry is a note, not a failure', () => {
  // Kit has a chart and a secret but deliberately no oke-fleet config entry.
  const decl = { ...demo(), app: 'kit' };
  const { errors, notes } = run({ 'kit.json': decl });
  assert.deepEqual(errors, []);
  assert.match(notes.join('\n'), /has no .*config\/\*\.json entry/);
});

test('an app in the fleet declaring a DIFFERENT namespace fails', () => {
  // The one thing here that looks completely correct and cannot work: a
  // secretKeyRef resolves only in the pod's own namespace, so this Secret would
  // be created, be valid, and never be readable by the app that names it.
  const { errors } = run({ 'demo.json': { ...demo(), namespace: 'data' } });
  assert.match(errors.join('\n'), /the fleet deploys "demo" into "balenthiran"/);
});

test('an app NOT in the fleet may use any namespace — there is nothing to disagree with', () => {
  const { errors } = run({ 'kit.json': { ...demo(), app: 'kit', namespace: 'data' } });
  assert.deepEqual(errors, []);
});

test('a fleet entry with no targetNamespace does not manufacture a mismatch', () => {
  // validate-config.mjs owns that error. Reporting it here too would make one
  // problem look like two, and `undefined !== 'balenthiran'` is the shape that
  // would do exactly that.
  const { errors } = run(
    { 'demo.json': demo() },
    { 'demo.json': { appName: 'demo', repoURL: 'r', chartPath: 'helm' } },
  );
  assert.deepEqual(errors, []);
});

test('malformed JSON is reported against its path', () => {
  const { errors } = run({ 'demo.json': '{ not json' });
  assert.equal(errors.length, 1);
  assert.match(errors[0], /not valid JSON/);
});

test('an unknown top-level field fails rather than being ignored', () => {
  const { errors } = run({ 'demo.json': { ...demo(), databse: 'demo' } });
  assert.match(errors.join('\n'), /unknown field\(s\) databse/);
});

test('a non-lowercase namespace fails', () => {
  const { errors } = run({ 'demo.json': { ...demo(), namespace: 'Balenthiran' } });
  assert.match(errors.join('\n'), /"namespace" must be a lowercase DNS label/);
});

test('an empty keys array fails — a declaration that provisions nothing is a mistake', () => {
  const { errors } = run({ 'demo.json': { ...demo(), keys: [] } });
  assert.match(errors.join('\n'), /"keys" must be a non-empty array/);
});

test('the same key declared twice in one file fails', () => {
  const decl = demo();
  decl.keys = [
    { key: 'Jwt__Secret', type: 'random' },
    { key: 'Jwt__Secret', type: 'random' },
  ];
  assert.match(run({ 'demo.json': decl }).errors.join('\n'), /duplicate key "Jwt__Secret"/);
});

test('two files claiming one namespace/secret/key fail — last writer would silently win', () => {
  const a = { ...demo(), app: 'demo', keys: [{ key: 'Jwt__Secret', type: 'random' }] };
  const b = { ...demo(), app: 'other', keys: [{ key: 'Jwt__Secret', type: 'random' }] };
  const { errors } = run(
    { 'demo.json': a, 'other.json': b },
    {
      'demo.json': { appName: 'demo', repoURL: 'r', chartPath: 'helm', targetNamespace: 'balenthiran' },
      'other.json': { appName: 'other', repoURL: 'r', chartPath: 'helm', targetNamespace: 'balenthiran' },
    },
  );
  assert.match(errors.join('\n'), /balenthiran\/demo-secrets#Jwt__Secret is already declared/);
});

test('two files declaring the same app fail', () => {
  const a = { ...demo(), secretName: 'a-secrets' };
  const b = { ...demo(), secretName: 'b-secrets' };
  assert.match(run({ 'a.json': a, 'b.json': b }).errors.join('\n'), /duplicate app "demo"/);
});

test('an unrecognised type fails and names the three that exist', () => {
  const decl = demo();
  decl.keys = [{ key: 'X', type: 'sealed' }];
  assert.match(run({ 'demo.json': decl }).errors.join('\n'), /"type" must be one of postgres-db, random, external/);
});

test('postgres-db without a database fails', () => {
  const decl = demo();
  decl.keys = [{ key: 'X', type: 'postgres-db', role: 'demo' }];
  assert.match(run({ 'demo.json': decl }).errors.join('\n'), /requires "database"/);
});

test('a database name that would break out of the DDL statement fails', () => {
  // CREATE DATABASE takes no bind parameter, so the provisioner must build that
  // statement as text. This check is the injection guard, and it runs in CI
  // rather than in the thing holding the Postgres credential.
  const decl = demo();
  decl.keys = [{ key: 'X', type: 'postgres-db', database: 'demo"; DROP DATABASE postgres; --', role: 'demo' }];
  assert.match(run({ 'demo.json': decl }).errors.join('\n'), /"database" must be a lowercase Postgres identifier/);
});

test('a database name over 63 bytes fails, because Postgres would silently truncate it', () => {
  const decl = demo();
  decl.keys = [{ key: 'X', type: 'postgres-db', database: 'd'.repeat(64), role: 'demo' }];
  assert.match(run({ 'demo.json': decl }).errors.join('\n'), /"database" must be a lowercase Postgres identifier/);
});

test('random bytes below the floor fails', () => {
  const decl = demo();
  decl.keys = [{ key: 'X', type: 'random', bytes: 4 }];
  assert.match(run({ 'demo.json': decl }).errors.join('\n'), /"bytes" must be an integer between 16 and 256/);
});

test('random bytes must be an integer, not a numeric string', () => {
  const decl = demo();
  decl.keys = [{ key: 'X', type: 'random', bytes: '32' }];
  assert.match(run({ 'demo.json': decl }).errors.join('\n'), /"bytes" must be an integer/);
});

test('external takes no generation fields — declaring bytes on it is a misunderstanding', () => {
  const decl = demo();
  decl.keys = [{ key: 'X', type: 'external', bytes: 32 }];
  assert.match(run({ 'demo.json': decl }).errors.join('\n'), /type "external" does not take bytes/);
});

test('a field belonging to another type fails rather than being silently dropped', () => {
  const decl = demo();
  decl.keys = [{ key: 'X', type: 'random', database: 'demo' }];
  assert.match(run({ 'demo.json': decl }).errors.join('\n'), /type "random" does not take database/);
});

test('a filename that disagrees with the app is a note, not a failure', () => {
  const { errors, notes } = run({ 'wrong-name.json': demo() });
  assert.deepEqual(errors, []);
  assert.match(notes.join('\n'), /file is named for "wrong-name" but declares app "demo"/);
});

test('every declaration is returned, so a caller can plan from them', () => {
  const { declarations } = run({ 'demo.json': demo() });
  assert.equal(declarations.length, 1);
  assert.equal(declarations[0].keys.length, 3);
});
