// Unit tests for the dry-run planner (#7, slice 2).
//
// Run with: node --test scripts/plan-secrets.test.mjs
//
// ⚠️ Name the FILE, not the directory. `node --test scripts/` fails here with
// "Cannot find module .../scripts" — this repo has no package.json, so Node
// resolves the argument as a module to execute rather than a tree to walk.
//
// ⚠️ These are NOT gated in CI. .github/workflows/ci.yml runs
// `node scripts/validate-config.mjs` and nothing else, so a red test here would
// not fail a pull request. Adding the step is a workflow change and therefore
// James's under his #83 rule, offered as its own one-line PR (slice 3). Until
// that merges, a green run here is something a human saw, not a gate.
//
// The declarations used below are the REAL ones from secrets/*.json, not
// invented shapes. The five-key `around-the-world-secrets` is the case the whole
// slice exists for, so testing a tidy two-key stand-in would prove the wrong
// thing.
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { planSecrets, assertNeverClobbers, normaliseObservation, DEFAULT_RANDOM_BYTES } from './plan-secrets.mjs';

// secrets/around-the-world.json, verbatim. Five keys: one Postgres, two random,
// two that nothing can generate.
const aroundTheWorld = () => ({
  app: 'around-the-world',
  namespace: 'balenthiran',
  secretName: 'around-the-world-secrets',
  keys: [
    { key: 'ConnectionStrings__DefaultConnection', type: 'postgres-db', database: 'aroundtheworld', role: 'aroundtheworld' },
    { key: 'Jwt__Secret', type: 'random', bytes: 32 },
    { key: 'Admin__Key', type: 'random', bytes: 16 },
    { key: 'PhotoStorage__AccessKeyId', type: 'external' },
    { key: 'PhotoStorage__SecretAccessKey', type: 'external' },
  ],
});

// secrets/macro-metrics.json, verbatim.
const macroMetrics = () => ({
  app: 'macro-metrics',
  namespace: 'balenthiran',
  secretName: 'macro-metrics-secrets',
  keys: [{ key: 'FRED_API_KEY', type: 'external' }],
});

const emptyEstate = (pg = { roles: [], databases: [] }) => ({ namespaces: ['balenthiran'], secrets: {}, postgres: pg });

const kinds = (plan) => plan.steps.map((s) => s.kind);
const keysOf = (list) => list.map((e) => e.key).sort();

// ---------------------------------------------------------------------------
// A first provision, from nothing
// ---------------------------------------------------------------------------

test('an empty estate: role and database before the Secret that names them', () => {
  const plan = planSecrets([aroundTheWorld()], emptyEstate());

  assert.deepEqual(kinds(plan), ['create-role', 'create-database', 'create-secret']);

  // Ordering is not cosmetic: the connection string cannot be composed before
  // the role and database it names exist.
  assert.ok(plan.steps.findIndex((s) => s.kind === 'create-role') < plan.steps.findIndex((s) => s.kind === 'create-secret'));

  const create = plan.steps.at(-1);
  // Three of five keys. The two `external` ones are NOT in the created Secret —
  // inventing a placeholder value for an OCI credential would make the pod start
  // and then fail on its first upload, which is worse than not starting.
  assert.deepEqual(create.keys.map((k) => k.key).sort(), ['Admin__Key', 'ConnectionStrings__DefaultConnection', 'Jwt__Secret']);
  assert.deepEqual(keysOf(plan.blocked), ['PhotoStorage__AccessKeyId', 'PhotoStorage__SecretAccessKey']);
  assert.equal(plan.blocked[0].action, 'supply-externally');
});

test('random bytes default to 32 when the declaration does not say', () => {
  const decl = { app: 'd', namespace: 'balenthiran', secretName: 'd-secrets', keys: [{ key: 'K', type: 'random' }] };
  const plan = planSecrets([decl], emptyEstate());
  assert.match(plan.steps[0].keys[0].source, new RegExp(`${DEFAULT_RANDOM_BYTES} random bytes`));
});

test('two declarations in one namespace get one create-secret each, not one between them', () => {
  const plan = planSecrets([aroundTheWorld(), macroMetrics()], emptyEstate());
  // macro-metrics' single key is external, so it produces no write at all.
  assert.equal(plan.summary.createSecret, 1);
  assert.equal(plan.summary.blocked, 3);
});

// ---------------------------------------------------------------------------
// The case this slice exists for
// ---------------------------------------------------------------------------

test('an existing five-key Secret missing one key is PATCHED once, never created', () => {
  const live = [
    'ConnectionStrings__DefaultConnection',
    'Admin__Key',
    'PhotoStorage__AccessKeyId',
    'PhotoStorage__SecretAccessKey',
  ];
  const plan = planSecrets([aroundTheWorld()], {
    namespaces: ['balenthiran'],
    secrets: { 'balenthiran/around-the-world-secrets': live },
    postgres: { roles: ['aroundtheworld'], databases: ['aroundtheworld'] },
  });

  // The whole point. A create-secret here would delete the four keys above —
  // including Jwt__Secret and Admin__Key, which signs every guest out mid-party.
  assert.equal(plan.summary.createSecret, 0);
  assert.deepEqual(kinds(plan), ['patch-secret-key']);
  assert.equal(plan.steps[0].key, 'Jwt__Secret');

  // The step names what it must not disturb, so the failure is visible in the
  // plan a human reads rather than only in the client that executes it.
  assert.deepEqual(plan.steps[0].preserves, [...live].sort());

  // Everything already there is left alone, including the two external keys,
  // which are satisfied precisely because they are present.
  assert.deepEqual(keysOf(plan.noop), [...live].sort());
  assert.equal(plan.summary.blocked, 0);
});

test('an existing Secret with every key planned produces no steps at all', () => {
  const plan = planSecrets([aroundTheWorld()], {
    namespaces: ['balenthiran'],
    secrets: { 'balenthiran/around-the-world-secrets': aroundTheWorld().keys.map((k) => k.key) },
    postgres: { roles: ['aroundtheworld'], databases: ['aroundtheworld'] },
  });
  assert.deepEqual(plan.steps, []);
  assert.equal(plan.summary.noop, 5);
});

test('the clobber guard rejects a plan that creates over an existing Secret', () => {
  // Unreachable through planSecrets by construction, which is exactly why it is
  // called directly here: a guard no test can execute is indistinguishable from
  // one that does not work.
  const state = normaliseObservation({ namespaces: ['balenthiran'], secrets: { 'balenthiran/around-the-world-secrets': ['Jwt__Secret'] } });
  const bad = { steps: [{ kind: 'create-secret', namespace: 'balenthiran', secretName: 'around-the-world-secrets', keys: [] }] };

  assert.throws(() => assertNeverClobbers(bad, state), /planner bug: planned to create balenthiran\/around-the-world-secrets/);

  // And it does not fire on the legitimate shape.
  const good = { steps: [{ kind: 'create-secret', namespace: 'balenthiran', secretName: 'somewhere-else', keys: [] }] };
  assert.doesNotThrow(() => assertNeverClobbers(good, state));
});

// ---------------------------------------------------------------------------
// Create-only: what the planner refuses to do
// ---------------------------------------------------------------------------

test('an existing Postgres role blocks — its password is neither knowable nor ours to change', () => {
  const plan = planSecrets([aroundTheWorld()], {
    namespaces: ['balenthiran'],
    secrets: {},
    postgres: { roles: ['aroundtheworld'], databases: ['aroundtheworld'] },
  });

  const b = plan.blocked.find((e) => e.key === 'ConnectionStrings__DefaultConnection');
  assert.equal(b.action, 'rotate-by-hand');
  assert.match(b.reason, /ALTER ROLE would break whatever authenticates with it now/);
  // No DDL, and above all no Secret carrying a connection string we cannot compose.
  assert.equal(plan.summary.createRole, 0);
  assert.equal(plan.steps.find((s) => s.kind === 'create-secret').keys.some((k) => k.key === 'ConnectionStrings__DefaultConnection'), false);
});

test('a database that exists without its role blocks — create-only cannot reassign an owner', () => {
  const plan = planSecrets([aroundTheWorld()], {
    namespaces: ['balenthiran'],
    secrets: {},
    postgres: { roles: [], databases: ['aroundtheworld'] },
  });
  const b = plan.blocked.find((e) => e.key === 'ConnectionStrings__DefaultConnection');
  assert.equal(b.action, 'reassign-by-hand');
  assert.equal(plan.summary.createDatabase, 0);
});

test('two declarations claiming one Postgres role: the second blocks rather than silently skipping', () => {
  // validate-secrets.mjs already rejects this, but the planner must not depend
  // on having been run after the validator — that is a different program's
  // guarantee, and this is the failure that is silent and late.
  const second = { ...macroMetrics(), keys: [{ key: 'DB', type: 'postgres-db', database: 'other', role: 'aroundtheworld' }] };
  const plan = planSecrets([aroundTheWorld(), second], emptyEstate());

  assert.equal(plan.summary.createRole, 1);
  assert.equal(plan.blocked.find((e) => e.app === 'macro-metrics' && e.key === 'DB').action, 'rotate-by-hand');
});

test('keys in the cluster that no declaration claims are named, never deleted', () => {
  const plan = planSecrets([macroMetrics()], {
    namespaces: ['balenthiran'],
    secrets: { 'balenthiran/macro-metrics-secrets': ['FRED_API_KEY', 'OLD_TOKEN', 'ANOTHER'] },
    postgres: { roles: [], databases: [] },
  });
  assert.deepEqual(keysOf(plan.unmanaged), ['ANOTHER', 'OLD_TOKEN']);
  assert.deepEqual(plan.steps, []);
});

test('a present Postgres key whose role does not exist is reported as drift, not acted on', () => {
  const plan = planSecrets([aroundTheWorld()], {
    namespaces: ['balenthiran'],
    secrets: { 'balenthiran/around-the-world-secrets': aroundTheWorld().keys.map((k) => k.key) },
    postgres: { roles: [], databases: [] },
  });
  // A connection string that cannot authenticate. Create-only means we leave the
  // value alone — but nothing else in this estate would ever notice it.
  assert.equal(plan.summary.drift, 1);
  assert.match(plan.drift[0].reason, /cannot authenticate/);
  assert.deepEqual(plan.steps, []);
});

// ---------------------------------------------------------------------------
// "I did not look" is not "it is empty"
// ---------------------------------------------------------------------------

test('a namespace that was never enumerated plans nothing — it is undecidable, not empty', () => {
  const plan = planSecrets([aroundTheWorld()], { namespaces: [], secrets: {}, postgres: { roles: [], databases: [] } });

  assert.deepEqual(plan.steps, []);
  assert.equal(plan.summary.unknown, 5);
  assert.match(plan.unknown[0].reason, /could overwrite a Secret that already exists/);
});

test('an uninspected Postgres server makes only the postgres keys undecidable', () => {
  const plan = planSecrets([aroundTheWorld()], { namespaces: ['balenthiran'], secrets: {}, postgres: null });

  assert.deepEqual(keysOf(plan.unknown), ['ConnectionStrings__DefaultConnection']);
  // The random keys are unaffected — whether a role exists says nothing about them.
  assert.equal(plan.summary.createSecret, 1);
  assert.deepEqual(plan.steps.at(-1).keys.map((k) => k.key).sort(), ['Admin__Key', 'Jwt__Secret']);
});

test('an observation that does not say what it enumerated is refused outright', () => {
  assert.throws(() => planSecrets([], { secrets: {} }), /must list the namespaces it enumerated/);
  assert.throws(() => planSecrets([], null), /must be an object/);
  assert.throws(() => planSecrets([], { namespaces: ['x'], postgres: { roles: [] } }), /postgres must be null/);
  assert.throws(() => planSecrets([], { namespaces: ['x'], secrets: { 'x/y': 'k' } }), /must be an array of key names/);
});

test('a type the schema knows and the planner does not stops the plan', () => {
  // The two live in different files and will be edited apart. A fourth type
  // added to TYPES with no branch here must surface, not fall through as a noop.
  const decl = { app: 'd', namespace: 'balenthiran', secretName: 'd-secrets', keys: [{ key: 'K', type: 'ssh-keypair' }] };
  const plan = planSecrets([decl], emptyEstate());
  assert.equal(plan.summary.unknown, 1);
  assert.match(plan.unknown[0].reason, /knows a type this planner does not/);
});

// ---------------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------------

test('planning is pure: the same input twice gives byte-identical plans', () => {
  const observed = { namespaces: ['balenthiran'], secrets: { 'balenthiran/around-the-world-secrets': ['Admin__Key'] }, postgres: { roles: [], databases: [] } };
  const a = JSON.stringify(planSecrets([aroundTheWorld(), macroMetrics()], observed));
  const b = JSON.stringify(planSecrets([aroundTheWorld(), macroMetrics()], observed));
  assert.equal(a, b);
});

test('every declared key lands in exactly one bucket — nothing is silently dropped', () => {
  // Without this, a key that matched no branch would simply vanish from the
  // plan, which reads identically to "nothing to do".
  const decls = [aroundTheWorld(), macroMetrics()];
  const observed = { namespaces: ['balenthiran'], secrets: { 'balenthiran/around-the-world-secrets': ['Admin__Key', 'STRAY'] }, postgres: { roles: [], databases: [] } };
  const plan = planSecrets(decls, observed);

  const declared = decls.flatMap((d) => d.keys.map((k) => `${d.namespace}/${d.secretName}#${k.key}`));
  const accounted = [
    ...plan.blocked, ...plan.unknown, ...plan.drift, ...plan.noop,
    ...plan.steps.filter((s) => s.kind === 'patch-secret-key'),
    ...plan.steps.filter((s) => s.kind === 'create-secret').flatMap((s) => s.keys.map((k) => ({ ...k, namespace: s.namespace, secretName: s.secretName }))),
  ].map((e) => `${e.namespace}/${e.secretName}#${e.key}`);

  assert.deepEqual([...accounted].sort(), [...declared].sort());
  // …and STRAY, which is declared nowhere, is in unmanaged rather than lost.
  assert.deepEqual(keysOf(plan.unmanaged), ['STRAY']);
});

test('the planner never plans a delete, in any shape', () => {
  const observed = { namespaces: ['balenthiran'], secrets: { 'balenthiran/around-the-world-secrets': ['Admin__Key', 'STRAY'] }, postgres: { roles: ['aroundtheworld'], databases: ['aroundtheworld'] } };
  const plan = planSecrets([aroundTheWorld(), macroMetrics()], observed);
  const allowed = new Set(['create-role', 'create-database', 'create-secret', 'patch-secret-key']);
  for (const step of plan.steps) assert.ok(allowed.has(step.kind), `unexpected step kind ${step.kind}`);
});
