#!/usr/bin/env node
// The dry-run planner: given the declarations from secrets/*.json and what is
// observed in the cluster, decide what a provisioner WOULD do. Slice 2 of #7
// (claude-code-bot#97). It touches nothing — no Kubernetes client, no Postgres
// client, no network. That is the point: the decisions are the part worth
// proving correct, and they can be proven here, cheaply, against fixtures.
//
// THE FACT THAT BREAKS THE OBVIOUS IMPLEMENTATION
// `around-the-world-secrets` holds FIVE keys. The obvious provisioner writes a
// Secret; writing that Secret with the one key it is provisioning DELETES the
// other four, and two of them are `Jwt__Secret` and `Admin__Key` — so the visible
// symptom is every logged-in guest signed out mid-party, not an error. A Secret
// that already exists is therefore only ever PATCHED, one key at a time, and
// `assertNeverClobbers` below is the invariant, not a comment about one.
//
// CREATE-ONLY, NEVER DELETE, NEVER OVERWRITE (James, claude-code-bot#97)
// A key that is already present is left exactly alone, even when it looks wrong.
// An existing Postgres role is never given a new password. The planner's job
// when it cannot proceed within those rules is to say so and name the human
// step — never to widen its own remit.
//
// WHY THE OBSERVATION MUST SAY WHAT IT LOOKED AT
// "this namespace holds no secrets" and "I never listed this namespace" arrive
// at this function as the same empty object, and they could not be more
// different: the first means create, the second means a failed lookup would
// silently plan to create a Secret that already exists — which is the exact
// clobber described above. So an observation must NAME the namespaces it
// enumerated, and anything outside that list is planned as `unknown`, never as
// an action.
//
// Run standalone with:
//   node scripts/plan-secrets.mjs --assume-empty
//   node scripts/plan-secrets.mjs --observed <file.json> [--json]
import { readFileSync } from 'node:fs';
import { validateSecrets } from './validate-secrets.mjs';

export const DEFAULT_RANDOM_BYTES = 32;

/**
 * Normalise an observation, and refuse one that does not say what it looked at.
 *
 * @param {object} observed
 *   {
 *     namespaces: string[],            // namespaces whose Secrets were listed
 *     secrets: { "<ns>/<name>": string[] },  // keys present, per existing Secret
 *     postgres?: { roles: string[], databases: string[] } | null,
 *   }
 *   `postgres` absent or null means the server was not inspected — not that it
 *   is empty. A missing entry in `secrets` for an enumerated namespace DOES mean
 *   the Secret does not exist; that is what enumerating the namespace buys.
 */
export function normaliseObservation(observed) {
  if (observed === null || typeof observed !== 'object' || Array.isArray(observed)) {
    throw new TypeError('observation must be an object');
  }
  if (!Array.isArray(observed.namespaces)) {
    throw new TypeError('observation must list the namespaces it enumerated — an unlisted namespace is "I did not look", not "it is empty"');
  }

  const secrets = new Map();
  for (const [target, keys] of Object.entries(observed.secrets ?? {})) {
    if (!Array.isArray(keys)) throw new TypeError(`observation: secrets[${JSON.stringify(target)}] must be an array of key names`);
    secrets.set(target, new Set(keys));
  }

  const pg = observed.postgres ?? null;
  if (pg !== null && (typeof pg !== 'object' || !Array.isArray(pg.roles) || !Array.isArray(pg.databases))) {
    throw new TypeError('observation: postgres must be null (not inspected) or {roles: [], databases: []}');
  }

  return {
    namespaces: new Set(observed.namespaces),
    secrets,
    postgres: pg === null ? null : { roles: new Set(pg.roles), databases: new Set(pg.databases) },
  };
}

/**
 * Plan what a provisioner would do.
 *
 * Pure: same declarations and observation in, same plan out. No I/O.
 *
 * @returns {{
 *   steps: object[],     // ordered, executable-shaped, Postgres DDL before the writes
 *   blocked: object[],   // a human must act; the provisioner cannot, by the rules
 *   unknown: object[],   // could not decide, because the observation did not cover it
 *   drift: object[],     // present and inconsistent — reported, never acted on
 *   unmanaged: object[], // keys in a declared Secret that no declaration claims
 *   noop: object[],      // already as declared
 *   summary: object,
 * }}
 */
export function planSecrets(declarations, observed) {
  const state = normaliseObservation(observed);

  const steps = [];
  const ddl = [];
  const blocked = [];
  const unknown = [];
  const drift = [];
  const unmanaged = [];
  const noop = [];

  // (namespace/secretName) -> keys this run would write into it.
  const writes = new Map();
  // Postgres identifiers this run has already planned to create. Two
  // declarations may not claim one role — validate-secrets.mjs rejects that — but
  // the planner must not depend on having been run after the validator.
  const planned = { roles: new Set(), databases: new Set() };

  for (const decl of declarations) {
    const target = `${decl.namespace}/${decl.secretName}`;
    const at = { app: decl.app, namespace: decl.namespace, secretName: decl.secretName };

    // Did we actually look here? See the header. This is the difference between
    // "create it" and "I have no idea whether it exists".
    const enumerated = state.namespaces.has(decl.namespace);
    const existing = state.secrets.get(target) ?? null;

    for (const entry of decl.keys) {
      const where = { ...at, key: entry.key, type: entry.type };

      if (!enumerated) {
        unknown.push({ ...where, reason: `namespace ${decl.namespace} was not enumerated — planning a create here could overwrite a Secret that already exists` });
        continue;
      }

      const present = existing !== null && existing.has(entry.key);

      if (present) {
        // Create-only: the value stays untouched. But a present Postgres key
        // whose role does not exist is a connection string that cannot
        // authenticate, and nothing else in this estate would ever notice.
        if (entry.type === 'postgres-db' && state.postgres !== null && !state.postgres.roles.has(entry.role)) {
          drift.push({ ...where, reason: `key is present but its Postgres role ${entry.role} does not exist — this connection string cannot authenticate` });
        } else {
          noop.push({ ...where, reason: 'already present — create-only leaves it alone' });
        }
        continue;
      }

      if (entry.type === 'external') {
        blocked.push({
          ...where,
          action: 'supply-externally',
          reason: `nothing can generate this value; a human must put it in ${target}#${entry.key}. Left as it is, the pod fails with CreateContainerConfigError minutes after it starts`,
        });
        continue;
      }

      if (entry.type === 'random') {
        const bytes = entry.bytes ?? DEFAULT_RANDOM_BYTES;
        addWrite(writes, target, { ...where, source: `generate ${bytes} random bytes, hex-encoded (openssl rand -hex ${bytes})` });
        continue;
      }

      if (entry.type === 'postgres-db') {
        if (state.postgres === null) {
          unknown.push({ ...where, reason: 'the Postgres server was not inspected — whether role and database already exist decides this entirely' });
          continue;
        }

        const roleExists = state.postgres.roles.has(entry.role) || planned.roles.has(entry.role);
        const dbExists = state.postgres.databases.has(entry.database) || planned.databases.has(entry.database);

        // The password is the whole difficulty. A role that already exists has a
        // password we do not know and may not change: create-only forbids it,
        // and an ALTER ROLE would instantly break whoever is authenticating with
        // the current one. So there is no connection string we can honestly
        // compose, and the honest output is to say so.
        if (roleExists) {
          blocked.push({
            ...where,
            action: 'rotate-by-hand',
            reason: `Postgres role ${entry.role} already exists, so its password is neither knowable nor ours to change (an ALTER ROLE would break whatever authenticates with it now). Compose the connection string by hand, or drop the role deliberately if nothing uses it`,
          });
          continue;
        }

        if (dbExists) {
          blocked.push({
            ...where,
            action: 'reassign-by-hand',
            reason: `database ${entry.database} already exists but role ${entry.role} does not, so it is owned by someone else — create-only cannot reassign an owner`,
          });
          continue;
        }

        planned.roles.add(entry.role);
        planned.databases.add(entry.database);
        ddl.push({ kind: 'create-role', ...where, role: entry.role, detail: `CREATE ROLE ${entry.role} LOGIN PASSWORD <generated>` });
        ddl.push({ kind: 'create-database', ...where, database: entry.database, role: entry.role, detail: `CREATE DATABASE ${entry.database} OWNER ${entry.role}` });
        addWrite(writes, target, { ...where, source: `the Npgsql connection string for ${entry.database} as ${entry.role}` });
        continue;
      }

      // Unreachable while TYPES and this switch agree. It is here because they
      // are edited in different files: a fourth type added to the schema without
      // a branch here must stop the plan, not fall through it as a silent noop.
      unknown.push({ ...where, reason: `no planner branch for type ${JSON.stringify(entry.type)} — the schema knows a type this planner does not` });
    }

    // Keys sitting in a Secret this estate declares, that no declaration claims.
    // Never deleted; only named, so an unexplained one is visible rather than
    // quietly load-bearing.
    if (existing !== null) {
      const declared = new Set(decl.keys.map((k) => k.key));
      for (const key of [...existing].sort()) {
        if (!declared.has(key)) unmanaged.push({ ...at, key, reason: 'present in the cluster but declared nowhere — left untouched' });
      }
    }
  }

  // Postgres DDL first: a connection string cannot be composed before the role
  // and database it names exist.
  steps.push(...ddl);

  for (const [target, keys] of writes) {
    const existing = state.secrets.get(target) ?? null;
    const [namespace, secretName] = splitTarget(target);

    if (existing === null) {
      steps.push({
        kind: 'create-secret',
        namespace,
        secretName,
        keys: keys.map((k) => ({ key: k.key, type: k.type, source: k.source })),
        detail: `create Secret ${target} with ${keys.length} key(s)`,
      });
      continue;
    }

    // THE invariant. One step per key, never a write of the whole Secret, and
    // each step names what it must not disturb — see the header.
    for (const k of keys) {
      steps.push({
        kind: 'patch-secret-key',
        namespace,
        secretName,
        key: k.key,
        type: k.type,
        source: k.source,
        preserves: [...existing].sort(),
        detail: `patch ${target}#${k.key}, preserving ${existing.size} existing key(s)`,
      });
    }
  }

  const plan = {
    steps,
    blocked,
    unknown,
    drift,
    unmanaged,
    noop,
    summary: {
      steps: steps.length,
      createSecret: steps.filter((s) => s.kind === 'create-secret').length,
      patchKey: steps.filter((s) => s.kind === 'patch-secret-key').length,
      createRole: steps.filter((s) => s.kind === 'create-role').length,
      createDatabase: steps.filter((s) => s.kind === 'create-database').length,
      blocked: blocked.length,
      unknown: unknown.length,
      drift: drift.length,
      unmanaged: unmanaged.length,
      noop: noop.length,
    },
  };

  assertNeverClobbers(plan, state);
  return plan;
}

function addWrite(writes, target, key) {
  if (!writes.has(target)) writes.set(target, []);
  writes.get(target).push(key);
}

// A Secret name may not contain a slash, so the first one always separates them.
function splitTarget(target) {
  const i = target.indexOf('/');
  return [target.slice(0, i), target.slice(i + 1)];
}

/**
 * The one property this whole slice exists to guarantee: no step ever writes a
 * Secret that already exists.
 *
 * This is checked rather than merely intended because the cost of getting it
 * wrong is silent and user-visible — four keys vanish from
 * `around-the-world-secrets` and every guest is signed out — while the code path
 * that would do it (a `create-secret` emitted for an existing target) looks
 * perfectly reasonable in a diff. A test can only cover the shapes it thought
 * of; this covers every plan ever produced, including by callers not yet
 * written.
 *
 * Exported because it is unreachable through planSecrets by construction, and a
 * guard that no test can execute is indistinguishable from one that does not
 * work. Its tests call it directly, with a plan hand-built to be wrong.
 */
export function assertNeverClobbers(plan, state) {
  for (const step of plan.steps) {
    if (step.kind !== 'create-secret') continue;
    const target = `${step.namespace}/${step.secretName}`;
    if (state.secrets.has(target)) {
      throw new Error(`planner bug: planned to create ${target}, which already exists with ${state.secrets.get(target).size} key(s) — that would delete every key not in this plan`);
    }
  }
}

function render(plan, { assumedEmpty }) {
  const out = [];
  const s = plan.summary;

  if (assumedEmpty) {
    out.push('⚠️  NO CLUSTER WAS INSPECTED. This is the plan for an empty estate — what a');
    out.push('    first provision would do. It is a hypothetical, not a statement about the');
    out.push('    live cluster, where most of these keys already exist.');
    out.push('');
  }

  const line = (icon, e) => `  ${icon} ${e.namespace}/${e.secretName}#${e.key}  ${e.reason ?? e.detail ?? ''}`;

  if (plan.steps.length) {
    out.push(`Would do (${plan.steps.length} step(s)):`);
    for (const step of plan.steps) out.push(`  → ${step.kind}: ${step.detail}`);
    out.push('');
  }
  if (plan.blocked.length) {
    out.push(`Blocked — needs a human (${plan.blocked.length}):`);
    for (const e of plan.blocked) out.push(line('🔴', e));
    out.push('');
  }
  if (plan.unknown.length) {
    out.push(`Could not decide — the observation did not cover it (${plan.unknown.length}):`);
    for (const e of plan.unknown) out.push(line('⚪', e));
    out.push('');
  }
  if (plan.drift.length) {
    out.push(`Present but inconsistent — reported, not acted on (${plan.drift.length}):`);
    for (const e of plan.drift) out.push(line('🟠', e));
    out.push('');
  }
  if (plan.unmanaged.length) {
    out.push(`In the cluster, declared nowhere — left alone (${plan.unmanaged.length}):`);
    for (const e of plan.unmanaged) out.push(line('🔵', e));
    out.push('');
  }

  out.push(`${s.steps} step(s): ${s.createSecret} create-secret, ${s.patchKey} patch-key, ${s.createRole} create-role, ${s.createDatabase} create-database`);
  out.push(`${s.noop} already present, ${s.blocked} blocked, ${s.unknown} undecidable, ${s.drift} drifted, ${s.unmanaged} unmanaged`);
  return out.join('\n');
}

// Standalone entry point. Exit 1 means a human is needed (blocked); exit 2 means
// the planner could not decide, which is deliberately NOT the same as "nothing
// to do" — an observation that failed to cover a namespace must not read as a
// clean run.
if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  const argv = process.argv.slice(2);
  const assumedEmpty = argv.includes('--assume-empty');
  const at = argv.indexOf('--observed');
  const observedFile = at === -1 ? null : argv[at + 1];
  const asJson = argv.includes('--json');

  if (assumedEmpty === (observedFile !== null)) {
    console.error('usage: plan-secrets.mjs (--assume-empty | --observed <file.json>) [--json]');
    console.error('  Exactly one. An observation is never assumed: an unlisted namespace means');
    console.error('  "I did not look", and planning a create from that is how a live Secret gets');
    console.error('  overwritten.');
    process.exit(2);
  }

  const { errors, declarations } = validateSecrets('secrets', 'config');
  if (errors.length) {
    console.error(`refusing to plan: ${errors.length} declaration problem(s) — run node scripts/validate-secrets.mjs`);
    process.exit(2);
  }

  const observed = assumedEmpty
    ? { namespaces: [...new Set(declarations.map((d) => d.namespace))], secrets: {}, postgres: { roles: [], databases: [] } }
    : JSON.parse(readFileSync(observedFile, 'utf8'));

  const plan = planSecrets(declarations, observed);
  console.log(asJson ? JSON.stringify(plan, null, 2) : render(plan, { assumedEmpty }));

  if (plan.unknown.length) process.exit(2);
  if (plan.blocked.length) process.exit(1);
}
