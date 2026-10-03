#!/usr/bin/env node
// Validates secrets/*.json — the declarations that the secret/database
// provisioner acts on (claude-code-bot#97, tracked here as #7).
//
// WHY THESE ARE NOT IN config/
// apps-root/fleet-generator.yaml globs `config/*.json` as its Argo CD git
// generator, so every file in there IS an Application. James asked to keep the
// secret flow decoupled from the Argo flow; a declaration living in config/
// would re-template an Application and trip a sync on every edit to it. The
// generator never looks at secrets/, so adding a database declaration causes no
// sync at all. That decoupling is the whole reason for the separate directory —
// do not "tidy" these files back into config/.
//
// WHY THIS IS CALLED FROM validate-config.mjs RATHER THAN ITS OWN CI STEP
// .github/workflows/ci.yml already runs `node scripts/validate-config.mjs`, and
// a workflow edit is James's call under his #83 rule. Hanging this off the
// existing entry point gates it in CI while needing no workflow change at all.
//
// A DECLARATION CONTAINS NO SECRET VALUE, EVER. It states intent — which
// namespace, which Secret, which key, and how the value should come to exist.
// This repo is public; the values only ever live in the cluster, which is
// James's ruling on claude-code-bot#97: "The secrets should live only in the
// cluster. Definitely not in git."
//
// Run standalone with: node scripts/validate-secrets.mjs [secretsDir] [configDir]
import { readdirSync, readFileSync, existsSync } from 'node:fs';
import { join, basename } from 'node:path';

// How a value comes to exist. James's primitive on claude-code-bot#97: "Maybe
// this config defines a namespace a secret name and type. Type can determine
// how it is generated."
//
// `extra` lists the fields that type alone may carry. Anything else on an entry
// is an error rather than a note: a mistyped `databse` would otherwise read as
// "field absent", and on a create-only provisioner that means it silently does
// nothing instead of failing.
export const TYPES = {
  // Generate a password, CREATE ROLE + CREATE DATABASE ... OWNER, then write the
  // composed Npgsql connection string into this one key.
  'postgres-db': { extra: { database: 'required', role: 'required' } },
  // Generate `bytes` random bytes and write them into this one key, HEX-ENCODED
  // — so 32 bytes is the 64-character value `openssl rand -hex 32` produces.
  // The encoding is fixed rather than declarable because every runbook in this
  // estate already says `openssl rand -hex N`; a `random` that sometimes meant
  // base64 would silently change the shape of a value an app already parses.
  random: { extra: { bytes: 'optional' } },
  // Assert the key is already present and fail loudly if it is not. Nobody can
  // generate an OCI Object Storage credential; it can only be checked for.
  // Today a missing one surfaces as CreateContainerConfigError minutes after
  // the pod starts, which is a slow way to learn it.
  external: { extra: {} },
};

const DEFAULT_RANDOM_BYTES = 32;
const MIN_RANDOM_BYTES = 16;
const MAX_RANDOM_BYTES = 256;

// RFC 1123 label — what Kubernetes requires of a namespace.
const isNamespace = (s) => /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/.test(s) && s.length <= 63;
// RFC 1123 subdomain — what Kubernetes requires of a Secret name (dots allowed).
const isSecretName = (s) => /^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$/.test(s) && s.length <= 253;
// Keys inside a Secret follow a different rule from the Secret's own name:
// underscores and capitals are legal. `ConnectionStrings__DefaultConnection` is
// a real key in this estate, and it would fail a name check applied by mistake.
const isSecretKey = (s) => /^[-._a-zA-Z0-9]+$/.test(s) && s.length <= 253;
// A Postgres identifier that is safe to interpolate unquoted into DDL.
// CREATE DATABASE cannot take a bind parameter, so the provisioner must build
// that statement as text — this check is the injection guard, and it is the
// reason database/role are restricted far more tightly than Postgres itself
// would restrict them.
const isPgIdentifier = (s) => /^[a-z_][a-z0-9_]*$/.test(s) && Buffer.byteLength(s) <= 63;

const quote = (v) => JSON.stringify(v);

/**
 * Validate every declaration in `secretsDir`.
 *
 * Pure apart from reading the two directories: it returns problems rather than
 * printing or exiting, so it can be unit-tested and so validate-config.mjs can
 * merge its findings into one report.
 *
 * @returns {{errors: string[], notes: string[], declarations: object[]}}
 */
export function validateSecrets(secretsDir = 'secrets', configDir = 'config') {
  const errors = [];
  const notes = [];
  const declarations = [];

  if (!existsSync(secretsDir)) {
    // Not an error. A branch that predates this directory still validates, and
    // an estate that declares nothing is a legitimate (if temporary) state.
    notes.push(`${secretsDir}/: no declarations directory — nothing to provision`);
    return { errors, notes, declarations };
  }

  // appName -> targetNamespace, read from the fleet config. Two uses, and they
  // differ in severity: an app that is absent from the fleet is a note (Kit has
  // a chart and a secret but deliberately no fleet entry yet), whereas an app
  // that IS in the fleet and declares a different namespace is an error — a
  // secretKeyRef only ever resolves in the pod's own namespace, so that Secret
  // could never be read by the app it is for, however correct it looks.
  const fleetApps = new Map();
  if (existsSync(configDir)) {
    for (const file of readdirSync(configDir).filter((f) => f.endsWith('.json'))) {
      try {
        const parsed = JSON.parse(readFileSync(join(configDir, file), 'utf8'));
        if (parsed && typeof parsed.appName === 'string') fleetApps.set(parsed.appName, parsed.targetNamespace);
      } catch {
        // validate-config.mjs owns reporting malformed fleet config; reporting
        // the same broken file twice would just make one problem look like two.
      }
    }
  }

  const seenApp = new Map();
  // (namespace, secretName, key) -> path. Two declarations writing one key is
  // the collision that matters: both would "succeed" and the last writer wins.
  const seenTarget = new Map();
  // Postgres identifiers are estate-wide, not per-declaration: one server, one
  // shared `pg-postgresql`. Two declarations naming one role is the nastiest
  // shape a create-only provisioner has, because it fails SILENTLY and LATE —
  // the role already exists, so creation is skipped, so the freshly generated
  // password is never applied to it, and the second app ships a connection
  // string that simply does not authenticate. A duplicate database is the same
  // story one step along: the second app's role owns nothing in it.
  const seenPg = { database: new Map(), role: new Map() };

  const files = readdirSync(secretsDir).filter((f) => f.endsWith('.json')).sort();

  for (const file of files) {
    const path = join(secretsDir, file);
    let decl;

    try {
      decl = JSON.parse(readFileSync(path, 'utf8'));
    } catch (e) {
      errors.push(`${path}: not valid JSON — ${e.message}`);
      continue;
    }

    if (decl === null || typeof decl !== 'object' || Array.isArray(decl)) {
      errors.push(`${path}: must be a JSON object`);
      continue;
    }

    const unknownTop = Object.keys(decl).filter((k) => !['app', 'namespace', 'secretName', 'keys'].includes(k));
    if (unknownTop.length) {
      errors.push(`${path}: unknown field(s) ${unknownTop.join(', ')} — allowed: app, namespace, secretName, keys`);
    }

    const { app, namespace, secretName } = decl;

    if (typeof app !== 'string' || app.trim() === '') {
      errors.push(`${path}: "app" must be a non-empty string (got ${quote(app)})`);
    } else {
      if (seenApp.has(app)) errors.push(`${path}: duplicate app ${quote(app)} — also declared in ${seenApp.get(app)}`);
      else seenApp.set(app, path);

      if (basename(file, '.json') !== app) {
        notes.push(`${path}: file is named for ${quote(basename(file, '.json'))} but declares app ${quote(app)}`);
      }
      if (fleetApps.size > 0 && !fleetApps.has(app)) {
        notes.push(`${path}: app ${quote(app)} has no ${configDir}/*.json entry — fine if it is not in the fleet yet`);
      }

      // The error half of the two uses described above. A secretKeyRef resolves
      // only within the pod's own namespace, so a Secret provisioned into a
      // different one can never be read by the app it names — it would simply
      // sit there while the pod stays in CreateContainerConfigError. Only
      // compare when the fleet actually states a namespace; a fleet entry
      // missing `targetNamespace` is validate-config.mjs's error to report, and
      // reporting it here too would make one problem look like two.
      const fleetNamespace = fleetApps.get(app);
      if (typeof fleetNamespace === 'string' && fleetNamespace !== '' && fleetNamespace !== namespace) {
        errors.push(
          `${path}: namespace ${quote(namespace)} but the fleet deploys ${quote(app)} into ${quote(fleetNamespace)} — a secretKeyRef only resolves in the pod's own namespace, so this Secret could never be read`,
        );
      }
    }

    if (typeof namespace !== 'string' || !isNamespace(namespace)) {
      errors.push(`${path}: "namespace" must be a lowercase DNS label (got ${quote(namespace)})`);
    }

    if (typeof secretName !== 'string' || !isSecretName(secretName)) {
      errors.push(`${path}: "secretName" must be a lowercase DNS subdomain (got ${quote(secretName)})`);
    }

    if (!Array.isArray(decl.keys) || decl.keys.length === 0) {
      errors.push(`${path}: "keys" must be a non-empty array`);
      continue;
    }

    const seenKey = new Set();

    decl.keys.forEach((entry, i) => {
      const at = `${path}: keys[${i}]`;

      if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) {
        errors.push(`${at}: must be an object`);
        return;
      }

      const { key, type } = entry;

      if (typeof key !== 'string' || !isSecretKey(key)) {
        errors.push(`${at}: "key" must match [-._a-zA-Z0-9]+ (got ${quote(key)})`);
      } else if (seenKey.has(key)) {
        errors.push(`${at}: duplicate key ${quote(key)} in this declaration`);
      } else {
        seenKey.add(key);
        if (typeof namespace === 'string' && typeof secretName === 'string') {
          const target = `${namespace}/${secretName}#${key}`;
          if (seenTarget.has(target)) {
            errors.push(`${at}: ${target} is already declared in ${seenTarget.get(target)} — two declarations would fight over one key`);
          } else {
            seenTarget.set(target, path);
          }
        }
      }

      if (typeof type !== 'string' || !Object.hasOwn(TYPES, type)) {
        errors.push(`${at}: "type" must be one of ${Object.keys(TYPES).join(', ')} (got ${quote(type)})`);
        return;
      }

      const spec = TYPES[type];
      const allowed = ['key', 'type', ...Object.keys(spec.extra)];
      const unknown = Object.keys(entry).filter((k) => !allowed.includes(k));
      if (unknown.length) {
        errors.push(`${at}: type ${quote(type)} does not take ${unknown.join(', ')} — allowed: ${allowed.join(', ')}`);
      }

      for (const [field, need] of Object.entries(spec.extra)) {
        if (need === 'required' && !Object.hasOwn(entry, field)) {
          errors.push(`${at}: type ${quote(type)} requires "${field}"`);
        }
      }

      if (type === 'postgres-db') {
        for (const field of ['database', 'role']) {
          const value = entry[field];
          if (value === undefined) continue;
          if (typeof value !== 'string' || !isPgIdentifier(value)) {
            errors.push(`${at}: "${field}" must be a lowercase Postgres identifier — [a-z_][a-z0-9_]*, max 63 bytes (got ${quote(value)})`);
            continue;
          }
          const claimed = seenPg[field];
          if (claimed.has(value)) {
            errors.push(`${at}: ${field} ${quote(value)} is already claimed by ${claimed.get(value)} — create-only means the second one is skipped, not merged, so its generated password would never be applied`);
          } else {
            claimed.set(value, path);
          }
        }
      }

      if (type === 'random' && Object.hasOwn(entry, 'bytes')) {
        const { bytes } = entry;
        if (!Number.isInteger(bytes) || bytes < MIN_RANDOM_BYTES || bytes > MAX_RANDOM_BYTES) {
          errors.push(`${at}: "bytes" must be an integer between ${MIN_RANDOM_BYTES} and ${MAX_RANDOM_BYTES} (got ${quote(bytes)})`);
        }
      }
    });

    declarations.push(decl);
  }

  return { errors, notes, declarations };
}

export { DEFAULT_RANDOM_BYTES, MIN_RANDOM_BYTES, MAX_RANDOM_BYTES };

// Standalone entry point. validate-config.mjs is what CI runs; this exists so a
// human can check one directory without the fleet config in the way.
if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  const { errors, notes, declarations } = validateSecrets(process.argv[2] ?? 'secrets', process.argv[3] ?? 'config');
  for (const n of notes) console.log(`note: ${n}`);
  if (errors.length) {
    console.error(`\n${errors.length} problem(s):`);
    for (const e of errors) console.error(`  ✗ ${e}`);
    process.exit(1);
  }
  const keyCount = declarations.reduce((n, d) => n + (Array.isArray(d.keys) ? d.keys.length : 0), 0);
  console.log(`✓ ${declarations.length} secret declaration(s) valid, ${keyCount} key(s)`);
}
