# Secret declarations

What each app needs to exist before it can run. **No value is ever stored here** —
this repo is public, and the values live only in the cluster
(claude-code-bot#97: *"The secrets should live only in the cluster. Definitely not
in git."*).

One file per app. `scripts/validate-secrets.mjs` checks them, and CI already runs it
via `scripts/validate-config.mjs`, so a malformed declaration fails the pull request.

```json
{
  "app": "around-the-world",          // must match a config/*.json appName, if it has one
  "namespace": "balenthiran",         // must match that app's targetNamespace
  "secretName": "around-the-world-secrets",
  "keys": [
    { "key": "Jwt__Secret", "type": "random", "bytes": 32 }
  ]
}
```

`type` decides how the value comes to exist:

| type | what the provisioner does |
| --- | --- |
| `postgres-db` | generate a password, `CREATE ROLE` + `CREATE DATABASE … OWNER`, write the Npgsql connection string into this key. Needs `database` and `role`. |
| `random` | write `bytes` random bytes, hex-encoded — the same value `openssl rand -hex N` gives. Defaults to 32. |
| `external` | nobody can generate this one (a third-party API key). Assert it is present and say so loudly if it is not. |

## Seeing what would happen

`scripts/plan-secrets.mjs` turns declarations plus an observation of the cluster into
the list of actions a provisioner *would* take. It opens no socket — no Kubernetes
client, no Postgres client — so it is safe to run anywhere:

```sh
node scripts/plan-secrets.mjs --assume-empty          # what a first provision does
node scripts/plan-secrets.mjs --observed state.json   # what is left to do right now
```

Exit `0` clean, `1` something needs a human, `2` it could not decide — which is
deliberately not the same as "nothing to do".

An observation must **name the namespaces it enumerated**:

```json
{
  "namespaces": ["balenthiran"],
  "secrets": { "balenthiran/around-the-world-secrets": ["Jwt__Secret", "Admin__Key"] },
  "postgres": { "roles": ["aroundtheworld"], "databases": ["aroundtheworld"] }
}
```

That list is not bookkeeping. "This namespace holds no Secrets" and "I never listed
this namespace" arrive as the same empty object, and a failed lookup read as the first
would plan to *create* a Secret that already exists — which deletes every key not in
the plan. Anything outside `namespaces` is reported as undecidable instead. `postgres`
may be `null`, meaning the server was not inspected.

### What it refuses to do

Create-only, never delete, never overwrite — so:

- **An existing Secret is only ever patched, one key at a time.**
  `around-the-world-secrets` holds five keys; writing it whole to add one deletes
  `Jwt__Secret` and `Admin__Key`, so the symptom is every guest signed out mid-party
  rather than an error. This is asserted on every plan, not just tested.
- **An existing Postgres role blocks.** Its password is neither knowable nor ours to
  change, and an `ALTER ROLE` would break whatever authenticates with it now. There is
  no connection string that can honestly be composed, so it asks for a human.
- **An existing database whose role is missing blocks** — create-only cannot reassign
  an owner.
- **Keys in the cluster that no declaration claims are named, never removed.**

**These are not in `config/`, deliberately.** `apps-root/fleet-generator.yaml` globs
`config/*.json` as its Argo CD git generator, so every file in there *is* an
Application; a declaration living there would trip a sync on every edit. James asked
for the secret flow to stay decoupled from the Argo flow. The generator never looks
at `secrets/`.

## What is deliberately not declared

- **TLS secrets** (`balenthiran-tls`, `balenthiran-www-tls`). cert-manager creates and
  rotates these; asserting them here would go red for a minute every time a new
  certificate is issued.
- **`ocir-secret`** (the registry credential). Two apps share it, and a per-app file
  cannot express one secret owned by the estate rather than by an app — the validator
  rejects two declarations claiming one key, which is the right answer for app
  secrets and the wrong shape for this. Unresolved on purpose; see the pull request.
- **`holiday-planning`** and **`silverton-sweepstake`** have no app-level secrets at
  all, only the shared TLS certificate. There is nothing to declare.
- **`kit`**, because release is parked (kit#48). Its chart is on an unmerged branch
  and it has no fleet entry.

## The `postgres-db` names are intent, not a readback

For the apps that are already live, `database` and `role` say what a **fresh** provision
would create. They are not read back from the running cluster — the live connection
strings are in the cluster, this repo is public, and nothing here can see them. The
provisioner is create-only, so for those apps it will find every key already present
and plan no action; the names matter the first time an app is provisioned from scratch.
