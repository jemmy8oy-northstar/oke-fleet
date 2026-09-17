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
