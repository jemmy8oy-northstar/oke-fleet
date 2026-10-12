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

## What acts on these

[secret-provisioner](https://github.com/jemmy8oy-northstar/secret-provisioner) reads
this directory on **`dev`**, so a declaration is provisioned before its app is released.
It is internal (no Ingress); reach it with a port-forward:

```sh
kubectl port-forward -n balenthiran svc/secret-provisioner-secret-provisioner 8080:80
curl localhost:8080/plan                   # what a reconcile would do; changes nothing
curl -X POST localhost:8080/reconcile      # does it; takes no body
```

It is create-only: an existing key is left alone, an existing Secret is only ever patched
one key at a time, and an existing Postgres role or database **blocks** with the human step
named, rather than being changed. The planner and its rules live in that repo, not here.

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
- **`kit`**. All three reasons this used to give are now false — the chart is merged on
  kit's `dev`, release is not parked, and `config/kit.json` registers it as of this
  commit. The real reason is narrower: Kit's one secret is `kit-auth/password`, a literal
  James chooses, and every `type` the validator accepts describes a resource the
  provisioner *creates* (a Postgres database and role). Whether a declaration may ask for
  a generated literal is unsettled — jemmy8oy-northstar/kit#46 is where the password was
  decided, and the provisioner's own shape is still open on #7. Until that resolves,
  `kit-auth` is created by hand:

  ```
  kubectl create secret generic kit-auth --from-literal=password=<the password> -n balenthiran
  ```

## The `postgres-db` names are intent, not a readback

For the apps that are already live, `database` and `role` say what a **fresh** provision
would create. They are not read back from the running cluster — the live connection
strings are in the cluster, this repo is public, and nothing here can see them. The
provisioner is create-only, so for those apps it will find every key already present
and plan no action; the names matter the first time an app is provisioned from scratch.
