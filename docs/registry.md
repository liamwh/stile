# Registry reference

The registry is a TOML file, version-controlled in your infrastructure
repository and installed root-owned at `/etc/stile/registry.toml`. It
is re-read for every request. The broker refuses operations on
identifiers not present here and refuses any command, URL, path, user
or mode not declared here. All values below are synthetic.

## Top level

| Key | Type | Meaning |
|---|---|---|
| `version` | int | Must be `1` |
| `repo_root` | path | Absolute path of the SOPS repository root. Creation rules in `.sops.yaml` are path-relative, so encryption happens at the canonical path. |

## `[[secret]]`

| Key | Type | Notes |
|---|---|---|
| `id` | string | `namespace/name`; unique; used verbatim in reports |
| `store` | table | Where the encrypted value lives (below) |
| `generation` | table? | Required for `policy = "auto"` |
| `consumers` | array | Runtime files to update |
| `backends` | array | Mutually exclusive runtime alternatives (see below) |
| `pre_reload` | array | Privileged hooks (e.g. database passwords) |
| `reload` | array | Commands to run after consumers are updated |
| `checks` | array | End-to-end consumer health checks + optional reloads |
| `verify` | array | Post-rotation verification steps |
| `policy` | string | `auto` \| `provider-assisted` \| `manual` \| `forbidden` |
| `reason` | string? | Shown by `stile status`; never contains values |
| `human_step` | string? | Required for `provider-assisted`: the console action a human performs |

### `[secret.store]`

| Key | Meaning |
|---|---|
| `file` | Path relative to `repo_root`; must match a SOPS creation rule |
| `type` | `dotenv` (a key within the file) or `binary` (whole file is the value) |
| `key` | Required for `dotenv` |

### `[secret.generation]`

`type` = `hex` (2 chars/byte) or `urlsafe` (base64url); `bytes` =
entropy input length (≥ 16 enforced).

### `[[secret.consumers]]`

| Key | Meaning |
|---|---|
| `type` | `dotenv-file` (update one key) or `raw-file` (replace the file) |
| `path` | Absolute path of the deployed runtime file |
| `key` | For `dotenv-file` |
| `owner` | Unix user the deployed file is chowned to |
| `mode` | Octal as a TOML integer, e.g. `256` for `0o400` |

### `[[secret.pre_reload]]`

| Key | Meaning |
|---|---|
| `type` | `postgres-role-password` (only kind today) |
| `container` | Docker container running postgres |
| `role` | Role whose password is set |

The SQL is piped via stdin to `psql` inside the container as the
container's postgres OS user — the secret never appears in argv.

### `[[secret.reload]]` and check/backend commands

| Key | Meaning |
|---|---|
| `type` | `run-command` (only kind today) |
| `user` | User the command runs as (via `runuser`) |
| `command` | Absolute executable path |
| `args` | Literal arguments; must never contain secret material |

Commands run with a minimal environment (`HOME`, `USER`, `LOGNAME`,
`PATH`, plus `XDG_RUNTIME_DIR`/`DBUS_SESSION_BUS_ADDRESS` for UID ≥
1000 so `systemctl --user` works).

### `[[secret.backends]]`

Mutually exclusive runtime alternatives (e.g. two inference servers,
one active at a time). `active` is a declared command whose exit status
selects the backend; exactly one must be active for backend-aware
operations.

| Key | Meaning |
|---|---|
| `id` | Stable non-secret identifier |
| `consumes_secret` | Whether this backend uses this secret (default true) |
| `active` | Selection command (`run-command` table) |
| `reload` | Minimal reload to ingest the current secret (required if consuming) |
| `verify` | Credential-aware check (`bearer-probe`, required if consuming) |

### `[[secret.checks]]`

`id` + `command` (zero exit = healthy) + optional `reload`.

### `[[secret.verify]]`

| Key | Meaning |
|---|---|
| `type` | `http-status` (no credential) or `bearer-probe` |
| `url` | URL to GET — registry-declared, never caller-supplied |
| `expect_status` | Status the (new) credential must produce |
| `old_expect_status` | If set, the old credential must produce this (revocation check) |

Bearer credentials are attached via a `0600` header file in the
broker's private work dir, unlinked immediately; never argv.

## Full synthetic example

See [examples/registry.toml](../examples/registry.toml).

## Validation performed at load

- `version` must be 1; ids unique and `namespace/name`-shaped.
- `dotenv` stores declare a `key`.
- `auto` policy declares `generation`; `provider-assisted` declares
  `human_step`.
- Secret-consuming backends declare both `reload` and a `bearer-probe`
  verify; non-consuming backends declare neither.
- Check ids are unique per secret.
