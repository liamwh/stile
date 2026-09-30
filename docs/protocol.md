# Wire protocol

Transport between `stile` (unprivileged) and `stile-brokerd`
(privileged).

- Unix domain socket, default `/run/stile/sock`, mode `0660`, owner
  `root`, group the configured access group (`stile-access` in the
  examples). Its parent directory must be owned by the broker's euid
  and must not be world-writable; the broker refuses to start
  otherwise.
- Newline-delimited JSON, one frame per line, UTF-8.
- One request line in → one response line out. A connection may carry
  several request/response exchanges; the import flow is the single
  two-message exception.
- Request lines are capped at 64 KiB (1 MiB for the import value); the
  broker drops connections that stall past a read timeout
  (`STILE_TEST_REQUEST_TIMEOUT_SECS` overrides it in tests).

## Authentication

`SO_PEERCRED` at accept time yields the caller's uid/gid. Authorised
callers: uid 0, UIDs listed in `allowed_uids`, or users whose group
membership (primary or supplementary, resolved with `getgrouplist`)
contains the configured `access_group`. Everyone else receives an error
report immediately.

## Requests

Every request is `{"op": "<kebab-case>", ...}` with
`deny_unknown_fields` on every type. The complete allowlist:

| Frame | Fields | Meaning |
|---|---|---|
| `rotate` | `secret` | Generate, store, deploy, reload, verify |
| `verify` | `secret` | Re-run declared verification only |
| `reconcile` | `secret` | Repair stale consumers/reloads; never generates |
| `status` | `secret` | Registry metadata for one secret |
| `list` | — | All logical ids + policies |
| `import-provider-secret` | `secret` | Begin provider-assisted import (broker replies `ready-for-import`) |
| `import-value` | `value` | The only frame carrying secret bytes: client→broker, sent only after `ready-for-import`, never echoed |

Anything else — `get-secret`, `read_secret`, `export`, `decrypt`,
`exec`, unknown keys, wrong types, `null`, arrays — fails
deserialization and is rejected with an error report. There is no
versioning escape hatch and no `#[serde(flatten)]` smuggling.

Example:

```json
{"op":"rotate","secret":"example-app/session-key"}
```

## Responses

Either `{"type":"report", ...}` or `{"type":"ready-for-import"}`.

`report` fields: `status` (`success`|`error`), `operation`, `secret`,
`store_updated`, `runtime_updated`, `services_reloaded`,
`verification_passed`, `fingerprint_changed` (bool, opaque),
`old_credential_revoked` (bool), `stages` (ordered `stage`/`result`/
`detail` records), `message`. Booleans, identifiers and declared
URLs/paths only — the type cannot carry secret bytes.

Client-side errors are deliberately coarse (`stile-protocol`
`ProtocolError`); broker stderr is never forwarded verbatim.

## Import exchange

```text
client → {"op":"import-provider-secret","secret":"…"}
broker → {"type":"ready-for-import"}
client → {"op":"import-value","value":"…"}        # secret bytes, once
broker → {"type":"report", …}
```

The connection closes after one import. An `import-value` without a
pending import is rejected; an empty or whitespace-only value is
refused.

## Framing notes for implementors

- Responses are exactly one line; read until `\n`, not to EOF.
- The broker is single-threaded: requests are served strictly in
  connection order. Long operations (verification settle retries) delay
  later requests by design.
- Oversized frames receive one error report naming the size limit, then
  the connection is closed.
