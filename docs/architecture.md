# Architecture

## Layers

```text
  agent / untrusted process (any user in stile-access)
        │
        ▼
  stile                  unprivileged CLI; no code path can receive a secret
        │  newline-delimited JSON over a Unix socket
        ▼
  stile-brokerd          privileged daemon (root); sole owner of secret bytes
        │
        ├─▶ SOPS encrypted store (age key 0400, root-only)
        ├─▶ declared consumer files (owner + mode enforced)
        ├─▶ declared reload commands (runuser, allowlisted)
        └─▶ verification probes (curl; registry-declared URLs)
```

| Crate | Links secret bytes? | Role |
|---|---|---|
| `stile` | never | Agent-facing CLI; prints structured reports only |
| `stile-protocol` | never (types forbid it) | Wire protocol between CLI and broker |
| `stile-brokerd` | yes | Privileged daemon; socket ownership, peer auth, dispatch |
| `stile-core` | yes (broker-side library) | Registry, generation, SOPS store, deploy, verify, audit |
| `stile-integration` | test sentinels only | End-to-end + adversarial tests against fakes |

## Enforcement, in one page

The property "the agent can request that a secret change but can never
read it" is enforced three times over:

1. **Protocol** (`stile-protocol`): there is no `get`/`read`/`export`
   variant; every type uses `deny_unknown_fields`; responses carry only
   booleans, stage names, ids and declared identifiers. Unknown
   operations fail deserialization. Adding a value-returning variant is
   a deliberate security-review event.
2. **Operating system**: the agent user has no age identity able to
   decrypt the stores; the socket is `0660 root:stile-access`, so group
   membership grants *request* rights, nothing more; the broker's
   work/backup dirs and audit log are root-only.
3. **Broker scope**: the only commands ever executed, URLs ever probed,
   and files ever written are declared in the root-owned registry.
   The protocol has no execution primitive; request content beyond the
   logical id never reaches a command line.

## Peer authentication and authorisation

- `SO_PEERCRED` at accept yields the caller's uid/gid/pid.
- Allowed: uid 0; UIDs in `allowed_uids`; any user whose group
  membership (primary or supplementary, via `getgrouplist`) contains the
  configured `access_group`.
- Authorisation failures receive an error report and are not audited as
  operations (nothing ran).

## SOPS store sequence (`write_value_atomic`)

1. `ensure_encrypted` — refuse and alarm if the store path does not look
   encrypted (guards against an interrupted earlier rotation).
2. Back up the current encrypted file to the broker-private backup dir
   (`0400`, last 5 kept).
3. Stage the new plaintext **at the canonical path** (SOPS creation
   rules are path-relative) with mode tightened to `0600` *before* any
   byte is written, and `O_NOFOLLOW` refusing a planted symlink.
4. `sops encrypt --in-place`, stdout/stderr captured.
5. Decrypt-verify the stored value matches, restore the tracked file's
   original mode and owner.
6. Any failure restores the backup byte-for-byte (fail closed).

The value is never in child argv, child environment (`SOPS_AGE_KEY` is
explicitly removed), or a world-readable file. There is a short window
where the canonical path holds plaintext at `0600` root-owned — this is
inherent to in-place SOPS encryption and documented in
[THREAT_MODEL.md](../THREAT_MODEL.md).

## Consumer deployment (`deploy_consumer`)

- Stages into a uniquely-named sibling file created `O_EXCL | O_NOFOLLOW`
  at mode `0600` (never predictable, never world-readable, never
  symlink-following).
- `fsync`, `rename` over the target, then apply the declared owner and
  mode. Rollback on any failure.

## Audit trail

JSONL, one record per operation: timestamp, operation, logical id,
caller uid/gid/pid, result, per-stage outcomes, duration in
milliseconds. No values, no fingerprints (a boolean `changed` flag at
most). Location is configured in `brokerd.toml`
(`/var/lib/stile/audit/audit.log` in the example unit).
