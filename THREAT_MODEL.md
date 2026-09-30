# Threat model

This document describes what `stile` is designed to protect, against
whom, and — just as important — what it does not protect against. It is
implementation-specific: every claim below maps to code in this
repository.

## Assets

1. **Secret values**: the plaintext bytes of each logical secret, from
   their SOPS-encrypted store, through broker memory, into declared
   consumers.
2. **Credentials' authority**: the access those secrets grant on target
   services (e.g. a bearer token's rights on an internal API).
3. **Capability configuration**: the root-owned registry
   (`/etc/stile/registry.toml`) and daemon config
   (`/etc/stile/brokerd.toml`) — they define everything the broker may
   do. Compromise of these is compromise of the system.
4. **Integrity of the encrypted-at-rest property**: an interrupted
   rotation must never leave plaintext at the canonical store path.

## Trusted components

| Component | Runs as | Why trusted |
|---|---|---|
| `stile-brokerd` | root | Holds secret bytes by design; enforces the registry; systemd-hardened |
| `stile-core` (library inside the broker) | root | Same trust domain as the broker |
| SOPS + age identity (`/etc/stile/age.key`, `0400` root) | invoked by root | Decrypts/encrypts store files |
| The registry + daemon config | root-owned files | The complete declaration of allowed behaviour; only editable by root |
| Declared reload/check commands | declared users | Chosen by the registry author; run via `runuser` with a minimal environment |
| The kernel, systemd, and filesystem permissions | — | The boundary itself is Unix credentials and Unix sockets |

## Untrusted components

- **The calling process** — the AI agent, or any process running as a
  member of the `stile-access` group (or a UID on the allowlist). It
  controls every byte it sends: request ids, malformed frames, timing,
  connection counts, and (for provider-assisted imports) the value it
  submits.
- **The agent user's own account**: its files, environment, and
  transcripts are assumed readable by the attacker.
- Anything the agent can execute as itself (a compromised tool it runs).

## Trust boundaries

```text
┌─ untrusted ────────────────────────┐   ┌─ trusted (root) ─────────────────────┐
│  agent process                     │   │  stile-brokerd                        │
│    │                               │   │    ├── SOPS store + age key           │
│    └── stile CLI                   │   │    ├── declared consumers (files)     │
│          │  NDJSON over Unix socket│   │    ├── declared reloads (runuser)     │
│          ▼  0660 root:stile-access │──▶│    └── verification probes (curl)     │
│        (SO_PEERCRED at accept)     │   └──────────────────────────────────────┘
└────────────────────────────────────┘
```

The single crossing point is the Unix socket. Everything on the trusted
side is driven by the root-owned registry, never by request contents
beyond the logical secret id.

## Attacker capabilities (assumed)

- Full control of the client: arbitrary bytes on the socket, arbitrary
  timing, repeated connections, malformed and oversized frames.
- Membership in the access group (i.e. the ability to legitimately
  connect and authenticate).
- Ability to read its own process's environment, files, and responses.
- Ability to run code as the agent user, including planting files in
  directories that user can write to.
- Ability to observe success/failure and timing of its own operations.

## Attacker non-capabilities (relied upon)

- Cannot authenticate as root or a non-allowlisted UID/group.
- Cannot write to `/etc/stile/`, the SOPS repo, the broker's work/backup
  dirs, or the socket directory.
- Cannot read the broker's age identity or memory (`/proc` of a root
  process is root-only).
- Cannot modify the registry.

If any of these fail, the model has failed — see Non-goals.

## Security goals

1. **No raw-secret retrieval.** No request can ask for, and no response
   can carry, secret bytes. Enforced by the closed protocol types
   (`stile-protocol`: `deny_unknown_fields`, no value-returning variant,
   unknown ops fail deserialization; responses contain only booleans,
   stage names, ids and declared URLs/paths).
2. **Only declared capabilities.** The caller controls exactly one
   string: a logical secret id, matched against the registry. Commands,
   URLs, paths, users and modes all come from the root-owned registry.
   The protocol has no execution primitive.
3. **No credential redirection by the caller.** Verification URLs,
   reload commands and consumer paths are registry-declared. The caller
   cannot point a credential at an endpoint of their choosing.
4. **No side channels through errors or logs.** Subprocess stderr is
   sanitised and kept in the broker's journal (root-readable), never in
   client-visible reports or the audit log. Error text carries exit
   codes and declared identifiers only.
5. **Fail closed.** Interrupted rotations restore previous encrypted
   bytes; plaintext staging is refused at symlinked paths; unsafe socket
   directories abort startup; a live instance blocks a second broker.
6. **Auditable without disclosure.** Every operation records uid, gid,
   pid, operation, per-stage outcomes and duration — never values.

## Capability inventory (what an authorised caller can do)

| Operation | Capability granted | Secrets involved internally | Caller-controlled input | Caller receives | Exfiltration possible? |
|---|---|---|---|---|---|
| `rotate <id>` | Force a full rotation of one auto-policy secret | Reads old value (rollback/revocation check), generates new | the id | stage report (booleans) | No value-returning path; the caller can *destroy* the old value's usefulness (DoS) but not read it |
| `verify <id>` | Trigger a credential-bearing probe of declared endpoints | Decrypts current value | the id | pass/fail | The probe URL is registry-declared; the response is one bit per step. A caller cannot supply candidate values to test. |
| `reconcile <id>` | Repair stale consumers/reloads without generating | Decrypts current value | the id | stage report | As above |
| `status <id>` | Read registry metadata (policy, counts, human step) | None | the id | policy summary | Registry metadata is non-secret by declaration |
| `list` | Enumerate logical ids + policies | None | — | id/policy list | Reveals which secrets exist (acceptable: ids are declared non-secret) |
| `import-provider-secret <id>` | Supply a chosen value for a provider-assisted secret | Persists supplied value | the id + the value | success/failure | The caller *chooses* the new value — this is by design (a human pastes it). The OLD value is never returned. Abuse = installing a known value (equivalent authority to rotation, audited). |

**Composition analysis**: none of these operations returns bytes, and
their combination cannot: the only credential-bearing network traffic
goes to registry-declared URLs with registry-declared expectations, and
its result collapses to booleans. The one oracle — `old_expect_status`
revocation checks — probes with the *stored* old value, not with any
caller-supplied candidate, so it cannot be used to brute-force a secret.

## Non-goals / limitations

- **Root compromise or broker compromise** is game over: the broker is
  the component designed to hold secrets.
- **SOPS key compromise** (the age identity) exposes the store.
- **Malicious registry/config author**: whoever writes the root-owned
  registry defines the capabilities; a malicious author can declare a
  verification URL that echoes the bearer token (the broker would then
  hold it in curl's memory; it still would not return it to the
  caller, but the credential would be *sent* somewhere chosen by the
  registry).
- **Malicious kernel / hypervisor / ptrace of the broker**: out of scope.
- **Side channels**: timing, file metadata, `/proc` of the broker,
  CPU/memory signatures — not defended.
- **A capability's inherent authority**: rotation is a destructive
  operation; a caller with `rotate` can break a service's sessions at
  will. The audit trail records who.
- **Other hosts**: consumers on machines sharing the SOPS repo must
  pull + redeploy manually; stile does not distribute secrets.
- **Zeroisation**: secret buffers are ordinary Rust strings/vecs and are
  not scrubbed after use. Within the trusted broker this defends
  against nothing that is not already a full compromise; see *Future
  hardening*.
- **Availability**: the broker is single-threaded by design (this
  serialises rotations and prevents concurrent-rotation races). Read
  timeouts and line caps bound how long one client can stall it.

## Data flows

1. `rotate`: generate (broker RNG) → SOPS store update (encrypted) →
   pre-reload hooks (secret via stdin) → consumer files (`0600` staging,
   rename, declared owner/mode) → declared reloads (`runuser`, no
   secrets in argv/env) → probes (bearer via `0600` header file,
   unlinked immediately) → structured report + audit record.
2. `import-provider-secret`: client TTY (no echo) → one `ImportValue`
   frame over the socket → treated exactly like a generated value
   thereafter. The value appears in: the socket buffer, broker memory,
   the encrypted store, declared consumers — nowhere else by design.
3. Audit log: JSONL at `/var/lib/stile/audit/audit.log` — ids, stages,
   outcomes, uid/gid/pid, duration. Never values, never fingerprints
   (only a boolean "changed").

## Known risks (accepted, with rationale)

- **Single-threaded broker**: a long verification (settle retries,
  ~80 s) delays other requests. Accepted: availability risk, not
  confidentiality; concurrency would introduce rotation races.
- **Verification settle window**: a rotation whose service is slow to
  start reports an error while the credential is applied. The report
  says so; `verify` re-checks later.
- **Plaintext window at the canonical store path** during
  `sops encrypt --in-place` (file is `0600`, root-owned dir assumed).
  Required by SOPS path-relative creation rules; minimised, not zero.
- **The socket grants request authority to every group member**: group
  membership is the authorisation. Administer it accordingly.

## Security decisions (and where they live)

- Closed protocol types with `deny_unknown_fields`:
  `crates/stile-protocol/src/lib.rs`.
- Request line cap (64 KiB / 1 MiB import) and read timeouts:
  `crates/stile-brokerd/src/main.rs` (`read_capped_line`,
  `REQUEST_READ_TIMEOUT`).
- Socket dir safety (owner, no world-write, group-write only by own
  egid) and live-instance refusal: same file (`prepare_socket_dir`,
  `refuse_if_live_instance`).
- Symlink refusal + `0600` staging for consumer files: 
  `crates/stile-core/src/deploy.rs` (`deploy_consumer`).
- Mode tightened *before* plaintext staging + `O_NOFOLLOW` for the
  store: `crates/stile-core/src/sops.rs` (`write_value_atomic`).
- Bearer header file created `0600`/unique/unlinked:
  `crates/stile-core/src/verify.rs` (`probe`).
- Subprocess stderr confined to the broker journal:
  `deploy.rs`, `sops.rs`, `verify.rs` error paths.
- `SO_PEERCRED` + group/allowlist authorisation:
  `crates/stile-brokerd/src/config.rs` (`peer_allowed`, supplementary
  groups via `getgrouplist`).
- Secrets never in argv/env of children: stdin for psql; header file
  for curl; `SOPS_AGE_KEY` explicitly removed from the sops
  environment (`sops_base`).

## Future hardening (not yet done)

- Per-secret or per-operation authorisation (today the group grants all
  operations on all secrets).
- Zeroisation of secret buffers in the broker (meaningful only against
  a narrower attacker than the current model assumes).
- Rate limiting / lockout on repeated failing operations.
- A second store backend (e.g. Infisical) behind the existing
  `SecretStore` trait — explicitly out of scope for v0.1.
- External security review before any 1.0 claim.
