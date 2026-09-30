# Contributing

Thanks for contributing to a small, security-sensitive project. Keep
changes boring, auditable and minimal.

## Development

```console
$ git clone https://github.com/liamwh/stile && cd stile
$ cargo fmt
$ cargo clippy --all-targets --all-features -- -D warnings
$ cargo test --all-features
```

For the full end-to-end suite (spawns the real broker against fake
`sops`/`curl`/`runuser`), build the binaries into the repo-local
target dir first — the tests locate them there deliberately, ignoring
any shared `CARGO_TARGET_DIR` cache:

```console
$ CARGO_TARGET_DIR=target cargo build --all-targets
$ CARGO_TARGET_DIR=target cargo build --release -p stile -p stile-brokerd
$ cargo nextest run
```

`nextest` runs each test in its own process, which the adversarial
suite relies on (several tests set process-wide env overrides for the
broker they spawn). If you must fall back to plain `cargo test`, pass
`-- --test-threads=1`. Set
`STILE_IT_KEEP=1` to preserve a failing fixture under `/tmp/stile-it-*`
for inspection.

## Review rules

- `unsafe` is `libc` FFI only; every block carries a `SAFETY` comment.
- No secret value may ever appear in: a child process's argv or
  environment, a client-visible response field, the audit log, or an
  error message forwarded to a caller.
- Anything crossing the socket belongs in `crates/stile-protocol` and
  must keep `deny_unknown_fields`.
- If your change touches the boundary (protocol, authorisation, file
  staging, subprocess spawning), say so explicitly in the PR and expect
  close review against [THREAT_MODEL.md](THREAT_MODEL.md).

## Designing a new capability

The core principle:

> **A capability should expose the narrowest operation necessary. It
> must not expose a lower-level primitive the caller can repurpose to
> redirect or reveal the credential.**

Concretely, when adding an operation:

1. **Name the operation, not a mechanism.** `rotate`, `reconcile`,
   `verify` — never `run`, `send`, `fetch`, or `read`. If the request
   would carry a URL, command, path, or transform chosen by the caller,
   it is wrong: those belong in the root-owned registry, where they are
   auditable and unforgeable by callers.
2. **Decide the response before the mechanism.** Responses carry
   booleans, stage names and identifiers. If you cannot describe the
   output without the words "value", "content", "body" or "payload",
   stop.
3. **Check composability.** Ask how a malicious authorised caller
   combines the new operation with the existing ones. Any construction
   that turns capabilities into an oracle for secret bytes (or a
   redirect for credential use) must be impossible, not merely
   discouraged.
4. **Audit it.** The operation must land in the audit trail with
   caller identity and duration, and add adversarial tests: malformed
   variants, oversized frames, sentinel non-disclosure across every
   observable channel.
5. **Fail closed.** Unrecoverable mid-operation state must restore
   previous state; ambiguous configuration must abort, not guess.

## Commit style

Imperative subject line, wrapped body; explain *why*, especially for
security-relevant changes. Reference the issue or incident where
applicable.
