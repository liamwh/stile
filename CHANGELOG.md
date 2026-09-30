# Changelog

Notable changes to `stile`. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versioning
is semver-ish for a pre-1.0 project: breaking changes may land in minor
versions.

## [0.1.0] — unreleased

Initial public release.

- Capability-oriented secret broker: privileged `stile-brokerd` performs
  SOPS-backed secret lifecycle operations (rotate, verify, reconcile,
  status, list, provider-assisted import) on behalf of untrusted
  callers; the wire protocol cannot express a value-returning
  operation.
- Unix-socket boundary with `SO_PEERCRED` authentication; authorisation
  via root, UID allowlist, or access-group membership.
- Declarative root-owned registry driving stores, consumers, backends,
  pre-reload hooks (postgres role passwords), reloads and verification
  probes — no caller-controlled commands, URLs or paths.
- Atomic fail-closed SOPS writes with encrypted backups and rollback;
  unencrypted-store refusal guard.
- Non-disclosing audit trail (uid/gid/pid, stages, duration).
- Adversarial test suite: sentinel non-disclosure across responses,
  logs, argv and temp files; malformed/oversized/banned request
  rejection; symlink and unsafe-directory refusal.
