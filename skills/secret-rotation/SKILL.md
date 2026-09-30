---
name: secret-rotation
description: Rotate, replace, or revoke credentials safely through the stile broker when a secret was leaked, exposed in a transcript, or needs scheduled rotation. Use when the user mentions rotating a secret, replacing a leaked credential or API key, revoking a key, regenerating a password or token, credential compromise, OAuth secret rotation, or a secret-exposure incident.
---

# Secret rotation via stile

Secrets are identified by **logical id only** (`stile list`). The
broker (`stile-brokerd`) is the only process that ever holds secret
bytes; the CLI cannot return them. Use it; do not work around it.

## Rules (hard)

1. Never request or attempt to print a secret's value. There is no
   command that can; do not try to make one (no `sops -d` into output,
   no `docker inspect`, no reading deployed secret files into context).
2. Never put a replacement value in argv, a file you echo, or a
   `docker exec -e` argument. That is the broker's job.
3. Treat any secret that appeared in a transcript, terminal, or log as
   burned: rotate it via the broker.
4. Never rotate an encryption-at-rest key (a data-encryption key or
   key-derivation salt): the broker refuses (`policy = forbidden`)
   because rotation would destroy persisted data. Escalate to the
   user instead.
5. If an operation would make a new credential appear in model context:
   stop and redesign the approach.

## Commands

```bash
stile list                            # logical ids + policies
stile status <id>                     # policy, consumers, verify steps, human_step
stile rotate <id>                     # generate → SOPS → deploy → reload → verify
stile verify <id>                     # re-run verification only
stile reconcile <id>                  # repair stale consumers without rotating
stile import-provider-secret <id>     # hidden prompt for provider-issued values
```

All commands accept `--socket <path>` (default `/run/stile/sock`).

`rotate` prints a JSON report: every stage must be `ok` and
`verification_passed: true`. If verification fails, run
`stile verify <id>` again after the service settles; if it still
fails, investigate the service health — do not rotate blindly again.

## Provider-assisted secrets (e.g. Google OAuth client secret)

`stile status <id>` shows the `human_step` (the console action the
user must perform). Flow: user resets the secret at the provider →
`stile import-provider-secret <id>` → paste at the hidden prompt.
The pasted value goes straight to the broker over the socket; never
echo, quote, or retype it into chat.

## After any rotation

- The SOPS store in your infrastructure repository is updated
  (encrypted bytes only); commit and push it, and tell the user which
  machines need `git pull` + redeploy (see the secret's consumers in
  the registry).
- Report only what the JSON report contains. Never speculate about
  values.

## Incident quick path

Exposure reported → `stile list` → identify ids → for each:
`status` (check policy) → `rotate` (auto) / `import-provider-secret`
(provider-assisted) / escalate (forbidden) → verify JSON stages →
report which succeeded, which need the user, and what must be
committed.

The broker and Unix permissions are the enforcement; this skill is
guidance. If `stile` cannot do what seems needed, that is the boundary
working as designed — say so instead of bypassing it.
