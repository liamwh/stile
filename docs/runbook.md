# Runbook

Operational procedures for a `stile` deployment. All examples use the
synthetic `example-app/session-key` id.

## Credential exposure incident

1. **Treat the value as burned.** Do not paste it into chat, tickets or
   logs while reporting. If it appeared in an agent transcript, a
   terminal, or any file the agent user can read, rotate.
2. **Identify the logical secret:**

   ```console
   $ stile list
   $ stile status example-app/session-key
   ```

3. **Rotate according to policy:**
   - `auto` → `stile rotate <id>`; require every stage `ok` and
     `verification_passed: true`.
   - `provider-assisted` → follow the `human_step` shown by `status`
     (reset at the provider's console), then
     `stile import-provider-secret <id>` and paste at the hidden prompt.
   - `forbidden` → **stop**. These are typically data-encryption keys
     whose rotation destroys persisted data; escalate to the human
     owner. The broker refuses; that is the boundary working.
4. **Verification failed but stages applied?** Services can lag after a
   recreate. Re-run `stile verify <id>` after the service settles; if
   it still fails, investigate service health — do not rotate blindly.
5. **Check other machines.** Consumers on other hosts that decrypt the
   same SOPS file need `git pull` + redeploy; the broker only repairs
   what its registry declares locally.
6. **Review the audit trail** (`/var/lib/stile/audit/audit.log`):
   which uid/pid requested what, when, and each stage outcome.
7. **Commit the store.** The SOPS repo now holds new encrypted bytes;
   commit and push it like any other infrastructure change.

## Broker operations

- Service: `systemctl status stile-brokerd` (journald carries the
  broker's own diagnostics, including sanitised subprocess stderr).
- The broker refuses to start if: the socket directory is unsafe
  (world-writable / wrong owner), or another broker is already serving
  the socket.
- A second instance on the same socket path exits with an error rather
  than silently splitting requests.
- Restarting the broker never touches stored values; interrupted
  rotations restore previous encrypted bytes automatically, and a
  store file that does not look encrypted trips the refusal guard
  (`UNENCRYPTED … refusing`) — restore from the encrypted backups in
  `/var/lib/stile/backup/` if that ever fires.

## Backups

- Encrypted pre-rotation snapshots: `/var/lib/stile/backup/` (`0400`,
  last 5 per store file).
- The ultimate backup is the SOPS repository itself (git history).

## Adding a secret

1. Add the encrypted value to the SOPS repo (create a store file
   covered by a `.sops.yaml` creation rule using the broker's age
   recipient).
2. Declare the `[[secret]]` in the registry (see
   [examples/registry.toml](../examples/registry.toml)); install it
   root-owned to `/etc/stile/registry.toml`.
3. `stile status <new-id>` to confirm the declaration parses; `stile
   verify <new-id>` to check the current value works end-to-end.
