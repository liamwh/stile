# stile (CLI)

Unprivileged CLI for the stile capability broker: request allowlisted
secret lifecycle operations (rotate, verify, reconcile, status, list,
provider-assisted import) and print structured reports. Never receives
secret material — there is deliberately no get/reveal/exec command.

- Repository, threat model and setup: https://github.com/liamwh/stile
- The privileged daemon is the separate `stile-brokerd` crate.

```console
stile list
stile rotate example-app/session-key
```
