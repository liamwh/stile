# Submitting stile to nixpkgs

Two layers exist upstream and they intentionally ship separately:

- **the flake** (`../../flake.nix`): packages for both binaries, an
  overlay, the NixOS module (`nix/module.nix`) and checks including a
  VM test. This is the supported user-facing surface today and works
  with no nixpkgs inclusion.
- **nixpkgs**: contributes just the *package* initially. The NixOS
  module stays upstream until stile has real users depending on it
  (nixpkgs review friction for new service modules is high, and the
  module's `extraReadWritePaths`-style interface may still evolve
  before 1.0). Revisit once there is demand.

## Steps (package only)

1. Fork/clone nixpkgs; branch.
2. Add this file as `pkgs/by-name/st/stile/package.nix`
   (by-name needs no all-packages edit).
3. Copy the release's `Cargo.lock` next to it and fill the fetch hash:

   ```console
   $ curl -L -o Cargo.lock \
       https://github.com/liamwh/stile/raw/v<VERSION>/Cargo.lock
   $ nix-build -A stile   # first run reports the correct src hash; paste it
   ```

4. Bump `version`, `tag` and `hash` together on updates.
5. Register as a maintainer in `maintainers/maintainer-list.nix` and add
   your handle to `meta.maintainers`.
6. Verify with:

   ```console
   $ nix-build -A stile && ./result/bin/stile --version
   $ nix-shell -p nixpkgs-review --run "nixpkgs-review rev HEAD"
   ```

7. PR titled `stile: init at <VERSION>` against `NixOS/nixpkgs:master`.

## Module (later, optional)

When the module is ready to move, it imports almost verbatim: take
`nix/module.nix`, replace the store-path `ExecStart` config reference
with nixpkgs' `settingsFormat` (`pkgs.formats.toml`), keep the
`types.str` (never `types.path`) registry/age options so secret-bearing
files cannot leak into the store, and add a VM test derived from
`nix/test.nix`.
