# Submitting stile to nixpkgs

The repository ships a [flake](../../flake.nix) (`nix profile install
github:liamwh/stile`), which works today. Shipping in nixpkgs itself
additionally gives stile to every NixOS user and enables it inside NixOS
configurations directly. This directory holds the package expression
ready to submit.

## Steps

1. Fork/clone nixpkgs, create a branch.
2. Add this file as `pkgs/by-name/st/stile/package.nix`
   (the by-name scheme needs no all-packages edit).
3. In that directory, copy `Cargo.lock` next to `package.nix`
   (`src = lib.cleanSource ./.` + `cargoLock.lockFile` expect the lock
   from the same release tag):

   ```console
   $ curl -LO https://github.com/liamwh/stile/raw/v0.1.0/Cargo.lock
   ```

   and adjust `src` to the release tarball instead:

   ```nix
   src = fetchFromGitHub {
     owner = "liamwh";
     repo = "stile";
     tag = "v${version}";
     hash = ""; # let nix fill this in on the first build
   };
   ```

4. Build and test:

   ```console
   $ nix-build -A stile
   $ ./result/bin/stile --version
   ```

5. Add yourself (or leave empty initially) to `meta.maintainers` with
   your `lib.maintainers` handle after registering in
   `maintainers/maintainer-list.nix`.
6. Open a PR titled `stile: init at 0.1.0` against
   `NixOS/nixpkgs:master`, mentioning `meta.mainProgram` is set. Nixpkgs
   review generally asks for `nixpkgs-review` output — run:

   ```console
   $ nix-shell -p nixpkgs-review --run "nixpkgs-review rev HEAD"
   ```

After merge, updates ride the normal ofBorg/r-ryantm automation keyed
off the GitHub releases.
