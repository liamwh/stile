{
  description = "stile — capability-oriented secret broker (rotate, verify, reconcile, status, list, provider-assisted import) with no operation that returns secret material";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems =
        f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
      version = (builtins.fromTOML (builtins.readFile ./Cargo.toml)).workspace.package.version;
      stilePackage =
        pkgs:
        pkgs.rustPlatform.buildRustPackage {
          pname = "stile";
          inherit version;
          src = self;

          cargoLock.lockFile = ./Cargo.lock;

          # Virtual workspace: build every member, ship both binaries.
          cargoBuildFlags = [ "--workspace" ];

          # The full suite needs cargo-nextest and spawnable fake tools
          # at repo-local paths; CI covers it. Build only here.
          doCheck = false;

          # cargoBuildHook builds with an explicit --target, so binaries
          # land in target/<triple>/release, not target/release.
          postInstall = ''
            for f in stile stile-brokerd; do
              bin="$(find target -type f -executable -name "$f" -path '*/release/*' ! -path '*/deps/*' | head -n1)"
              install -Dm755 "$bin" "$out/bin/$f"
            done
          '';

          meta = with pkgs.lib; {
            description = "Capability-oriented secret broker: lifecycle operations for untrusted callers, secret values stay behind the broker";
            homepage = "https://github.com/liamwh/stile";
            changelog = "https://github.com/liamwh/stile/blob/main/CHANGELOG.md";
            license = licenses.asl20;
            mainProgram = "stile";
            platforms = platforms.linux;
          };
        };
    in
    {
      packages = forAllSystems (
        pkgs:
        let
          stile = stilePackage pkgs;
        in
        {
          inherit stile;
          stile-brokerd = stile;
          default = stile;
        }
      );

      # So `pkgs.stile` exists for hosts importing nixosModules.stile
      # without setting services.stile.package themselves.
      overlays.default = final: prev: { stile = stilePackage final; };

      nixosModules = {
        stile = import ./nix/module.nix;
        default = self.nixosModules.stile;
      };

      checks = forAllSystems (pkgs: {
        stile = self.packages.${pkgs.system}.stile;
        module-eval =
          (nixpkgs.lib.nixosSystem {
            system = pkgs.system;
            modules = [
              self.nixosModules.stile
              {
                fileSystems."/" = {
                  device = "tmpfs";
                  fsType = "tmpfs";
                };
                boot.loader.grub.device = "nodev";
                services.stile = {
                  enable = true;
                  package = self.packages.${pkgs.system}.stile;
                };
              }
            ];
          }).config.system.build.toplevel;
        module-vm-test = import ./nix/test.nix { inherit pkgs self; };
      });

      apps = forAllSystems (pkgs: {
        stile = {
          type = "app";
          program = "${self.packages.${pkgs.system}.stile}/bin/stile";
        };
        default = self.apps.${pkgs.system}.stile;
      });

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = with pkgs; [
            cargo
            rustc
            rustfmt
            clippy
            cargo-nextest
            ripsecrets
          ];
        };
      });
    };
}
