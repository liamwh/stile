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
    in
    {
      packages = forAllSystems (
        pkgs:
        let
          stile = pkgs.rustPlatform.buildRustPackage {
            pname = "stile";
            inherit version;
            src = self;

            cargoLock.lockFile = ./Cargo.lock;

            # Virtual workspace: build every member, ship both binaries.
            cargoBuildFlags = [ "--workspace" ];

            # The full suite needs cargo-nextest and spawnable fake tools
            # at repo-local paths; CI covers it. Build only here.
            doCheck = false;

            postInstall = ''
              install -Dm755 target/release/stile-brokerd $out/bin/stile-brokerd
            '';

            meta = with pkgs.lib; {
              description = "Capability-oriented secret broker: lifecycle operations for untrusted callers, secret values stay behind the broker";
              homepage = "https://github.com/liamwh/stile";
              license = licenses.asl20;
              mainProgram = "stile";
              platforms = platforms.linux;
            };
          };
        in
        {
          inherit stile;
          stile-brokerd = stile;
          default = stile;
        }
      );

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
