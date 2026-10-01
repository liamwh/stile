{
  lib,
  rustPlatform,
  fetchFromGitHub,
}:
rustPlatform.buildRustPackage {
  pname = "stile";
  version = "0.1.0";

  src = fetchFromGitHub {
    owner = "liamwh";
    repo = "stile";
    tag = "v${version}";
    hash = "";
  };

  cargoLock.lockFile = ./Cargo.lock;

  # Virtual workspace: build every member, ship both binaries.
  cargoBuildFlags = [ "--workspace" ];

  # The full suite needs cargo-nextest plus spawnable fake tools at
  # repo-local paths; upstream CI covers it.
  doCheck = false;

  # cargoBuildHook builds with an explicit --target, so binaries land
  # in target/<triple>/release, not target/release.
  postInstall = ''
    for f in stile stile-brokerd; do
      bin="$(find target -type f -executable -name "$f" -path '*/release/*' ! -path '*/deps/*' | head -n1)"
      install -Dm755 "$bin" "$out/bin/$f"
    done
  '';

  meta = {
    description = "Capability-oriented secret broker: lifecycle operations for untrusted callers, secret values stay behind the broker";
    homepage = "https://github.com/liamwh/stile";
    changelog = "https://github.com/liamwh/stile/blob/main/CHANGELOG.md";
    license = lib.licenses.asl20;
    mainProgram = "stile";
    platforms = lib.platforms.linux;
    maintainers = [ ];
  };
}
