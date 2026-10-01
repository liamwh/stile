# NixOS module for the stile capability broker.
#
# Threat-model notes for reviewers:
# - The generated brokerd.toml contains ONLY paths, the access-group
#   name and tool locations — no secret material — so placing it in the
#   (world-readable) Nix store is safe.
# - registryFile and ageKeyFile are deliberately `types.str`, NOT
#   `types.path`: interpolating a Nix *path* value would copy that file
#   into the world-readable store. Point them at root-owned runtime
#   locations (/etc/stile/... or a secrets-manager mount). Provisioning
#   the registry and the age identity is the administrator's job.
# - The module never generates keys and never writes registry content.
{
  config,
  lib,
  pkgs,
  ...
}:

with lib;

let
  cfg = config.services.stile;

  # Non-secret configuration only (paths, group name, tool location).
  brokerdToml = (pkgs.formats.toml { }).generate "stile-brokerd.toml" {
    socket_path = cfg.socketPath;
    registry_path = cfg.registryFile;
    audit_path = "${cfg.stateDir}/audit/audit.log";
    work_dir = "${cfg.stateDir}/work";
    backup_dir = "${cfg.stateDir}/backup";
    sops_bin = "${cfg.sopsPackage}/bin/sops";
    age_key_file = cfg.ageKeyFile;
    access_group = cfg.accessGroup;
    allowed_uids = [ ];
  };
in
{
  options.services.stile = {
    enable = mkEnableOption "stile-brokerd, the privileged capability broker. Enabling this adds the service, the access group and the stile CLI to the system; the registry and age identity must still be provisioned by the administrator.";

    package = mkOption {
      type = types.package;
      default = pkgs.stile or (throw "services.stile.package: pkgs.stile does not exist; add the stile flake overlay (overlays.default) or set services.stile.package explicitly");
      defaultText = literalExpression "pkgs.stile";
      description = "Package providing `stile` and `stile-brokerd`. When used without this flake's overlay, set it explicitly.";
    };

    accessGroup = mkOption {
      type = types.str;
      default = "stile-access";
      description = "Members of this group may connect to the broker socket and request lifecycle operations. They still never receive secret values.";
    };

    registryFile = mkOption {
      type = types.str;
      default = "/etc/stile/registry.toml";
      description = ''
        Root-owned declarative registry defining every secret and every
        action the broker may take. This is a path STRING on purpose: a
        Nix path value would copy the file into the world-readable
        store. Provision it as a root-owned file outside the store.
      '';
    };

    ageKeyFile = mkOption {
      type = types.str;
      default = "/etc/stile/age.key";
      description = ''
        Root-owned (0400) SOPS age identity the broker decrypts with.
        Path string, never a Nix path — its contents must not enter the
        store. Generate with `age-keygen` as the administrator.
      '';
    };

    socketPath = mkOption {
      type = types.str;
      default = "/run/stile/sock";
      description = "Unix socket path. The parent directory must be owned by the broker user (root) and not world-writable; the broker verifies this at start.";
    };

    stateDir = mkOption {
      type = types.str;
      default = "/var/lib/stile";
      description = "State root: audit log, broker work dir, encrypted backups (all broker-private).";
    };

    sopsPackage = mkOption {
      type = types.package;
      default = pkgs.sops;
      defaultText = literalExpression "pkgs.sops";
      description = "SOPS used by the broker for store encryption.";
    };

    extraReadWritePaths = mkOption {
      type = types.listOf types.str;
      default = [ ];
      example = [
        "/srv/infra"
        "/etc/example-app"
      ];
      description = ''
        Additional writable paths for the hardened unit. The broker
        writes the SOPS repository at the registry's repo_root and the
        declared consumer files — add those paths (and /run/docker.sock
        if the registry declares postgres hooks) here.
      '';
    };
  };

  config = mkIf cfg.enable (mkMerge [
    {
      users.groups.${cfg.accessGroup} = { };

      # The unprivileged client for agent users.
      environment.systemPackages = [ cfg.package ];

      systemd.services.stile-brokerd = {
        description = "stile capability broker (stile-brokerd)";
        documentation = [ "https://github.com/liamwh/stile" ];
        after = [ "network.target" ];
        wantedBy = [ "multi-user.target" ];

        serviceConfig = {
          Type = "simple";
          ExecStart = "${cfg.package}/bin/stile-brokerd ${brokerdToml}";
          User = "root";
          Group = "root";
          RuntimeDirectory = "stile";
          RuntimeDirectoryMode = "0750";
          StateDirectory = "stile";
          StateDirectoryMode = "0750";

          # Hardening. The broker must: write its state dirs; run sops
          # against the SOPS repo (canonical-path encryption); write the
          # deployed consumer files; exec curl for verification probes.
          # NoNewPrivileges is deliberately NOT set: with it, systemd
          # withholds CAP_SETUID from the permitted set and runuser's
          # setuid(2) to the declared command user fails with EPERM. The
          # broker must drop privileges for declared reload commands;
          # capability containment comes from CapabilityBoundingSet (no
          # CAP_SYS_ADMIN, no module loading).
          ProtectSystem = "strict";
          ReadWritePaths = [
            "/run/stile"
            cfg.stateDir
          ] ++ cfg.extraReadWritePaths;
          PrivateTmp = true;
          PrivateDevices = true;
          ProtectClock = true;
          ProtectHostname = true;
          ProtectKernelTunables = true;
          ProtectKernelModules = true;
          ProtectControlGroups = true;
          RestrictAddressFamilies = [
            "AF_UNIX"
            "AF_INET"
            "AF_INET6"
          ];
          RestrictRealtime = true;
          RestrictSUIDSGID = true;
          LockPersonality = true;
          MemoryDenyWriteExecute = true;
          CapabilityBoundingSet = [
            "CAP_CHOWN"
            "CAP_DAC_OVERRIDE"
            "CAP_FOWNER"
            "CAP_SETUID"
            "CAP_SETGID"
          ];
          SystemCallFilter = [ "@system-service" ];
          SystemCallArchitectures = "native";
          Restart = "on-failure";
          RestartSec = "5s";
        };
      };
    }
    {
      assertions = [
        {
          assertion = !(hasPrefix "/nix/store/" cfg.registryFile);
          message = "services.stile.registryFile must be a runtime path (e.g. /etc/stile/registry.toml), not a store path — registry content must stay root-only.";
        }
        {
          assertion = !(hasPrefix "/nix/store/" cfg.ageKeyFile);
          message = "services.stile.ageKeyFile must be a runtime path (e.g. /etc/stile/age.key), not a store path — the age identity must stay root-only.";
        }
      ];
    }
  ]);
}
