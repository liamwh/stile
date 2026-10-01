# NixOS VM test for the stile module.
#
# Exercises the real broker with a synthetic registry and a fake sops:
# - service starts and stays up
# - socket ownership root:stile-access, mode 0660, dir 0750
# - a member of the access group can run `stile list`
# - a non-member cannot connect
#
# The registry/age key here are throwaway synthetic values; list/status
# never touch the store, so no decryption is needed.
{
pkgs,
self,
}:
pkgs.testers.nixosTest (
  { ... }:
  {

    name = "stile";

    nodes.machine =
      { config, pkgs, ... }:
      {
        imports = [ self.nixosModules.stile ];

        services.stile = {
          enable = true;
          package = self.packages.${pkgs.system}.stile;
          registryFile = "/etc/stile/registry.toml";
          ageKeyFile = "/etc/stile/age.key";
        };

        users.users = {
          alice = {
            isNormalUser = true;
            extraGroups = [ "stile-access" ];
          };
          mallory = {
            isNormalUser = true;
          };
        };

        # Synthetic registry (list/status only read this file).
        environment.etc."stile/registry.toml".text = ''
          version = 1
          repo_root = "/var/lib/stile/repo"

          [[secret]]
          id = "test/auto-secret"
          policy = "auto"
          [secret.store]
          file = "secrets/test.env"
          type = "dotenv"
          key = "TEST_SECRET"
          [secret.generation]
          type = "hex"
          bytes = 32
        '';
        # Placeholder identity (never used by list/status).
        environment.etc."stile/age.key".text = "AGE-TEST-ONLY-NOT-A-REAL-KEY";
      };

    testScript = ''
      machine.wait_for_unit("stile-brokerd.service")

      with subtest("socket ownership and mode"):
          machine.succeed("test \"$(stat -c %U /run/stile/sock)\" = root")
          machine.succeed("test \"$(stat -c %G /run/stile/sock)\" = stile-access")
          machine.succeed("test \"$(stat -c %a /run/stile/sock)\" = 660")
          machine.succeed("test \"$(stat -c %a /run/stile)\" = 750")

      with subtest("authorised user can list secrets"):
          out = machine.succeed("su - alice -c 'stile list'")
          assert "test/auto-secret auto" in out, out

      with subtest("unauthorised user cannot connect"):
          machine.fail("su - mallory -c 'stile list'")

      with subtest("status is a safe read-only operation"):
          out = machine.succeed("su - alice -c 'stile status test/auto-secret'")
          assert '"status": "success"' in out, out

      with subtest("service still healthy"):
          machine.succeed("systemctl is-active stile-brokerd")
    '';
  }
)
