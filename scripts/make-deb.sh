#!/usr/bin/env bash
# Build the stile Debian package from prebuilt binaries.
#
# Usage: make-deb.sh <binary-dir> <out.deb> <arch: amd64|arm64> [version]
#
# The package installs a complete-but-inactive system integration:
#   /usr/bin/stile, /usr/bin/stile-brokerd
#   /usr/lib/systemd/system/stile-brokerd.service
#   /usr/lib/sysusers.d/stile.conf        (creates the stile-access group)
#   /usr/lib/tmpfiles.d/stile.conf        (state directories)
#   /etc/stile/brokerd.toml               (conffile: valid defaults)
#   /usr/share/doc/stile/...              (README, THREAT_MODEL, examples)
#
# Policy:
# - the service is installed but NOT enabled or started: the broker
#   cannot work until the administrator provides the registry and the
#   SOPS age identity;
# - no keys are generated, no registry content is invented;
# - removal never touches /etc/stile or /var/lib/stile (only `purge`
#   does, which is standard Debian semantics).
set -euo pipefail

bindir="$1"; out="$2"; arch="$3"; version="${4:-0.1.0}"

for f in stile stile-brokerd; do
    [ -x "$bindir/$f" ] || { echo "missing $bindir/$f" >&2; exit 1; }
done

root="$(mktemp -d)"
trap 'rm -rf "$root"' EXIT

# ── binaries ──────────────────────────────────────────────────────────
install -Dm755 "$bindir/stile"          "$root/usr/bin/stile"
install -Dm755 "$bindir/stile-brokerd"  "$root/usr/bin/stile-brokerd"

# ── systemd unit (distro paths; same hardening as the repo example) ──
# ReadWritePaths covers the default state layout only. Deployments whose
# SOPS repo or consumer files live elsewhere must add a drop-in, e.g.
# /etc/systemd/system/stile-brokerd.service.d/paths.conf
#   [Service]
#   ReadWritePaths=/srv/infra /etc/example-app
install -Dm644 /dev/stdin "$root/usr/lib/systemd/system/stile-brokerd.service" <<EOF
[Unit]
Description=stile capability broker (stile-brokerd)
Documentation=https://github.com/liamwh/stile
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/stile-brokerd /etc/stile/brokerd.toml
User=root
Group=root
RuntimeDirectory=stile
RuntimeDirectoryMode=0750
# Hardening rationale is documented in the repository's
# examples/stile-brokerd.service and THREAT_MODEL.md. In short: the
# broker must write its state dirs, the SOPS repo and deployed consumer
# files, and must keep CAP_SETUID so runuser can drop privileges to the
# users declared in the registry (NoNewPrivileges would break that).
ProtectSystem=strict
ReadWritePaths=/var/lib/stile /run/stile
PrivateTmp=yes
PrivateDevices=yes
ProtectClock=yes
ProtectHostname=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER CAP_SETUID CAP_SETGID
SystemCallFilter=@system-service
SystemCallArchitectures=native
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# ── system users / runtime state (idempotent, no shell logic) ────────
install -Dm644 /dev/stdin "$root/usr/lib/sysusers.d/stile.conf" <<'EOF'
# Type Name         ID  GECOS
g      stile-access -
EOF

install -Dm644 /dev/stdin "$root/usr/lib/tmpfiles.d/stile.conf" <<'EOF'
# stile persistent state (kept on package removal; 'purge' removes them).
d /var/lib/stile        0750 root root -
d /var/lib/stile/work   0700 root root -
d /var/lib/stile/backup 0700 root root -
d /var/lib/stile/audit  0750 root root -
EOF

# ── configuration (conffile: valid defaults, admin-owned afterwards) ──
install -Dm640 /dev/stdin "$root/etc/stile/brokerd.toml" <<EOF
# stile-brokerd configuration. dpkg treats this file as a conffile:
# your edits are preserved across upgrades.
#
# The broker cannot start until you also provide:
#   1. the registry at registry_path (see
#      /usr/share/doc/stile/examples/registry.toml) and
#   2. the broker's SOPS age identity at age_key_file (age-keygen -o
#      /etc/stile/age.key && chmod 0400 /etc/stile/age.key), whose
#      public key must be a recipient for the store files.
#
# Default layout: the SOPS repository is expected under
# /var/lib/stile/repo (writable by the hardened unit). If yours lives
# elsewhere, add a systemd drop-in extending ReadWritePaths (see
# /usr/share/doc/stile/examples/paths.conf).
socket_path = "/run/stile/sock"
registry_path = "/etc/stile/registry.toml"
audit_path = "/var/lib/stile/audit/audit.log"
work_dir = "/var/lib/stile/work"
sops_bin = "/usr/bin/sops"
age_key_file = "/etc/stile/age.key"
backup_dir = "/var/lib/stile/backup"
access_group = "stile-access"
allowed_uids = []
EOF

# ── documentation and examples ────────────────────────────────────────
doc="$root/usr/share/doc/stile"
install -Dm644 README.md      "$doc/README.md"
install -Dm644 THREAT_MODEL.md "$doc/THREAT_MODEL.md"
install -Dm644 SECURITY.md    "$doc/SECURITY.md"
install -Dm644 CHANGELOG.md   "$doc/changelog"
install -Dm644 LICENSE        "$doc/LICENSE"
install -Dm644 examples/registry.toml "$doc/examples/registry.toml"
install -Dm644 /dev/stdin "$doc/examples/paths.conf" <<'EOF'
# Additional writable paths for stile-brokerd (systemd drop-in).
# Install as /etc/systemd/system/stile-brokerd.service.d/paths.conf and
# adjust to your registry's repo_root and consumer file locations; add
# /run/docker.sock if the registry declares postgres hooks.
[Service]
ReadWritePaths=/srv/infra /etc/example-app
EOF
gzip -9n "$doc/changelog"

# ── Debian control ────────────────────────────────────────────────────
install -d -m 0755 "$root/DEBIAN"

cat > "$root/DEBIAN/control" <<EOF
Package: stile
Version: ${version}
Section: admin
Priority: optional
Architecture: ${arch}
Maintainer: Liam Woodleigh-Hardinge <liam.woodleigh@gmail.com>
Description: capability-oriented secret broker
 stile lets untrusted processes (AI coding agents, CI jobs, helpers)
 perform narrowly defined lifecycle operations on SOPS-managed secrets
 (rotate, verify, reconcile, status, list, provider-assisted import)
 while secret values stay behind a privileged broker boundary.
 .
 Installs the stile CLI, the stile-brokerd systemd unit, the
 stile-access group and a default /etc/stile/brokerd.toml. The service
 is NOT enabled: provide your registry and SOPS age identity, then
 'systemctl enable --now stile-brokerd'.
Homepage: https://github.com/liamwh/stile
EOF

echo "/etc/stile/brokerd.toml" > "$root/DEBIAN/conffiles"

install -m755 /dev/stdin "$root/DEBIAN/postinst" <<'EOF'
#!/bin/sh
# Minimal and idempotent: no secrets, no auto-enable, no config writes.
set -e
if [ -d /run/systemd/system ]; then
    systemd-sysusers /usr/lib/sysusers.d/stile.conf || true
    systemd-tmpfiles --create /usr/lib/tmpfiles.d/stile.conf || true
    systemctl daemon-reload || true
fi
if [ "$1" = "configure" ] && [ ! -e /etc/stile/registry.toml ]; then
    echo ""
    echo "stile: the broker is installed but NOT enabled."
    echo "stile: next steps:"
    echo "stile:   1. install your registry:      cp /usr/share/doc/stile/examples/registry.toml /etc/stile/registry.toml (edit it)"
    echo "stile:   2. provision the age identity: age-keygen -o /etc/stile/age.key; chmod 0400 /etc/stile/age.key"
    echo "stile:   3. add callers:                usermod -aG stile-access <user>"
    echo "stile:   4. systemctl enable --now stile-brokerd"
    echo "stile: see /usr/share/doc/stile/README.md and THREAT_MODEL.md"
fi
exit 0
EOF

install -m755 /dev/stdin "$root/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = "remove" ] && [ -d /run/systemd/system ]; then
    systemctl stop stile-brokerd.service || true
fi
exit 0
EOF

install -m755 /dev/stdin "$root/DEBIAN/postrm" <<'EOF'
#!/bin/sh
# 'remove' keeps all administrator data (config, state, keys).
# 'purge' deletes them, per Debian policy.
set -e
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
fi
if [ "$1" = "purge" ]; then
    rm -rf /var/lib/stile
    rm -rf /etc/stile
fi
exit 0
EOF

dpkg-deb --root-owner-group --build "$root" "$out"
echo "built $out"
