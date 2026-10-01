#!/usr/bin/env bash
# Build a .deb from prebuilt static musl binaries.
#
# Usage: make-deb.sh <binary-dir> <out.deb> <arch: amd64|arm64> [version]
#
# The binaries must already exist (release workflow cross-builds them).
# Layout is deliberately minimal: /usr/local/bin plus docs.
set -euo pipefail

bindir="$1"; out="$2"; arch="$3"; version="${4:-0.1.0}"

for f in stile stile-brokerd; do
    [ -x "$bindir/$f" ] || { echo "missing $bindir/$f" >&2; exit 1; }
done

root="$(mktemp -d)"
trap 'rm -rf "$root"' EXIT

install -Dm755 "$bindir/stile" "$root/usr/local/bin/stile"
install -Dm755 "$bindir/stile-brokerd" "$root/usr/local/bin/stile-brokerd"
install -Dm644 README.md "$root/usr/local/share/doc/stile/README.md"
install -Dm644 THREAT_MODEL.md "$root/usr/local/share/doc/stile/THREAT_MODEL.md"
install -Dm644 SECURITY.md "$root/usr/local/share/doc/stile/SECURITY.md"
install -Dm644 LICENSE "$root/usr/local/share/doc/stile/LICENSE"
install -Dm644 examples/stile-brokerd.service \
    "$root/usr/local/share/doc/stile/examples/stile-brokerd.service"
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
Homepage: https://github.com/liamwh/stile
Built-Using: stile ${version}
EOF

dpkg-deb --root-owner-group --build "$root" "$out"
echo "built $out ($(dpkg-deb --info "$out" | grep -c .) control lines)"
