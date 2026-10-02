#!/usr/bin/env bash
# End-to-end Debian package test in a clean debian:bookworm-slim
# container. Exercises: install, contents/modes, sysusers/tmpfiles,
# pre-configuration state (service present but NOT enabled), broker
# startup with a synthetic config + fake sops, authorised vs
# unauthorised clients, conffile preservation across upgrade, and
# remove-vs-purge data retention.
#
# Usage: scripts/test-deb.sh [deb-file]   (default: builds one from
#        target/release into /tmp; those are host-glibc binaries, so run
#        with IMAGE=debian:trixie-slim. Release debs are static musl and
#        run against the default bookworm-slim.)
set -euo pipefail
cd "$(dirname "$0")/.."
repo="$PWD"

deb="${1:-}"
if [ -z "$deb" ]; then
    cargo build --release --locked -p stile -p stile-brokerd 2>/dev/null | tail -1 || true
    [ -x target/release/stile ] || cargo build --release --locked -p stile -p stile-brokerd >/dev/null
    deb=/tmp/stile_0.1.0_amd64.deb
    bash scripts/make-deb.sh target/release "$deb" amd64 0.1.0
fi
abs_deb="$(readlink -f "$deb")"
IMAGE="${IMAGE:-debian:bookworm-slim}"
CID=$(docker run -d --rm --entrypoint sleep "$IMAGE" infinity)
cleanup() { [ -n "$CID" ] && docker rm -f "$CID" >/dev/null 2>&1 || true; }
trap cleanup EXIT
dc() { docker exec "$CID" sh -c "$*"; }
cp_deb() { docker cp "$abs_deb" "$CID:/tmp/stile.deb"; }
cp_deb

fail() { echo "FAIL: $*" >&2; exit 1; }

# Cross-arch (e.g. arm64 deb on an amd64 runner): structural verification
# only — dpkg-deb inspects the archive; lifecycle tests need a native arch
# (or emulation, which we deliberately do not assume).
deb_arch=$(dpkg-deb --info "$abs_deb" | awk '/Architecture:/ {print $2}')
if [ "$deb_arch" != "$(docker exec $CID dpkg --print-architecture)" ]; then
    echo "== cross-arch ($deb_arch deb): structural verification only =="
    docker cp "$abs_deb" "$CID:/tmp/stile.deb"
    dc "dpkg-deb -I /tmp/stile.deb | grep -q 'Package: stile'" || fail "control"
    dc "dpkg-deb -c /tmp/stile.deb | grep -q 'usr/bin/stile-brokerd'" || fail "binary payload"
    dc "dpkg-deb -c /tmp/stile.deb | grep -q 'usr/lib/systemd/system/stile-brokerd.service'" || fail "unit payload"
    dc "dpkg-deb -c /tmp/stile.deb | grep -q 'usr/lib/sysusers.d/stile.conf'" || fail "sysusers payload"
    dc "dpkg-deb -c /tmp/stile.deb | grep -q 'etc/stile/brokerd.toml'" || fail "conffile payload"
    echo "CROSS-ARCH STRUCTURAL CHECKS PASSED"
    exit 0
fi

echo "== 1. install =="
dc "apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq /tmp/stile.deb >/dev/null" || fail "dpkg install"
dc "dpkg -s stile | grep -q 'Status: install ok installed'" || fail "package status"

echo "== 2. contents and permissions =="
dc "test -x /usr/bin/stile && test -x /usr/bin/stile-brokerd" || fail "binaries in /usr/bin"
dc "test -f /usr/lib/systemd/system/stile-brokerd.service" || fail "unit installed"
dc "test -f /usr/lib/sysusers.d/stile.conf" || fail "sysusers installed"
dc "test -f /usr/lib/tmpfiles.d/stile.conf" || fail "tmpfiles installed"
dc "dpkg -L stile | grep -q '/etc/stile/brokerd.toml'" || fail "conffile listed"
dc "stat -c %a /etc/stile/brokerd.toml | grep -qx 640" || fail "conffile mode 640"
dc "stat -c %a /usr/bin/stile | grep -qx 755" || fail "binary mode"

echo "== 3. binaries run =="
dc "/usr/bin/stile --version" | grep -q "stile 0.1.0" || fail "CLI version"
dc "/usr/bin/stile-brokerd --help" >/dev/null || fail "brokerd help"

echo "== 4. sysusers + tmpfiles =="
dc "apt-get update -qq >/dev/null 2>&1; apt-get install -y -qq systemd procps >/dev/null 2>&1 || true"
dc "systemd-sysusers /usr/lib/sysusers.d/stile.conf" || fail "sysusers run"
dc "getent group stile-access" || fail "group exists"
dc "systemd-tmpfiles --create /usr/lib/tmpfiles.d/stile.conf" || fail "tmpfiles run"
dc "stat -c %a /var/lib/stile | grep -qx 750" || fail "state dir mode"

echo "== 5. pre-configuration state: unit present, NOT enabled =="
dc "test -f /etc/stile/brokerd.toml" || fail "default config present"
dc "! test -e /etc/systemd/system/multi-user.target.wants/stile-brokerd.service" || fail "service must not be auto-enabled"
dc "! pgrep -x stile-brokerd" || fail "broker must not be running"

echo "== 6. broker starts with synthetic configuration =="
# fake sops so no real crypto is needed
dc "printf '%s\n' '#!/bin/sh' 'if [ \"\$1\" = \"-d\" ]; then for l in \"\$@\"; do :; done; printf \"SOPSFAKE:dotenv\\nKEY=v-TEST-DEB-CANARY-not-real\\nsops_version=3.13.3\\n\"; exit 0; fi' 'if [ \"\$1\" = \"encrypt\" ]; then exit 0; fi' 'exit 1' > /usr/local/bin/fake-sops && chmod 755 /usr/local/bin/fake-sops"
dc "mkdir -p /var/lib/stile/repo/secrets /etc/stile"
dc "printf 'SOPSFAKE:dotenv\nKEY=v-TEST-DEB-CANARY-not-real\nsops_version=3.13.3\n' > /var/lib/stile/repo/secrets/test.env"
dc "printf 'AGE-TEST-DEB-NOT-REAL\n' > /etc/stile/age.key && chmod 400 /etc/stile/age.key"
dc "cat > /etc/stile/registry.toml <<'REG'
version = 1
repo_root = \"/var/lib/stile/repo\"

[[secret]]
id = \"test/deb-secret\"
policy = \"auto\"
reason = \"synthetic package test\"
[secret.store]
file = \"secrets/test.env\"
type = \"dotenv\"
key = \"KEY\"
[secret.generation]
type = \"hex\"
bytes = 32
REG"
dc "sed -i 's|^sops_bin = .*|sops_bin = \"/usr/local/bin/fake-sops\"|' /etc/stile/brokerd.toml"
# repo_root is under /var/lib/stile → already writable by the unit; but we
# run the broker directly (no systemd in the container) as root:
dc "/usr/bin/stile-brokerd /etc/stile/brokerd.toml >/tmp/broker.log 2>&1 &"
for i in $(seq 1 30); do dc "test -S /run/stile/sock" && break; sleep 0.3; done
dc "test -S /run/stile/sock" || { dc "cat /tmp/broker.log"; fail "socket appeared"; }

echo "== 7. socket ownership/mode =="
dc "stat -c %U /run/stile/sock | grep -qx root" || fail "socket owner"
dc "stat -c %G /run/stile/sock | grep -qx stile-access" || fail "socket group"
dc "stat -c %a /run/stile/sock | grep -qx 660" || fail "socket mode"
dc "stat -c %a /run/stile | grep -qx 750" || fail "socket dir mode"

echo "== 8. authorised vs unauthorised clients =="
dc "id alice >/dev/null 2>&1 || useradd -m -G stile-access alice"
dc "id mallory >/dev/null 2>&1 || useradd -m mallory"
dc "su -s /bin/sh alice -c '/usr/bin/stile list'" | grep -q "test/deb-secret auto" || fail "authorised list"
if dc "su -s /bin/sh mallory -c '/usr/bin/stile list'" >/dev/null 2>&1; then
    fail "unauthorised user must not connect"
fi

echo "== 9. audited operation; canary never leaves the store/deployed paths =="
# list/status are not audited by design; the read-only 'verify' op is.
dc "su -s /bin/sh alice -c '/usr/bin/stile verify test/deb-secret'" | grep -q '"status": "success"' || fail "verify op"
dc "test -f /var/lib/stile/audit/audit.log" || fail "audit record written"
AUDIT=$(dc "cat /var/lib/stile/audit/audit.log")
echo "$AUDIT" | grep -q "v-TEST-DEB-CANARY-not-real" && fail "canary in audit log"
dc "grep -r 'v-TEST-DEB-CANARY-not-real' /tmp/broker.log" && fail "canary in broker log" || true
dc "pkill stile-brokerd || true"

echo "== 10. upgrade preserves conffile edits =="
dc "echo '# local edit' >> /etc/stile/brokerd.toml"
docker cp "$abs_deb" "$CID:/tmp/stile.deb"
dc "dpkg -i --force-confold /tmp/stile.deb >/dev/null 2>&1 || apt-get install -y -qq -f >/dev/null 2>&1"
dc "grep -q '# local edit' /etc/stile/brokerd.toml" || fail "conffile edit preserved"
dc "test -f /etc/stile/registry.toml && test -f /etc/stile/age.key" || fail "admin files survive upgrade"

echo "== 11. remove keeps data; purge deletes it =="
dc "dpkg -r stile >/dev/null 2>&1"
dc "ls -la /etc/stile /var/lib/stile /var/lib/stile/audit || true"
dc "test -f /etc/stile/registry.toml && test -f /var/lib/stile/audit/audit.log" || fail "remove must keep admin data (listing above)"
dc "dpkg -P stile >/dev/null 2>&1"
dc "test ! -e /etc/stile && test ! -e /var/lib/stile" || fail "purge must remove config+state"

echo "ALL DEB TESTS PASSED"
