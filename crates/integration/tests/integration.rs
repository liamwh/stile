//! End-to-end integration tests. Everything runs against fakes: a fake
//! `sops` (marker-line "encryption"), fake `curl`, fake `runuser`, fake
//! `docker` — and throwaway sentinel secrets. The core assertions are
//! NON-DISCLOSURE: sentinel bytes must never appear in responses, logs,
//! audit output, or process arguments.

use serde_json::Value;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

// ─── fixture ───────────────────────────────────────────────────────────

struct Fixture {
    root: PathBuf,
    broker: Option<Child>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if std::env::var_os("STILE_IT_KEEP").is_some() {
            eprintln!("KEEPING fixture at {}", self.root.display());
            if let Some(mut child) = self.broker.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
            return;
        }
        if let Some(mut child) = self.broker.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn uid_gid() -> (u32, u32) {
    // SAFETY: getuid(2) is infallible and returns a plain id.
    let uid = unsafe { libc::getuid() };
    // SAFETY: getgid(2) is infallible and returns a plain id.
    let gid = unsafe { libc::getgid() };
    (uid, gid)
}

fn current_user_group() -> (String, String) {
    let (uid, gid) = uid_gid();
    let user = {
        // SAFETY: getpwuid(3) static storage read immediately.
        let pw = unsafe { libc::getpwuid(uid) };
        if pw.is_null() {
            "nobody".into()
        } else {
            // SAFETY: pw_name is NUL-terminated and owned by getpwuid(3).
            unsafe { std::ffi::CStr::from_ptr((*pw).pw_name) }
                .to_string_lossy()
                .into_owned()
        }
    };
    let group = {
        // SAFETY: getgrgid(3) static storage read immediately.
        let gr = unsafe { libc::getgrgid(gid) };
        if gr.is_null() {
            "nogroup".into()
        } else {
            // SAFETY: gr_name is NUL-terminated and owned by getgrgid(3).
            unsafe { std::ffi::CStr::from_ptr((*gr).gr_name) }
                .to_string_lossy()
                .into_owned()
        }
    };
    (user, group)
}

fn write_exec(path: &Path, body: &str) {
    std::fs::write(path, body).expect("write script");
    make_exec(path);
}

fn make_exec(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
}

fn markerize(kind: &str, plaintext: &[u8]) -> Vec<u8> {
    let mut out = format!("SOPSFAKE:{kind}\n").into_bytes();
    out.extend_from_slice(plaintext);
    if kind == "dotenv" {
        // Real SOPS dotenv files carry sops_* metadata; ensure_encrypted
        // checks for it.
        out.extend_from_slice(b"sops_version=3.13.3\n");
    }
    out
}

fn demarkered(raw: &[u8]) -> Option<Vec<u8>> {
    let text = String::from_utf8_lossy(raw);
    let mut lines = text.splitn(2, '\n');
    let first = lines.next()?;
    if first.starts_with("SOPSFAKE:") {
        let rest = lines.next()?;
        Some(rest.as_bytes().to_vec())
    } else {
        None
    }
}

/// Build a full fixture: fake tools, repo with fake-encrypted stores,
/// registry, brokerd config. Sentinel values are throwaway.
fn build_fixture(group: &str, allowed_uids: &[u32]) -> Fixture {
    let root = std::env::temp_dir().join(format!(
        "stile-it-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    for dir in ["bin", "logs", "run", "work", "backup", "repo/secrets"] {
        std::fs::create_dir_all(root.join(dir)).expect("mkdir");
    }

    let old_sentinel = "OLD-SENTINEL-4f3c2b1a-not-a-real-secret";
    let old_binary_sentinel = "old-binary-sentinel-9911-not-real";

    // Fake sops: marker-line encryption. Logs argv (never sees values).
    let sops = root.join("bin/sops");
    write_exec(
        &sops,
        r#"#!/bin/bash
# fake sops for integration tests
echo "sops $*" >> "__LOGS__/sops.argv"
if [ "$1" = "-d" ]; then
  for last in "$@"; do :; done
  first_line="$(head -n1 "$last")"
  case "$first_line" in
    SOPSFAKE:*) tail -n +2 "$last"; exit 0 ;;
    *) echo "sops: file is not encrypted" >&2; exit 1 ;;
  esac
fi
if [ "$1" = "encrypt" ]; then
  if [ -f "__ROOT__/fail-encrypt" ]; then echo "sops: simulated failure" >&2; exit 1; fi
  for last in "$@"; do :; done
  tmp="$(mktemp)"
  cp "$last" "$tmp"
  { echo "SOPSFAKE:dotenv"; cat "$tmp"; } > "$last"
  rm -f "$tmp"
  exit 0
fi
echo "sops: unsupported invocation" >&2; exit 1
"#,
    );

    // Fake curl: logs argv only; status from map files; header file
    // contents are read to select status but never logged.
    let curl = root.join("bin/curl");
    write_exec(
        &curl,
        r#"#!/bin/bash
# fake curl: logs argv; selects status by bearer token; never logs tokens
printf 'curl' >> "__LOGS__/curl.argv"
for a in "$@"; do printf ' %q' "$a" >> "__LOGS__/curl.argv"; done
printf '\n' >> "__LOGS__/curl.argv"
default=200
[ -f "__ROOT__/curl-status" ] && default="$(cat "__ROOT__/curl-status")"
token=""
hdr=0
for a in "$@"; do
  if [ "$hdr" = "1" ]; then
    hf="${a#@}"
    sz=$(wc -c < "$hf" 2>/dev/null)
    token="$(tail -n1 "$hf" 2>/dev/null | sed 's/Authorization: Bearer //')"
    echo "hdrfile size=${sz:-missing} tokenlen=${#token}" >> "__LOGS__/curl.decisions"
    break
  fi
  [ "$a" = "-H" ] && hdr=1
done
if [ -n "$token" ]; then
  if grep -qxF "$token" "__ROOT__/tokens-old" 2>/dev/null; then
    st=401
    [ -f "__ROOT__/curl-old-status" ] && st="$(cat "__ROOT__/curl-old-status")"
    echo "decision old-token -> $st" >> "__LOGS__/curl.decisions"
    echo "$st"; exit 0
  fi
  if [ -f "__ROOT__/server-token" ]; then
    if grep -qxF "$token" "__ROOT__/server-token"; then
      echo "decision current-server-token -> $default" >> "__LOGS__/curl.decisions"
      echo "$default"
    else
      echo "decision stale-server-token -> 401" >> "__LOGS__/curl.decisions"
      echo 401
    fi
    exit 0
  fi
  echo "decision unknown-token -> $default" >> "__LOGS__/curl.decisions"
  echo "$default"; exit 0
fi
echo "decision no-token -> $default" >> "__LOGS__/curl.decisions"
echo "$default"; exit 0
"#,
    );

    // Fake runuser: records argv then execs the command.
    let runuser = root.join("bin/runuser");
    write_exec(
        &runuser,
        r#"#!/bin/bash
# fake runuser: records argv then execs the command
printf 'runuser' >> "__LOGS__/runuser.argv"
for a in "$@"; do printf ' %q' "$a" >> "__LOGS__/runuser.argv"; done
printf '\n' >> "__LOGS__/runuser.argv"
shift 2
[ "$1" = "--" ] && shift
if [ "$1" = "env" ]; then
  while [ $# -gt 0 ]; do
    case "$1" in *=*) shift ;; *) break ;; esac
  done
fi
exec "$@"
"#,
    );

    // Reload recorder script (runs as the fixture user via fake runuser).
    let reload = root.join("bin/reload-recorder");
    write_exec(
        &reload,
        &format!(
            r#"#!/bin/bash
printf 'reload' >> "{logs}/reload.argv"
for a in "$@"; do printf ' %q' "$a" >> "{logs}/reload.argv"; done
printf '\n' >> "{logs}/reload.argv"
exit 0
"#,
            logs = root.join("logs").display()
        ),
    );

    let backend_active = root.join("bin/backend-active");
    write_exec(
        &backend_active,
        &format!(
            r#"#!/bin/bash
[ "$(cat "{root}/active-backend")" = "$1" ]
"#,
            root = root.display()
        ),
    );
    let backend_reload = root.join("bin/backend-reload");
    write_exec(
        &backend_reload,
        &format!(
            r#"#!/bin/bash
cp "{root}/deployed.key" "{root}/server-token"
printf '%s\n' "$1" >> "{logs}/backend-reload.log"
"#,
            root = root.display(),
            logs = root.join("logs").display()
        ),
    );
    let consumer_check = root.join("bin/consumer-check");
    write_exec(
        &consumer_check,
        &format!(
            "#!/bin/bash\n[ -f \"{root}/$1-healthy\" ]\n",
            root = root.display()
        ),
    );
    let consumer_reload = root.join("bin/consumer-reload");
    write_exec(
        &consumer_reload,
        &format!(
            "#!/bin/bash\ntouch \"{root}/$1-healthy\"\nprintf '%s\\n' \"$1\" >> \"{logs}/consumer-reload.log\"\n",
            root = root.display(),
            logs = root.join("logs").display()
        ),
    );

    // Bake absolute paths into fake scripts (children get no env).
    for tool in ["bin/sops", "bin/curl", "bin/runuser"] {
        let path = root.join(tool);
        let body = std::fs::read_to_string(&path).unwrap_or_default();
        let baked = body
            .replace("__LOGS__", &root.join("logs").display().to_string())
            .replace("__ROOT__", &root.display().to_string());
        std::fs::write(&path, baked).unwrap();
    }

    // Stores.
    let env_store_plain = format!("OTHER_KEY=keepme\nTEST_SECRET={old}\n", old = old_sentinel);
    std::fs::write(
        root.join("repo/secrets/test.env"),
        markerize("dotenv", env_store_plain.as_bytes()),
    )
    .expect("write store");
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(
        root.join("repo/secrets/test.env"),
        std::fs::Permissions::from_mode(0o644),
    )
    .expect("mode");
    std::fs::write(
        root.join("repo/secrets/test.key"),
        markerize("binary", format!("{old_binary_sentinel}\n").as_bytes()),
    )
    .expect("write binary store");
    std::fs::write(
        root.join("repo/secrets/provider.env"),
        markerize(
            "dotenv",
            "PROVIDER_SECRET=old-provider-not-real\n".as_bytes(),
        ),
    )
    .expect("write provider store");
    std::fs::write(
        root.join("repo/secrets/verify-fail.env"),
        markerize("dotenv", "VF_SECRET=old-vf-not-real\n".as_bytes()),
    )
    .expect("write vf store");
    std::fs::write(root.join("active-backend"), "syv\n").expect("active backend");

    // Deployed runtime env (consumer).
    std::fs::write(root.join("omp-healthy"), "").expect("omp health");
    std::fs::write(root.join("inbox-zero-healthy"), "").expect("inbox health");
    std::fs::write(
        root.join("deployed.env"),
        "OTHER_KEY=keepme\nTEST_SECRET=whatever-old\n",
    )
    .expect("write deployed");

    let (user, _group) = current_user_group();

    // Registry.
    let registry = format!(
        r#"version = 1
repo_root = "{root}/repo"

[[secret]]
id = "test/auto-secret"
policy = "auto"
reason = "integration test secret"
[secret.store]
file = "secrets/test.env"
type = "dotenv"
key = "TEST_SECRET"
[secret.generation]
type = "hex"
bytes = 32
[[secret.consumers]]
type = "dotenv-file"
path = "{root}/deployed.env"
key = "TEST_SECRET"
owner = "{user}"
mode = 256
[[secret.reload]]
type = "run-command"
user = "{user}"
command = "{root}/bin/reload-recorder"
args = ["stack-restarted"]
[[secret.verify]]
type = "http-status"
url = "https://example.test/login"
expect_status = 200

[[secret]]
id = "test/binary-secret"
policy = "auto"
[secret.store]
file = "secrets/test.key"
type = "binary"
[secret.generation]
type = "hex"
bytes = 32
[[secret.consumers]]
type = "raw-file"
path = "{root}/deployed.key"
owner = "{user}"
mode = 256
[[secret.backends]]
id = "syv"
[secret.backends.active]
type = "run-command"
user = "{user}"
command = "{root}/bin/backend-active"
args = ["syv"]
[secret.backends.reload]
type = "run-command"
user = "{user}"
command = "{root}/bin/backend-reload"
args = ["syv"]
[secret.backends.verify]
type = "bearer-probe"
url = "http://127.0.0.1:8090/v1/models"
expect_status = 200
old_expect_status = 401
[[secret.backends]]
id = "swift"
[secret.backends.active]
type = "run-command"
user = "{user}"
command = "{root}/bin/backend-active"
args = ["swift"]
[secret.backends.reload]
type = "run-command"
user = "{user}"
command = "{root}/bin/backend-reload"
args = ["swift"]
[secret.backends.verify]
type = "bearer-probe"
url = "http://127.0.0.1:8092/v1/models"
expect_status = 200
old_expect_status = 401
[[secret.backends]]
id = "llama"
consumes_secret = false
[secret.backends.active]
type = "run-command"
user = "{user}"
command = "{root}/bin/backend-active"
args = ["llama"]

[[secret.checks]]
id = "omp"
[secret.checks.command]
type = "run-command"
user = "{user}"
command = "{root}/bin/consumer-check"
args = ["omp"]
[secret.checks.reload]
type = "run-command"
user = "{user}"
command = "{root}/bin/consumer-reload"
args = ["omp"]
[[secret.checks]]
id = "inbox-zero"
[secret.checks.command]
type = "run-command"
user = "{user}"
command = "{root}/bin/consumer-check"
args = ["inbox-zero"]
[secret.checks.reload]
type = "run-command"
user = "{user}"
command = "{root}/bin/consumer-reload"
args = ["inbox-zero"]

[[secret]]
id = "test/forbidden-secret"
policy = "forbidden"
reason = "data-encryption key; rotation requires migration"
[secret.store]
file = "secrets/test.env"
type = "dotenv"
key = "TEST_SECRET"

[[secret]]
id = "test/provider-secret"
policy = "provider-assisted"
human_step = "rotate in provider console, then paste the new secret"
[secret.store]
file = "secrets/provider.env"
type = "dotenv"
key = "PROVIDER_SECRET"
[[secret.consumers]]
type = "dotenv-file"
path = "{root}/deployed-provider.env"
key = "PROVIDER_SECRET"
owner = "{user}"
mode = 256
[[secret.verify]]
type = "http-status"
url = "https://example.test/ping"
expect_status = 200

[[secret]]
id = "test/verify-fails"
policy = "auto"
[secret.store]
file = "secrets/verify-fail.env"
type = "dotenv"
key = "VF_SECRET"
[secret.generation]
type = "hex"
bytes = 32
[[secret.verify]]
type = "http-status"
url = "https://example.test/broken"
expect_status = 200
"#,
        root = root.display(),
        user = user,
    );
    std::fs::write(root.join("registry.toml"), registry).expect("write registry");

    // Broker config.
    let config = format!(
        r#"socket_path = "{root}/run/sock"
registry_path = "{root}/registry.toml"
audit_path = "{root}/logs/audit.log"
work_dir = "{root}/work"
sops_bin = "{root}/bin/sops"
age_key_file = "{root}/age.key"
backup_dir = "{root}/backup"
access_group = "{group}"
allowed_uids = [{uids}]
"#,
        root = root.display(),
        group = group,
        uids = allowed_uids
            .iter()
            .map(|u| u.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );
    std::fs::write(root.join("brokerd.toml"), config).expect("write config");
    std::fs::write(root.join("age.key"), "AGE-TEST-ONLY-NOT-A-REAL-KEY\n").expect("key");

    Fixture { root, broker: None }
}

fn start_broker(fixture: &mut Fixture) {
    let bin = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/stile-brokerd");
    let stdout_file = std::fs::File::create(fixture.root.join("logs/broker-stdout")).unwrap();
    let stderr_file = std::fs::File::create(fixture.root.join("logs/broker-stderr")).unwrap();
    let child = Command::new(bin)
        .arg(fixture.root.join("brokerd.toml"))
        .env("STILE_TEST_CURL", fixture.root.join("bin/curl"))
        .env("STILE_TEST_RUNUSER", fixture.root.join("bin/runuser"))
        .env("STILE_TEST_DOCKER", fixture.root.join("bin/docker"))
        .stdout(Stdio::from(stdout_file))
        .stderr(Stdio::from(stderr_file))
        .spawn()
        .expect("spawn broker");
    fixture.broker = Some(child);

    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if fixture.root.join("run/sock").exists() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("broker socket did not appear");
}

/// Send a raw line, read the first response line, parse as JSON.
fn exchange(fixture: &Fixture, raw_line: &str) -> Value {
    let mut stream = UnixStream::connect(fixture.root.join("run/sock")).expect("connect");
    stream.write_all(raw_line.as_bytes()).expect("write");
    let first = read_one_line(&mut stream);
    serde_json::from_str(&first).expect("response json")
}

fn request(fixture: &Fixture, request: &stile_protocol::Request) -> Value {
    exchange(fixture, &stile_protocol::encode_request(request))
}

fn report(json: &Value) -> OperationReportView {
    assert_eq!(json["type"], "Report", "expected a report response: {json}");
    serde_json::from_value(json.clone()).expect("report view")
}

/// Read a single newline-terminated line from the stream.
fn read_one_line(stream: &mut UnixStream) -> String {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match stream.read(&mut byte) {
            Ok(0) => break,
            Ok(_) if byte[0] == b'\n' => break,
            Ok(_) => line.push(byte[0]),
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&line).into_owned()
}

#[allow(dead_code)] // documents the wire shape; not every field is asserted
#[derive(Debug, serde::Deserialize)]
struct OperationReportView {
    status: String,
    operation: String,
    #[serde(default)]
    secret: Option<String>,
    store_updated: bool,
    runtime_updated: bool,
    services_reloaded: bool,
    verification_passed: bool,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    old_credential_revoked: Option<bool>,
    #[serde(default)]
    fingerprint_changed: Option<bool>,
}

/// Scan every disclosure channel for the sentinels.
fn assert_no_sentinel(fixture: &Fixture, sentinels: &[&str]) {
    let channels = [
        "logs/audit.log",
        "logs/sops.argv",
        "logs/curl.argv",
        "logs/curl.decisions",
        "logs/runuser.argv",
        "logs/reload.argv",
        "logs/broker-stdout",
        "logs/broker-stderr",
        "logs/backend-reload.log",
        "logs/consumer-reload.log",
    ];
    // Credential staging inside the broker's work dir must not outlive
    // the operation that created it.
    if let Ok(entries) = std::fs::read_dir(fixture.root.join("work")) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            assert!(
                !name.starts_with("hdr-"),
                "leftover credential header file in work dir: {name}"
            );
        }
    }
    for channel in channels {
        let path = fixture.root.join(channel);
        let content = std::fs::read_to_string(&path).unwrap_or_default();
        for sentinel in sentinels {
            assert!(
                !content.contains(sentinel),
                "SENTINEL LEAK in {channel}: found sentinel (len {})",
                sentinel.len()
            );
        }
    }
}

fn current_deployed_secret(fixture: &Fixture) -> String {
    let text = std::fs::read_to_string(fixture.root.join("deployed.env")).unwrap();
    stile_core::dotenv::get(&stile_core::dotenv::parse(&text), "TEST_SECRET")
        .expect("TEST_SECRET present")
        .to_string()
}

// ─── tests ─────────────────────────────────────────────────────────────

#[test]
fn unknown_secret_is_rejected() {
    let (_, group) = current_user_group();
    let uid = uid_gid().0;
    let mut fixture = build_fixture(&group, &[uid]);
    start_broker(&mut fixture);
    let json = request(
        &fixture,
        &stile_protocol::Request::Status {
            secret: "nope/does-not-exist".into(),
        },
    );
    let view = report(&json);
    assert_eq!(view.status, "error");
    assert!(view.message.unwrap().contains("unknown logical secret"));
}

#[test]
fn forbidden_policy_is_refused_without_touching_the_store() {
    let (_, group) = current_user_group();
    let uid = uid_gid().0;
    let mut fixture = build_fixture(&group, &[uid]);
    start_broker(&mut fixture);
    let json = request(
        &fixture,
        &stile_protocol::Request::Rotate {
            secret: "test/forbidden-secret".into(),
        },
    );
    let view = report(&json);
    assert_eq!(view.status, "error");
    let message = view.message.unwrap();
    assert!(message.contains("forbidden"), "message: {message}");
    assert!(!view.store_updated);
    // Store untouched: no sops invocation happened.
    let sops_log = std::fs::read_to_string(fixture.root.join("logs/sops.argv")).unwrap_or_default();
    assert!(
        !sops_log.contains("encrypt"),
        "store was written: {sops_log}"
    );
}

#[test]
fn list_shows_ids_and_policies() {
    let (_, group) = current_user_group();
    let uid = uid_gid().0;
    let mut fixture = build_fixture(&group, &[uid]);
    start_broker(&mut fixture);
    let json = request(&fixture, &stile_protocol::Request::List);
    let view = report(&json);
    assert_eq!(view.status, "success");
    let message = view.message.unwrap();
    assert!(message.contains("test/auto-secret auto"));
    assert!(message.contains("test/forbidden-secret forbidden"));
    assert!(message.contains("test/provider-secret provider-assisted"));
}

#[test]
fn full_rotation_flow_updates_everything_and_discloses_nothing() {
    let (_user, group) = current_user_group();
    let uid = uid_gid().0;
    let mut fixture = build_fixture(&group, &[uid]);
    start_broker(&mut fixture);

    let old_sentinel = "OLD-SENTINEL-4f3c2b1a-not-a-real-secret";
    let json = request(
        &fixture,
        &stile_protocol::Request::Rotate {
            secret: "test/auto-secret".into(),
        },
    );
    let view = report(&json);
    assert_eq!(view.status, "success", "raw: {json}");
    assert!(view.store_updated);
    assert!(view.runtime_updated);
    assert!(view.services_reloaded);
    assert!(view.verification_passed);

    // Runtime file has a NEW value, different from the old sentinel,
    // hex-shaped, and other keys preserved.
    let deployed = current_deployed_secret(&fixture);
    assert_ne!(deployed, old_sentinel);
    assert_eq!(deployed.len(), 64);
    let text = std::fs::read_to_string(fixture.root.join("deployed.env")).unwrap();
    assert!(text.contains("OTHER_KEY=keepme"));

    // Reload actually ran via the fake runuser.
    let reload_log =
        std::fs::read_to_string(fixture.root.join("logs/reload.argv")).unwrap_or_default();
    assert!(reload_log.contains("stack-restarted"));

    // The store now decrypts (via fake) to the new value.
    let stored = std::fs::read(fixture.root.join("repo/secrets/test.env")).unwrap();
    let plain = demarkered(&stored).expect("still fake-encrypted");
    assert!(String::from_utf8_lossy(&plain).contains(&deployed));

    // Permissions preserved on the store file.
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(fixture.root.join("repo/secrets/test.env"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o644);

    // An encrypted backup of the ORIGINAL exists.
    let backups: Vec<_> = std::fs::read_dir(fixture.root.join("backup"))
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.to_string_lossy().ends_with(".sops.bak"))
        .collect();
    assert_eq!(backups.len(), 1);

    // Non-disclosure across every channel for old AND new values.
    assert_no_sentinel(&fixture, &[old_sentinel, deployed.as_str()]);
}

#[test]
fn binary_secret_rotation_with_old_key_revocation_probe() {
    let (_user, group) = current_user_group();
    let uid = uid_gid().0;
    let mut fixture = build_fixture(&group, &[uid]);
    // Register the old token as "old" for the fake curl (read from store).
    let stored = std::fs::read(fixture.root.join("repo/secrets/test.key")).unwrap();
    let old = String::from_utf8_lossy(&demarkered(&stored).unwrap())
        .trim()
        .to_string();
    std::fs::write(fixture.root.join("tokens-old"), &old).unwrap();
    // The deployed key file becomes the "new" token AFTER rotation; the
    std::fs::write(fixture.root.join("server-token"), &old).unwrap();
    // fake curl treats any token not in tokens-old as new → 200.
    start_broker(&mut fixture);

    let json = request(
        &fixture,
        &stile_protocol::Request::Rotate {
            secret: "test/binary-secret".into(),
        },
    );
    let view = report(&json);
    assert_eq!(view.status, "success", "raw: {json}");
    assert!(view.verification_passed);
    assert_eq!(view.old_credential_revoked, Some(true));

    let new_deployed = std::fs::read_to_string(fixture.root.join("deployed.key")).unwrap();
    let new = new_deployed.trim();
    assert_eq!(new.len(), 64);
    assert_ne!(new, old);
    assert_no_sentinel(&fixture, &[old.as_str(), new]);
}

#[test]
fn backend_transition_uses_active_endpoint_8090_then_8092() {
    let (_, group) = current_user_group();
    let uid = uid_gid().0;
    let mut fixture = build_fixture(&group, &[uid]);
    let stored = std::fs::read(fixture.root.join("repo/secrets/test.key")).unwrap();
    let current = demarkered(&stored).unwrap();
    std::fs::write(fixture.root.join("server-token"), &current).unwrap();
    start_broker(&mut fixture);

    let syv = request(
        &fixture,
        &stile_protocol::Request::Verify {
            secret: "test/binary-secret".into(),
        },
    );
    assert!(report(&syv).verification_passed, "raw: {syv}");
    let first_log = std::fs::read_to_string(fixture.root.join("logs/curl.argv")).unwrap();
    assert!(first_log.contains("127.0.0.1:8090"));
    assert!(!first_log.contains("127.0.0.1:8092"));

    std::fs::write(fixture.root.join("active-backend"), "swift\n").unwrap();
    std::fs::write(fixture.root.join("logs/curl.argv"), "").unwrap();
    let swift = request(
        &fixture,
        &stile_protocol::Request::Verify {
            secret: "test/binary-secret".into(),
        },
    );
    assert!(report(&swift).verification_passed, "raw: {swift}");
    let second_log = std::fs::read_to_string(fixture.root.join("logs/curl.argv")).unwrap();
    assert!(second_log.contains("127.0.0.1:8092"));
    assert!(!second_log.contains("127.0.0.1:8090"));
}

#[test]
fn reconcile_keeps_credential_and_repairs_stale_active_backend() {
    let (_, group) = current_user_group();
    let uid = uid_gid().0;
    let mut fixture = build_fixture(&group, &[uid]);
    let store_before = std::fs::read(fixture.root.join("repo/secrets/test.key")).unwrap();
    let current = demarkered(&store_before).unwrap();
    std::fs::write(fixture.root.join("deployed.key"), &current).unwrap();
    std::fs::write(
        fixture.root.join("server-token"),
        "stale-server-only-test-value",
    )
    .unwrap();
    std::fs::write(fixture.root.join("active-backend"), "swift\n").unwrap();
    std::fs::remove_file(fixture.root.join("omp-healthy")).unwrap();
    std::fs::remove_file(fixture.root.join("inbox-zero-healthy")).unwrap();
    // SAFETY: integration tests run serially under nextest's process model.
    unsafe { std::env::set_var("STILE_TEST_VERIFY_ATTEMPTS", "1") };
    start_broker(&mut fixture);

    let stale = request(
        &fixture,
        &stile_protocol::Request::Verify {
            secret: "test/binary-secret".into(),
        },
    );
    let stale_report = report(&stale);
    assert_eq!(stale_report.status, "error");
    assert!(!stale_report.verification_passed);

    let reconciled = request(
        &fixture,
        &stile_protocol::Request::Reconcile {
            secret: "test/binary-secret".into(),
        },
    );
    let reconciled_report = report(&reconciled);
    assert_eq!(reconciled_report.status, "success", "raw: {reconciled}");
    assert!(reconciled_report.verification_passed);
    assert_eq!(reconciled_report.fingerprint_changed, Some(false));
    assert!(!reconciled_report.store_updated);
    assert!(!reconciled_report.runtime_updated);
    assert!(reconciled_report.services_reloaded);
    assert_eq!(
        std::fs::read(fixture.root.join("repo/secrets/test.key")).unwrap(),
        store_before,
        "reconcile must not rotate or rewrite the encrypted store"
    );
    assert_eq!(
        std::fs::read_to_string(fixture.root.join("logs/backend-reload.log"))
            .unwrap()
            .trim(),
        "swift"
    );
    let consumer_reloads =
        std::fs::read_to_string(fixture.root.join("logs/consumer-reload.log")).unwrap();
    assert!(consumer_reloads.lines().any(|line| line == "omp"));
    assert!(consumer_reloads.lines().any(|line| line == "inbox-zero"));
    let runuser_log = std::fs::read_to_string(fixture.root.join("logs/runuser.argv")).unwrap();
    assert!(runuser_log.contains("HOME="));
    assert!(runuser_log.contains("USER="));
    assert!(runuser_log.contains("LOGNAME="));
    let curl_log = std::fs::read_to_string(fixture.root.join("logs/curl.argv")).unwrap();
    assert!(curl_log.contains("127.0.0.1:8092"));
}

#[test]
fn failed_encrypt_rolls_back_byte_for_byte() {
    let (_user, group) = current_user_group();
    let uid = uid_gid().0;
    let mut fixture = build_fixture(&group, &[uid]);
    let original = std::fs::read(fixture.root.join("repo/secrets/test.env")).unwrap();
    std::fs::write(fixture.root.join("fail-encrypt"), "1").unwrap();
    start_broker(&mut fixture);

    let json = request(
        &fixture,
        &stile_protocol::Request::Rotate {
            secret: "test/auto-secret".into(),
        },
    );
    let view = report(&json);
    assert_eq!(view.status, "error");
    assert!(!view.store_updated);

    let after = std::fs::read(fixture.root.join("repo/secrets/test.env")).unwrap();
    assert_eq!(
        original, after,
        "store must be byte-identical after failure"
    );
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(fixture.root.join("repo/secrets/test.env"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o644);
    // Deployed file untouched.
    assert!(
        std::fs::read_to_string(fixture.root.join("deployed.env"))
            .unwrap()
            .contains("whatever-old")
    );
}

#[test]
fn unencrypted_store_is_refused_and_alarmed() {
    // Library-level check (no broker needed for this path).
    let root = std::env::temp_dir().join(format!("stile-plain-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("repo")).unwrap();
    std::fs::write(root.join("repo/plain.env"), "TEST_SECRET=plaintext\n").unwrap();
    let store = stile_core::sops::SopsStore::new(stile_core::sops::SopsConfig {
        sops_bin: PathBuf::from("/bin/false"),
        age_key_file: PathBuf::from("/nonexistent"),
        work_dir: root.join("work"),
        backup_dir: root.join("backup"),
        backups_kept: 2,
    })
    .unwrap();
    let location = stile_core::backend::StoreLocation {
        path: root.join("repo/plain.env"),
        dotenv_key: Some("TEST_SECRET".into()),
    };
    use stile_core::backend::SecretStore as _;
    let err = store.read_value(&location).unwrap_err();
    assert!(matches!(
        err,
        stile_core::backend::StoreError::Unencrypted(_)
    ));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn verification_failure_marks_report_and_audits() {
    let (_user, group) = current_user_group();
    let uid = uid_gid().0;
    let mut fixture = build_fixture(&group, &[uid]);
    // SAFETY: single-threaded test process.
    unsafe { std::env::set_var("STILE_TEST_VERIFY_ATTEMPTS", "1") };
    // Fake curl returns 500 for this URL.
    std::fs::write(fixture.root.join("curl-status"), "500").unwrap();
    start_broker(&mut fixture);
    let json = request(
        &fixture,
        &stile_protocol::Request::Rotate {
            secret: "test/verify-fails".into(),
        },
    );
    let view = report(&json);
    // Rotation applied, but the operation must not report success while its
    // declared path is failing verification.
    assert_eq!(view.status, "error");
    assert!(view.store_updated);
    assert!(!view.verification_passed);
    // Audit captured the failed verify stage.
    let audit = std::fs::read_to_string(fixture.root.join("logs/audit.log")).unwrap();
    assert!(audit.contains("verify"));
    assert!(audit.contains("failed"));
}

#[test]
fn unauthorized_caller_is_rejected_at_the_socket() {
    // Broker's access group is one we are NOT in, allowlist empty.
    let mut fixture = build_fixture("nogroup", &[]);
    start_broker(&mut fixture);
    let json = request(&fixture, &stile_protocol::Request::List);
    let view = report(&json);
    assert_eq!(view.status, "error");
    assert!(view.message.unwrap().contains("not authorized"));
}

#[test]
fn malformed_and_banned_requests_are_rejected() {
    let (_, group) = current_user_group();
    let uid = uid_gid().0;
    let mut fixture = build_fixture(&group, &[uid]);
    start_broker(&mut fixture);

    let json = exchange(&fixture, "this is not json\n");
    let view = report(&json);
    assert_eq!(view.status, "error");
    assert!(view.message.unwrap().contains("malformed"));

    let banned = r#"{"op":"get-secret","secret":"test/auto-secret"}"#;
    let json = exchange(&fixture, &format!("{banned}\n"));
    let view = report(&json);
    assert_eq!(view.status, "error");

    let banned = r#"{"op":"export_secret","secret":"test/auto-secret"}"#;
    let json = exchange(&fixture, &format!("{banned}\n"));
    assert_eq!(report(&json).status, "error");
}

#[test]
fn provider_assisted_import_persists_without_disclosure() {
    let (_user, group) = current_user_group();
    let uid = uid_gid().0;
    let mut fixture = build_fixture(&group, &[uid]);
    start_broker(&mut fixture);

    let imported_sentinel = "NEW-PROVIDER-SENTINEL-not-a-real-secret";
    let mut stream = UnixStream::connect(fixture.root.join("run/sock")).unwrap();
    stream
        .write_all(
            stile_protocol::encode_request(&stile_protocol::Request::ImportProviderSecret {
                secret: "test/provider-secret".into(),
            })
            .as_bytes(),
        )
        .unwrap();
    let first = read_one_line(&mut stream);
    assert!(
        first.contains("ReadyForImport"),
        "expected ready-for-import, got: {first}"
    );
    stream
        .write_all(
            stile_protocol::encode_request(&stile_protocol::Request::ImportValue {
                value: imported_sentinel.into(),
            })
            .as_bytes(),
        )
        .unwrap();
    let first = read_one_line(&mut stream);
    assert!(!first.contains(imported_sentinel));
    let json: Value = serde_json::from_str(&first).unwrap();
    let view = report(&json);
    assert_eq!(view.status, "success", "raw {json}");
    assert!(view.store_updated);

    // Persisted in the store (via fake decrypt) and deployed.
    let stored = std::fs::read(fixture.root.join("repo/secrets/provider.env")).unwrap();
    assert!(String::from_utf8_lossy(&stored).contains("SOPSFAKE:"));
    let plain = demarkered(&stored).unwrap();
    assert!(String::from_utf8_lossy(&plain).contains(imported_sentinel));
    assert!(
        std::fs::read_to_string(fixture.root.join("deployed-provider.env"))
            .unwrap()
            .contains(imported_sentinel)
    );

    assert_no_sentinel(&fixture, &[imported_sentinel]);
}

#[test]
fn import_requires_provider_assisted_policy() {
    let (_, group) = current_user_group();
    let uid = uid_gid().0;
    let mut fixture = build_fixture(&group, &[uid]);
    start_broker(&mut fixture);
    let mut stream = UnixStream::connect(fixture.root.join("run/sock")).unwrap();
    stream
        .write_all(
            stile_protocol::encode_request(&stile_protocol::Request::ImportProviderSecret {
                secret: "test/auto-secret".into(),
            })
            .as_bytes(),
        )
        .unwrap();
    let response = read_one_line(&mut stream);
    assert!(
        response.contains("not provider-assisted"),
        "got: {response}"
    );
}

#[test]
fn verify_bearer_direct_library_check() {
    let (_, group) = current_user_group();
    let uid = uid_gid().0;
    let fixture = build_fixture(&group, &[uid]);
    // SAFETY: single-threaded test process, before any threads spawn.
    unsafe { std::env::set_var("STILE_TEST_CURL", fixture.root.join("bin/curl")) };
    std::fs::write(
        fixture.root.join("tokens-old"),
        "old-binary-sentinel-9911-not-real",
    )
    .unwrap();
    let result = stile_core::verify::verify_bearer(
        "http://127.0.0.1:9/v1/models",
        "new-token-abc",
        Some("old-binary-sentinel-9911-not-real\n"),
        200,
        Some(401),
        &fixture.root.join("work"),
    )
    .unwrap();
    eprintln!("verify_bearer direct result: {result}");
    assert!(result);
}

#[test]
fn cli_binary_end_to_end() {
    let (_, group) = current_user_group();
    let uid = uid_gid().0;
    let mut fixture = build_fixture(&group, &[uid]);
    start_broker(&mut fixture);
    // Repo-local target dir only: CARGO_TARGET_DIR may point at a shared
    // cache holding stale binaries.
    let cli = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/release/stile");
    if !cli.exists() {
        eprintln!("skipping: {cli:?} not built (run cargo build --release --target-dir target)");
        return;
    }
    let out = Command::new(&cli)
        .arg("--socket")
        .arg(fixture.root.join("run/sock"))
        .arg("list")
        .output()
        .expect("run cli");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let json: Value = serde_json::from_str(&stdout).expect("cli prints one JSON object");
    let view: OperationReportView = serde_json::from_value(json).expect("view");
    assert_eq!(view.status, "success");
    assert!(view.message.unwrap().contains("test/auto-secret auto"));

    let out = Command::new(&cli)
        .arg("--socket")
        .arg(fixture.root.join("run/sock"))
        .arg("rotate")
        .arg("test/auto-secret")
        .output()
        .expect("run cli rotate");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let json: Value =
        serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).expect("rotate json");
    let view: OperationReportView = serde_json::from_value(json).expect("view");
    assert!(view.store_updated && view.verification_passed);
}

// ─── adversarial / protocol-abuse tests ───────────────────────────────

/// A request line far beyond the cap is rejected, the connection is
/// closed, and the broker keeps serving other clients.
#[test]
fn oversized_request_is_rejected_and_broker_survives() {
    let (_, group) = current_user_group();
    let uid = uid_gid().0;
    let mut fixture = build_fixture(&group, &[uid]);
    start_broker(&mut fixture);

    let junk = "x".repeat(200 * 1024);
    let mut stream = UnixStream::connect(fixture.root.join("run/sock")).unwrap();
    stream.write_all(format!("{junk}\n").as_bytes()).unwrap();
    let response = read_one_line(&mut stream);
    let view = report(&serde_json::from_str(&response).expect("json"));
    assert_eq!(view.status, "error");
    assert!(
        response.contains("size limit"),
        "expected size-limit rejection, got: {response}"
    );
    drop(stream);

    // The broker must still serve a normal request afterwards.
    let json = request(&fixture, &stile_protocol::Request::List);
    assert_eq!(report(&json).status, "success");
}

/// An import value beyond the cap is refused without touching the store.
#[test]
fn oversized_import_value_is_rejected() {
    let (_, group) = current_user_group();
    let uid = uid_gid().0;
    let mut fixture = build_fixture(&group, &[uid]);
    start_broker(&mut fixture);
    let store_before = std::fs::read(fixture.root.join("repo/secrets/provider.env")).unwrap();

    let mut stream = UnixStream::connect(fixture.root.join("run/sock")).unwrap();
    stream
        .write_all(
            stile_protocol::encode_request(&stile_protocol::Request::ImportProviderSecret {
                secret: "test/provider-secret".into(),
            })
            .as_bytes(),
        )
        .unwrap();
    let first = read_one_line(&mut stream);
    assert!(first.contains("ReadyForImport"), "got: {first}");

    let huge = "v".repeat(2 * 1024 * 1024);
    let payload = format!("{{\"op\":\"import-value\",\"value\":\"{huge}\"}}\n");
    // The broker aborts the connection as soon as the cap is exceeded;
    // a broken pipe mid-write is the expected outcome.
    let mut bytes = payload.as_bytes();
    while !bytes.is_empty() {
        match stream.write(bytes) {
            Ok(0) | Err(_) => break,
            Ok(n) => bytes = &bytes[n..],
        }
    }
    let _ = std::io::Write::flush(&mut stream);
    let response = read_one_line(&mut stream);
    assert!(
        response.contains("size limit"),
        "expected size-limit rejection, got: {response}"
    );
    assert!(!response.contains("vvvv"), "response echoed payload");
    assert_eq!(
        std::fs::read(fixture.root.join("repo/secrets/provider.env")).unwrap(),
        store_before,
        "oversized import must not touch the store"
    );
}

/// A client that connects and stalls must not block everyone else: the
/// broker drops it after the (test-shortened) read timeout.
#[test]
fn stalled_connection_does_not_block_other_clients() {
    let (_, group) = current_user_group();
    let uid = uid_gid().0;
    let mut fixture = build_fixture(&group, &[uid]);
    // SAFETY: single-threaded test process, before any threads spawn.
    unsafe { std::env::set_var("STILE_TEST_REQUEST_TIMEOUT_SECS", "2") };
    start_broker(&mut fixture);

    let mut stalled = UnixStream::connect(fixture.root.join("run/sock")).unwrap();
    stalled.write_all(b"{\"op\":\"li").unwrap(); // partial frame, no newline

    let started = Instant::now();
    let json = request(&fixture, &stile_protocol::Request::List);
    assert_eq!(report(&json).status, "success");
    assert!(
        started.elapsed() < Duration::from_secs(30),
        "stalled client blocked the broker"
    );
    drop(stalled);
}

/// Every banned or smuggled request shape is rejected with an error that
/// carries no sentinel and no unexpected response fields.
#[test]
fn banned_and_smuggled_request_shapes_are_rejected() {
    let (_, group) = current_user_group();
    let uid = uid_gid().0;
    let mut fixture = build_fixture(&group, &[uid]);
    start_broker(&mut fixture);

    let attacks = [
        r#"{"op":"reveal","secret":"test/auto-secret"}"#,
        r#"{"op":"decrypt","secret":"test/auto-secret"}"#,
        r#"{"op":"exec","command":"cat","args":["/etc/shadow"]}"#,
        r#"{"op":"read_file","path":"/etc/stile/brokerd.toml"}"#,
        r#"{"op":"status","secret":"test/auto-secret","value":"x"}"#,
        r#"{"op":"status","secret":"test/auto-secret","extra":true}"#,
        r#"{"op":"status","secret":123}"#,
        r#"{"op":"status"}"#,
        r#"{"op":"rotate","secret":"../../etc/passwd"}"#,
        r#"{"op":"rotate","secret":"test/auto-secret","provided":"NEW-VALUE"}"#,
        "[]",
        "null",
    ];
    for attack in attacks {
        let json = exchange(&fixture, &format!("{attack}\n"));
        let response = json.to_string();
        let view = report(&json);
        assert_eq!(view.status, "error", "attack accepted: {attack}");
        assert!(
            !response.contains("OLD-SENTINEL"),
            "attack {attack}: response disclosed sentinel: {response}"
        );
    }
    // Path-traversal ids must not have reached sops either.
    let sops_log = std::fs::read_to_string(fixture.root.join("logs/sops.argv")).unwrap_or_default();
    assert!(
        !sops_log.contains(".."),
        "traversal id reached sops: {sops_log}"
    );
}

/// The rotate response itself (not just files) carries neither sentinel
/// nor any field capable of carrying one.
#[test]
fn rotate_response_carries_no_secret_material() {
    let (_, group) = current_user_group();
    let uid = uid_gid().0;
    let mut fixture = build_fixture(&group, &[uid]);
    start_broker(&mut fixture);
    let old_sentinel = "OLD-SENTINEL-4f3c2b1a-not-a-real-secret";

    let json = request(
        &fixture,
        &stile_protocol::Request::Rotate {
            secret: "test/auto-secret".into(),
        },
    );
    let raw = json.to_string();
    assert!(!raw.contains(old_sentinel), "response leaked old value");
    let deployed = current_deployed_secret(&fixture);
    assert!(!raw.contains(&deployed), "response leaked new value");

    // Every key in the response must be from the closed schema.
    fn assert_known_keys(value: &Value) {
        match value {
            Value::Object(map) => {
                for (key, inner) in map {
                    assert!(
                        [
                            "type",
                            "status",
                            "operation",
                            "secret",
                            "store_updated",
                            "runtime_updated",
                            "services_reloaded",
                            "verification_passed",
                            "fingerprint_changed",
                            "old_credential_revoked",
                            "stages",
                            "stage",
                            "result",
                            "detail",
                            "message",
                        ]
                        .contains(&key.as_str()),
                        "unexpected response field: {key}"
                    );
                    assert_known_keys(inner);
                }
            }
            Value::Array(items) => items.iter().for_each(assert_known_keys),
            _ => {}
        }
    }
    assert_known_keys(&json);
}

/// A symlink planted at the encrypted store path must not be written
/// through, and the victim file must remain byte-identical.
#[test]
fn symlinked_store_file_is_refused() {
    let (_, group) = current_user_group();
    let uid = uid_gid().0;
    let mut fixture = build_fixture(&group, &[uid]);
    let victim = fixture.root.join("victim.txt");
    std::fs::write(&victim, "VICTIM-ORIGINAL-CONTENT\n").unwrap();
    std::fs::remove_file(fixture.root.join("repo/secrets/test.env")).unwrap();
    std::os::unix::fs::symlink(&victim, fixture.root.join("repo/secrets/test.env")).unwrap();
    start_broker(&mut fixture);

    let json = request(
        &fixture,
        &stile_protocol::Request::Rotate {
            secret: "test/auto-secret".into(),
        },
    );
    let view = report(&json);
    assert_eq!(view.status, "error");
    assert!(!view.store_updated);
    assert_eq!(
        std::fs::read(&victim).unwrap(),
        b"VICTIM-ORIGINAL-CONTENT\n",
        "broker wrote through the symlink"
    );
    assert_eq!(
        std::fs::read_to_string(&victim).unwrap(),
        "VICTIM-ORIGINAL-CONTENT\n",
        "victim content must be untouched"
    );
}

/// The broker must refuse to start on a world-writable socket directory.
#[test]
fn world_writable_socket_dir_refuses_to_start() {
    let (_, group) = current_user_group();
    let uid = uid_gid().0;
    let fixture = build_fixture(&group, &[uid]); // no start_broker
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(
        fixture.root.join("run"),
        std::fs::Permissions::from_mode(0o777),
    )
    .unwrap();
    let bin = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/stile-brokerd");
    let out = Command::new(bin)
        .arg(fixture.root.join("brokerd.toml"))
        .output()
        .expect("spawn broker");
    assert!(!out.status.success(), "broker started on insecure dir");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("world-writable"),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!fixture.root.join("run/sock").exists());
}

/// Audit records must carry pid and duration but never values.
#[test]
fn audit_records_carry_pid_and_duration() {
    let (_, group) = current_user_group();
    let uid = uid_gid().0;
    let mut fixture = build_fixture(&group, &[uid]);
    start_broker(&mut fixture);
    let json = request(
        &fixture,
        &stile_protocol::Request::Rotate {
            secret: "test/auto-secret".into(),
        },
    );
    assert_eq!(report(&json).status, "success");
    let audit = std::fs::read_to_string(fixture.root.join("logs/audit.log")).unwrap();
    let line = audit
        .lines()
        .rev()
        .find(|l| l.contains("\"rotate\""))
        .expect("rotate audit record");
    let record: Value = serde_json::from_str(line).expect("audit json");
    assert!(record["pid"].is_u64(), "pid missing: {line}");
    assert!(record["duration_ms"].is_u64(), "duration missing: {line}");
    assert!(record["uid"].is_u64());
    let deployed = current_deployed_secret(&fixture);
    assert!(!audit.contains(&deployed));
    assert!(!audit.contains("OLD-SENTINEL"));
}
