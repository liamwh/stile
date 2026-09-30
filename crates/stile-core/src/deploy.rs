//! Runtime consumer deployment and declared reload actions. All commands
//! come from the root-owned registry; the protocol has no execution
//! primitive. Secret values reach files via in-process writes and reach
//! subprocesses via stdin only — never argv.

use crate::registry::{ConsumerDef, ConsumerKind, PreReloadDef, ReloadDef};
use crate::{dotenv, sanitize_output_for_log};
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};

/// Deployment errors; messages are safe to log.
#[derive(Debug, thiserror::Error)]
pub enum DeployError {
    /// Filesystem failure.
    #[error("io: {0}")]
    Io(String),
    /// Declared owner unknown.
    #[error("unknown owner {0}")]
    UnknownOwner(String),
    /// Declared subprocess failed.
    #[error("command failed: {0}")]
    Command(String),
}

fn account_of(user: &str) -> Result<(u32, String), DeployError> {
    let cuser = std::ffi::CString::new(user).map_err(|_| DeployError::UnknownOwner(user.into()))?;
    // SAFETY: getpwnam(3) with a NUL-terminated name; the passwd
    // pointer is copied out before any other libc passwd call.
    unsafe {
        let pw = libc::getpwnam(cuser.as_ptr());
        if pw.is_null() {
            return Err(DeployError::UnknownOwner(user.into()));
        }
        let home = std::ffi::CStr::from_ptr((*pw).pw_dir)
            .to_string_lossy()
            .into_owned();
        Ok(((*pw).pw_uid, home))
    }
}

fn uid_of(user: &str) -> Result<u32, DeployError> {
    account_of(user).map(|(uid, _)| uid)
}

fn chown(path: &Path, uid: u32) -> Result<(), DeployError> {
    let cpath = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|e| DeployError::Io(e.to_string()))?;
    // SAFETY: FFI chown(2) with a NUL-terminated path; gid -1 (u32::MAX) leaves the group unchanged.
    let rc = unsafe { libc::chown(cpath.as_ptr(), uid, u32::MAX) };
    if rc != 0 {
        return Err(DeployError::Io(format!(
            "chown {}: errno {rc}",
            path.display()
        )));
    }
    Ok(())
}

fn desired_consumer_content(consumer: &ConsumerDef, value: &[u8]) -> Result<Vec<u8>, DeployError> {
    match consumer.kind {
        ConsumerKind::RawFile => {
            let mut content = value.to_vec();
            if !content.ends_with(b"\n") {
                content.push(b'\n');
            }
            Ok(content)
        }
        ConsumerKind::DotenvFile => {
            let key = consumer
                .key
                .as_deref()
                .ok_or_else(|| DeployError::Io("dotenv-file consumer requires key".into()))?;
            let existing = fs::read_to_string(&consumer.path).unwrap_or_default();
            Ok(dotenv::serialize(&dotenv::set(
                &dotenv::parse(&existing),
                key,
                &String::from_utf8_lossy(value),
            ))
            .into_bytes())
        }
    }
}

/// Update a runtime consumer with the new value.
pub fn deploy_consumer(consumer: &ConsumerDef, value: &[u8]) -> Result<(), DeployError> {
    let parent = consumer
        .path
        .parent()
        .ok_or_else(|| DeployError::Io(format!("bad path {}", consumer.path.display())))?;
    fs::create_dir_all(parent).map_err(|e| DeployError::Io(e.to_string()))?;

    let new_content = desired_consumer_content(consumer, value)?;

    // Atomic-ish: stage a uniquely-named sibling (0600 from creation,
    // O_NOFOLLOW so a planted symlink cannot redirect the write, created
    // with O_EXCL so it cannot be pre-created), fsync, rename over the
    // target, then fix owner/mode. The secret is never world-readable on
    // disk, even transiently.
    let tmp = consumer.path.with_extension(format!(
        "stage-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp)
        {
            Ok(f) => f,
            Err(e) => {
                let _ = fs::remove_file(&tmp);
                return Err(DeployError::Io(format!("stage {}: {e}", tmp.display())));
            }
        };
        if let Err(e) = f.write_all(&new_content).and_then(|_| f.sync_all()) {
            let _ = fs::remove_file(&tmp);
            return Err(DeployError::Io(format!("stage {}: {e}", tmp.display())));
        }
    }
    if let Err(e) = fs::rename(&tmp, &consumer.path) {
        let _ = fs::remove_file(&tmp);
        return Err(DeployError::Io(e.to_string()));
    }
    fs::set_permissions(&consumer.path, fs::Permissions::from_mode(consumer.mode))
        .map_err(|e| DeployError::Io(e.to_string()))?;
    let uid = uid_of(&consumer.owner)?;
    chown(&consumer.path, uid)
}

/// Compare a deployed consumer with a stored value without returning either.
pub fn consumer_matches(consumer: &ConsumerDef, value: &[u8]) -> Result<bool, DeployError> {
    let expected = desired_consumer_content(consumer, value)?;
    match fs::read(&consumer.path) {
        Ok(actual) => Ok(actual == expected),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(DeployError::Io(e.to_string())),
    }
}

/// Run a pre-reload hook. The postgres hook pipes SQL (with the new
/// password embedded) through stdin to `docker exec -i` running psql as
/// the container's postgres OS user — the local trust socket needs no
/// password and nothing secret appears in argv.
pub fn run_pre_reload(hook: &PreReloadDef, new_value: &[u8]) -> Result<(), DeployError> {
    match hook.kind {
        crate::registry::PreReloadKind::PostgresRolePassword => {
            let escaped = String::from_utf8_lossy(new_value).replace('\'', "''");
            let sql = format!("ALTER ROLE {} PASSWORD '{}';\n", hook.role, escaped);
            let mut cmd = Command::new(crate::tools::docker());
            cmd.args(["exec", "-i", "-u", "postgres", &hook.container])
                .args([
                    "psql",
                    "-U",
                    "postgres",
                    "-d",
                    "postgres",
                    "-v",
                    "ON_ERROR_STOP=1",
                ])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let mut child = cmd
                .spawn()
                .map_err(|e| DeployError::Command(format!("docker exec: {e}")))?;
            if let Some(stdin) = child.stdin.as_mut() {
                stdin
                    .write_all(sql.as_bytes())
                    .map_err(|e| DeployError::Command(format!("stdin: {e}")))?;
            }
            let output = child
                .wait_with_output()
                .map_err(|e| DeployError::Command(e.to_string()))?;
            if !output.status.success() {
                // Subprocess stderr can echo received bytes (psql quotes
                // failing statements); it goes to the broker's journal
                // (root-readable) only, never into client-visible errors.
                eprintln!(
                    "stile-brokerd: pre-reload hook stderr: {}",
                    sanitize_output_for_log(&output.stderr)
                );
                return Err(DeployError::Command(format!(
                    "psql exited {:?}",
                    output.status.code()
                )));
            }
            Ok(())
        }
    }
}

fn declared_command(action: &ReloadDef) -> Result<std::process::Output, DeployError> {
    let (uid, home) = account_of(&action.user)?;
    let mut cmd = Command::new(crate::tools::runuser());
    cmd.arg("-u")
        .arg(&action.user)
        .arg("--")
        .arg("env")
        .arg("-i")
        .arg(format!("HOME={home}"))
        .arg(format!("USER={}", action.user))
        .arg(format!("LOGNAME={}", action.user))
        .arg(format!(
            "PATH={home}/.nix-profile/bin:/usr/local/bin:/usr/bin:/bin"
        ));
    if uid >= 1000 {
        let runtime = format!("/run/user/{uid}");
        cmd.arg(format!("XDG_RUNTIME_DIR={runtime}"))
            .arg(format!("DBUS_SESSION_BUS_ADDRESS=unix:path={runtime}/bus"));
    }
    cmd.arg(&action.command).args(&action.args);
    cmd.output()
        .map_err(|e| DeployError::Command(format!("runuser: {e}")))
}

/// Run a declared status command. Exit zero means selected/active; any other
/// exit status means not selected. Spawn failures remain errors.
pub fn command_succeeds(action: &ReloadDef) -> Result<bool, DeployError> {
    declared_command(action).map(|output| output.status.success())
}

/// Run a declared reload command as a declared user. Uses `runuser` (root
/// dropping to the user) with the user's systemd runtime environment so
/// `systemctl --user` and compose wrappers work.
pub fn run_reload(action: &ReloadDef) -> Result<(), DeployError> {
    let output = declared_command(action)?;
    if !output.status.success() {
        // See run_pre_reload: stderr detail stays in the journal.
        eprintln!(
            "stile-brokerd: declared command {} stderr: {}",
            action.command,
            sanitize_output_for_log(&output.stderr)
        );
        return Err(DeployError::Command(format!(
            "command exited {:?}",
            output.status.code()
        )));
    }
    Ok(())
}

/// Resolve a declared owner's uid (root context in production) — test helper.
#[cfg(test)]
pub fn test_uid_of(user: &str) -> Option<u32> {
    uid_of(user).ok()
}
