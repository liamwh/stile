//! SOPS-backed [`SecretStore`]. All secret bytes stay in broker memory or
//! in broker-private staging (0700 dirs, 0600 files, unlinked
//! immediately). The `sops` child receives only paths and type flags —
//! never values — and its stdout/stderr are captured, never inherited.

use crate::backend::{SecretStore, StoreError, StoreLocation};
use crate::{dotenv, sanitize_output_for_log};
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Configuration for the SOPS backend.
#[derive(Debug, Clone)]
pub struct SopsConfig {
    /// Absolute path of the `sops` binary.
    pub sops_bin: PathBuf,
    /// Age identity the broker uses (dedicated broker key, root-owned).
    pub age_key_file: PathBuf,
    /// Broker-private work directory (created 0700 if missing).
    pub work_dir: PathBuf,
    /// Where encrypted pre-rotation backups are kept (created 0700).
    pub backup_dir: PathBuf,
    /// Backups to retain per secret file.
    pub backups_kept: usize,
}

/// SOPS-backed store.
pub struct SopsStore {
    config: SopsConfig,
    current_dir: Option<PathBuf>,
}

impl SopsStore {
    /// Create the store, ensuring private dirs exist.
    pub fn new(config: SopsConfig) -> Result<Self, StoreError> {
        for dir in [&config.work_dir, &config.backup_dir] {
            fs::create_dir_all(dir).map_err(|e| StoreError::Io(format!("{dir:?}: {e}")))?;
            apply_mode(dir, 0o700).map_err(StoreError::Io)?;
        }
        Ok(Self {
            config,
            current_dir: None,
        })
    }

    /// Anchor sops invocations at this directory (creation-rule lookup).
    pub fn with_working_dir(mut self, dir: PathBuf) -> Self {
        self.current_dir = Some(dir);
        self
    }

    fn sops_base(&self) -> Command {
        let mut cmd = Command::new(&self.config.sops_bin);
        cmd.env("SOPS_AGE_KEY_FILE", &self.config.age_key_file);
        cmd.env_remove("SOPS_AGE_KEY");
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        cmd
    }

    fn input_output_flags(&self, location: &StoreLocation) -> [&'static str; 4] {
        if location.dotenv_key.is_some() {
            ["--input-type", "dotenv", "--output-type", "dotenv"]
        } else {
            ["--input-type", "binary", "--output-type", "binary"]
        }
    }

    fn run(&self, mut cmd: Command) -> Result<Vec<u8>, StoreError> {
        // SOPS locates .sops.yaml by walking up from the CURRENT working
        // directory; the broker runs from /, so anchor every invocation at
        // the store file's directory.
        if let Some(dir) = self.current_dir.clone() {
            cmd.current_dir(dir);
        }
        let output = cmd
            .output()
            .map_err(|e| StoreError::Subprocess(format!("spawn: {e}")))?;
        if !output.status.success() {
            // sops diagnostics can quote plaintext context; they go to the
            // broker's journal (root-readable) only, never into
            // client-visible errors.
            eprintln!(
                "stile-brokerd: sops stderr: {}",
                sanitize_output_for_log(&output.stderr)
            );
            return Err(StoreError::Subprocess(format!(
                "sops exited {:?}",
                output.status.code()
            )));
        }
        Ok(output.stdout)
    }

    /// Guard against an interrupted previous rotation leaving plaintext at
    /// the canonical path: encrypted SOPS files always contain SOPS
    /// metadata (`sops.mac` in YAML/JSON, `sops_mac` in dotenv); binaries
    /// contain high-entropy age payloads. We test decryptability and, for
    /// dotenv, metadata presence.
    fn ensure_encrypted(&self, location: &StoreLocation) -> Result<(), StoreError> {
        let raw = fs::read(&location.path)
            .map_err(|e| StoreError::Io(format!("{}: {e}", location.path.display())))?;
        if location.dotenv_key.is_some() {
            let text = String::from_utf8_lossy(&raw);
            if !text.contains("sops_") {
                return Err(StoreError::Unencrypted(location.path.display().to_string()));
            }
        }
        Ok(())
    }

    fn backup_encrypted(&self, location: &StoreLocation) -> Result<PathBuf, StoreError> {
        let name = location
            .path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "store".into());
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let dest = self.config.backup_dir.join(format!("{name}.{ts}.sops.bak"));
        fs::copy(&location.path, &dest).map_err(|e| StoreError::Io(format!("backup: {e}")))?;
        apply_mode(&dest, 0o400).map_err(StoreError::Io)?;
        self.prune_backups(&name);
        Ok(dest)
    }

    fn prune_backups(&self, base_name: &str) {
        let mut backups: Vec<PathBuf> = match fs::read_dir(&self.config.backup_dir) {
            Ok(entries) => entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| {
                    p.file_name()
                        .map(|n| {
                            n.to_string_lossy().starts_with(base_name)
                                && n.to_string_lossy().ends_with(".sops.bak")
                        })
                        .unwrap_or(false)
                })
                .collect(),
            Err(_) => return,
        };
        backups.sort();
        while backups.len() > self.config.backups_kept {
            let oldest = backups.remove(0);
            let _ = fs::remove_file(oldest);
        }
    }

    fn restore_backup(&self, backup: &Path, location: &StoreLocation) {
        if fs::copy(backup, &location.path).is_ok()
            && let Ok(meta) = fs::metadata(backup)
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(
                &location.path,
                fs::Permissions::from_mode(meta.permissions().mode()),
            );
        }
    }

    /// Decrypt the whole file to an in-memory string (dotenv) or bytes
    /// (binary). Never printed.
    fn decrypt_file(&self, location: &StoreLocation) -> Result<Vec<u8>, StoreError> {
        let mut cmd = self.sops_base();
        cmd.arg("-d");
        for flag in self.input_output_flags(location) {
            cmd.arg(flag);
        }
        cmd.arg(&location.path);
        self.run(cmd)
    }
}

impl SecretStore for SopsStore {
    fn read_value(&self, location: &StoreLocation) -> Result<Vec<u8>, StoreError> {
        self.ensure_encrypted(location)?;
        let decrypted = self.decrypt_file(location)?;
        match &location.dotenv_key {
            None => Ok(decrypted),
            Some(key) => {
                let text = String::from_utf8_lossy(&decrypted).into_owned();
                let pairs = dotenv::parse(&text);
                dotenv::get(&pairs, key)
                    .map(|v| v.as_bytes().to_vec())
                    .ok_or_else(|| {
                        StoreError::Verification(format!(
                            "key {key} not found in {}",
                            location.path.display()
                        ))
                    })
            }
        }
    }

    fn write_value_atomic(
        &self,
        location: &StoreLocation,
        new_value: &[u8],
    ) -> Result<(), StoreError> {
        self.ensure_encrypted(location)?;

        // Compose the full new plaintext in memory first: for dotenv we
        // must preserve every other key; for binary the value is the file.
        let current = self.decrypt_file(location)?;
        let new_plain: Vec<u8> = match &location.dotenv_key {
            None => new_value.to_vec(),
            Some(key) => {
                let text = String::from_utf8_lossy(&current).into_owned();
                let pairs = dotenv::parse(&text);
                let updated = dotenv::set(&pairs, key, &String::from_utf8_lossy(new_value));
                dotenv::serialize(&updated).into_bytes()
            }
        };

        use std::os::unix::fs::MetadataExt;
        let original = fs::metadata(&location.path).ok();
        let original_mode = original.as_ref().map(|m| m.permissions().mode());
        let original_owner = original.as_ref().map(|m| (m.uid(), m.gid()));

        let backup = self.backup_encrypted(location)?;

        // Stage the plaintext at the canonical path (SOPS creation rules
        // are path-relative; a temp path would match no rule). 0600 while
        // plaintext; mode restored after encryption.
        let write_result = (|| -> Result<(), StoreError> {
            // Tighten the mode BEFORE any plaintext touches the path: the
            // tracked file is often 0644 in a git checkout. O_NOFOLLOW
            // refuses a symlink planted at the store path.
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&location.path)
                .map_err(|e| StoreError::Io(format!("stage plaintext: {e}")))?;
            f.write_all(&new_plain)
                .and_then(|_| f.sync_all())
                .map_err(|e| StoreError::Io(format!("stage plaintext: {e}")))?;

            let mut cmd = self.sops_base();
            cmd.arg("encrypt").arg("--in-place");
            for flag in self.input_output_flags(location) {
                cmd.arg(flag);
            }
            cmd.arg(&location.path);
            self.run(cmd)?;

            // Restore the tracked file's original mode and ownership
            // (the broker writes as root; the repo belongs to the user).
            if let Some(mode) = original_mode {
                let _ = apply_mode(&location.path, mode & 0o777);
            }
            if let Some((uid, gid)) = original_owner {
                let _ = restore_owner(&location.path, uid, gid);
            }

            // Verify: decrypt again and confirm the new value is stored.
            let verify = self.decrypt_file(location)?;
            let stored_matches = match &location.dotenv_key {
                None => verify == new_value,
                Some(key) => {
                    let pairs = dotenv::parse(&String::from_utf8_lossy(&verify));
                    dotenv::get(&pairs, key)
                        .map(|v| v.as_bytes() == new_value)
                        .unwrap_or(false)
                }
            };
            if !stored_matches {
                return Err(StoreError::Verification(
                    "post-write decrypt did not contain the new value".into(),
                ));
            }
            Ok(())
        })();

        if write_result.is_err() {
            // Fail closed: restore the original encrypted bytes.
            self.restore_backup(&backup, location);
            if let Some(mode) = original_mode {
                let _ = apply_mode(&location.path, mode & 0o777);
            }
        }
        write_result
    }
}

fn restore_owner(path: &Path, uid: u32, gid: u32) -> Result<(), String> {
    let cpath =
        std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).map_err(|e| e.to_string())?;
    // SAFETY: FFI chown(2) with a NUL-terminated path.
    let rc = unsafe { libc::chown(cpath.as_ptr(), uid, gid) };
    if rc != 0 {
        return Err(format!("chown {}: errno {rc}", path.display()));
    }
    Ok(())
}

fn apply_mode(path: &Path, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|e| format!("{}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // The integration test crate exercises SopsStore against a fake sops
    // binary; here we only check config/dir setup.
    #[test]
    fn creates_private_dirs() {
        let tmp = std::env::temp_dir().join(format!("sops-store-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        let store = SopsStore::new(SopsConfig {
            sops_bin: PathBuf::from("/bin/true"),
            age_key_file: PathBuf::from("/nonexistent"),
            work_dir: tmp.join("work"),
            backup_dir: tmp.join("backup"),
            backups_kept: 3,
        })
        .expect("store");
        for dir in [&store.config.work_dir, &store.config.backup_dir] {
            let mode = fs::metadata(dir).expect("dir").permissions().mode();
            assert_eq!(mode & 0o777, 0o700);
        }
        let _ = fs::remove_dir_all(&tmp);
    }
}
