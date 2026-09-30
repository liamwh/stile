//! Post-rotation verification. HTTP probes only; credentials are attached
//! via a header file (`curl -H @file`), never argv, and the header file
//! lives in the broker's private work dir, unlinked immediately.

use crate::sanitize_output_for_log;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

/// Verification errors; messages safe to log.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    /// Probe process failed.
    #[error("probe failed: {0}")]
    Probe(String),
    /// Status mismatch.
    #[error("expected status {expected}, got {got} ({url})")]
    Status {
        /// Expected HTTP status.
        expected: u16,
        /// Actual HTTP status.
        got: u16,
        /// Probed URL.
        url: String,
    },
}

/// GET `url` with an optional bearer token; return the HTTP status.
fn probe(url: &str, bearer: Option<&str>, work_dir: &Path) -> Result<u16, VerifyError> {
    let mut cmd = Command::new(crate::tools::curl());
    cmd.args([
        "-s",
        "-o",
        "/dev/null",
        "-w",
        "%{http_code}",
        "--max-time",
        "30",
    ]);
    let mut header_file: Option<PathBuf> = None;
    if let Some(token) = bearer {
        // Credentials may carry a trailing newline from whole-file stores;
        // HTTP headers must be single-line.
        let token = token.trim();
        // Unique name + create_new + 0600 from creation: nothing else can
        // pre-place or read this file (work_dir is broker-private 0700,
        // this defends in depth against a same-uid intruder).
        let path = work_dir.join(format!(
            "hdr-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let wrote = (|| -> std::io::Result<()> {
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)?;
            f.write_all(format!("Authorization: Bearer {token}\n").as_bytes())
        })();
        if let Err(e) = wrote {
            return Err(VerifyError::Probe(format!("header staging: {e}")));
        }
        cmd.arg("-H").arg(format!("@{}", path.display()));
        header_file = Some(path);
    }
    cmd.arg(url)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = cmd
        .output()
        .map_err(|e| VerifyError::Probe(format!("curl: {e}")));
    if let Some(path) = header_file {
        let _ = fs::remove_file(path);
    }
    let output = output?;
    if !output.status.success() {
        // curl stderr stays in the broker's journal (root-readable) only;
        // client-visible errors carry the exit status alone.
        eprintln!(
            "stile-brokerd: curl stderr: {}",
            sanitize_output_for_log(&output.stderr)
        );
        return Err(VerifyError::Probe(format!(
            "curl exited {:?}",
            output.status.code()
        )));
    }
    let code = String::from_utf8_lossy(&output.stdout).trim().to_string();
    code.parse::<u16>()
        .map_err(|_| VerifyError::Probe(format!("unparseable status {code:?}")))
}

/// How long a verification keeps retrying after a service restart:
/// reload actions like `compose up -d --force-recreate` return before the
/// container accepts traffic, so a single immediate probe races startup.
pub const VERIFY_SETTLE_ATTEMPTS: usize = 8;
/// Seconds between post-reload verification attempts.
pub const VERIFY_SETTLE_INTERVAL_SECS: u64 = 10;

fn settle_attempts() -> usize {
    std::env::var("STILE_TEST_VERIFY_ATTEMPTS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(VERIFY_SETTLE_ATTEMPTS)
}

fn retry_probe<F>(mut attempt: F) -> Result<u16, VerifyError>
where
    F: FnMut() -> Result<u16, VerifyError>,
{
    let mut last_err = None;
    for i in 0..settle_attempts() {
        match attempt() {
            Ok(status) => return Ok(status),
            Err(VerifyError::Status { expected, got, url }) => {
                // Mismatch may be a warming service; retry until settled.
                last_err = Some(VerifyError::Status { expected, got, url });
            }
            Err(e) => return Err(e),
        }
        if i + 1 < settle_attempts() {
            std::thread::sleep(Duration::from_secs(VERIFY_SETTLE_INTERVAL_SECS));
        }
    }
    Err(last_err.unwrap_or(VerifyError::Probe("no probe result".into())))
}

/// Plain status check (no credential), retried while services settle.
pub fn verify_http_status(url: &str, expect: u16, work_dir: &Path) -> Result<(), VerifyError> {
    let got = retry_probe(|| {
        let got = probe(url, None, work_dir)?;
        check_status(url, got, expect)?;
        Ok(got)
    })?;
    let _ = got;
    Ok(())
}

fn check_status(url: &str, got: u16, expect: u16) -> Result<(), VerifyError> {
    if got != expect {
        return Err(VerifyError::Status {
            expected: expect,
            got,
            url: url.into(),
        });
    }
    Ok(())
}
/// Single credential probe used only to decide whether reconciliation needs
/// a reload. Final verification still uses the bounded settle retry below.
pub fn verify_bearer_once(
    url: &str,
    value: &str,
    expect_status: u16,
    work_dir: &Path,
) -> Result<(), VerifyError> {
    let got = probe(url, Some(value), work_dir)?;
    check_status(url, got, expect_status)
}

/// Bearer probe: new credential must yield `expect_status`; if
/// `old_expect_status` is set, the old credential must yield it.
pub fn verify_bearer(
    url: &str,
    new_value: &str,
    old_value: Option<&str>,
    expect_status: u16,
    old_expect_status: Option<u16>,
    work_dir: &Path,
) -> Result<bool, VerifyError> {
    retry_probe(|| {
        let got = probe(url, Some(new_value), work_dir)?;
        check_status(url, got, expect_status)?;
        Ok(got)
    })?;
    if let (Some(old), Some(expected_old)) = (old_value, old_expect_status) {
        let got_old = probe(url, Some(old), work_dir)?;
        if got_old != expected_old {
            return Ok(false);
        }
    }
    Ok(true)
}
