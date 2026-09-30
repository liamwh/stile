//! Non-sensitive audit trail (JSONL). Records logical ids, operations,
//! caller identity, stages and results — never values, decrypted content,
//! fingerprints or provider payloads.

use serde::Serialize;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

/// One audit record.
#[derive(Debug, Serialize)]
pub struct AuditRecord<'a> {
    /// ISO-8601 UTC timestamp.
    pub ts: String,
    /// Operation requested.
    pub op: &'a str,
    /// Logical secret id.
    pub secret: &'a str,
    /// Calling uid.
    pub uid: u32,
    /// Calling gid.
    pub gid: u32,
    /// Calling pid (`SO_PEERCRED`; best-effort attribution).
    pub pid: u32,
    /// Operation duration in milliseconds.
    pub duration_ms: u64,
    /// `success` or `error`.
    pub result: &'a str,
    /// Which stages ran and their outcomes (non-sensitive detail only).
    pub stages: &'a [(&'a str, &'a str, Option<&'a str>)],
}

/// Append a record. Best-effort: audit failure logs to stderr (message
/// only) but never fails the operation.
pub fn append(path: &Path, record: &AuditRecord<'_>) {
    let line = serde_json::to_string(record).unwrap_or_else(|_| "{}".into());
    let result = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .and_then(|mut f| writeln!(f, "{line}"));
    if let Err(e) = result {
        eprintln!("stile-brokerd: audit append failed: {e}");
    }
}

/// Current UTC timestamp, second precision, ISO-8601.
pub fn now_iso() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let (year, month, day) = civil_from_days(days as i64);
    format!("{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}Z")
}

/// Days-since-epoch to civil date (Howard Hinnant's algorithm).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_shape() {
        let ts = now_iso();
        assert_eq!(ts.len(), 20);
        assert!(ts.ends_with('Z'));
        assert!(ts.starts_with("20"));
    }

    #[test]
    fn record_serializes_without_secret_material_fields() {
        let record = AuditRecord {
            ts: now_iso(),
            op: "rotate",
            secret: "ns/name",
            uid: 1000,
            gid: 1000,
            pid: 4242,
            duration_ms: 12,
            result: "success",
            stages: &[("generate", "ok", None)],
        };
        let json = serde_json::to_string(&record).expect("serialize");
        for banned in ["value", "plaintext", "token", "material", "fingerprint"] {
            assert!(!json.contains(&format!("\"{banned}\"")));
        }
    }
}
