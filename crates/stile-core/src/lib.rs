//! Core secret machinery. Only `stile-brokerd` (and tests) link this
//! crate: it is the only place that ever holds secret bytes, and it never
//! logs, returns, or places them in child-process arguments.

pub mod audit;
pub mod backend;
pub mod deploy;
pub mod dotenv;
pub mod generation;
pub mod registry;
pub mod sops;
pub mod tools;
pub mod verify;

/// Sanitize a subprocess error message for logging: keep it short and
/// structure-free. Subprocess stderr could echo secret-adjacent text
/// (e.g. sops diagnostics); we keep only a bounded prefix of the first
/// line.
pub fn sanitize_output_for_log(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let first_line = text.lines().next().unwrap_or("").trim();
    let mut out: String = first_line.chars().take(200).collect();
    if first_line.len() > 200 {
        out.push('…');
    }
    out
}
