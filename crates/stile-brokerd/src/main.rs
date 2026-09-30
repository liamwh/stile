//! `stile-brokerd`: the privileged side of the boundary. Owns a Unix
//! socket, authenticates peers via `SO_PEERCRED`, and executes only the
//! allowlisted lifecycle operations from `stile-protocol` against the
//! root-owned registry. It has no operation that returns secret material.

mod config;
mod rotate;

use std::io::BufReader;
use std::io::Write;
use std::os::unix::net::UnixListener;
use std::os::unix::net::UnixStream;
use std::time::Duration;
use std::time::Instant;
use stile_protocol::{OperationReport, Request, Response, decode_request, encode_response};

/// Largest accepted request line (non-import). Requests name a logical
/// secret id; anything larger is abuse.
const MAX_REQUEST_BYTES: usize = 64 * 1024;
/// Largest accepted import value. Provider-issued secrets (keys, tokens)
/// stay far below this; it exists only to bound broker memory.
const MAX_IMPORT_BYTES: usize = 1024 * 1024;
/// How long the broker waits for a request line before dropping the
/// connection. The broker is single-threaded by design: one silent
/// client must not block everyone else.
const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(60);
/// The import value is typed by a human after a prompt; allow more time.
const IMPORT_READ_TIMEOUT: Duration = Duration::from_secs(600);

pub(crate) use config::Config;

fn main() {
    let mut args = std::env::args();
    let _program = args.next();
    let config_path = match args.next().as_deref() {
        None => "/etc/stile/brokerd.toml".to_string(),
        Some("-h" | "--help") => {
            eprintln!("usage: stile-brokerd [CONFIG]");
            eprintln!("  CONFIG  path to the daemon config (default /etc/stile/brokerd.toml)");
            std::process::exit(0);
        }
        Some(path) => path.to_string(),
    };
    let config = match Config::load(&config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("stile-brokerd: {e}");
            std::process::exit(2);
        }
    };

    if let Some(dir) = config.file.socket_path.parent() {
        prepare_socket_dir(dir, config.access_group());
    }
    refuse_if_live_instance(&config.file.socket_path);
    // Safe now: proven not served; parent dir verified.
    let _ = std::fs::remove_file(&config.file.socket_path);

    let listener = match UnixListener::bind(&config.file.socket_path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!(
                "stile-brokerd: bind {}: {e}",
                config.file.socket_path.display()
            );
            std::process::exit(2);
        }
    };
    {
        use std::os::unix::fs::PermissionsExt;
        let group = config.access_group();
        if let Err(e) = std::fs::set_permissions(
            &config.file.socket_path,
            std::fs::Permissions::from_mode(0o660),
        ) {
            eprintln!("stile-brokerd: chmod socket: {e}");
        }
        if let Some(gid) = group {
            let cpath =
                std::ffi::CString::new(config.file.socket_path.as_os_str().as_encoded_bytes())
                    .expect("path");
            // SAFETY: FFI chown(2); uid -1 (u32::MAX) leaves the owner unchanged.
            let rc = unsafe { libc::chown(cpath.as_ptr(), u32::MAX, gid) };
            if rc != 0 {
                eprintln!("stile-brokerd: chown socket to group failed (errno {rc})");
            }
        }
    }

    eprintln!(
        "stile-brokerd: listening on {}",
        config.file.socket_path.display()
    );

    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        handle_connection(stream, &config);
    }
}

fn handle_connection(mut stream: UnixStream, config: &Config) {
    let creds = match peer_creds(&stream) {
        Some(p) => p,
        None => return,
    };
    if !config.peer_allowed(creds.uid, creds.gid) {
        let report =
            OperationReport::error("connect", None, "caller is not authorized for this broker");
        let _ = stream.write_all(encode_response(&Response::Report(report)).as_bytes());
        return;
    }
    let _ = stream.set_read_timeout(Some(request_timeout()));

    let reader = match stream.try_clone() {
        Ok(r) => r,
        Err(_) => return,
    };
    let mut reader = BufReader::new(reader);

    loop {
        let line = match read_capped_line(&mut reader, MAX_REQUEST_BYTES) {
            Ok(Some(line)) => line,
            Ok(None) => return, // clean EOF
            Err(ReadError::TooLarge) => {
                let report = OperationReport::error(
                    "malformed",
                    None,
                    "request exceeds size limit; connection closed",
                );
                let _ = stream.write_all(encode_response(&Response::Report(report)).as_bytes());
                return;
            }
            Err(ReadError::Io(e)) => {
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut
                {
                    eprintln!(
                        "stile-brokerd: uid {} stalled on a partial request; dropped",
                        creds.uid
                    );
                }
                return;
            }
        };

        let request = match decode_request(&line) {
            Ok(r) => r,
            Err(e) => {
                let report = OperationReport::error(
                    "malformed",
                    None,
                    &format!("rejected malformed request: {e}"),
                );
                if stream
                    .write_all(encode_response(&Response::Report(report)).as_bytes())
                    .is_err()
                {
                    return;
                }
                continue;
            }
        };
        // Provider-assisted import is a two-message exchange: ack, then
        // receive the value, then run the rotation with it.
        if let Request::ImportProviderSecret { ref secret } = request {
            match rotate::prepare_import(config, secret, peer_of(&creds)) {
                Ok(()) => {
                    if stream
                        .write_all(encode_response(&Response::ReadyForImport).as_bytes())
                        .is_err()
                    {
                        return;
                    }
                    let _ = stream.set_read_timeout(Some(IMPORT_READ_TIMEOUT));
                    let value_line = match read_capped_line(&mut reader, MAX_IMPORT_BYTES) {
                        Ok(Some(l)) => l,
                        Ok(None) => return,
                        Err(ReadError::TooLarge) => {
                            let report = OperationReport::error(
                                "import-provider-secret",
                                Some(secret),
                                "import value exceeds size limit; aborted",
                            );
                            let _ = stream
                                .write_all(encode_response(&Response::Report(report)).as_bytes());
                            return;
                        }
                        Err(ReadError::Io(_)) => return,
                    };
                    let _ = stream.set_read_timeout(Some(request_timeout()));
                    let value_request = match decode_request(&value_line) {
                        Ok(Request::ImportValue { value }) => value,
                        _ => {
                            let report = OperationReport::error(
                                "import-provider-secret",
                                Some(secret),
                                "expected import value message; aborting",
                            );
                            let _ = stream
                                .write_all(encode_response(&Response::Report(report)).as_bytes());
                            return;
                        }
                    };
                    let report =
                        rotate::run_import(config, secret, &value_request, peer_of(&creds));
                    let _ = stream.write_all(encode_response(&Response::Report(report)).as_bytes());
                    return; // connection closes after one import
                }
                Err(message) => {
                    let report =
                        OperationReport::error("import-provider-secret", Some(secret), &message);
                    let _ = stream.write_all(encode_response(&Response::Report(report)).as_bytes());
                    return;
                }
            }
        }

        let peer = peer_of(&creds);
        let report = match request {
            Request::Rotate { secret } => rotate::dispatch_rotate(config, &secret, None, peer),
            Request::Verify { secret } => rotate::dispatch_verify(config, &secret, peer),
            Request::Reconcile { secret } => rotate::dispatch_reconcile(config, &secret, peer),
            Request::Status { secret } => rotate::dispatch_status(config, &secret, peer),
            Request::List => rotate::dispatch_list(config, peer),
            Request::ImportValue { .. } => OperationReport::error(
                "import-value",
                None,
                "import value without a pending import request; rejected",
            ),
            Request::ImportProviderSecret { .. } => unreachable!("handled above"),
        };
        if stream
            .write_all(encode_response(&Response::Report(report)).as_bytes())
            .is_err()
        {
            return;
        }
    }
}

/// Peer credentials from `SO_PEERCRED`.
fn peer_creds(stream: &UnixStream) -> Option<libc::ucred> {
    use std::os::fd::AsRawFd;
    // SAFETY: ucred is a plain POD struct; zeroed() is the valid
    // initialiser for the getsockopt write below.
    let mut ucred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as u32;
    // SAFETY: getsockopt(2) with correct fd, level, option and a
    // buffer of the declared size.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut ucred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if rc == 0 { Some(ucred) } else { None }
}

/// A fresh per-request peer context (starts the audit clock).
fn peer_of(creds: &libc::ucred) -> rotate::Peer {
    rotate::Peer {
        uid: creds.uid,
        gid: creds.gid,
        pid: creds.pid as u32,
        started: Instant::now(),
    }
}

/// Why a capped line read failed.
enum ReadError {
    /// Underlying socket error (including read timeout).
    Io(std::io::Error),
    /// Line exceeded the byte cap.
    TooLarge,
}

/// Read one newline-terminated line of at most `max_bytes` bytes.
/// `Ok(None)` is a clean EOF before any bytes.
fn read_capped_line<R: std::io::BufRead>(
    reader: &mut R,
    max_bytes: usize,
) -> Result<Option<String>, ReadError> {
    let mut buf: Vec<u8> = Vec::new();
    loop {
        let available = match reader.fill_buf() {
            Ok(a) => a,
            Err(e) => return Err(ReadError::Io(e)),
        };
        if available.is_empty() {
            return if buf.is_empty() {
                Ok(None)
            } else {
                // Client closed mid-line; treat the remainder as the line.
                Ok(Some(String::from_utf8_lossy(&buf).into_owned()))
            };
        }
        match available.iter().position(|&b| b == b'\n') {
            Some(i) => {
                buf.extend_from_slice(&available[..=i]);
                let total = buf.len();
                reader.consume(i + 1);
                if total > max_bytes {
                    return Err(ReadError::TooLarge);
                }
                return Ok(Some(String::from_utf8_lossy(&buf).into_owned()));
            }
            None => {
                let n = available.len();
                if buf.len() + n > max_bytes {
                    return Err(ReadError::TooLarge);
                }
                buf.extend_from_slice(available);
                reader.consume(n);
            }
        }
    }
}
/// Create/tighten the socket's parent directory and verify it is safe:
/// owned by the effective uid, never world-writable, and group-writable
/// only when the group is the broker's own effective gid. Any looser
/// directory would let an unprivileged user intercept or replace the
/// socket (e.g. plant their own listener), so we fail closed instead.
fn prepare_socket_dir(dir: &std::path::Path, access_gid: Option<u32>) {
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::PermissionsExt;
    if let Err(e) = std::fs::create_dir_all(dir) {
        eprintln!("stile-brokerd: mkdir {}: {e}", dir.display());
        std::process::exit(2);
    }
    // SAFETY: geteuid(2)/getegid(2) are infallible and return plain ids.
    let euid = unsafe { libc::geteuid() };
    // SAFETY: see above.
    let egid = unsafe { libc::getegid() };
    let meta = match std::fs::metadata(dir) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("stile-brokerd: stat {}: {e}", dir.display());
            std::process::exit(2);
        }
    };
    let mode = meta.mode() & 0o777;
    if mode & 0o002 != 0 {
        eprintln!(
            "stile-brokerd: socket directory {} is world-writable (mode {mode:o}); refusing",
            dir.display()
        );
        std::process::exit(2);
    }
    if mode & 0o020 != 0 && meta.gid() != egid {
        eprintln!(
            "stile-brokerd: socket directory {} is group-writable by gid {} (broker egid {egid}); refusing",
            dir.display(),
            meta.gid()
        );
        std::process::exit(2);
    }
    if meta.uid() != euid {
        eprintln!(
            "stile-brokerd: socket directory {} is owned by uid {}, not the broker (euid {euid}); refusing",
            dir.display(),
            meta.uid()
        );
        std::process::exit(2);
    }
    if let Err(e) = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o750)) {
        eprintln!("stile-brokerd: chmod {}: {e}", dir.display());
        std::process::exit(2);
    }
    // Grant the access group traversal into the runtime directory
    // (systemd creates RuntimeDirectory as root:root).
    if let Some(gid) = access_gid
        && let Ok(cdir) = std::ffi::CString::new(dir.as_os_str().as_encoded_bytes())
    {
        // SAFETY: FFI chown(2); owner unchanged (uid -1).
        let _ = unsafe { libc::chown(cdir.as_ptr(), u32::MAX, gid) };
    }
}

/// If something is already serving on this socket, refuse to start: a
/// second broker would silently steal or split requests after we removed
/// the first one's socket file.
fn refuse_if_live_instance(socket_path: &std::path::Path) {
    if UnixStream::connect(socket_path).is_ok() {
        eprintln!(
            "stile-brokerd: refusing to start: another broker is already serving {}",
            socket_path.display()
        );
        std::process::exit(2);
    }
}

/// Request read timeout, overridable (down or up) for tests.
fn request_timeout() -> Duration {
    std::env::var("STILE_TEST_REQUEST_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(REQUEST_READ_TIMEOUT)
}
