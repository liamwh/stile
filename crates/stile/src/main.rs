//! `stile`: the agent-facing CLI. It speaks only logical operations
//! over the broker socket and prints only the structured JSON report. It
//! has no code path that can receive or print a secret value.

use clap::{Parser, Subcommand};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use stile_protocol::{
    OperationReport, ProtocolError, Request, Response, decode_response, encode_request,
};

/// Default broker socket.
pub const DEFAULT_SOCKET: &str = "/run/stile/sock";

#[derive(Parser)]
#[command(
    name = "stile",
    about = "Request allowlisted secret lifecycle operations (never secret values)",
    version
)]
struct Cli {
    /// Broker socket path.
    #[arg(long, global = true, default_value = DEFAULT_SOCKET)]
    socket: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Rotate a secret: broker generates, updates SOPS, deploys, reloads,
    /// verifies. Returns structured status only.
    Rotate {
        /// Logical secret id (see `stile list`).
        secret: String,
    },
    /// Re-run verification for a secret without changing it.
    Verify {
        /// Logical secret id.
        secret: String,
    },
    /// Reconcile the stored secret into stale consumers and the active
    /// backend without generating a replacement.
    Reconcile {
        /// Logical secret id.
        secret: String,
    },
    /// Show policy/consumers/verification for one secret.
    Status {
        /// Logical secret id.
        secret: String,
    },
    /// List defined logical secrets with their policies.
    List,
    /// Provider-assisted import: you paste a provider-issued secret at a
    /// hidden prompt; the broker persists it and rotates consumers. The
    /// value is never echoed, logged, or returned.
    ImportProviderSecret {
        /// Logical secret id.
        secret: String,
    },
}

fn main() {
    let cli = Cli::parse();
    let request = match &cli.command {
        Command::Rotate { secret } => Request::Rotate {
            secret: secret.clone(),
        },
        Command::Verify { secret } => Request::Verify {
            secret: secret.clone(),
        },
        Command::Reconcile { secret } => Request::Reconcile {
            secret: secret.clone(),
        },
        Command::Status { secret } => Request::Status {
            secret: secret.clone(),
        },
        Command::List => Request::List,
        Command::ImportProviderSecret { secret } => match import_flow(&cli.socket, secret) {
            Ok(report) => {
                print_report(&report);
                std::process::exit(exit_code(&report));
            }
            Err(e) => {
                eprintln!("stile: {e}");
                std::process::exit(2);
            }
        },
    };

    match roundtrip(&cli.socket, &request, None) {
        Ok(Response::Report(report)) => {
            print_report(&report);
            std::process::exit(exit_code(&report));
        }
        Ok(Response::ReadyForImport) => unreachable!("only import flow yields this"),
        Err(e) => {
            eprintln!("stile: {e}");
            std::process::exit(2);
        }
    }
}

fn print_report(report: &OperationReport) {
    println!(
        "{}",
        serde_json::to_string_pretty(report).expect("report serializes")
    );
}

fn exit_code(report: &OperationReport) -> i32 {
    if report.status == "success" { 0 } else { 1 }
}

/// One request/response exchange. `value` is used only by the import flow.
fn roundtrip(
    socket: &PathBuf,
    request: &Request,
    value: Option<&str>,
) -> Result<Response, ProtocolError> {
    let mut stream =
        UnixStream::connect(socket).map_err(|e| ProtocolError::Connect(e.to_string()))?;
    stream
        .write_all(encode_request(request).as_bytes())
        .map_err(|_| ProtocolError::ClosedEarly)?;
    if let Some(value) = value {
        let import = Request::ImportValue {
            value: value.to_string(),
        };
        stream
            .write_all(encode_request(&import).as_bytes())
            .map_err(|_| ProtocolError::ClosedEarly)?;
    }
    read_one_response(&mut stream)
}

/// Read exactly one newline-terminated response line. The broker keeps
/// the connection open for further requests, so reading to EOF would
/// block forever.
fn read_one_response(stream: &mut UnixStream) -> Result<Response, ProtocolError> {
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
    if line.is_empty() {
        return Err(ProtocolError::ClosedEarly);
    }
    decode_response(&String::from_utf8_lossy(&line)).map_err(|_| ProtocolError::MalformedFrame)
}

/// Provider-assisted flow: send import request, wait for ReadyForImport,
/// read the value from the TTY with echo disabled, send it, print report.
fn import_flow(socket: &PathBuf, secret: &str) -> Result<OperationReport, ProtocolError> {
    let mut stream =
        UnixStream::connect(socket).map_err(|e| ProtocolError::Connect(e.to_string()))?;
    stream
        .write_all(
            encode_request(&Request::ImportProviderSecret {
                secret: secret.into(),
            })
            .as_bytes(),
        )
        .map_err(|_| ProtocolError::ClosedEarly)?;

    // Read the broker's first response (a complete newline-terminated
    // frame; a single read() may return a partial frame).
    match read_one_response(&mut stream)? {
        Response::ReadyForImport => {}
        Response::Report(report) => return Ok(report),
    }

    eprintln!("Paste the new provider secret for {secret} (input hidden, ends on Enter):");
    let value = read_hidden_tty().map_err(ProtocolError::Connect)?;
    if value.trim().is_empty() {
        let abort = OperationReport::error(
            "import-provider-secret",
            Some(secret),
            "empty input; aborted without changes",
        );
        return Ok(abort);
    }
    stream
        .write_all(
            encode_request(&Request::ImportValue {
                value: value.trim().to_string(),
            })
            .as_bytes(),
        )
        .map_err(|_| ProtocolError::ClosedEarly)?;

    match read_one_response(&mut stream)? {
        Response::Report(report) => Ok(report),
        Response::ReadyForImport => Err(ProtocolError::MalformedFrame),
    }
}

/// Read one line from the controlling TTY with echo disabled. The value
/// stays in this process's memory and the socket; it is never in argv,
/// environment, or a file.
fn read_hidden_tty() -> Result<String, String> {
    use std::fs::File;
    use std::io::BufRead;
    let tty = File::open("/dev/tty").map_err(|e| format!("open tty: {e}"))?;
    let fd = {
        use std::os::fd::AsRawFd;
        tty.as_raw_fd()
    };
    // SAFETY: termios via libc on our own /dev/tty fd; all pointers are
    // stack addresses valid for the call, and tcsetattr is restored on
    // every path.
    unsafe {
        let mut term: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(fd, &mut term) != 0 {
            return Err("tcgetattr failed".into());
        }
        let saved = term;
        term.c_lflag &= !libc::ECHO;
        if libc::tcsetattr(fd, libc::TCSAFLUSH, &term) != 0 {
            return Err("tcsetattr failed".into());
        }
        let mut line = String::new();
        let result = std::io::BufReader::new(tty).read_line(&mut line);
        let _ = libc::tcsetattr(fd, libc::TCSAFLUSH, &saved);
        eprintln!();
        result.map(|_| line).map_err(|e| format!("read tty: {e}"))
    }
}
