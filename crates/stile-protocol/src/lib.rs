//! Wire protocol between `stile` (unprivileged client) and
//! `stile-brokerd` (privileged daemon).
//!
//! Design invariant, enforced by the shape of these types: **no request can
//! ask for secret material and no response can carry it.** Requests name
//! logical secrets and lifecycle operations only; responses carry
//! non-sensitive structured status (booleans, counts, opaque `changed`
//! flags). There is deliberately no `get`/`read`/`export`/`decrypt` variant
//! and no free-form field a future endpoint could smuggle plaintext
//! through. Extending this enum is a security review event: see
//! `docs/threat-model.md`.
//!
//! Transport: newline-delimited JSON over a Unix domain socket
//! (`/run/stile/sock` by default). One request line in, one
//! response line out, then the client closes.

use serde::{Deserialize, Serialize};

/// A lifecycle operation on a logical secret. The complete allowlist; the
/// broker rejects anything that does not deserialize into this enum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case", tag = "op")]
pub enum Request {
    /// Rotate a secret: generate (or receive, for provider-assisted flow)
    /// a new value inside the broker, update the SOPS store, redeploy
    /// runtime consumers, reload services, verify.
    Rotate {
        /// Logical identifier, e.g. `inbox-zero/auth-secret`.
        secret: String,
    },
    /// Re-run the declared verification for a secret without changing it.
    Verify {
        /// Logical identifier.
        secret: String,
    },
    /// Reconcile the existing stored value into stale consumers, reload only
    /// affected services, discover the active backend, and verify end-to-end.
    /// Unlike `rotate`, this never generates or persists a new value.
    Reconcile {
        /// Logical secret id.
        secret: String,
    },
    /// Report declarative status: defined? policy? last rotation stage
    /// results from the audit trail. Never includes values.
    Status {
        /// Logical identifier.
        secret: String,
    },
    /// List defined logical secret identifiers with their rotation policy.
    List,
    /// Provider-assisted import: the human types a provider-issued secret
    /// into a no-echo TTY on the client; it transits the socket once and is
    /// persisted by the broker. Response reports success only.
    ImportProviderSecret {
        /// Logical identifier.
        secret: String,
    },
    /// Value transport for `import-provider-secret`. Sent by the client
    /// immediately after the broker acknowledges the import request with
    /// [`Response::ReadyForImport`]. This is the ONLY message in the
    /// protocol that carries secret bytes, it is client→broker only,
    /// and it exists solely because provider-side credentials cannot be
    /// generated locally. The broker never echoes it.
    ImportValue {
        /// The secret value being imported (never logged, never returned).
        value: String,
    },
}

/// Stage-level outcome of an operation, for audit and status reporting.
/// Contains no secret material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StageResult {
    /// Stage succeeded.
    Ok,
    /// Stage failed; operation aborted.
    Failed,
    /// Stage not applicable for this secret/operation.
    Skipped,
}

/// Non-sensitive structured response body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationReport {
    /// `success` or `error`.
    pub status: String,
    /// Which operation ran.
    pub operation: String,
    /// Logical secret the operation targeted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
    /// Encrypted store (SOPS) updated.
    pub store_updated: bool,
    /// Runtime deployment (deployed files/containers) updated.
    pub runtime_updated: bool,
    /// Declared reload/restart actions executed.
    pub services_reloaded: bool,
    /// Post-rotation verification passed.
    pub verification_passed: bool,
    /// Whether the secret's fingerprint changed (opaque boolean; the
    /// fingerprint itself is never exposed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint_changed: Option<bool>,
    /// Old credential revoked where revocation is supported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_credential_revoked: Option<bool>,
    /// Per-stage results, in execution order.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stages: Option<Vec<StageRecord>>,
    /// Human-oriented message; never contains secret material.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// One named stage's outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StageRecord {
    /// Stage name (e.g. `generate`, `store`, `deploy`, `reload`, `verify`).
    pub stage: String,
    /// Outcome.
    pub result: StageResult,
    /// Non-sensitive detail (e.g. unit name reloaded, URL verified).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl OperationReport {
    /// A successful report for the given operation/secret.
    pub fn success(operation: &str, secret: Option<&str>) -> Self {
        Self {
            status: "success".into(),
            operation: operation.into(),
            secret: secret.map(String::from),
            store_updated: false,
            runtime_updated: false,
            services_reloaded: false,
            verification_passed: false,
            fingerprint_changed: None,
            old_credential_revoked: None,
            stages: None,
            message: None,
        }
    }

    /// An error report with a stage trail.
    pub fn error(operation: &str, secret: Option<&str>, message: &str) -> Self {
        Self {
            status: "error".into(),
            operation: operation.into(),
            secret: secret.map(String::from),
            store_updated: false,
            runtime_updated: false,
            services_reloaded: false,
            verification_passed: false,
            fingerprint_changed: None,
            old_credential_revoked: None,
            stages: None,
            message: Some(message.into()),
        }
    }
}

/// Broker response. `ReadyForImport` is the only intermediate control
/// message; every terminal response is an [`OperationReport`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, tag = "type")]
pub enum Response {
    /// Terminal structured result.
    Report(OperationReport),
    /// Broker acknowledges `import-provider-secret` and is ready to
    /// receive exactly one `ImportValue` message.
    ReadyForImport,
}

/// Errors the client surfaces to the user. Deliberately coarse: broker
/// stderr detail is not forwarded verbatim because subprocess output could
/// someday contain secret-adjacent text.
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    /// Could not reach the broker socket.
    #[error("cannot connect to broker socket: {0}")]
    Connect(String),
    /// Malformed frame from broker.
    #[error("malformed protocol frame")]
    MalformedFrame,
    /// Broker closed the connection unexpectedly.
    #[error("broker closed connection mid-operation")]
    ClosedEarly,
}

/// Serialize a request as one protocol frame (JSON + `\n`).
pub fn encode_request(request: &Request) -> String {
    let mut line = serde_json::to_string(request).expect("request serializes");
    line.push('\n');
    line
}

/// Serialize a response as one protocol frame.
pub fn encode_response(response: &Response) -> String {
    let mut line = serde_json::to_string(response).expect("response serializes");
    line.push('\n');
    line
}

/// Parse one protocol frame (with or without trailing newline).
pub fn decode_request(frame: &str) -> Result<Request, serde_json::Error> {
    serde_json::from_str(frame.trim_end())
}

/// Parse one response frame.
pub fn decode_response(frame: &str) -> Result<Response, serde_json::Error> {
    serde_json::from_str(frame.trim_end())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_operations_are_rejected_at_deserialize_time() {
        for banned in [
            "get-secret",
            "read_secret",
            "export-secret",
            "decrypt",
            "show",
            "dump-environment",
            "exec",
        ] {
            let frame = format!("{{\"op\":\"{banned}\",\"secret\":\"x\"}}");
            assert!(
                decode_request(&frame).is_err(),
                "operation {banned} must not deserialize"
            );
        }
    }

    #[test]
    fn request_roundtrip() {
        for request in [
            Request::Rotate {
                secret: "a/b".into(),
            },
            Request::Verify {
                secret: "a/b".into(),
            },
            Request::Reconcile {
                secret: "a/b".into(),
            },
            Request::Status {
                secret: "a/b".into(),
            },
            Request::List,
        ] {
            let encoded = encode_request(&request);
            assert!(encoded.ends_with('\n'));
            let decoded = decode_request(&encoded).expect("roundtrip");
            assert_eq!(decoded, request);
        }
    }

    #[test]
    fn response_never_has_a_value_field() {
        let report = Response::Report(OperationReport::success("rotate", Some("x/y")));
        let json = serde_json::to_string(&report).expect("serialize");
        for banned in ["value", "secret_value", "plaintext", "token", "material"] {
            assert!(
                !json.contains(&format!("\"{banned}\"")),
                "response must not contain a {banned} field"
            );
        }
    }

    #[test]
    fn unknown_response_fields_rejected() {
        let frame = r#"{"type":"Report","status":"success","value":"nope"}"#;
        assert!(decode_response(frame).is_err());
    }
}
