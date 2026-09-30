//! Logical secret registry: declarative, version-controlled in the infra
//! repository, installed to a root-owned path the broker reads. The broker
//! refuses operations on identifiers not present here, and refuses any
//! command not declared here.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Top-level registry file (`[[secret]]` array of tables).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Registry {
    /// Schema version; currently 1.
    pub version: u32,
    /// Absolute path of the SOPS repository root (creation rules are
    /// path-relative, so SOPS writes must happen at the canonical path).
    pub repo_root: PathBuf,
    /// Declared secrets.
    #[serde(rename = "secret")]
    pub secret_list: Vec<SecretDef>,
}

/// One logical secret and everything the broker may do with it.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretDef {
    /// Logical identifier, `namespace/name` (e.g. `inbox-zero/auth-secret`).
    pub id: String,
    /// Where the encrypted value lives.
    pub store: StoreDef,
    /// How to generate a replacement (absent for provider-assisted-only).
    #[serde(default)]
    pub generation: Option<GenerationDef>,
    /// Runtime consumers to update on rotation.
    #[serde(default)]
    pub consumers: Vec<ConsumerDef>,
    /// Mutually exclusive runtime backends selected by declared status
    /// checks. Consumers describe where bytes go; backends describe which
    /// server currently consumes them and where that server is verified.
    #[serde(default)]
    pub backends: Vec<BackendDef>,
    /// Privileged hooks that must run before consumer reload (e.g.
    /// database role password changes).
    #[serde(default)]
    pub pre_reload: Vec<PreReloadDef>,
    /// Reload/restart actions after runtime files are updated.
    #[serde(default)]
    pub reload: Vec<ReloadDef>,
    /// End-to-end consumer checks. During rotation their reloads run after
    /// deployment; during reconciliation only a failing check is reloaded.
    #[serde(default)]
    pub checks: Vec<CheckDef>,
    /// Post-rotation verification.
    #[serde(default)]
    pub verify: Vec<VerifyDef>,
    /// Rotation policy.
    pub policy: Policy,
    /// Human-readable policy rationale (shown by `stile status`;
    /// never contains values).
    #[serde(default)]
    pub reason: Option<String>,
    /// For provider-assisted secrets: the minimal human step, verbatim
    /// from the registry.
    #[serde(default)]
    pub human_step: Option<String>,
}

impl Registry {
    /// Parse and validate a registry from a TOML file.
    pub fn load(path: &Path) -> Result<Self, RegistryError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| RegistryError::Read(format!("{}: {e}", path.display())))?;
        let registry: Registry =
            toml::from_str(&text).map_err(|e| RegistryError::Parse(e.to_string()))?;
        registry.validate()?;
        Ok(registry)
    }

    /// Secrets keyed by logical id.
    pub fn secrets(&self) -> BTreeMap<&str, &SecretDef> {
        self.secret_list
            .iter()
            .map(|s| (s.id.as_str(), s))
            .collect()
    }

    /// Look up a secret definition by logical id.
    pub fn get(&self, id: &str) -> Option<&SecretDef> {
        self.secret_list.iter().find(|s| s.id == id)
    }

    /// Absolute path of a secret's SOPS file inside the repo.
    pub fn store_path(&self, def: &SecretDef) -> PathBuf {
        self.repo_root.join(&def.store.file)
    }

    fn validate(&self) -> Result<(), RegistryError> {
        if self.version != 1 {
            return Err(RegistryError::Parse(format!(
                "unsupported registry version {}",
                self.version
            )));
        }
        let mut seen = BTreeMap::new();
        for def in &self.secret_list {
            if !def.id.contains('/') || def.id.starts_with('/') || def.id.ends_with('/') {
                return Err(RegistryError::Parse(format!(
                    "logical id {} must be namespace/name",
                    def.id
                )));
            }
            if seen.insert(&def.id, ()).is_some() {
                return Err(RegistryError::Parse(format!(
                    "duplicate logical id {}",
                    def.id
                )));
            }
            if def.store.kind == StoreKind::Dotenv && def.store.key.is_none() {
                return Err(RegistryError::Parse(format!(
                    "{}: dotenv store requires a key",
                    def.id
                )));
            }
            if def.policy == Policy::Auto && def.generation.is_none() {
                return Err(RegistryError::Parse(format!(
                    "{}: auto policy requires a generation strategy",
                    def.id
                )));
            }
            if def.policy == Policy::ProviderAssisted && def.human_step.is_none() {
                return Err(RegistryError::Parse(format!(
                    "{}: provider-assisted policy requires a human_step",
                    def.id
                )));
            }
            let mut backend_ids = BTreeMap::new();
            for backend in &def.backends {
                if backend_ids.insert(&backend.id, ()).is_some() {
                    return Err(RegistryError::Parse(format!(
                        "{}: duplicate backend {}",
                        def.id, backend.id
                    )));
                }
                if backend.consumes_secret {
                    if backend.reload.is_none() || backend.verify.is_none() {
                        return Err(RegistryError::Parse(format!(
                            "{} backend {}: secret-consuming backend requires reload and verify",
                            def.id, backend.id
                        )));
                    }
                    if backend
                        .verify
                        .as_ref()
                        .is_some_and(|step| step.kind != VerifyKind::BearerProbe)
                    {
                        return Err(RegistryError::Parse(format!(
                            "{} backend {}: backend verify must be bearer-probe",
                            def.id, backend.id
                        )));
                    }
                } else if backend.reload.is_some() || backend.verify.is_some() {
                    return Err(RegistryError::Parse(format!(
                        "{} backend {}: non-consuming backend cannot reload or verify this secret",
                        def.id, backend.id
                    )));
                }
            }
            let mut check_ids = BTreeMap::new();
            for check in &def.checks {
                if check_ids.insert(&check.id, ()).is_some() {
                    return Err(RegistryError::Parse(format!(
                        "{}: duplicate check {}",
                        def.id, check.id
                    )));
                }
            }
        }
        Ok(())
    }
}

/// Encrypted store location.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreDef {
    /// Path relative to `repo_root` (must match a SOPS creation rule).
    pub file: String,
    /// `dotenv` (key within file) or `binary` (whole file is the value).
    #[serde(rename = "type")]
    pub kind: StoreKind,
    /// Key for dotenv stores.
    #[serde(default)]
    pub key: Option<String>,
}

/// Store format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StoreKind {
    /// dotenv key/value file.
    Dotenv,
    /// Whole-file binary secret.
    Binary,
}

/// Generation policy.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationDef {
    /// `hex` (lowercase hex, 2 chars/byte) or `urlsafe` (base64url).
    #[serde(rename = "type")]
    pub kind: GenerationKind,
    /// Entropy input length in bytes (output length depends on encoding).
    pub bytes: usize,
}

/// Generation encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GenerationKind {
    /// Lowercase hexadecimal, 2 characters per byte.
    Hex,
    /// URL-safe base64 (unpadded), ~1.33 chars per byte.
    Urlsafe,
}

/// Runtime consumer of a secret value.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsumerDef {
    /// Consumer kind.
    #[serde(rename = "type")]
    pub kind: ConsumerKind,
    /// Absolute path of the deployed runtime file.
    pub path: PathBuf,
    /// Key to update within a deployed dotenv file.
    #[serde(default)]
    pub key: Option<String>,
    /// Owning user for the deployed file.
    pub owner: String,
    /// Octal mode (TOML integer, e.g. 256 for 0o400).
    pub mode: u32,
}

/// Consumer kinds the broker knows how to deploy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConsumerKind {
    /// Update one key inside an existing deployed dotenv file.
    DotenvFile,
    /// Replace the whole deployed file with the value.
    RawFile,
}

/// Pre-reload privileged hook.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreReloadDef {
    /// Hook kind.
    #[serde(rename = "type")]
    pub kind: PreReloadKind,
    /// Container name for docker-executed hooks.
    pub container: String,
    /// Role whose password is set.
    pub role: String,
}

/// Pre-reload hook kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PreReloadKind {
    /// `ALTER ROLE <role> PASSWORD <new>` inside the declared container,
    /// executed as the container's postgres OS user over the local trust
    /// socket: no secret in argv, SQL on stdin only.
    PostgresRolePassword,
}

/// Reload/restart action.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReloadDef {
    /// Action kind.
    #[serde(rename = "type")]
    pub kind: ReloadKind,
    /// Unix user the command runs as (via `runuser`).
    pub user: String,
    /// Absolute executable path.
    pub command: String,
    /// Literal arguments (never contain secret material).
    #[serde(default)]
    pub args: Vec<String>,
}

/// Reload action kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReloadKind {
    /// Run a declared command as a declared user (e.g. the compose wrapper
    /// with `up -d --force-recreate …`). Only registry-declared commands
    /// are ever executed; the protocol has no exec primitive.
    RunCommand,
}
/// One mutually exclusive runtime backend for a secret.
///
/// `active` is a root-owned, declaratively allowlisted status command whose
/// zero exit status means this backend is selected. Exactly one backend must
/// be active for backend-aware verification or reconciliation.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackendDef {
    /// Stable non-secret backend identifier used in reports.
    pub id: String,
    /// Whether this backend uses this logical secret. Declaring non-consuming
    /// alternatives makes selecting (for example) a different credential
    /// domain fail explicitly instead of probing the same port silently.
    #[serde(default = "default_true")]
    pub consumes_secret: bool,
    /// Declared command whose exit status identifies the active backend.
    pub active: ReloadDef,
    /// Minimal reload needed to ingest the current secret.
    #[serde(default)]
    pub reload: Option<ReloadDef>,
    /// Credential-aware endpoint for this backend.
    #[serde(default)]
    pub verify: Option<VerifyDef>,
}

fn default_true() -> bool {
    true
}
/// End-to-end check for a consumer which does not own a separate secret file
/// (for example a process that receives the credential at startup).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckDef {
    /// Stable non-secret identifier used in reports.
    pub id: String,
    /// Declared command whose zero exit status means the consumer is healthy.
    pub command: ReloadDef,
    /// Minimal reload to re-ingest the current credential.
    #[serde(default)]
    pub reload: Option<ReloadDef>,
}

/// Post-rotation verification step.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyDef {
    /// Verification kind.
    #[serde(rename = "type")]
    pub kind: VerifyKind,
    /// URL to probe.
    pub url: String,
    /// Expected HTTP status for `http-status`, or for `bearer-probe` the
    /// status the NEW credential must produce.
    pub expect_status: u16,
    /// For `bearer-probe`: status the OLD credential must produce for the
    /// revocation check to pass.
    #[serde(default)]
    pub old_expect_status: Option<u16>,
}

/// Verification kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum VerifyKind {
    /// GET the URL, expect the given status. No credential involved.
    HttpStatus,
    /// GET the URL with `Authorization: Bearer <credential>` — the header
    /// is built in-process and passed to curl via a header file, never
    /// argv. `old_expect_status` additionally probes with the previous
    /// credential (revocation check).
    BearerProbe,
}

/// Rotation policy for a logical secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Policy {
    /// Broker may generate, deploy and verify without human input.
    Auto,
    /// A human supplies the new value via `stile import-provider-secret`
    /// (provider-side credential; no safe automated rotation exists).
    ProviderAssisted,
    /// Rotation requires coordinated manual work; the broker refuses.
    Manual,
    /// Rotation forbidden by policy (e.g. data-encryption keys without a
    /// proven migration path). The broker refuses.
    Forbidden,
}

/// Registry loading errors.
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    /// File could not be read.
    #[error("registry read failed: {0}")]
    Read(String),
    /// Content invalid.
    #[error("registry invalid: {0}")]
    Parse(String),
}
