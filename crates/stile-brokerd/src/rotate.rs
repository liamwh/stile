//! Lifecycle orchestration: rotate / verify / status / list, driven
//! exclusively by the registry. Every stage outcome lands in the audit
//! trail; no stage ever surfaces secret bytes.

use crate::config::Config;
use stile_core::audit::{AuditRecord, append, now_iso};
use stile_core::backend::{SecretStore, StoreLocation};
use stile_core::deploy;
use stile_core::generation::{generate_hex, generate_urlsafe};
use stile_core::registry::{BackendDef, Policy, Registry, SecretDef, VerifyDef, VerifyKind};
use stile_core::sops::{SopsConfig, SopsStore};
use stile_core::verify;
use stile_protocol::{OperationReport, StageRecord, StageResult};

/// Peer identity for audit records, captured per request from
/// `SO_PEERCRED` (uid/gid/pid) plus the request start time.
pub struct Peer {
    /// Calling uid.
    pub uid: u32,
    /// Calling gid.
    pub gid: u32,
    /// Calling pid (from `SO_PEERCRED`; best-effort attribution).
    pub pid: u32,
    /// When this request started; the audit trail records elapsed time.
    pub started: std::time::Instant,
}

fn fail(op: &str, secret: &str, message: String) -> OperationReport {
    OperationReport::error(op, Some(secret), &message)
}

/// Look up a secret definition; on miss produce the standard error.
pub(crate) fn lookup<'r>(registry: &'r Registry, secret: &str) -> Result<&'r SecretDef, String> {
    registry
        .get(secret)
        .ok_or_else(|| format!("unknown logical secret {secret}"))
}

fn store_for(config: &Config, repo_root: &std::path::Path) -> Result<SopsStore, String> {
    SopsStore::new(SopsConfig {
        sops_bin: config.file.sops_bin.clone(),
        age_key_file: config.file.age_key_file.clone(),
        work_dir: config.file.work_dir.clone(),
        backup_dir: config.file.backup_dir.clone(),
        backups_kept: 5,
    })
    .map(|store| store.with_working_dir(repo_root.to_path_buf()))
    .map_err(|e| format!("store init: {e}"))
}

fn location_of(registry: &Registry, def: &SecretDef) -> StoreLocation {
    StoreLocation {
        path: registry.store_path(def),
        dotenv_key: def.store.key.clone(),
    }
}

fn generate_for(def: &SecretDef) -> Result<String, String> {
    let gen_def = def
        .generation
        .as_ref()
        .ok_or_else(|| "no generation strategy declared".to_string())?;
    let secret = match gen_def.kind {
        stile_core::registry::GenerationKind::Hex => generate_hex(gen_def.bytes),
        stile_core::registry::GenerationKind::Urlsafe => generate_urlsafe(gen_def.bytes),
    }
    .map_err(|e| e.to_string())?;
    Ok(secret.as_str().to_string())
}

fn active_backend(def: &SecretDef) -> Result<Option<&BackendDef>, String> {
    if def.backends.is_empty() {
        return Ok(None);
    }
    let mut active = Vec::new();
    for backend in &def.backends {
        if deploy::command_succeeds(&backend.active)
            .map_err(|e| format!("backend {} status check failed: {e}", backend.id))?
        {
            active.push(backend);
        }
    }
    match active.as_slice() {
        [] => Err("no declared backend is active".into()),
        [backend] => {
            if backend.consumes_secret {
                Ok(Some(*backend))
            } else {
                Err(format!(
                    "active backend {} does not consume {}",
                    backend.id, def.id
                ))
            }
        }
        _ => Err(format!(
            "multiple declared backends active: {}",
            active
                .iter()
                .map(|backend| backend.id.as_str())
                .collect::<Vec<_>>()
                .join(",")
        )),
    }
}

fn verify_step(
    config: &Config,
    step: &VerifyDef,
    value: &str,
    old_value: Option<&str>,
) -> Result<bool, String> {
    match step.kind {
        VerifyKind::HttpStatus => {
            verify::verify_http_status(&step.url, step.expect_status, &config.file.work_dir)
                .map(|_| true)
                .map_err(|e| e.to_string())
        }
        VerifyKind::BearerProbe => verify::verify_bearer(
            &step.url,
            value,
            old_value,
            step.expect_status,
            step.old_expect_status,
            &config.file.work_dir,
        )
        .map_err(|e| e.to_string()),
    }
}

fn verify_declared(
    config: &Config,
    def: &SecretDef,
    value: &str,
    old_value: Option<&str>,
    stages: &mut Vec<StageRecord>,
) -> (bool, Option<bool>) {
    let mut passed = true;
    let mut old_revoked = None;
    let mut steps: Vec<(&str, &VerifyDef)> = Vec::new();
    match active_backend(def) {
        Ok(Some(backend)) => {
            if let Some(step) = backend.verify.as_ref() {
                steps.push(("verify-backend", step));
            }
        }
        Ok(None) => {}
        Err(message) => {
            stages.push(StageRecord {
                stage: "discover-backend".into(),
                result: StageResult::Failed,
                detail: Some(message),
            });
            return (false, None);
        }
    }
    steps.extend(def.verify.iter().map(|step| ("verify", step)));
    for (stage, step) in steps {
        match verify_step(config, step, value, old_value) {
            Ok(revoked) => {
                stages.push(StageRecord {
                    stage: stage.into(),
                    result: StageResult::Ok,
                    detail: Some(step.url.clone()),
                });
                if step.kind == VerifyKind::BearerProbe && step.old_expect_status.is_some() {
                    old_revoked = Some(revoked);
                }
            }
            Err(message) => {
                passed = false;
                stages.push(StageRecord {
                    stage: stage.into(),
                    result: StageResult::Failed,
                    detail: Some(message),
                });
            }
        }
    }
    for check in &def.checks {
        match deploy::command_succeeds(&check.command) {
            Ok(true) => stages.push(StageRecord {
                stage: "verify-consumer".into(),
                result: StageResult::Ok,
                detail: Some(check.id.clone()),
            }),
            Ok(false) => {
                passed = false;
                stages.push(StageRecord {
                    stage: "verify-consumer".into(),
                    result: StageResult::Failed,
                    detail: Some(check.id.clone()),
                });
            }
            Err(error) => {
                passed = false;
                stages.push(StageRecord {
                    stage: "verify-consumer".into(),
                    result: StageResult::Failed,
                    detail: Some(format!("{}: {error}", check.id)),
                });
            }
        }
    }
    (passed, old_revoked)
}

/// Execute the post-generation phases shared by `rotate` and
/// `import-provider-secret`. `value` is the new secret (broker memory).
fn run_phases(
    config: &Config,
    registry: &Registry,
    def: &SecretDef,
    value: &str,
    old_value: Option<Vec<u8>>,
    operation: &str,
    peer: Peer,
) -> OperationReport {
    let mut report = OperationReport::success(operation, Some(&def.id));
    let mut stages: Vec<StageRecord> = Vec::new();

    let store = match store_for(config, &registry.repo_root) {
        Ok(s) => s,
        Err(e) => return fail(operation, &def.id, e),
    };
    let location = location_of(registry, def);

    // 1. Encrypted store.
    let store_stage = match store.write_value_atomic(&location, value.as_bytes()) {
        Ok(()) => {
            report.store_updated = true;
            ("store", StageResult::Ok, Some("sops updated".into()))
        }
        Err(e) => ("store", StageResult::Failed, Some(e.to_string())),
    };
    let store_ok = store_stage.1 == StageResult::Ok;
    stages.push(StageRecord {
        stage: store_stage.0.into(),
        result: store_stage.1,
        detail: store_stage.2,
    });

    if !store_ok {
        return finish(config, report, stages, def, peer, false);
    }

    // 2. Pre-reload hooks (e.g. database role passwords).
    let mut pre_ok = true;
    for hook in &def.pre_reload {
        let result = deploy::run_pre_reload(hook, value.as_bytes());
        let (res, detail) = match &result {
            Ok(()) => (StageResult::Ok, format!("hook {} applied", hook.container)),
            Err(e) => {
                pre_ok = false;
                (StageResult::Failed, e.to_string())
            }
        };
        stages.push(StageRecord {
            stage: "pre-reload".into(),
            result: res,
            detail: Some(detail),
        });
        if !pre_ok {
            break;
        }
    }
    if !pre_ok {
        rollback(config, registry, def, old_value.as_deref(), &mut stages);
        return finish(config, report, stages, def, peer, false);
    }

    // 3. Runtime consumers.
    let mut consumers_ok = true;
    for consumer in &def.consumers {
        let result = deploy::deploy_consumer(consumer, value.as_bytes());
        let (res, detail) = match &result {
            Ok(()) => (StageResult::Ok, format!("{}", consumer.path.display())),
            Err(e) => {
                consumers_ok = false;
                (StageResult::Failed, e.to_string())
            }
        };
        stages.push(StageRecord {
            stage: "deploy".into(),
            result: res,
            detail: Some(detail),
        });
        if !consumers_ok {
            break;
        }
    }
    if consumers_ok {
        report.runtime_updated = true;
    } else {
        rollback(config, registry, def, old_value.as_deref(), &mut stages);
        return finish(config, report, stages, def, peer, false);
    }

    // 4. Reload the selected backend first, then non-backend consumers.
    // Backend discovery is declarative; no endpoint is hardcoded here.
    let backend = match active_backend(def) {
        Ok(backend) => backend,
        Err(message) => {
            stages.push(StageRecord {
                stage: "discover-backend".into(),
                result: StageResult::Failed,
                detail: Some(message),
            });
            rollback(config, registry, def, old_value.as_deref(), &mut stages);
            return finish(config, report, stages, def, peer, false);
        }
    };
    let mut actions = Vec::new();
    if let Some(action) = backend.and_then(|backend| backend.reload.as_ref()) {
        actions.push(("reload-backend", action));
    }
    actions.extend(def.reload.iter().map(|action| ("reload", action)));
    actions.extend(
        def.checks
            .iter()
            .filter_map(|check| check.reload.as_ref())
            .map(|action| ("reload-consumer", action)),
    );
    let mut reload_ok = true;
    let mut did_reload = false;
    for (stage, action) in actions {
        let result = deploy::run_reload(action);
        let (res, detail) = match &result {
            Ok(()) => {
                did_reload = true;
                (
                    StageResult::Ok,
                    format!("{} as {}", action.command, action.user),
                )
            }
            Err(e) => {
                reload_ok = false;
                (StageResult::Failed, e.to_string())
            }
        };
        stages.push(StageRecord {
            stage: stage.into(),
            result: res,
            detail: Some(detail),
        });
        if !reload_ok {
            break;
        }
    }
    report.services_reloaded = did_reload;
    if !reload_ok {
        rollback(config, registry, def, old_value.as_deref(), &mut stages);
        return finish(config, report, stages, def, peer, false);
    }

    // 5. Verification failures keep the applied credential (a backend may
    // still be warming) but the operation itself is an error, never success.
    let old = old_value
        .as_deref()
        .map(|bytes| String::from_utf8_lossy(bytes).into_owned());
    let (verification_passed, old_revoked) =
        verify_declared(config, def, value, old.as_deref(), &mut stages);
    report.verification_passed = verification_passed;
    report.old_credential_revoked = old_revoked;
    report.fingerprint_changed = Some(true);

    finish(config, report, stages, def, peer, verification_passed)
}

/// Best-effort rollback: restore the previous value end-to-end.
#[allow(clippy::too_many_arguments)]
fn rollback(
    config: &Config,
    registry: &Registry,
    def: &SecretDef,
    old_value: Option<&[u8]>,
    stages: &mut Vec<StageRecord>,
) {
    let Some(old) = old_value else {
        stages.push(StageRecord {
            stage: "rollback".into(),
            result: StageResult::Skipped,
            detail: Some("no previous value available".into()),
        });
        return;
    };
    let detail = (|| -> Result<String, String> {
        let store = store_for(config, &registry.repo_root)?;
        let location = location_of(registry, def);
        store
            .write_value_atomic(&location, old)
            .map_err(|e| e.to_string())?;
        for hook in &def.pre_reload {
            deploy::run_pre_reload(hook, old).map_err(|e| e.to_string())?;
        }
        for consumer in &def.consumers {
            deploy::deploy_consumer(consumer, old).map_err(|e| e.to_string())?;
        }
        if let Some(action) = active_backend(def)?.and_then(|backend| backend.reload.as_ref()) {
            deploy::run_reload(action).map_err(|e| e.to_string())?;
        }
        for action in &def.reload {
            deploy::run_reload(action).map_err(|e| e.to_string())?;
        }
        for action in def.checks.iter().filter_map(|check| check.reload.as_ref()) {
            deploy::run_reload(action).map_err(|e| e.to_string())?;
        }
        Ok("previous value restored".into())
    })()
    .unwrap_or_else(|e| format!("rollback incomplete: {e}"));
    let result = if detail.starts_with("previous value restored") {
        StageResult::Ok
    } else {
        StageResult::Failed
    };
    stages.push(StageRecord {
        stage: "rollback".into(),
        result,
        detail: Some(detail),
    });
}

fn finish(
    config: &Config,
    mut report: OperationReport,
    stages: Vec<StageRecord>,
    def: &SecretDef,
    peer: Peer,
    ok: bool,
) -> OperationReport {
    report.stages = Some(stages.clone());
    if !ok {
        report.status = "error".into();
        if report.message.is_none() {
            report.message = Some(format!("{} failed; see stages", report.operation));
        }
    }
    let audit_stages: Vec<(&str, &str, Option<&str>)> = stages
        .iter()
        .map(|s| {
            (
                s.stage.as_str(),
                match s.result {
                    StageResult::Ok => "ok",
                    StageResult::Failed => "failed",
                    StageResult::Skipped => "skipped",
                },
                s.detail.as_deref(),
            )
        })
        .collect();
    append(
        &config.file.audit_path,
        &AuditRecord {
            ts: now_iso(),
            op: &report.operation,
            secret: &def.id,
            uid: peer.uid,
            gid: peer.gid,
            pid: peer.pid,
            duration_ms: peer.started.elapsed().as_millis() as u64,
            result: if ok { "success" } else { "error" },
            stages: &audit_stages,
        },
    );
    report
}

pub(crate) fn dispatch_rotate(
    config: &Config,
    secret: &str,
    _provided: Option<&str>,
    peer: Peer,
) -> OperationReport {
    let registry = match Registry::load(&config.file.registry_path) {
        Ok(r) => r,
        Err(e) => return fail("rotate", secret, format!("registry: {e}")),
    };
    let def = match lookup(&registry, secret) {
        Ok(d) => d,
        Err(e) => return fail("rotate", secret, e),
    };
    if def.policy != Policy::Auto {
        return fail(
            "rotate",
            secret,
            format!(
                "policy is {}{} — {}",
                serde_json::to_string(&def.policy)
                    .unwrap_or_default()
                    .trim_matches('"'),
                def.reason
                    .as_deref()
                    .map(|r| format!(" ({r})"))
                    .unwrap_or_default(),
                match def.policy {
                    Policy::ProviderAssisted => "use import-provider-secret",
                    _ => "rotation refused",
                }
            ),
        );
    }
    let new_value = match generate_for(def) {
        Ok(v) => v,
        Err(e) => return fail("rotate", secret, e),
    };
    let old_value = store_for(config, &registry.repo_root)
        .and_then(|s| {
            let location = location_of(&registry, def);
            s.read_value(&location).map_err(|e| e.to_string())
        })
        .ok();
    run_phases(
        config, &registry, def, &new_value, old_value, "rotate", peer,
    )
}

/// Validate that an import may proceed (policy is provider-assisted and
/// the secret exists). On Ok the broker announces [`Response::ReadyForImport`].
pub(crate) fn prepare_import(config: &Config, secret: &str, _peer: Peer) -> Result<(), String> {
    let registry =
        Registry::load(&config.file.registry_path).map_err(|e| format!("registry: {e}"))?;
    let def = lookup(&registry, secret)?;
    if def.policy != Policy::ProviderAssisted {
        return Err(format!(
            "secret {secret} is not provider-assisted (policy {}); import refused",
            serde_json::to_string(&def.policy)
                .unwrap_or_default()
                .trim_matches('"')
        ));
    }
    Ok(())
}

/// Complete a provider-assisted rotation with the imported value.
pub(crate) fn run_import(
    config: &Config,
    secret: &str,
    value: &str,
    peer: Peer,
) -> OperationReport {
    let registry = match Registry::load(&config.file.registry_path) {
        Ok(r) => r,
        Err(e) => return fail("import-provider-secret", secret, format!("registry: {e}")),
    };
    let def = match lookup(&registry, secret) {
        Ok(d) => d,
        Err(e) => return fail("import-provider-secret", secret, e),
    };
    if value.trim().is_empty() {
        return fail(
            "import-provider-secret",
            secret,
            "empty import value refused".into(),
        );
    }
    let old_value = store_for(config, &registry.repo_root)
        .and_then(|s| {
            let location = location_of(&registry, def);
            s.read_value(&location).map_err(|e| e.to_string())
        })
        .ok();
    run_phases(
        config,
        &registry,
        def,
        value.trim(),
        old_value,
        "import-provider-secret",
        peer,
    )
}

pub(crate) fn dispatch_verify(config: &Config, secret: &str, peer: Peer) -> OperationReport {
    let registry = match Registry::load(&config.file.registry_path) {
        Ok(registry) => registry,
        Err(error) => return fail("verify", secret, format!("registry: {error}")),
    };
    let def = match lookup(&registry, secret) {
        Ok(def) => def,
        Err(error) => return fail("verify", secret, error),
    };
    let value = match store_for(config, &registry.repo_root).and_then(|store| {
        store
            .read_value(&location_of(&registry, def))
            .map_err(|error| error.to_string())
    }) {
        Ok(value) => String::from_utf8_lossy(&value).into_owned(),
        Err(error) => return fail("verify", secret, error),
    };
    let mut report = OperationReport::success("verify", Some(secret));
    let mut stages = Vec::new();
    let (passed, _) = verify_declared(config, def, &value, None, &mut stages);
    report.verification_passed = passed;
    finish(config, report, stages, def, peer, passed)
}

pub(crate) fn dispatch_reconcile(config: &Config, secret: &str, peer: Peer) -> OperationReport {
    let registry = match Registry::load(&config.file.registry_path) {
        Ok(registry) => registry,
        Err(error) => return fail("reconcile", secret, format!("registry: {error}")),
    };
    let def = match lookup(&registry, secret) {
        Ok(def) => def,
        Err(error) => return fail("reconcile", secret, error),
    };
    let value = match store_for(config, &registry.repo_root).and_then(|store| {
        store
            .read_value(&location_of(&registry, def))
            .map_err(|error| error.to_string())
    }) {
        Ok(value) => value,
        Err(error) => return fail("reconcile", secret, error),
    };
    let value_text = String::from_utf8_lossy(&value).into_owned();
    let mut report = OperationReport::success("reconcile", Some(secret));
    report.fingerprint_changed = Some(false);
    let mut stages = Vec::new();

    let backend = match active_backend(def) {
        Ok(backend) => backend,
        Err(message) => {
            stages.push(StageRecord {
                stage: "discover-backend".into(),
                result: StageResult::Failed,
                detail: Some(message),
            });
            return finish(config, report, stages, def, peer, false);
        }
    };

    let mut consumer_changed = false;
    for consumer in &def.consumers {
        let matches = match deploy::consumer_matches(consumer, &value) {
            Ok(matches) => matches,
            Err(error) => {
                stages.push(StageRecord {
                    stage: "compare-consumer".into(),
                    result: StageResult::Failed,
                    detail: Some(error.to_string()),
                });
                return finish(config, report, stages, def, peer, false);
            }
        };
        if !matches {
            if let Err(error) = deploy::deploy_consumer(consumer, &value) {
                stages.push(StageRecord {
                    stage: "deploy".into(),
                    result: StageResult::Failed,
                    detail: Some(error.to_string()),
                });
                return finish(config, report, stages, def, peer, false);
            }
            consumer_changed = true;
            stages.push(StageRecord {
                stage: "deploy".into(),
                result: StageResult::Ok,
                detail: Some(consumer.path.display().to_string()),
            });
        }
    }
    report.runtime_updated = consumer_changed;

    let backend_stale = backend
        .and_then(|selected| selected.verify.as_ref())
        .is_some_and(|step| {
            verify::verify_bearer_once(
                &step.url,
                &value_text,
                step.expect_status,
                &config.file.work_dir,
            )
            .is_err()
        });
    let stale_checks: Vec<_> = def
        .checks
        .iter()
        .filter(|check| !matches!(deploy::command_succeeds(&check.command), Ok(true)))
        .collect();
    let mut did_reload = false;
    if (consumer_changed || backend_stale)
        && let Some(action) = backend.and_then(|selected| selected.reload.as_ref())
    {
        match deploy::run_reload(action) {
            Ok(()) => {
                did_reload = true;
                stages.push(StageRecord {
                    stage: "reload-backend".into(),
                    result: StageResult::Ok,
                    detail: backend.map(|selected| selected.id.clone()),
                });
            }
            Err(error) => {
                stages.push(StageRecord {
                    stage: "reload-backend".into(),
                    result: StageResult::Failed,
                    detail: Some(error.to_string()),
                });
                return finish(config, report, stages, def, peer, false);
            }
        }
    }
    if consumer_changed {
        for action in &def.reload {
            if let Err(error) = deploy::run_reload(action) {
                stages.push(StageRecord {
                    stage: "reload".into(),
                    result: StageResult::Failed,
                    detail: Some(error.to_string()),
                });
                return finish(config, report, stages, def, peer, false);
            }
            did_reload = true;
            stages.push(StageRecord {
                stage: "reload".into(),
                result: StageResult::Ok,
                detail: Some(format!("{} as {}", action.command, action.user)),
            });
        }
    }
    for check in &def.checks {
        let needs_reload =
            consumer_changed || stale_checks.iter().any(|stale| stale.id == check.id);
        if !needs_reload {
            continue;
        }
        if let Some(action) = check.reload.as_ref() {
            if let Err(error) = deploy::run_reload(action) {
                stages.push(StageRecord {
                    stage: "reload-consumer".into(),
                    result: StageResult::Failed,
                    detail: Some(format!("{}: {error}", check.id)),
                });
                return finish(config, report, stages, def, peer, false);
            }
            did_reload = true;
            stages.push(StageRecord {
                stage: "reload-consumer".into(),
                result: StageResult::Ok,
                detail: Some(check.id.clone()),
            });
        }
    }
    report.services_reloaded = did_reload;

    let (passed, _) = verify_declared(config, def, &value_text, None, &mut stages);
    report.verification_passed = passed;
    finish(config, report, stages, def, peer, passed)
}

pub(crate) fn dispatch_status(config: &Config, secret: &str, _peer: Peer) -> OperationReport {
    let registry = match Registry::load(&config.file.registry_path) {
        Ok(r) => r,
        Err(e) => return fail("status", secret, format!("registry: {e}")),
    };
    let def = match lookup(&registry, secret) {
        Ok(d) => d,
        Err(e) => return fail("status", secret, e),
    };
    let mut report = OperationReport::success("status", Some(secret));
    let policy: String = serde_json::to_string(&def.policy)
        .unwrap_or_default()
        .trim_matches('"')
        .to_string();
    report.message = Some(format!(
        "policy={policy} consumers={} backends={} reload={} checks={} verify={}{}{}",
        def.consumers.len(),
        def.backends.len(),
        def.reload.len(),
        def.checks.len(),
        def.verify.len(),
        def.reason
            .as_deref()
            .map(|r| format!(" reason={r}"))
            .unwrap_or_default(),
        def.human_step
            .as_deref()
            .map(|h| format!(" human_step={h}"))
            .unwrap_or_default(),
    ));
    report
}

pub(crate) fn dispatch_list(config: &Config, _peer: Peer) -> OperationReport {
    let registry = match Registry::load(&config.file.registry_path) {
        Ok(r) => r,
        Err(e) => return fail("list", "", format!("registry: {e}")),
    };
    let mut report = OperationReport::success("list", None);
    let ids: Vec<String> = registry
        .secrets()
        .values()
        .map(|def| {
            let policy = serde_json::to_string(&def.policy)
                .unwrap_or_default()
                .trim_matches('"')
                .to_string();
            format!("{} {}", def.id, policy)
        })
        .collect();
    report.message = Some(ids.join("\n"));
    report
}
