//! 原生密文写钥的受控切换：先分发读取能力，再切换写入，最后按领域事务重加密。
use super::{Error, Result, install::Input, local::Journal, runtime_files};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::Connection;
use uuid::Uuid;

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Purpose {
    Native,
    Windows,
    OidcCredentials,
    Recovery,
}
impl Purpose {
    fn path(self) -> &'static str {
        match self {
            Self::Native => "/native_protection",
            Self::Windows => "/native_protocols/windows/protocol_protection",
            Self::OidcCredentials => "/identity/oidc",
            Self::Recovery => "/recovery_credentials",
        }
    }
    fn stages(
        self,
        original: &Value,
        next: &std::path::Path,
        key_id: &str,
    ) -> Result<(Value, Value)> {
        match self {
            Self::Native | Self::Windows => key_stages(original, next),
            Self::OidcCredentials | Self::Recovery => {
                let (map, active, limit) = if self == Self::OidcCredentials {
                    ("credential_keys", "active_credential_key", 8)
                } else {
                    ("key_files", "active_key", 32)
                };
                let mut read = original.clone();
                let keys = read[map].as_object_mut().ok_or(Error::Corrupt)?;
                if keys.len() >= limit || keys.contains_key(key_id) {
                    return Err(Error::Conflict);
                }
                keys.insert(key_id.into(), json!(next));
                let mut write = read.clone();
                write[active] = json!(key_id);
                Ok((read, write))
            }
        }
    }
    fn active_id(self, config: &crate::config::Config) -> Result<String> {
        match self {
            Self::Native | Self::Windows => Ok(self.protector(config)?.id().to_owned()),
            Self::OidcCredentials => {
                let oidc = config.identity.oidc.as_ref().ok_or(Error::Corrupt)?;
                oidc.credential_keys().map_err(|_| Error::Corrupt)?;
                Ok(oidc.active_credential_key.clone())
            }
            Self::Recovery => Ok(config
                .recovery_credentials
                .as_ref()
                .ok_or(Error::Corrupt)?
                .open()
                .map_err(|_| Error::Corrupt)?
                .keys
                .active()
                .to_owned()),
        }
    }
    fn protector(
        self,
        config: &crate::config::Config,
    ) -> Result<std::sync::Arc<rss_mdm_native_protection::Protector>> {
        match self {
            Self::Native => config.native_protector().map_err(|_| Error::Corrupt),
            Self::OidcCredentials | Self::Recovery => Err(Error::Input),
            Self::Windows => config
                .native_protocols
                .windows
                .as_ref()
                .ok_or(Error::Input)?
                .protocol_protection
                .load()
                .map_err(|_| Error::Corrupt),
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub installation: Input,
    pub purpose: Purpose,
    pub operation_id: Uuid,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Distributing,
    Activating,
    Rewrapping,
    Complete,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Receipt {
    pub operation_id: Uuid,
    pub phase: Phase,
    pub key_id: String,
    pub purpose: Purpose,
    pub rewritten: u64,
    pub historical_keys_retained: bool,
}
#[derive(Serialize, Deserialize)]
struct Saved {
    receipt: Receipt,
    base: Value,
    read: Value,
    write: Value,
    tenants: Vec<Uuid>,
}

fn successor(mut runtime: Value, protection: Value, purpose: Purpose) -> Result<Value> {
    *runtime.pointer_mut(purpose.path()).ok_or(Error::Corrupt)? = protection;
    let revision = runtime["runtime_binding"]["revision"]
        .as_u64()
        .and_then(|r| r.checked_add(1))
        .filter(|r| *r <= i64::MAX as u64)
        .ok_or(Error::Corrupt)?;
    let digest = super::application::fingerprint(&runtime)?;
    runtime["runtime_binding"]["revision"] = json!(revision);
    runtime["runtime_binding"]["operation_id"] = json!(Uuid::new_v4());
    runtime["runtime_binding"]["material_digest"] = json!(digest);
    Ok(runtime)
}
pub async fn rotate(request: Request) -> Result<Receipt> {
    if request.operation_id.is_nil() {
        return Err(Error::Input);
    }
    let input = &request.installation;
    let journal = Journal::open(&input.directory)?;
    admit_rotation(&journal).await?;
    let operation = Journal::open(
        &input
            .directory
            .join(format!("protection-{}", request.operation_id)),
    )?;
    operation.secret(
        "request.json",
        &serde_json::to_vec(&request).map_err(|_| Error::Input)?,
    )?;
    let original: Option<Saved> = operation.load("rotation.json")?;
    let base = match &original {
        Some(saved) => saved.base.clone(),
        None => runtime_files::current(&journal)?,
    };
    let mut c = rotation_connection(input, &base).await?;
    let mut saved = match original {
        Some(saved) => saved,
        None => reserve_rotation(&request, &journal, &operation, &mut c, &base).await?,
    };
    if saved.receipt.phase != Phase::Complete {
        let active = journal
            .load::<Option<Uuid>>("protection-operation.json")?
            .flatten();
        if active.is_some_and(|id| id != request.operation_id) {
            return Err(Error::Busy);
        }
        journal.save("protection-operation.json", &request.operation_id)?;
    }
    if saved.receipt.purpose != request.purpose {
        return Err(Error::Conflict);
    }
    verify_candidates(&saved)?;
    if saved.receipt.phase == Phase::Distributing {
        distribute(input, &operation, &mut saved).await?;
    }
    if saved.receipt.phase == Phase::Activating {
        activate_writers(input, &operation, &mut saved).await?;
    }
    if saved.receipt.phase == Phase::Rewrapping {
        rewrap_batch(&operation, &mut saved, &mut c).await?;
    }
    if saved.receipt.phase == Phase::Complete
        && journal
            .load::<Option<Uuid>>("protection-operation.json")?
            .flatten()
            == Some(request.operation_id)
    {
        journal.save("protection-operation.json", &Option::<Uuid>::None)?;
    }
    c.close().await.map_err(|_| Error::Storage)?;
    Ok(saved.receipt)
}
async fn apply(input: &Input, runtime: &Value) -> Result<bool> {
    match runtime_files::apply(&input.directory, &input.deployment, runtime).await {
        Ok(_) => Ok(true),
        Err(Error::Storage | Error::Conflict) => Ok(false),
        Err(error) => Err(error),
    }
}

fn key_stages(original: &Value, next: &std::path::Path) -> Result<(Value, Value)> {
    let mut read = original.clone();
    let history = read["historical_files"]
        .as_array_mut()
        .ok_or(Error::Corrupt)?;
    if history.len() >= 15 {
        return Err(Error::Conflict);
    }
    history.push(json!(next));
    let mut write = original.clone();
    let previous = write["active_file"].clone();
    write["active_file"] = json!(next);
    write["historical_files"]
        .as_array_mut()
        .ok_or(Error::Corrupt)?
        .push(previous);
    Ok((read, write))
}

async fn reserve_rotation(
    request: &Request,
    journal: &Journal,
    operation: &Journal,
    c: &mut sqlx::PgConnection,
    base: &Value,
) -> Result<Saved> {
    let existing = journal
        .load::<Option<Uuid>>("protection-operation.json")?
        .flatten();
    if existing.is_some_and(|id| id != request.operation_id) {
        return Err(Error::Busy);
    }
    let next_path = operation.path("encryption.key")?;
    if !next_path.exists() {
        use ring::rand::SecureRandom;
        let mut bytes = zeroize::Zeroizing::new([0u8; 32]);
        ring::rand::SystemRandom::new()
            .fill(bytes.as_mut())
            .map_err(|_| Error::Storage)?;
        if request.purpose == Purpose::OidcCredentials {
            let encoded = zeroize::Zeroizing::new(
                bytes.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            );
            operation.secret("encryption.key", encoded.as_bytes())?;
        } else {
            operation.secret("encryption.key", bytes.as_slice())?;
        }
    }
    let next = if request.purpose == Purpose::OidcCredentials {
        zeroize::Zeroizing::new(
            crate::identity::key(&next_path)
                .map_err(|_| Error::Corrupt)?
                .to_vec(),
        )
    } else {
        crate::config::read(&next_path, 32, true).map_err(|_| Error::Corrupt)?
    };
    let key_id = rss_mdm_native_protection::Protector::new(&next)
        .map_err(|_| Error::Corrupt)?
        .id()
        .to_owned();
    let tenants = sqlx::query_scalar(
        "SELECT tenant_id FROM public.mdm_tenants WHERE NOT deleted ORDER BY tenant_id",
    )
    .fetch_all(&mut *c)
    .await
    .map_err(|_| Error::Storage)?;
    let original = base
        .pointer(request.purpose.path())
        .filter(|v| v.is_object())
        .ok_or(Error::Conflict)?;
    let (read_protection, write_protection_stage) =
        request.purpose.stages(original, &next_path, &key_id)?;
    let read = successor(base.clone(), read_protection, request.purpose)?;
    let write = successor(read.clone(), write_protection_stage, request.purpose)?;
    let saved = Saved {
        receipt: Receipt {
            operation_id: request.operation_id,
            phase: Phase::Distributing,
            key_id,
            purpose: request.purpose,
            rewritten: 0,
            historical_keys_retained: true,
        },
        base: base.clone(),
        read,
        write,
        tenants,
    };
    operation.save("rotation.json", &saved)?;
    Ok(saved)
}

async fn rewrap_native(
    c: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
    protector: &rss_mdm_native_protection::Protector,
) -> Result<u64> {
    let tenant_uuid = uuid::Uuid::parse_str(&tenant.to_string()).map_err(|_| Error::Corrupt)?;
    let mut rewritten = 0;

    rewritten += rss_mdm_webhook_service::materials::rewrap(&mut *c, tenant_uuid, protector)
        .await
        .map_err(|_| Error::Corrupt)?;
    rewritten += rss_mdm_mail_service::store::rewrap(&mut *c, &tenant.to_string(), protector)
        .await
        .map_err(|_| Error::Corrupt)?;
    rewritten +=
        rss_mdm_windows_channel::wns_materials::rewrap(&mut *c, &tenant.to_string(), protector)
            .await
            .map_err(|_| Error::Corrupt)?;
    rewritten += rss_mdm_content_service::connections::rewrap(&mut *c, tenant, protector)
        .await
        .map_err(|_| Error::Corrupt)?;
    rewritten += rss_mdm_registration_service::agent::connections::rewrap(
        rss_mdm_install_support::StorageProfile::Mdm,
        &mut *c,
        tenant,
        protector,
    )
    .await
    .map_err(|_| Error::Corrupt)?;
    rewritten += rss_mdm_task_trust::trust::rewrap(
        rss_mdm_install_support::StorageProfile::Mdm,
        rss_mdm_task_trust::Use::AgentTask,
        &mut *c,
        tenant,
        protector,
    )
    .await
    .map_err(|_| Error::Corrupt)?;
    rewritten += rss_mdm_apple_channel::rewrap::run(&mut *c, &tenant.to_string(), protector)
        .await
        .map_err(|_| Error::Corrupt)?;
    rewritten +=
        rss_mdm_apple_channel::runtime_materials::rewrap(&mut *c, &tenant.to_string(), protector)
            .await
            .map_err(|_| Error::Corrupt)?;
    Ok(rewritten)
}

async fn rewrap_recovery(
    c: &mut sqlx::PgConnection,
    tenant: Uuid,
    config: &crate::config::Config,
) -> Result<u64> {
    let recovery = config
        .recovery_credentials
        .as_ref()
        .ok_or(Error::Corrupt)?
        .open()
        .map_err(|_| Error::Corrupt)?;
    let prepared = rss_mdm_recovery_credentials::storage::prepare_rewrap_in(
        rss_mdm_recovery_credentials::Custody::new(
            rss_mdm_install_support::StorageProfile::Mdm,
            None,
        ),
        c,
        tenant,
        &recovery.keys,
    )
    .await
    .map_err(|_| Error::Corrupt)?;
    rss_mdm_recovery_credentials::storage::rewrap_in(
        rss_mdm_recovery_credentials::Custody::new(
            rss_mdm_install_support::StorageProfile::Mdm,
            None,
        ),
        c,
        prepared,
        &recovery.keys,
    )
    .await
    .map_err(|_| Error::Corrupt)
}

async fn rewrap_tenant(
    c: &mut sqlx::PgConnection,
    tenant_id: Uuid,
    runtime: &Value,
    purpose: Purpose,
) -> Result<u64> {
    let mut rewritten = 0;

    let config: crate::config::Config =
        serde_json::from_value(runtime.clone()).map_err(|_| Error::Corrupt)?;
    let tenant =
        rss_request_context::TenantId::parse(&tenant_id.to_string()).map_err(|_| Error::Corrupt)?;
    let mut tx = c.begin().await.map_err(|_| Error::Storage)?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant_id.to_string())
        .execute(&mut *tx)
        .await
        .map_err(|_| Error::Storage)?;
    match purpose {
        Purpose::OidcCredentials => {
            let oidc = config.identity.oidc.as_ref().ok_or(Error::Corrupt)?;
            let keys = oidc.credential_keys().map_err(|_| Error::Corrupt)?;
            let instance = rss_identity_core::InstanceId::parse(&config.identity.instance_id)
                .map_err(|_| Error::Corrupt)?;
            rewritten += keys
                .reencrypt_tenant(&mut tx, instance, tenant)
                .await
                .map_err(|_| Error::Corrupt)? as u64;
        }
        Purpose::Recovery => {
            rewritten += rewrap_recovery(&mut tx, tenant_id, &config).await?;
        }
        Purpose::Windows => {
            let protector = purpose.protector(&config)?;
            rewritten += rss_mdm_windows_channel::enrollment_store::rewrap_protocol(
                &mut tx,
                &tenant_id.to_string(),
                &protector,
            )
            .await
            .map_err(|_| Error::Corrupt)?;
        }
        Purpose::Native => {
            let protector = purpose.protector(&config)?;
            rewritten += rewrap_native(&mut tx, tenant, &protector).await?;
        }
    }
    tx.commit().await.map_err(|_| Error::Storage)?;

    Ok(rewritten)
}

async fn admit_rotation(journal: &Journal) -> Result<()> {
    if journal
        .load::<Option<Uuid>>("backup-operation.json")?
        .flatten()
        .is_some()
    {
        return Err(Error::Busy);
    }
    if journal
        .load::<Option<Uuid>>("configuration-operation.json")?
        .flatten()
        .is_some()
    {
        return Err(Error::Busy);
    }

    Ok(())
}

async fn distribute(input: &Input, operation: &Journal, saved: &mut Saved) -> Result<()> {
    let observed = apply(input, &saved.read).await?;
    if !observed {
        return Ok(());
    }
    saved.receipt.phase = Phase::Activating;
    operation.save("rotation.json", saved)?;

    Ok(())
}

async fn activate_writers(input: &Input, operation: &Journal, saved: &mut Saved) -> Result<()> {
    let observed = apply(input, &saved.write).await?;
    if !observed {
        return Ok(());
    }
    // apply has atomically retained the complete write input with its real observation.
    saved.receipt.phase = Phase::Rewrapping;
    operation.save("rotation.json", saved)?;

    Ok(())
}

async fn rewrap_batch(
    operation: &Journal,
    saved: &mut Saved,
    c: &mut sqlx::PgConnection,
) -> Result<()> {
    let mut rewritten = 0;
    for tenant in &saved.tenants {
        rewritten += rewrap_tenant(&mut *c, *tenant, &saved.write, saved.receipt.purpose).await?;
    }
    saved.receipt.rewritten = saved
        .receipt
        .rewritten
        .checked_add(rewritten)
        .ok_or(Error::Corrupt)?;
    if rewritten == 0 || saved.receipt.purpose == Purpose::OidcCredentials {
        saved.receipt.phase = Phase::Complete;
    }
    operation.save("rotation.json", saved)?;

    Ok(())
}

fn verify_candidates(saved: &Saved) -> Result<()> {
    let purpose = saved.receipt.purpose;
    let original: crate::config::Config =
        serde_json::from_value(saved.base.clone()).map_err(|_| Error::Corrupt)?;
    let old_key = purpose.active_id(&original)?;
    if old_key == saved.receipt.key_id {
        return Err(Error::Conflict);
    }
    let write = saved.write.pointer(purpose.path()).ok_or(Error::Corrupt)?;
    let next = match purpose {
        Purpose::Native | Purpose::Windows => &write["active_file"],
        Purpose::OidcCredentials => &write["credential_keys"][&saved.receipt.key_id],
        Purpose::Recovery => &write["key_files"][&saved.receipt.key_id],
    };
    let (expected_read, expected_write) = purpose.stages(
        saved.base.pointer(purpose.path()).ok_or(Error::Corrupt)?,
        std::path::Path::new(next.as_str().ok_or(Error::Corrupt)?),
        &saved.receipt.key_id,
    )?;
    if saved.read.pointer(purpose.path()) != Some(&expected_read) || write != &expected_write {
        return Err(Error::Conflict);
    }
    for (runtime, active) in [
        (&saved.read, &old_key),
        (&saved.write, &saved.receipt.key_id),
    ] {
        let candidate: crate::config::Config =
            serde_json::from_value(runtime.clone()).map_err(|_| Error::Corrupt)?;
        // Construction loads every retained key; exact stage equality preserves historical readers.
        if purpose.active_id(&candidate)? != *active {
            return Err(Error::Conflict);
        }
    }
    Ok(())
}

async fn rotation_connection(input: &Input, base: &Value) -> Result<sqlx::PgConnection> {
    let decoded: crate::config::Config =
        serde_json::from_value(base.clone()).map_err(|_| Error::Corrupt)?;
    let mut c = sqlx::PgConnection::connect_with(
        &input
            .database("mdm_owner")?
            .options()
            .map_err(|_| Error::Input)?,
    )
    .await
    .map_err(|_| Error::Storage)?;
    sqlx::raw_sql("SET statement_timeout='10s'; SET lock_timeout='6s'")
        .execute(&mut c)
        .await
        .map_err(|_| Error::Storage)?;
    if !crate::migration::owner_admitted(&mut c)
        .await
        .map_err(|_| Error::Storage)?
    {
        return Err(Error::Input);
    }
    let identity = crate::migration::Installation {
        instance_id: decoded.identity.instance_id.clone(),
        target: decoded.storage_binding.target,
        lineage: decoded.storage_binding.lineage,
        audit_mode: decoded.audit.mode(),
    };
    crate::migration::verify_identity(&mut c, &identity)
        .await
        .map_err(|_| Error::Conflict)?;
    sqlx::query("SELECT pg_advisory_lock(2823,1)")
        .execute(&mut c)
        .await
        .map_err(|_| Error::Storage)?;
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn distribution_keeps_old_writer_and_both_stages_read_new_and_old_keys() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let old = root.join("old");
        let next = root.join("next");
        for (path, bytes) in [(&old, [1u8; 32]), (&next, [2u8; 32])] {
            std::fs::write(path, bytes).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let new_id = rss_mdm_native_protection::Protector::new(&[2; 32])
            .unwrap()
            .id()
            .to_owned();
        for purpose in [Purpose::Native, Purpose::Windows] {
            let mut base: Value =
                serde_json::from_str(include_str!("../../../../fixtures/mdm-config.example.json"))
                    .unwrap();
            let original = json!({"active_file":old,"historical_files":[],"fingerprint_file":old});
            *base.pointer_mut(purpose.path()).unwrap() = original.clone();
            let (read, write) = purpose.stages(&original, &next, &new_id).unwrap();
            let saved = Saved {
                receipt: Receipt {
                    operation_id: Uuid::new_v4(),
                    phase: Phase::Distributing,
                    key_id: new_id.clone(),
                    purpose,
                    rewritten: 0,
                    historical_keys_retained: true,
                },
                read: successor(base.clone(), read, purpose).unwrap(),
                write: successor(base.clone(), write, purpose).unwrap(),
                base,
                tenants: vec![],
            };
            verify_candidates(&saved).unwrap();
            let read = purpose
                .protector(&serde_json::from_value(saved.read.clone()).unwrap())
                .unwrap();
            let write = purpose
                .protector(&serde_json::from_value(saved.write.clone()).unwrap())
                .unwrap();
            let aad = rss_mdm_native_protection::ProtectionContext::new(
                rss_request_context::TenantId::parse("11111111-1111-4111-8111-111111111111")
                    .unwrap(),
                "rotation",
                "phase-test",
                1,
            )
            .unwrap()
            .derive();
            for sealed in [
                read.seal_bytes(b"retained", &aad).unwrap(),
                write.seal_bytes(b"retained", &aad).unwrap(),
            ] {
                assert_eq!(
                    read.open_bytes(&sealed, &aad).unwrap().expose(),
                    b"retained"
                );
                assert_eq!(
                    write.open_bytes(&sealed, &aad).unwrap().expose(),
                    b"retained"
                );
            }
            let mut invalid = saved;
            invalid.read = invalid.write.clone();
            assert!(matches!(verify_candidates(&invalid), Err(Error::Conflict)));
        }
        for (purpose, keys, active) in [
            (
                Purpose::OidcCredentials,
                "credential_keys",
                "active_credential_key",
            ),
            (Purpose::Recovery, "key_files", "active_key"),
        ] {
            let original = json!({keys:{"old":old},active:"old"});
            let (read, write) = purpose.stages(&original, &next, &new_id).unwrap();
            assert_eq!(read[active], "old");
            assert_eq!(write[active], new_id);
            assert_eq!(read[keys], write[keys]);
            assert_eq!(read[keys]["old"], json!(old));
            assert_eq!(read[keys][&new_id], json!(next));
        }
    }
}
