//! Bounded first-installation preparation with stable, durable identities and separate credentials.
use super::{Error, Result, local::Journal};
use crate::migration::{AuditMode, Installation};
use base64::Engine;
use ring::{
    hmac,
    rand::{SecureRandom, SystemRandom},
};
use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
};
use uuid::Uuid;

pub(super) const ROLES: &[&str] = &[
    "mdm_owner",
    "mdm_identity_maintenance",
    "mdm_identity_runtime",
    "mdm_identity_audit",
    "mdm_audit_worker",
    "mdm_access",
    "mdm_runtime",
    "mdm_command_runtime",
    "mdm_flow_runtime",
    "mdm_software_driver",
    "mdm_webhook_operator",
    "mdm_tenant_registry",
    "mdm_identity_provisioning",
];
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatabaseInput {
    /// Cluster bootstrap login is confined to the deployment operator.
    pub administrator: crate::config::Database,
    pub name: String,
}
#[derive(Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentStorage {
    #[default]
    Volume,
    /// Qualify a tenant connection before the first content-store admission.
    S3,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub directory: PathBuf,
    pub deployment: super::runtime_files::Config,
    #[serde(default)]
    pub additional_hosts: Vec<super::tenant_hosts::Slot>,
    #[serde(default)]
    pub storage_profiles: Vec<super::providers::storage::Profile>,
    #[serde(default)]
    pub mail_profiles: Vec<super::providers::mail::Profile>,
    #[serde(default)]
    pub content_storage: ContentStorage,
    pub database: DatabaseInput,
    pub audit_mode: AuditMode,
    pub organization_name: String,
    pub platform_login: String,
    pub administrator_login: String,
    pub platform_password_file: Option<PathBuf>,
    pub administrator_password_file: Option<PathBuf>,
    pub origin: String,
    pub listen: SocketAddr,
    pub trusted_gateway: IpAddr,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    Prepared,
    Database,
    Platform,
    Business,
    HostPending,
    Initialized,
}
/// An installation receipt is deliberately not a deployment-success declaration.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Receipt {
    pub operation_id: Uuid,
    pub instance_id: Uuid,
    pub tenant_id: Uuid,
    pub platform_principal_id: Uuid,
    pub administrator_id: Uuid,
    pub host_id: Uuid,
    pub stage: Stage,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Saved {
    version: u8,
    fingerprint: String,
    receipt: Receipt,
    target: [u8; 16],
    lineage: [u8; 16],
    tenant_operation: Uuid,
    platform_authorization: Uuid,
    business_authorization: Uuid,
}
fn invalid<T>(_: T) -> Error {
    Error::Input
}
impl Input {
    fn validate(&self) -> Result<()> {
        super::tenant_hosts::validate_slots(self)?;
        let u = url::Url::parse(&self.origin).map_err(invalid)?;
        if u.scheme() != "https"
            || u.host_str().is_none()
            || !u.username().is_empty()
            || u.password().is_some()
            || u.origin().ascii_serialization() != self.origin
            || self.listen.ip().is_unspecified()
            || self.trusted_gateway.is_unspecified()
            || self.listen.port() == 0
            || self.database.name.is_empty()
            || self.organization_name.trim().is_empty()
            || self.organization_name.chars().count() > 128
            || self.organization_name.contains('\0')
            || self.database.name.len() > 63
            || !self
                .database
                .name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
            || !self
                .database
                .name
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_lowercase)
        {
            return Err(Error::Input);
        }
        rss_identity_core::account::LoginKey::parse(&self.platform_login).map_err(invalid)?;
        rss_identity_core::account::LoginKey::parse(&self.administrator_login).map_err(invalid)?;
        self.database.administrator.options().map_err(invalid)?;
        Ok(())
    }
    pub(super) fn database(&self, role: &str) -> Result<crate::config::Database> {
        if !ROLES.contains(&role) {
            return Err(Error::Input);
        }
        Ok(crate::config::Database {
            host: self.database.administrator.host.clone(),
            port: self.database.administrator.port,
            name: self.database.name.clone(),
            user: role.into(),
            password_file: self.directory.join(format!("database-{role}.password")),
            ca_file: self.database.administrator.ca_file.clone(),
        })
    }

    fn audit(&self, journal: &Journal) -> Result<crate::config::AuditConfig> {
        Ok(match self.audit_mode {
            AuditMode::Plain => crate::config::AuditConfig::Plain,
            AuditMode::Ledger => crate::config::AuditConfig::Ledger {
                key_id: "installation-ledger".into(),
                key_file: journal.path("ledger.key")?,
            },
        })
    }
}
fn random(length: usize) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    let mut bytes = zeroize::Zeroizing::new(vec![0; length]);
    SystemRandom::new()
        .fill(bytes.as_mut())
        .map_err(|_| Error::Storage)?;
    Ok(bytes)
}
fn protected(
    journal: &Journal,
    name: &str,
    length: usize,
    first: bool,
) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    let path = journal.path(name)?;
    match std::fs::symlink_metadata(&path) {
        Ok(_) => {
            let value =
                crate::config::read(&path, length as u64, true).map_err(|_| Error::Corrupt)?;
            if value.len() != length {
                return Err(Error::Corrupt);
            }
            Ok(value)
        }
        Err(e) if first && e.kind() == std::io::ErrorKind::NotFound => {
            let bytes = random(length)?;
            journal.secret(name, &bytes)?;
            Ok(bytes)
        }
        Err(_) => Err(Error::Corrupt),
    }
}
fn password(
    journal: &Journal,
    name: &str,
    input: Option<&Path>,
    first: bool,
) -> Result<zeroize::Zeroizing<String>> {
    let path = journal.path(name)?;
    let supplied = input
        .map(crate::config::secret)
        .transpose()
        .map_err(invalid)?;
    let value = match std::fs::symlink_metadata(&path) {
        Ok(_) => crate::config::secret(&path).map_err(|_| Error::Corrupt)?,
        Err(e) if first && e.kind() == std::io::ErrorKind::NotFound => {
            let value = match &supplied {
                Some(value) => zeroize::Zeroizing::new(value.to_string()),
                None => zeroize::Zeroizing::new(
                    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random(32)?.as_slice()),
                ),
            };
            journal.secret(name, value.as_bytes())?;
            value
        }
        Err(_) => return Err(Error::Corrupt),
    };
    if supplied
        .as_ref()
        .is_some_and(|expected| expected.as_str() != value.as_str())
    {
        return Err(Error::Conflict);
    }
    rss_identity_core::account::Password::new(value.to_string()).map_err(invalid)?;
    Ok(value)
}
fn coordinates(input: &Input, saved: &Saved) -> Installation {
    Installation {
        audit_mode: input.audit_mode,
        instance_id: saved.receipt.instance_id.to_string(),
        target: saved.target,
        lineage: saved.lineage,
    }
}
/// Resume the original installation. Host activation is separately observed by the deployment owner.
/// Passwords are delivered through owner-only journal files, never the serialized receipt or logs.
pub async fn install(input: Input) -> Result<Receipt> {
    let journal = admit_installation(&input)?;
    if journal
        .load::<Option<Uuid>>("backup-operation.json")?
        .flatten()
        .is_some()
    {
        return Err(Error::Busy);
    }
    let previous = journal.load::<Saved>("installation.json")?;
    let first = previous.is_none();
    let fingerprint_key = protected(&journal, "operation.key", 32, first)?;
    let platform = password(
        &journal,
        "platform-password",
        input.platform_password_file.as_deref(),
        first,
    )?;
    let administrator = password(
        &journal,
        "administrator-password",
        input.administrator_password_file.as_deref(),
        first,
    )?;
    let mut database_passwords = Vec::new();
    for role in ROLES {
        database_passwords.push(password(
            &journal,
            &format!("database-{role}.password"),
            None,
            first,
        )?);
    }
    let audit_recovery = protected(&journal, "audit-recovery.key", 32, first)?;
    let identity_audit_recovery = protected(&journal, "identity-audit-recovery.key", 32, first)?;
    let native_key = protected(&journal, "native.key", 32, first)?;
    let native_fingerprint = protected(&journal, "native-fingerprint.key", 32, first)?;
    let ledger_key = if input.audit_mode == AuditMode::Ledger {
        Some(protected(&journal, "ledger.key", 32, first)?)
    } else {
        None
    };
    let canonical = zeroize::Zeroizing::new(
        serde_json::to_vec(&(
            &input,
            platform.as_str(),
            administrator.as_str(),
            &database_passwords,
            audit_recovery.as_slice(),
            identity_audit_recovery.as_slice(),
            native_key.as_slice(),
            native_fingerprint.as_slice(),
            ledger_key.as_deref(),
        ))
        .map_err(invalid)?,
    );
    let fingerprint = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
        hmac::sign(
            &hmac::Key::new(hmac::HMAC_SHA256, &fingerprint_key),
            &canonical,
        )
        .as_ref(),
    );
    let saved = if let Some(saved) = previous {
        if saved.version != 1 || saved.fingerprint != fingerprint {
            return Err(Error::Conflict);
        }
        saved
    } else {
        let saved = Saved {
            version: 1,
            fingerprint,
            receipt: Receipt {
                operation_id: Uuid::new_v4(),
                instance_id: Uuid::new_v4(),
                tenant_id: Uuid::new_v4(),
                platform_principal_id: Uuid::new_v4(),
                administrator_id: Uuid::new_v4(),
                host_id: Uuid::new_v4(),
                stage: Stage::Prepared,
            },
            target: Uuid::new_v4().into_bytes(),
            lineage: Uuid::new_v4().into_bytes(),
            tenant_operation: Uuid::new_v4(),
            platform_authorization: Uuid::new_v4(),
            business_authorization: Uuid::new_v4(),
        };
        journal.save("installation.json", &saved)?;
        saved
    };
    resume(&input, &journal, saved).await
}
fn admit_installation(input: &Input) -> Result<Journal> {
    input.validate()?;
    let journal = Journal::open(&input.directory)?;
    Ok(journal)
}
async fn resume(input: &Input, journal: &Journal, mut saved: Saved) -> Result<Receipt> {
    initialize_platform(input, journal, &mut saved).await?;
    crate::tenant_registry::create(crate::tenant_registry::Create {
        database: input.database("mdm_owner")?,
        installation: coordinates(input, &saved),
        tenant_id: saved.receipt.tenant_id.to_string(),
        initial_epoch: 1,
        operation_id: saved.tenant_operation,
        name: Some(input.organization_name.clone()),
        notes: None,
    })
    .await
    .map_err(|_| Error::Storage)?;
    publish_progress(input, &saved, false, None).await?;
    if saved.receipt.stage == Stage::Platform {
        initialize_account(
            input,
            journal,
            &saved,
            &saved.receipt.tenant_id.to_string(),
            saved.receipt.administrator_id,
            &input.administrator_login,
            "administrator-password",
            saved.business_authorization,
        )
        .await?;
    }
    if saved.receipt.stage == Stage::Platform {
        saved.receipt.stage = Stage::Business;
        journal.save("installation.json", &saved)?;
    }
    if saved.receipt.stage == Stage::Initialized {
        return Ok(saved.receipt);
    }
    let mut runtime = runtime(input, journal, &saved)?;
    let telemetry =
        super::default_telemetry::prepare(input, journal, saved.receipt.tenant_id).await?;
    runtime["telemetry"] = serde_json::to_value(telemetry).map_err(invalid)?;
    runtime["content"] = match input.content_storage {
        ContentStorage::Volume => {
            let content = input.deployment.prepare_content_storage()?;
            serde_json::json!({"storage":content,"imports":{},"max_artifact_bytes":1073741824u64,"max_temporary_bytes":2147483648u64,"max_uploads":8,"transfer_seconds":60,"retention_seconds":86400,"max_bundle_bytes":1073741824u64,"max_bundle_entries":4096,"max_expansion_ratio":100})
        }
        ContentStorage::S3 => serde_json::Value::Null,
    };
    let _: crate::config::Config = serde_json::from_value(runtime.clone()).map_err(invalid)?;
    journal.save("runtime.json", &runtime)?;
    super::runtime_files::prepare(&input.directory, &input.deployment, &runtime).await?;
    publish_progress(input, &saved, true, None).await?;
    saved.receipt.stage = Stage::Initialized;
    journal.save("installation.json", &saved)?;
    Ok(saved.receipt)
}
fn initial_progress(saved: &Saved, account: bool) -> super::model::Provisioning {
    super::model::Provisioning {
        operation_id: saved.receipt.operation_id,
        tenant_id: saved.receipt.tenant_id,
        administrator_id: account.then_some(saved.receipt.administrator_id),
        host_id: saved.receipt.host_id,
        revision: 1,
        phase: if account {
            super::model::Phase::HostPending
        } else {
            super::model::Phase::Reserved
        },
        blocked: None,
        origin: None,
        application: None,
    }
}
async fn publish_progress(
    input: &Input,
    saved: &Saved,
    account: bool,
    progress: Option<super::model::Provisioning>,
) -> Result<()> {
    use sqlx::Connection;
    let mut c =
        sqlx::PgConnection::connect_with(&input.database("mdm_owner")?.options().map_err(invalid)?)
            .await
            .map_err(|_| Error::Storage)?;
    crate::migration::verify_identity(&mut c, &coordinates(input, saved))
        .await
        .map_err(|_| Error::Conflict)?;
    let mut tx = c.begin().await.map_err(|_| Error::Storage)?;
    sqlx::query("SELECT pg_advisory_xact_lock(2346)")
        .execute(&mut *tx)
        .await
        .map_err(|_| Error::Storage)?;
    let existing: Option<(serde_json::Value,serde_json::Value)> = sqlx::query_as("SELECT request,receipt FROM public.mdm_tenant_operations WHERE operation_id=$1 AND action='provision'")
        .bind(saved.receipt.operation_id).fetch_optional(&mut *tx).await.map_err(|_|Error::Storage)?;
    let mut value = progress.unwrap_or_else(|| initial_progress(saved, account));
    if let Some((request, receipt)) = &existing {
        if request["fingerprint"].as_str() != Some(saved.fingerprint.as_str()) {
            return Err(Error::Conflict);
        }
        let previous: crate::tenant_registry::Receipt =
            serde_json::from_value(receipt.clone()).map_err(|_| Error::Corrupt)?;
        let crate::tenant_registry::ReceiptResult::Provisioning(previous) = previous.result else {
            return Err(Error::Corrupt);
        };
        if !account {
            tx.rollback().await.map_err(|_| Error::Storage)?;
            return Ok(());
        }
        value.revision = previous.revision.checked_add(1).ok_or(Error::Corrupt)?;
    }
    let receipt = crate::tenant_registry::Receipt {
        operation_id: saved.receipt.operation_id,
        action: crate::tenant_registry::Action::Provision,
        result: crate::tenant_registry::ReceiptResult::Provisioning(value),
    };
    let public = serde_json::to_value(receipt).map_err(|_| Error::Corrupt)?;
    if existing.is_some() {
        sqlx::query("UPDATE public.mdm_tenant_operations SET receipt=$2 WHERE operation_id=$1 AND action='provision'")
            .bind(saved.receipt.operation_id).bind(public).execute(&mut *tx).await.map_err(|_|Error::Storage)?;
    } else {
        sqlx::query("INSERT INTO public.mdm_tenant_operations(operation_id,tenant_id,action,request,receipt,operator) VALUES($1,$2,'provision',$3,$4,$5)")
            .bind(saved.receipt.operation_id).bind(saved.receipt.tenant_id)
            .bind(serde_json::json!({"fingerprint":saved.fingerprint,"administratorOperationId":saved.business_authorization}))
            .bind(public).bind(serde_json::json!({"kind":"installation","instanceId":saved.receipt.instance_id})).execute(&mut *tx).await.map_err(|_|Error::Storage)?;
    }
    tx.commit().await.map_err(|_| Error::Storage)?;
    c.close().await.map_err(|_| Error::Storage)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn initialize_account(
    input: &Input,
    journal: &Journal,
    saved: &Saved,
    tenant: &str,
    principal: Uuid,
    login: &str,
    password_name: &str,
    operation: Uuid,
) -> Result<()> {
    let password_file = journal.path(password_name)?;
    // A rejected/unknown repeated initialize is never accepted as proof. The next call performs
    // a real login, verifies the exact expected subject and revokes the temporary session.
    let initialized = crate::maintenance::run(
        crate::maintenance::Config {
            database: input.database("mdm_identity_maintenance")?,
            installation: coordinates(input, saved),
            tenant_id: tenant.into(),
            expected_epoch: 1,
            principal_id: principal.to_string(),
            login: Some(login.into()),
            password_file: password_file.clone(),
        },
        true,
    )
    .await;
    let verified =
        crate::authorization_bootstrap::initialize(crate::authorization_bootstrap::Initialize {
            database: input.database("mdm_access")?,
            audit: input.audit(journal)?,
            identity_database: input.database("mdm_identity_runtime")?,
            installation: coordinates(input, saved),
            expected_epoch: 1,
            login: login.into(),
            password_file,
            operation_id: operation,
            user: rss_mdm_authorization_service::User {
                instance_id: saved.receipt.instance_id.to_string(),
                tenant_id: tenant.into(),
                principal_id: principal.to_string(),
            },
        })
        .await;
    match verified {
        Ok(_) => Ok(()),
        Err(_) => {
            let _ = initialized;
            Err(Error::Storage)
        }
    }
}
fn runtime(input: &Input, journal: &Journal, saved: &Saved) -> Result<serde_json::Value> {
    let audit = match input.audit_mode {
        AuditMode::Plain => serde_json::json!({"mode":"plain"}),
        AuditMode::Ledger => {
            serde_json::json!({"mode":"ledger","key_id":"installation-ledger","key_file":journal.path("ledger.key")?})
        }
    };
    Ok(serde_json::json!({
        "runtime_binding":{"host_id":saved.receipt.host_id,"operation_id":saved.receipt.operation_id,"revision":1,"material_digest":saved.fingerprint_digest()},
        "agent_pki":{"mode":"disabled"},"device_pki":[],"native_protocols":{},"native_protection":{"active_file":journal.path("native.key")?,"historical_files":[],"fingerprint_file":journal.path("native-fingerprint.key")?},
        "audit_projection":{"database":input.database("mdm_audit_worker")?,"recovery_keys":{"active_file":journal.path("audit-recovery.key")?,"historical_files":[]},"max_events":100000,"max_bytes":1073741824},
        "audit":audit,"listen":input.listen,"product_origin":input.origin,"trusted_gateway":input.trusted_gateway,
        "identity":{"instance_id":saved.receipt.instance_id,"tenant_id":saved.receipt.tenant_id,"database":input.database("mdm_identity_runtime")?,"audit_worker":input.database("mdm_identity_audit")?,"audit_recovery_keys":{"active_file":journal.path("identity-audit-recovery.key")?,"historical_files":[]},"oidc":null},
        "access_database":input.database("mdm_access")?,"runtime_database":input.database("mdm_runtime")?,"execution":{"database":input.database("mdm_command_runtime")?},
        "flow":{"storage":{"database":input.database("mdm_flow_runtime")?,"target":saved.target,"lineage":saved.lineage,"epoch":1},"publication":{"database":input.database("mdm_software_driver")?,"sources":[]}},
        "tenant_administration":{"registry_database":input.database("mdm_tenant_registry")?,"provisioning_database":input.database("mdm_identity_provisioning")?,"fingerprint_key_file":journal.path("operation.key")?},
        "webhooks":{"networks":[],"recovery_database":input.database("mdm_webhook_operator")?},"content":null,"task_signing":null,"recovery_credentials":null
    }))
}

impl Saved {
    fn fingerprint_digest(&self) -> String {
        use sha2::{Digest, Sha256};
        format!("{:x}", Sha256::digest(self.fingerprint.as_bytes()))
    }
}

async fn initialize_platform(input: &Input, journal: &Journal, saved: &mut Saved) -> Result<()> {
    if saved.receipt.stage == Stage::Prepared {
        super::postgres::prepare(input, saved.receipt.instance_id).await?;
    }
    crate::migration::migrate(
        &input.database("mdm_owner")?.options().map_err(invalid)?,
        &coordinates(input, saved),
    )
    .await
    .map_err(|_| Error::Storage)?;
    if saved.receipt.stage == Stage::Prepared {
        saved.receipt.stage = Stage::Database;
        journal.save("installation.json", saved)?;
    }
    let tenants = crate::tenant_registry::list(crate::tenant_registry::List {
        database: input.database("mdm_owner")?,
        installation: coordinates(input, saved),
    })
    .await
    .map_err(|_| Error::Storage)?;
    let management = tenants
        .iter()
        .find(|t| t.management)
        .ok_or(Error::Corrupt)?
        .tenant_id
        .clone();
    if saved.receipt.stage == Stage::Database {
        initialize_account(
            input,
            journal,
            saved,
            &management,
            saved.receipt.platform_principal_id,
            &input.platform_login,
            "platform-password",
            saved.platform_authorization,
        )
        .await?;
    }
    if saved.receipt.stage == Stage::Database {
        saved.receipt.stage = Stage::Platform;
        journal.save("installation.json", saved)?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "../../tests/setup/installation.rs"]
mod tests;
