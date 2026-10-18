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
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
};
use uuid::Uuid;

const ROLES: &[&str] = &[
    "mdm_owner",
    "mdm_identity_maintenance",
    "mdm_identity_runtime",
    "mdm_identity_audit",
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
    pub host: String,
    pub port: u16,
    pub name: String,
    pub ca_file: PathBuf,
    /// Restricted profiles prepared by the deployment executor; never passed to the runtime en bloc.
    pub passwords: BTreeMap<String, PathBuf>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub directory: PathBuf,
    pub deployment: super::deployment::Config,
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
    Enabled,
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
        let u = url::Url::parse(&self.origin).map_err(invalid)?;
        if u.scheme() != "https"
            || u.host_str().is_none()
            || !u.username().is_empty()
            || u.password().is_some()
            || u.origin().ascii_serialization() != self.origin
            || !self.listen.ip().is_loopback()
            || self.listen.port() == 0
            || self.database.host.is_empty()
            || self.database.name.is_empty()
            || self.database.port == 0
            || self.organization_name.trim().is_empty()
            || self.organization_name.chars().count() > 128
            || self.organization_name.contains('\0')
            || self.database.passwords.len() != ROLES.len()
            || ROLES
                .iter()
                .any(|role| !self.database.passwords.contains_key(*role))
        {
            return Err(Error::Input);
        }
        rss_identity_core::account::LoginKey::parse(&self.platform_login).map_err(invalid)?;
        rss_identity_core::account::LoginKey::parse(&self.administrator_login).map_err(invalid)?;
        for path in self.database.passwords.values() {
            crate::config::secret(path).map_err(invalid)?;
        }
        crate::config::read(&self.database.ca_file, 1024 * 1024, false).map_err(invalid)?;
        Ok(())
    }
    fn database(&self, role: &str) -> Result<crate::config::Database> {
        Ok(crate::config::Database {
            host: self.database.host.clone(),
            port: self.database.port,
            name: self.database.name.clone(),
            user: role.into(),
            password_file: self
                .database
                .passwords
                .get(role)
                .ok_or(Error::Input)?
                .clone(),
            ca_file: self.database.ca_file.clone(),
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
    input.validate()?;
    let journal = Journal::open(&input.directory)?;
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
    let native_key = protected(&journal, "native.key", 32, first)?;
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
            native_key.as_slice(),
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
    let mut saved = if let Some(saved) = previous {
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
    crate::migration::migrate(
        &input.database("mdm_owner")?.options().map_err(invalid)?,
        &coordinates(&input, &saved),
    )
    .await
    .map_err(|_| Error::Storage)?;
    if saved.receipt.stage == Stage::Prepared {
        saved.receipt.stage = Stage::Database;
        journal.save("installation.json", &saved)?;
    }
    let tenants = crate::tenant_registry::list(crate::tenant_registry::List {
        database: input.database("mdm_owner")?,
        installation: coordinates(&input, &saved),
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
            &input,
            &journal,
            &saved,
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
        journal.save("installation.json", &saved)?;
    }
    crate::tenant_registry::create(crate::tenant_registry::Create {
        database: input.database("mdm_owner")?,
        installation: coordinates(&input, &saved),
        tenant_id: saved.receipt.tenant_id.to_string(),
        initial_epoch: 1,
        operation_id: saved.tenant_operation,
        name: Some(input.organization_name.clone()),
        notes: None,
    })
    .await
    .map_err(|_| Error::Storage)?;
    if saved.receipt.stage == Stage::Platform {
        initialize_account(
            &input,
            &journal,
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
    let runtime = runtime(&input, &journal, &saved)?;
    // Reuse the actual runtime decoder, not a second interpretation of configuration.
    let _: crate::config::Config = serde_json::from_value(runtime.clone()).map_err(invalid)?;
    journal.save("runtime.json", &runtime)?;
    journal.save(
        "ui.json",
        &serde_json::json!({"canonicalOrigin":input.origin,"oidcEnabled":false}),
    )?;
    journal.save(
        "mdm.json",
        &serde_json::json!({"canonicalOrigin":input.origin,"tenant":saved.receipt.tenant_id}),
    )?;
    saved.receipt.stage = Stage::HostPending;
    journal.save("installation.json", &saved)?;
    let observed = super::deployment::apply(&input.directory, &input.deployment, &runtime).await?;
    journal.save("host-observation.json", &observed)?;
    saved.receipt.stage = Stage::Enabled;
    journal.save("installation.json", &saved)?;
    Ok(saved.receipt)
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
        "agent_pki":{"mode":"disabled"},"device_pki":[],"native_protocols":{},"native_protection_key_file":journal.path("native.key")?,
        "audit":audit,"listen":input.listen,"product_origin":input.origin,"trusted_gateway":input.trusted_gateway,
        "identity":{"instance_id":saved.receipt.instance_id,"tenant_id":saved.receipt.tenant_id,"database":input.database("mdm_identity_runtime")?,"audit_worker":input.database("mdm_identity_audit")?,"oidc":null},
        "access_database":input.database("mdm_access")?,"runtime_database":input.database("mdm_runtime")?,"execution":{"database":input.database("mdm_command_runtime")?},
        "flow":{"storage":{"database":input.database("mdm_flow_runtime")?,"target":saved.target,"lineage":saved.lineage,"epoch":1},"publication":{"database":input.database("mdm_software_driver")?,"sources":[]}},
        "tenant_administration":{"registry_database":input.database("mdm_tenant_registry")?,"provisioning_database":input.database("mdm_identity_provisioning")?,"fingerprint_key_file":journal.path("operation.key")?},
        "webhooks":{"keys":[],"networks":[],"recovery_database":input.database("mdm_webhook_operator")?},"content":null,"task_signing":null,"recovery_credentials":null
    }))
}

impl Saved {
    fn fingerprint_digest(&self) -> String {
        use sha2::{Digest, Sha256};
        format!("{:x}", Sha256::digest(self.fingerprint.as_bytes()))
    }
}

#[cfg(test)]
#[path = "../../tests/setup/installation.rs"]
mod tests;
