//! Closed deployment settings. Each domain keeps its existing runtime and persistence owner.
use super::{Error, Result, install::Input, local::Journal};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::Connection;
use std::{collections::BTreeMap, path::PathBuf};
use uuid::Uuid;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Oidc {
    pub group_facts_max_age_seconds: i64,
    pub return_targets: BTreeMap<String, String>,
    pub assurance_profiles: Vec<crate::identity::AssuranceProfile>,
    pub private_providers: Vec<crate::identity::PrivateProvider>,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Recipient {
    Generate,
    Import {
        certificate_file: PathBuf,
        private_key_file: PathBuf,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Windows {
    pub entra: Option<rss_mdm_windows_channel::entra::Config>,
    pub enrollment: crate::native::PublicEndpoint,
    pub management: crate::native::PublicEndpoint,
    /// Omitted only in deployment input: preserve an existing identity or generate on first enablement.
    pub protocol_protection: Option<crate::config::NativeProtection>,
    #[serde(default)]
    pub lifetime: rss_mdm_certificate::windows::Lifetime,
    pub provider_id: String,
    pub poll: rss_mdm_windows_mdm::provisioning::Poll,
    pub additional_management: Vec<crate::native::PublicEndpoint>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Apple {
    pub management: crate::native::PublicEndpoint,
    pub webhooks: Vec<crate::ca_webhooks::Credentials>,
    pub identity_seed: Option<rss_mdm_apple_channel::IdentitySeed>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Channels {
    pub windows: Option<Windows>,
    pub apple: Option<Apple>,
    pub agent: crate::agent_pki::Config,
    #[serde(default)]
    pub providers: Vec<rss_mdm_pki_service::configuration::Provider>,
    pub apple_material_roots: Vec<PathBuf>,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Change {
    Telemetry {
        settings: Box<crate::telemetry::Config>,
    },
    GatewayTls {
        certificate_file: PathBuf,
        private_key_file: PathBuf,
        trust_file: PathBuf,
    },
    WebhookNetworks {
        networks: Vec<crate::config::webhooks::Network>,
    },
    Channels {
        settings: Box<Channels>,
    },
    EnrollmentEntries {
        settings: rss_mdm_registration_service::enrollment::task::Entries,
    },
    Oidc {
        settings: Oidc,
    },
    Recovery {
        profile: rss_mdm_install_support::StorageProfile,
        recipient: Recipient,
    },
    StepCa {
        settings: Box<super::providers::step_ca::initialize::Settings>,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub installation: Input,
    pub operation_id: Uuid,
    pub tenant: Option<Uuid>,
    pub expected_revision: u64,
    pub change: Change,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Receipt {
    pub operation_id: Uuid,
    pub host_id: Uuid,
    pub requested_revision: u64,
    pub deployment_required: bool,
    pub applied: Option<super::runtime_files::Applied>,
}
fn secret(journal: &Journal, name: &str) -> Result<PathBuf> {
    let path = journal.path(name)?;
    if !path.exists() {
        use ring::rand::SecureRandom;
        let mut bytes = zeroize::Zeroizing::new([0u8; 32]);
        ring::rand::SystemRandom::new()
            .fill(bytes.as_mut())
            .map_err(|_| Error::Storage)?;
        journal.secret(name, bytes.as_slice())?;
    }
    crate::config::read(&path, 32, true).map_err(|_| Error::Corrupt)?;
    Ok(path)
}
fn oidc_secret(journal: &Journal, name: &str) -> Result<PathBuf> {
    let path = journal.path(name)?;
    if !path.exists() {
        use ring::rand::SecureRandom;
        let mut bytes = zeroize::Zeroizing::new([0u8; 32]);
        ring::rand::SystemRandom::new()
            .fill(bytes.as_mut())
            .map_err(|_| Error::Storage)?;
        let encoded =
            zeroize::Zeroizing::new(bytes.iter().map(|b| format!("{b:02x}")).collect::<String>());
        journal.secret(name, encoded.as_bytes())?;
    }
    crate::identity::key(&path).map_err(|_| Error::Corrupt)?;
    Ok(path)
}
fn key_id(path: &std::path::Path) -> Result<String> {
    Ok(rss_mdm_native_protection::Protector::new(
        &crate::config::read(path, 32, true).map_err(|_| Error::Corrupt)?,
    )
    .map_err(|_| Error::Corrupt)?
    .id()
    .to_owned())
}
fn oidc(journal: &Journal, runtime: &mut Value, tenant: Uuid, settings: &Oidc) -> Result<()> {
    let tenant = tenant.to_string();
    if settings
        .assurance_profiles
        .iter()
        .any(|p| p.tenant_id != tenant)
        || settings
            .private_providers
            .iter()
            .any(|p| p.tenant_id != tenant)
    {
        return Err(Error::Input);
    }
    let original = runtime["identity"]["oidc"].clone();
    let mut next = serde_json::to_value(settings).map_err(|_| Error::Input)?;
    if original.is_null() {
        let state = oidc_secret(journal, "oidc-state.key")?;
        let credential = oidc_secret(journal, "oidc-credential.key")?;
        let id = rss_mdm_native_protection::Protector::new(
            crate::identity::key(&credential)
                .map_err(|_| Error::Corrupt)?
                .as_slice(),
        )
        .map_err(|_| Error::Corrupt)?
        .id()
        .to_owned();
        next["state_key_file"] = json!(state);
        next["active_credential_key"] = json!(id);
        next["credential_keys"] = json!({id:credential});
    } else {
        for field in ["state_key_file", "active_credential_key", "credential_keys"] {
            next[field] = original[field].clone();
        }
    }
    // Explicit tenant policy updates preserve every other tenant's installed OIDC grants.
    for field in ["assurance_profiles", "private_providers"] {
        let mut values = original[field].as_array().cloned().unwrap_or_default();
        values.retain(|value| value["tenant_id"] != tenant);
        values.extend(next[field].as_array().ok_or(Error::Input)?.iter().cloned());
        next[field] = json!(values);
    }
    let config: crate::identity::OidcConfig =
        serde_json::from_value(next.clone()).map_err(|_| Error::Input)?;
    config
        .validate_deployment(
            runtime["product_origin"].as_str().ok_or(Error::Corrupt)?,
            &serde_json::from_value::<crate::identity::policy::RuntimePolicy>(
                runtime["identity"]["runtime"].clone(),
            )
            .map_err(|_| Error::Corrupt)?
            .transport,
        )
        .map_err(|_| Error::Input)?;
    runtime["identity"]["oidc"] = next;
    Ok(())
}
#[allow(
    clippy::cognitive_complexity,
    reason = "one owner applies the selected material with its original receipt and error boundary"
)]
async fn recovery(
    input: &Input,
    journal: &Journal,
    c: &mut sqlx::PgConnection,
    runtime: &mut Value,
    tenant: Uuid,
    profile: rss_mdm_install_support::StorageProfile,
    source: &Recipient,
) -> Result<()> {
    use openssl::{
        asn1::Asn1Time,
        bn::{BigNum, MsbOption},
        hash::MessageDigest,
        pkey::PKey,
        rsa::Rsa,
        x509::{
            X509, X509NameBuilder,
            extension::{BasicConstraints, KeyUsage},
        },
    };
    let key_file = journal.path("recovery-recipient.key")?;
    let cert_file = journal.path("recovery-recipient.pem")?;
    if !key_file.exists() {
        let bytes = match source {
            Recipient::Import {
                private_key_file, ..
            } => crate::config::read(private_key_file, 32768, true).map_err(|_| Error::Input)?,
            Recipient::Generate => PKey::from_rsa(Rsa::generate(3072).map_err(|_| Error::Storage)?)
                .and_then(|k| k.private_key_to_pem_pkcs8())
                .map(zeroize::Zeroizing::new)
                .map_err(|_| Error::Storage)?,
        };
        journal.secret("recovery-recipient.key", &bytes)?;
    }
    if !cert_file.exists() {
        let bytes = match source {
            Recipient::Import {
                certificate_file, ..
            } => crate::config::read(certificate_file, 131072, false)
                .map_err(|_| Error::Input)?
                .to_vec(),
            Recipient::Generate => {
                let key = PKey::private_key_from_pem(
                    &crate::config::read(&key_file, 32768, true).map_err(|_| Error::Corrupt)?,
                )
                .map_err(|_| Error::Corrupt)?;
                let mut name = X509NameBuilder::new().map_err(|_| Error::Storage)?;
                name.append_entry_by_text("CN", &format!("RSS recovery {}", tenant))
                    .map_err(|_| Error::Storage)?;
                let name = name.build();
                let mut certificate = X509::builder().map_err(|_| Error::Storage)?;
                let mut serial = BigNum::new().map_err(|_| Error::Storage)?;
                serial
                    .rand(128, MsbOption::MAYBE_ZERO, false)
                    .map_err(|_| Error::Storage)?;
                let serial = serial.to_asn1_integer().map_err(|_| Error::Storage)?;
                let start = Asn1Time::days_from_now(0).map_err(|_| Error::Storage)?;
                let end = Asn1Time::days_from_now(365).map_err(|_| Error::Storage)?;
                certificate
                    .set_version(2)
                    .and_then(|_| certificate.set_serial_number(&serial))
                    .and_then(|_| certificate.set_subject_name(&name))
                    .and_then(|_| certificate.set_issuer_name(&name))
                    .and_then(|_| certificate.set_pubkey(&key))
                    .and_then(|_| certificate.set_not_before(&start))
                    .and_then(|_| certificate.set_not_after(&end))
                    .map_err(|_| Error::Storage)?;
                certificate
                    .append_extension(
                        BasicConstraints::new()
                            .critical()
                            .build()
                            .map_err(|_| Error::Storage)?,
                    )
                    .map_err(|_| Error::Storage)?;
                certificate
                    .append_extension(
                        KeyUsage::new()
                            .critical()
                            .key_encipherment()
                            .build()
                            .map_err(|_| Error::Storage)?,
                    )
                    .map_err(|_| Error::Storage)?;
                certificate
                    .sign(&key, MessageDigest::sha256())
                    .map_err(|_| Error::Storage)?;
                certificate.build().to_pem().map_err(|_| Error::Storage)?
            }
        };
        journal.secret("recovery-recipient.pem", &bytes)?;
    }
    let certificate = crate::config::read(&cert_file, 131072, false).map_err(|_| Error::Corrupt)?;
    let private = crate::config::read(&key_file, 32768, true).map_err(|_| Error::Corrupt)?;
    let recipient = rss_mdm_recovery_credentials::Recipient::from_pem(&certificate, &private)
        .map_err(|_| Error::Input)?;
    let certificate = X509::from_pem(&certificate).map_err(|_| Error::Input)?;
    let now = Asn1Time::days_from_now(0).map_err(|_| Error::Storage)?;
    use x509_cert::der::Decode;
    use x509_cert::ext::pkix::{BasicConstraints as ParsedConstraints, KeyUsage as ParsedUsage};
    let parsed = x509_cert::Certificate::from_der(&certificate.to_der().map_err(|_| Error::Input)?)
        .map_err(|_| Error::Input)?;
    if parsed
        .tbs_certificate
        .get::<ParsedConstraints>()
        .map_err(|_| Error::Input)?
        .is_some_and(|(_, c)| c.ca)
        || parsed
            .tbs_certificate
            .get::<ParsedUsage>()
            .map_err(|_| Error::Input)?
            .is_none_or(|(_, k)| !k.key_encipherment() || k.key_cert_sign() || k.crl_sign())
    {
        return Err(Error::Input);
    }
    if certificate.not_before() > now.as_ref() || certificate.not_after() <= now.as_ref() {
        return Err(Error::Input);
    }
    if runtime["recovery_credentials"].is_null() {
        let encryption = secret(journal, "recovery-encryption.key")?;
        let id = key_id(&encryption)?;
        runtime["recovery_credentials"] =
            json!({"active_key":id,"key_files":{id:encryption},"recipients":[]});
    }
    let config = &mut runtime["recovery_credentials"];
    let existing = rss_mdm_recovery_credentials::configuration::Config::open(
        &serde_json::from_value::<rss_mdm_recovery_credentials::configuration::Config>(
            config.clone(),
        )
        .map_err(|_| Error::Input)?,
    );
    let present = existing
        .as_ref()
        .is_ok_and(|p| p.recipient(recipient.id()).is_ok());
    if !present {
        config["recipients"]
            .as_array_mut()
            .ok_or(Error::Corrupt)?
            .push(json!({"certificate_file":cert_file,"private_key_file":key_file}));
    }
    let resources = serde_json::from_value::<rss_mdm_recovery_credentials::configuration::Config>(
        config.clone(),
    )
    .map_err(|_| Error::Input)?
    .open()
    .map_err(|_| Error::Input)?;
    resources
        .recipient(recipient.id())
        .map_err(|_| Error::Input)?;
    let mut da = if profile == rss_mdm_install_support::StorageProfile::Da {
        let config: crate::config::Config =
            serde_json::from_value(runtime.clone()).map_err(|_| Error::Corrupt)?;
        if config.device_access.is_none() {
            return Err(Error::Input);
        }
        let execution = config
            .storage_binding
            .execution(
                rss_request_context::TenantId::parse(&tenant.to_string())
                    .map_err(|_| Error::Input)?,
            )
            .map_err(|_| Error::Input)?;
        let mut connection = sqlx::PgConnection::connect_with(
            &input
                .database("da_owner")?
                .options()
                .map_err(|_| Error::Input)?,
        )
        .await
        .map_err(|_| Error::Storage)?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,false),set_config('rss.storage_target',$2,false),set_config('rss.storage_lineage',$3,false),set_config('rss.execution_epoch',$4,false)")
            .bind(tenant.to_string()).bind(Uuid::from_bytes(execution.storage().target()).simple().to_string()).bind(Uuid::from_bytes(execution.storage().lineage()).simple().to_string()).bind(execution.epoch().get().to_string()).execute(&mut connection).await.map_err(|_|Error::Storage)?;
        Some(connection)
    } else {
        None
    };
    let connection = da.as_mut().unwrap_or(c);
    let mut tx = connection.begin().await.map_err(|_| Error::Storage)?;
    sqlx::query("SELECT rss_transactional_messaging.check_execution()")
        .execute(&mut *tx)
        .await
        .map_err(|_| Error::Conflict)?;
    rss_mdm_recovery_credentials::Protection::select_on(profile, &mut tx, tenant, recipient.id())
        .await
        .map_err(|_| Error::Storage)?;
    tx.commit().await.map_err(|_| Error::Storage)?;
    if let Some(connection) = da {
        connection.close().await.map_err(|_| Error::Storage)?;
    }
    Ok(())
}

// A tenant's material attachment cannot erase another tenant's installed CA callback identity.
fn merge_callbacks(installed: &Value, requested: &Value) -> Result<Vec<Value>> {
    let mut callbacks = installed.as_array().cloned().unwrap_or_default();
    for callback in requested.as_array().into_iter().flatten() {
        if let Some(original) = callbacks.iter().find(|v| v["issuer"] == callback["issuer"]) {
            if original != callback {
                return Err(Error::Conflict);
            }
        } else {
            callbacks.push(callback.clone());
        }
    }
    Ok(callbacks)
}
#[allow(
    clippy::cognitive_complexity,
    reason = "one owner applies the selected material with its original receipt and error boundary"
)]
async fn channels(
    journal: &Journal,
    c: &mut sqlx::PgConnection,
    runtime: &mut Value,
    tenant: Uuid,
    settings: &Channels,
) -> Result<()> {
    let mut native = runtime["native_protocols"].clone();
    if !native.is_object() {
        native = json!({});
    }
    if let Some(windows) = &settings.windows {
        let mut config = json!({"enrollment":windows.enrollment,"management":windows.management,"additional_management":windows.additional_management,"protocol_protection":windows.protocol_protection});
        let original = &native["windows"]["protocol_protection"];
        if original.is_object() {
            if config["protocol_protection"].is_object()
                && config["protocol_protection"] != *original
            {
                return Err(Error::Conflict);
            }
            config["protocol_protection"] = original.clone();
        } else if config["protocol_protection"].is_null() {
            let key = secret(journal, "windows-protection.key")?;
            config["protocol_protection"] =
                json!({"active_file":key,"historical_files":[],"fingerprint_file":key});
        }
        serde_json::from_value::<crate::windows::WindowsConfig>(config.clone())
            .map_err(|_| Error::Input)?
            .validate(
                runtime["listen"]
                    .as_str()
                    .ok_or(Error::Corrupt)?
                    .parse()
                    .map_err(|_| Error::Corrupt)?,
            )
            .map_err(|_| Error::Input)?;
        native["windows"] = config;
    }
    if let Some(apple) = &settings.apple {
        let callbacks = merge_callbacks(
            &native["apple"]["webhooks"],
            &serde_json::to_value(&apple.webhooks).map_err(|_| Error::Input)?,
        )?;
        native["apple"] = json!({"management":apple.management,"webhooks":callbacks});
    }
    let target =
        rss_request_context::TenantId::parse(&tenant.to_string()).map_err(|_| Error::Input)?;
    let mut tx = c.begin().await.map_err(|_| Error::Storage)?;
    sqlx::query("SELECT rss_transactional_messaging.check_execution()")
        .execute(&mut *tx)
        .await
        .map_err(|_| Error::Conflict)?;
    if let Some(windows) = &settings.windows {
        let settings = rss_mdm_windows_channel::runtime_materials::Configuration {
            provider_id: windows.provider_id.clone(),
            poll: windows.poll.clone(),
            lifetime: windows.lifetime,
            entra: windows
                .entra
                .as_ref()
                .map(|config| serde_json::to_value(config).and_then(serde_json::from_value))
                .transpose()
                .map_err(|_| Error::Input)?,
        };
        rss_mdm_windows_channel::runtime_materials::install_on(&mut tx, target, &settings)
            .await
            .map_err(|_| Error::Input)?;
    }
    if let Some(apple) = &settings.apple {
        let existing:Option<(String,String)>=sqlx::query_as("SELECT challenge_id,notify_id FROM mdm_apple_runtime.identity WHERE tenant_id=$1 FOR UPDATE").bind(tenant).fetch_optional(&mut *tx).await.map_err(|_|Error::Storage)?;
        let seed = if let Some(seed) = &apple.identity_seed {
            serde_json::to_value(seed).map_err(|_| Error::Input)?
        } else if let Some((challenge, notify)) = &existing {
            json!({"challengeId":challenge,"notifyId":notify})
        } else {
            let seed = journal
                .load::<Value>("apple-seed.json")?
                .unwrap_or_else(|| json!({"challengeId":Uuid::new_v4(),"notifyId":Uuid::new_v4()}));
            journal.save("apple-seed.json", &seed)?;
            seed
        };
        let challenge = seed["challengeId"].as_str().ok_or(Error::Input)?;
        let notify = seed["notifyId"].as_str().ok_or(Error::Input)?;
        if let Some((old_challenge, old_notify)) = existing
            && (old_challenge != challenge || old_notify != notify)
        {
            return Err(Error::Conflict);
        }
        sqlx::query("INSERT INTO mdm_apple_runtime.identity(tenant_id,challenge_id,notify_id) VALUES($1,$2,$3) ON CONFLICT(tenant_id) DO NOTHING").bind(tenant).bind(challenge).bind(notify).execute(&mut *tx).await.map_err(|_|Error::Storage)?;
    }
    tx.commit().await.map_err(|_| Error::Storage)?;
    runtime["native_protocols"] = native;
    let mut agent = serde_json::to_value(&settings.agent).map_err(|_| Error::Input)?;
    if agent["mode"] == "step_ca" {
        let callbacks = merge_callbacks(
            &runtime["agent_pki"]["bootstrap"]["webhooks"],
            &agent["bootstrap"]["webhooks"],
        )?;
        if !callbacks.is_empty() {
            agent["bootstrap"] = json!({"webhooks":callbacks});
        }
    }
    runtime["agent_pki"] = agent;
    // Installed provider and callback resources are shared; selecting a tenant does not discard others.
    let providers = runtime["device_pki"].as_array_mut().ok_or(Error::Corrupt)?;
    for provider in &settings.providers {
        let value = serde_json::to_value(provider).map_err(|_| Error::Input)?;
        if let Some(old) = providers
            .iter_mut()
            .find(|v| v["purpose"] == value["purpose"] && v["issuer"] == value["issuer"])
        {
            *old = value;
        } else {
            providers.push(value);
        }
    }
    let mut roots = runtime["apple_material_roots"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    for root in &settings.apple_material_roots {
        let value = json!(root);
        if !roots.contains(&value) {
            roots.push(value);
        }
    }
    runtime["apple_material_roots"] = json!(roots);
    Ok(())
}
#[allow(
    clippy::cognitive_complexity,
    reason = "one owner applies the selected material with its original receipt and error boundary"
)]
pub async fn run(request: Request) -> Result<Receipt> {
    if request.operation_id.is_nil() || request.tenant.is_some_and(|id| id.is_nil()) {
        return Err(Error::Input);
    }
    let input = &request.installation;
    let root = Journal::open(&input.directory)?;
    admit_configuration(&root, request.operation_id).await?;
    let journal = Journal::open(
        &input
            .directory
            .join(format!("configuration-{}", request.operation_id)),
    )?;
    journal.secret(
        "request.json",
        &serde_json::to_vec(&request).map_err(|_| Error::Input)?,
    )?;
    if let Some(receipt) = completed(&root, &journal, request.operation_id)? {
        return Ok(receipt);
    }
    let base: Value = root.load("runtime.json")?.ok_or(Error::Corrupt)?;
    let base: crate::config::Config = serde_json::from_value(base).map_err(|_| Error::Corrupt)?;
    let host_id = base.runtime_binding.host_id;
    let mut c = sqlx::PgConnection::connect_with(
        &input
            .database("mdm_owner")?
            .options()
            .map_err(|_| Error::Input)?,
    )
    .await
    .map_err(|_| Error::Storage)?;
    if !crate::migration::owner_admitted(&mut c)
        .await
        .map_err(|_| Error::Storage)?
    {
        return Err(Error::Input);
    }
    crate::migration::verify_identity(
        &mut c,
        &crate::migration::Installation {
            instance_id: base.identity.instance_id,
            target: base.storage_binding.target,
            lineage: base.storage_binding.lineage,
            audit_mode: base.audit.mode(),
        },
    )
    .await
    .map_err(|_| Error::Conflict)?;
    if let Some(tenant) = request.tenant {
        let execution = base
            .storage_binding
            .execution(
                rss_request_context::TenantId::parse(&tenant.to_string())
                    .map_err(|_| Error::Input)?,
            )
            .map_err(|_| Error::Input)?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,false),set_config('rss.storage_target',$2,false),set_config('rss.storage_lineage',$3,false),set_config('rss.execution_epoch',$4,false)")
            .bind(tenant.to_string()).bind(Uuid::from_bytes(execution.storage().target()).simple().to_string()).bind(Uuid::from_bytes(execution.storage().lineage()).simple().to_string()).bind(execution.epoch().get().to_string()).execute(&mut c).await.map_err(|_|Error::Storage)?;
        if !sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT FROM public.mdm_tenants WHERE tenant_id=$1 AND NOT deleted)",
        )
        .bind(tenant)
        .fetch_one(&mut c)
        .await
        .map_err(|_| Error::Storage)?
        {
            return Err(Error::Input);
        }
    }
    sqlx::raw_sql("SET statement_timeout='10s'; SET lock_timeout='6s'")
        .execute(&mut c)
        .await
        .map_err(|_| Error::Storage)?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock(2823,1)")
        .fetch_one(&mut c)
        .await
        .map_err(|_| Error::Storage)?;
    if !locked {
        return Err(Error::Busy);
    }
    let host = Journal::open(
        &input
            .directory
            .join(format!("rss-mdm-{}", host_id.simple())),
    )?;
    if let Some(previous) = journal.load::<Receipt>("receipt.json")? {
        let requested: Value = host.load("requested-runtime.json")?.ok_or(Error::Corrupt)?;
        if previous.applied.is_none()
            && requested["runtime_binding"]["operation_id"] != json!(request.operation_id)
        {
            // A durably failed operation remains queryable after a correction supersedes it.
            // Replaying that original request must never overwrite the newer desired runtime.
            return Ok(previous);
        }
    }
    let candidate = if let Some(candidate) = journal.load::<Value>("candidate.json")? {
        candidate
    } else {
        let mut runtime: Value = host.load("requested-runtime.json")?.ok_or(Error::Corrupt)?;
        if runtime["runtime_binding"]["revision"].as_u64() != Some(request.expected_revision)
            || runtime["runtime_binding"]["host_id"] != json!(host_id)
        {
            return Err(Error::Conflict);
        }
        let previous = runtime.clone();
        apply_change(
            input,
            &root,
            &journal,
            &mut c,
            &mut runtime,
            request.tenant,
            &request.change,
        )
        .await?;
        if runtime == previous
            && journal
                .load::<super::runtime_files::GatewayTls>("gateway.json")?
                .is_none()
        {
            let receipt = Receipt {
                operation_id: request.operation_id,
                host_id,
                requested_revision: request.expected_revision,
                deployment_required: false,
                applied: None,
            };
            journal.save("receipt.json", &receipt)?;
            c.close().await.map_err(|_| Error::Storage)?;
            return Ok(receipt);
        }
        super::runtime_files::freeze(&mut runtime, &journal)?;
        let revision = request
            .expected_revision
            .checked_add(1)
            .filter(|r| *r <= i64::MAX as u64)
            .ok_or(Error::Input)?;
        let digest = super::application::fingerprint(
            &serde_json::json!({"runtime":runtime,"gateway":journal.load::<super::runtime_files::GatewayTls>("gateway.json")?}),
        )?;
        runtime["runtime_binding"] = json!({"host_id":host_id,"operation_id":request.operation_id,"revision":revision,"material_digest":digest});
        let config: crate::config::Config =
            serde_json::from_value(runtime.clone()).map_err(|_| Error::Input)?;
        super::runtime_files::validate_listeners(&config)?;
        config.compile().map_err(|_| Error::Input)?;
        journal.secret(
            "candidate.json",
            &serde_json::to_vec(&runtime).map_err(|_| Error::Corrupt)?,
        )?;
        runtime
    };
    let binding: super::host::Binding =
        serde_json::from_value(candidate["runtime_binding"].clone()).map_err(|_| Error::Corrupt)?;
    let mut result = Receipt {
        operation_id: request.operation_id,
        host_id,
        requested_revision: binding.revision,
        deployment_required: true,
        applied: None,
    };
    root.save("configuration-operation.json", &Some(request.operation_id))?;
    host.save("requested-runtime.json", &candidate)?;
    publish_gateway(&journal, &host)?;
    drop(host);
    let outcome =
        super::runtime_files::apply(&input.directory, &input.deployment, &candidate).await;
    match outcome {
        Ok(observed)
            if observed.host_id == result.host_id
                && observed.operation_id == result.operation_id =>
        {
            result.applied = Some(observed)
        }
        Ok(_) => return Err(Error::Conflict),
        Err(Error::Storage | Error::Conflict) => (),
        Err(error) => return Err(error),
    }
    journal.save("receipt.json", &result)?;
    // A persisted failure is a recoverable outcome, not an indefinitely active operation.
    // Unknown persistence outcomes above retain the fence until the original request resumes.
    root.save("configuration-operation.json", &Option::<Uuid>::None)?;
    c.close().await.map_err(|_| Error::Storage)?;
    Ok(result)
}

fn publish_gateway(journal: &Journal, host: &Journal) -> Result<()> {
    if let Some(tls) = journal.load::<super::runtime_files::GatewayTls>("gateway.json")? {
        host.save("gateway-tls.json", &tls)?;
    }
    Ok(())
}

async fn admit_configuration(root: &Journal, operation: Uuid) -> Result<()> {
    if root
        .load::<Option<Uuid>>("backup-operation.json")?
        .flatten()
        .is_some()
    {
        return Err(Error::Busy);
    }
    if root
        .load::<Option<Uuid>>("protection-operation.json")?
        .flatten()
        .is_some()
    {
        return Err(Error::Busy);
    }
    if root
        .load::<Option<Uuid>>("configuration-operation.json")?
        .flatten()
        .is_some_and(|id| id != operation)
    {
        return Err(Error::Busy);
    }
    Ok(())
}

fn completed(root: &Journal, journal: &Journal, operation: Uuid) -> Result<Option<Receipt>> {
    let receipt = journal
        .load::<Receipt>("receipt.json")?
        .filter(|r| !r.deployment_required || r.applied.is_some());
    if receipt.is_some()
        && root
            .load::<Option<Uuid>>("configuration-operation.json")?
            .flatten()
            == Some(operation)
    {
        root.save("configuration-operation.json", &Option::<Uuid>::None)?;
    }
    Ok(receipt)
}

#[allow(
    clippy::cognitive_complexity,
    reason = "one owner applies the selected material with its original receipt and error boundary"
)]
async fn apply_change(
    input: &Input,
    root: &Journal,
    journal: &Journal,
    c: &mut sqlx::PgConnection,
    runtime: &mut Value,
    tenant: Option<Uuid>,
    change: &Change,
) -> Result<()> {
    match change {
        Change::Telemetry { settings } => {
            use sqlx::Connection;
            let tenant = tenant.ok_or(Error::Input)?;
            let target = rss_request_context::TenantId::parse(&tenant.to_string())
                .map_err(|_| Error::Input)?;
            if settings
                .tenant()
                .map_err(|_| Error::Input)?
                .is_some_and(|t| t != target)
            {
                return Err(Error::Input);
            }
            let selected = settings.configuration_binding().map_err(|_| Error::Input)?;
            let value = serde_json::to_value(settings).map_err(|_| Error::Input)?;
            let resources = runtime["telemetry"].as_array().ok_or(Error::Corrupt)?;
            if let Some(previous) = resources
                .iter()
                .find(|r| r["resource_id"] == value["resource_id"])
                && previous != &value
            {
                return Err(Error::Conflict);
            }

            let config: crate::config::Config =
                serde_json::from_value(runtime.clone()).map_err(|_| Error::Corrupt)?;
            let execution = config
                .storage_binding
                .execution(target)
                .map_err(|_| Error::Input)?;
            let mut tx = c.begin().await.map_err(|_| Error::Storage)?;
            sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
                .bind(tenant.to_string())
                .execute(&mut *tx)
                .await
                .map_err(|_| Error::Storage)?;
            if !sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT FROM public.mdm_tenants WHERE tenant_id=$1 AND NOT deleted)",
            )
            .bind(tenant)
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| Error::Storage)?
            {
                return Err(Error::Input);
            }
            sqlx::query("SELECT set_config('rss.storage_target',$1,true),set_config('rss.storage_lineage',$2,true),set_config('rss.execution_epoch',$3,true)")
                .bind(Uuid::from_bytes(execution.storage().target()).simple().to_string()).bind(Uuid::from_bytes(execution.storage().lineage()).simple().to_string()).bind(execution.epoch().get().to_string()).execute(&mut *tx).await.map_err(|_|Error::Storage)?;
            sqlx::query("SELECT rss_transactional_messaging.check_execution()")
                .execute(&mut *tx)
                .await
                .map_err(|_| Error::Conflict)?;
            // Create-or-lock the same selection row used by first use and batch admission.
            sqlx::query("INSERT INTO mdm_telemetry.storage_binding(tenant_id,binding,expected_epoch) VALUES($1,$2,$3) ON CONFLICT DO NOTHING").bind(tenant).bind(selected.as_slice()).bind(execution.epoch().get()).execute(&mut *tx).await.map_err(|_|Error::Storage)?;
            let previous: Option<Vec<u8>> = sqlx::query_scalar(
                "SELECT binding FROM mdm_telemetry.storage_binding WHERE tenant_id=$1 FOR UPDATE",
            )
            .bind(tenant)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|_| Error::Storage)?;
            if previous.as_deref().is_some_and(|p| p != selected) {
                let used:bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM mdm_telemetry.batches WHERE tenant_id=$1) OR EXISTS(SELECT FROM mdm_telemetry.definition_progress WHERE tenant_id=$1) OR EXISTS(SELECT FROM mdm_telemetry.maintenance WHERE tenant_id=$1)").bind(tenant).fetch_one(&mut *tx).await.map_err(|_|Error::Storage)?;
                if used {
                    return Err(Error::Conflict);
                }
            }
            sqlx::query("INSERT INTO mdm_telemetry.storage_binding(tenant_id,binding,expected_epoch) VALUES($1,$2,$3) ON CONFLICT(tenant_id) DO UPDATE SET binding=excluded.binding,expected_epoch=excluded.expected_epoch").bind(tenant).bind(selected.as_slice()).bind(execution.epoch().get()).execute(&mut *tx).await.map_err(|_|Error::Storage)?;
            tx.commit().await.map_err(|_| Error::Storage)?;
            let resources = runtime["telemetry"].as_array_mut().ok_or(Error::Corrupt)?;
            if !resources
                .iter()
                .any(|r| r["resource_id"] == value["resource_id"])
            {
                resources.push(value);
            }
        }

        Change::GatewayTls {
            certificate_file,
            private_key_file,
            trust_file,
        } => {
            let tls = super::runtime_files::GatewayTls::prepare(
                journal,
                certificate_file,
                private_key_file,
                trust_file,
            )?;
            journal.secret(
                "gateway.json",
                &serde_json::to_vec(&tls).map_err(|_| Error::Input)?,
            )?;
        }
        Change::Oidc { settings } => oidc(journal, runtime, tenant.ok_or(Error::Input)?, settings)?,
        Change::WebhookNetworks { networks } => {
            let target = tenant.ok_or(Error::Input)?;
            if networks.iter().any(|n| n.tenant != target) {
                return Err(Error::Input);
            }
            let mut selected = runtime["webhooks"]["networks"]
                .as_array()
                .cloned()
                .ok_or(Error::Corrupt)?;
            selected.retain(|network| network["tenant"] != json!(target));
            selected.extend(
                serde_json::to_value(networks)
                    .map_err(|_| Error::Input)?
                    .as_array()
                    .ok_or(Error::Input)?
                    .iter()
                    .cloned(),
            );
            runtime["webhooks"]["networks"] = json!(selected);
            serde_json::from_value::<crate::config::webhooks::Config>(runtime["webhooks"].clone())
                .map_err(|_| Error::Input)?
                .material_configuration()
                .map_err(|_| Error::Input)?;
        }
        Change::Channels { settings } => {
            let tenant = tenant.ok_or(Error::Input)?;
            channels(journal, c, runtime, tenant, settings).await?;
            super::providers::step_ca::initialize::attach(root, journal, c, runtime, tenant)
                .await?;
        }
        Change::EnrollmentEntries { settings } => {
            settings.validate().map_err(|_| Error::Input)?;
            runtime["enrollment_entries"] =
                serde_json::to_value(settings).map_err(|_| Error::Input)?;
        }
        Change::Recovery { profile, recipient } => {
            recovery(
                input,
                journal,
                c,
                runtime,
                tenant.ok_or(Error::Input)?,
                *profile,
                recipient,
            )
            .await?
        }
        Change::StepCa { settings } => {
            super::providers::step_ca::initialize::prepare(
                root,
                journal,
                c,
                runtime,
                tenant.ok_or(Error::Input)?,
                settings,
            )
            .await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn oidc_keys_survive_settings_replay_and_use_identity_encoding() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().canonicalize().unwrap().join("operation");
        let tenant = Uuid::new_v4();
        let mut runtime = json!({"product_origin":"https://mdm.example.test","identity":{"oidc":null,"runtime":crate::identity::policy::RuntimePolicy::installation()}});
        let mut settings = Oidc {
            group_facts_max_age_seconds: 300,
            return_targets: BTreeMap::new(),
            assurance_profiles: vec![],
            private_providers: vec![],
        };
        {
            let journal = Journal::open(&path).unwrap();
            oidc(&journal, &mut runtime, tenant, &settings).unwrap();
        }
        let original = runtime["identity"]["oidc"].clone();
        let state = crate::identity::key(std::path::Path::new(
            original["state_key_file"].as_str().unwrap(),
        ))
        .unwrap();
        let credential = crate::identity::key(std::path::Path::new(
            original["credential_keys"]
                .as_object()
                .unwrap()
                .values()
                .next()
                .unwrap()
                .as_str()
                .unwrap(),
        ))
        .unwrap();
        assert_ne!(state.as_slice(), credential.as_slice());
        settings
            .return_targets
            .insert("portal".into(), "https://mdm.example.test/".into());
        let journal = Journal::open(&path).unwrap();
        oidc(&journal, &mut runtime, tenant, &settings).unwrap();
        for field in ["state_key_file", "active_credential_key", "credential_keys"] {
            assert_eq!(runtime["identity"]["oidc"][field], original[field]);
        }
        // A restart after key generation but before candidate persistence uses the original bytes.
        let mut replay = json!({"product_origin":"https://mdm.example.test","identity":{"oidc":null,"runtime":crate::identity::policy::RuntimePolicy::installation()}});
        oidc(&journal, &mut replay, tenant, &settings).unwrap();
        assert_eq!(runtime, replay);
    }
}
