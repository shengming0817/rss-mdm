//! Closed deployment settings. Each domain keeps its existing runtime and persistence owner.
use super::{Error, Result, installation::Input, local::Journal};
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
    pub enrollment: crate::native::TlsEndpoint,
    pub management: crate::native::TlsEndpoint,
    pub trust_file: PathBuf,
    /// Omitted only in deployment input: preserve an existing identity or generate on first enablement.
    pub protocol_protection: Option<crate::config::NativeProtection>,
    #[serde(default)]
    pub lifetime: rss_mdm_certificate::windows::Lifetime,
    pub provider_id: String,
    pub poll: rss_mdm_windows_mdm::provisioning::Poll,
    pub push: Option<crate::windows::WindowsPushConfig>,
    pub additional_management: Vec<crate::native::TlsEndpoint>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Channels {
    pub windows: Option<Windows>,
    pub apple: Option<crate::apple::config::Config>,
    pub agent: crate::agent_pki::Config,
    pub providers: Vec<crate::device_pki::Provider>,
    pub apple_material_roots: Vec<PathBuf>,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Change {
    WebhookNetworks {
        networks: Vec<crate::webhooks::Network>,
    },
    Channels {
        settings: Box<Channels>,
    },
    Oidc {
        settings: Oidc,
    },
    Recovery {
        recipient: Recipient,
    },
    Ca {
        preparation: Uuid,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub installation: Input,
    pub operation_id: Uuid,
    pub host_id: Uuid,
    pub expected_revision: u64,
    pub change: Change,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Receipt {
    pub operation_id: Uuid,
    pub host_id: Uuid,
    pub requested_revision: u64,
    pub applied: Option<super::deployment::Applied>,
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
fn oidc(journal: &Journal, runtime: &mut Value, settings: &Oidc) -> Result<()> {
    let tenant = runtime["identity"]["tenant_id"]
        .as_str()
        .ok_or(Error::Corrupt)?;
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
    let config: crate::identity::OidcConfig =
        serde_json::from_value(next.clone()).map_err(|_| Error::Input)?;
    config
        .validate_deployment(
            tenant,
            runtime["product_origin"].as_str().ok_or(Error::Corrupt)?,
        )
        .map_err(|_| Error::Input)?;
    runtime["identity"]["oidc"] = next;
    Ok(())
}
fn recovery(journal: &Journal, runtime: &mut Value, source: &Recipient) -> Result<()> {
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
                name.append_entry_by_text(
                    "CN",
                    &format!(
                        "RSS recovery {}",
                        runtime["identity"]["tenant_id"]
                            .as_str()
                            .ok_or(Error::Corrupt)?
                    ),
                )
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
        runtime["recovery_credentials"] = json!({"active_key":id,"key_files":{id:encryption},"active_recipient":recipient.id(),"recipients":[]});
    }
    let config = &mut runtime["recovery_credentials"];
    let recipients = config["recipients"].as_array_mut().ok_or(Error::Corrupt)?;
    if recipients.len() >= 32 {
        return Err(Error::Conflict);
    }
    recipients.push(json!({"certificate_file":cert_file,"private_key_file":key_file}));
    config["active_recipient"] = json!(recipient.id());
    serde_json::from_value::<crate::recovery_credentials::Config>(config.clone())
        .map_err(|_| Error::Input)?
        .open()
        .map_err(|_| Error::Input)?;
    Ok(())
}

fn channels(journal: &Journal, runtime: &mut Value, settings: &Channels) -> Result<()> {
    // Channel identity outlives availability. Removing a configured channel would discard
    // its fixed fingerprint/identity seed and make re-enabling silently create a new identity.
    if (runtime["native_protocols"]["windows"].is_object() && settings.windows.is_none())
        || (runtime["native_protocols"]["apple"].is_object() && settings.apple.is_none())
    {
        return Err(Error::Conflict);
    }
    let mut native = json!({});
    if let Some(windows) = &settings.windows {
        let mut config = serde_json::to_value(windows).map_err(|_| Error::Input)?;
        let original = &runtime["native_protocols"]["windows"]["protocol_protection"];
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
        let config = serde_json::to_value(apple).map_err(|_| Error::Input)?;
        let original = &runtime["native_protocols"]["apple"]["identity_seed"];
        if original.is_object() && original != &config["identity_seed"] {
            return Err(Error::Conflict);
        }
        native["apple"] = config;
    }
    runtime["native_protocols"] = native;
    runtime["agent_pki"] = serde_json::to_value(&settings.agent).map_err(|_| Error::Input)?;
    runtime["device_pki"] = serde_json::to_value(&settings.providers).map_err(|_| Error::Input)?;
    runtime["apple_material_roots"] = json!(settings.apple_material_roots);
    Ok(())
}
fn ca(input: &Input, runtime: &mut Value, operation: Uuid) -> Result<()> {
    use rss_mdm_agent_wire::pki::Purpose;
    if operation.is_nil() {
        return Err(Error::Input);
    }
    let journal = Journal::open(&input.directory.join(format!("ca-{operation}")))?;
    let receipt: super::providers::step_ca::Receipt =
        journal.load("receipt.json")?.ok_or(Error::Corrupt)?;
    if receipt.operation_id != operation
        || receipt.stage != super::providers::step_ca::Stage::Verified
        || runtime["identity"]["tenant_id"] != json!(receipt.tenant_id)
    {
        return Err(Error::Conflict);
    }
    let trust = crate::config::read(&journal.path("trust.json")?, 64 * 1024 * 1024, true)
        .map_err(|_| Error::Corrupt)?;
    if receipt.trust_digest.as_deref() != Some(rss_mdm_device_trust::digest(&trust).as_str()) {
        return Err(Error::Corrupt);
    }
    let path = match receipt.purpose {
        Purpose::Windows => "/native_protocols/windows",
        Purpose::Apple => "/native_protocols/apple",
        Purpose::Agent => "/agent_pki",
        Purpose::AgentBootstrap => "/agent_pki/bootstrap",
    };
    let channel = runtime
        .pointer(path)
        .filter(|v| v.is_object())
        .ok_or(Error::Conflict)?;
    if channel.get("trust_file").and_then(Value::as_str).is_none() {
        return Err(Error::Conflict);
    }
    let provider: Value = journal
        .load("runtime-provider.json")?
        .ok_or(Error::Corrupt)?;
    // The runtime decoder enforces the exact provider contract before any host side effect.
    serde_json::from_value::<crate::device_pki::Provider>(provider.clone())
        .map_err(|_| Error::Corrupt)?;
    let providers = runtime["device_pki"].as_array_mut().ok_or(Error::Corrupt)?;
    if let Some(existing) = providers
        .iter()
        .find(|p| p["purpose"] == provider["purpose"] && p["issuer"] == provider["issuer"])
    {
        if existing != &provider {
            return Err(Error::Conflict);
        }
    } else {
        providers.push(provider);
    }
    if matches!(receipt.purpose, Purpose::Apple | Purpose::AgentBootstrap) {
        let callbacks: Value = journal
            .load("runtime-callbacks.json")?
            .ok_or(Error::Corrupt)?;
        if callbacks["issuer"] != json!(receipt.issuer) {
            return Err(Error::Corrupt);
        }
        let entries = runtime.pointer_mut(path).ok_or(Error::Corrupt)?["webhooks"]
            .as_array_mut()
            .ok_or(Error::Corrupt)?;
        if let Some(existing) = entries
            .iter()
            .find(|entry| entry["issuer"] == callbacks["issuer"])
        {
            if existing != &callbacks {
                return Err(Error::Conflict);
            }
        } else {
            entries.push(callbacks);
        }
    }
    // Trust remains with the PKI registry. The real business session publishes/ACKs/activates it.
    Ok(())
}

pub async fn run(request: Request) -> Result<Receipt> {
    if !cfg!(target_os = "linux") || request.operation_id.is_nil() || request.host_id.is_nil() {
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
    if let Some(receipt) = journal.load::<Receipt>("receipt.json")?
        && receipt.applied.is_some()
    {
        if root
            .load::<Option<Uuid>>("configuration-operation.json")?
            .flatten()
            == Some(request.operation_id)
        {
            root.save("configuration-operation.json", &Option::<Uuid>::None)?;
        }
        return Ok(receipt);
    }
    let base: Value = root.load("runtime.json")?.ok_or(Error::Corrupt)?;
    let base: crate::config::Config = serde_json::from_value(base).map_err(|_| Error::Corrupt)?;
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
            target: base.flow.storage.target,
            lineage: base.flow.storage.lineage,
            audit_mode: base.audit.mode(),
        },
    )
    .await
    .map_err(|_| Error::Conflict)?;
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
    let mut original:Value=sqlx::query_scalar("SELECT receipt FROM public.mdm_tenant_operations WHERE action='provision' AND receipt->'result'->>'hostId'=$1 AND receipt->'result'->>'phase'='enabled'")
        .bind(request.host_id.to_string()).fetch_optional(&mut c).await.map_err(|_|Error::Storage)?.ok_or(Error::Conflict)?;
    let mut receipt: crate::tenant_registry::Receipt =
        serde_json::from_value(original.clone()).map_err(|_| Error::Corrupt)?;
    let crate::tenant_registry::ReceiptResult::Provisioning(progress) = &mut receipt.result else {
        return Err(Error::Corrupt);
    };
    let tenant = progress.tenant_id;
    let host = Journal::open(
        &input
            .directory
            .join(format!("rss-mdm-{}", request.host_id.simple())),
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
            || runtime["runtime_binding"]["host_id"] != json!(request.host_id)
            || runtime["identity"]["tenant_id"] != json!(tenant)
        {
            return Err(Error::Conflict);
        }
        match &request.change {
            Change::Oidc { settings } => oidc(&journal, &mut runtime, settings)?,
            Change::WebhookNetworks { networks } => {
                let tenant = runtime["identity"]["tenant_id"]
                    .as_str()
                    .ok_or(Error::Corrupt)?;
                if networks.iter().any(|n| n.tenant.to_string() != tenant) {
                    return Err(Error::Input);
                }
                runtime["webhooks"]["networks"] =
                    serde_json::to_value(networks).map_err(|_| Error::Input)?;
                serde_json::from_value::<crate::webhooks::Config>(runtime["webhooks"].clone())
                    .map_err(|_| Error::Input)?
                    .material_configuration()
                    .map_err(|_| Error::Input)?;
            }
            Change::Channels { settings } => channels(&journal, &mut runtime, settings)?,
            Change::Recovery { recipient } => recovery(&journal, &mut runtime, recipient)?,
            Change::Ca { preparation } => ca(input, &mut runtime, *preparation)?,
        }
        super::deployment::freeze(&mut runtime, &journal)?;
        let revision = request
            .expected_revision
            .checked_add(1)
            .filter(|r| *r <= i64::MAX as u64)
            .ok_or(Error::Input)?;
        let digest = super::application::fingerprint(&runtime)?;
        runtime["runtime_binding"] = json!({"host_id":request.host_id,"operation_id":request.operation_id,"revision":revision,"material_digest":digest});
        let config: crate::config::Config =
            serde_json::from_value(runtime.clone()).map_err(|_| Error::Input)?;
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
        host_id: request.host_id,
        requested_revision: binding.revision,
        applied: None,
    };
    root.save("configuration-operation.json", &Some(request.operation_id))?;
    host.save("requested-runtime.json", &candidate)?;
    drop(host);
    let old = progress
        .application
        .as_ref()
        .and_then(|p| p.observation.clone());
    progress.application = Some(super::model::Application {
        requested_revision: binding.revision,
        operation_id: binding.operation_id,
        material_digest: binding.material_digest,
        observation: old,
    });
    progress.revision = progress.revision.checked_add(1).ok_or(Error::Corrupt)?;
    original = super::application::save(&mut c, &receipt, &original).await?;
    let slots: BTreeMap<Uuid, usize> = root.load("host-reservations.json")?.unwrap_or_default();
    let deployment = match slots.get(&request.host_id) {
        Some(index) => {
            &input
                .additional_hosts
                .get(*index)
                .ok_or(Error::Corrupt)?
                .deployment
        }
        None => &input.deployment,
    };
    let outcome = super::deployment::apply(&input.directory, deployment, &candidate).await;
    let crate::tenant_registry::ReceiptResult::Provisioning(progress) = &mut receipt.result else {
        return Err(Error::Corrupt);
    };
    let now = crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)
        .map_err(|_| Error::Storage)?;
    record_application(progress, &mut result, outcome, now)?;
    progress.revision = progress.revision.checked_add(1).ok_or(Error::Corrupt)?;
    super::application::save(&mut c, &receipt, &original).await?;
    journal.save("receipt.json", &result)?;
    // A persisted failure is a recoverable outcome, not an indefinitely active operation.
    // Unknown persistence outcomes above retain the fence until the original request resumes.
    root.save("configuration-operation.json", &Option::<Uuid>::None)?;
    c.close().await.map_err(|_| Error::Storage)?;
    Ok(result)
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

fn record_application(
    progress: &mut super::model::Provisioning,
    result: &mut Receipt,
    outcome: Result<super::deployment::Applied>,
    now: i64,
) -> Result<()> {
    match outcome {
        Ok(observed) => {
            if observed.host_id != result.host_id
                || observed.operation_id != result.operation_id
                || observed.tenant_id != progress.tenant_id.to_string()
            {
                return Err(Error::Conflict);
            }
            progress
                .application
                .as_mut()
                .ok_or(Error::Corrupt)?
                .observation = Some(super::model::Observation {
                host_id: observed.host_id,
                process_generation: observed.process_generation,
                applied_revision: observed.revision,
                material_digest: observed.material_digest.clone(),
                observed_at: now,
                failure: None,
            });
            progress.blocked = None;
            result.applied = Some(observed);
        }
        Err(_) => {
            progress.blocked = Some(super::model::BlockedReason::HostUnavailable);
            if let Some(observation) = progress
                .application
                .as_mut()
                .and_then(|a| a.observation.as_mut())
            {
                observation.failure = Some(super::model::BlockedReason::HostUnavailable);
                observation.observed_at = now;
            }
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
        let mut runtime = json!({"product_origin":"https://mdm.example.test","identity":{"tenant_id":tenant,"oidc":null}});
        let mut settings = Oidc {
            group_facts_max_age_seconds: 300,
            return_targets: BTreeMap::new(),
            assurance_profiles: vec![],
            private_providers: vec![],
        };
        {
            let journal = Journal::open(&path).unwrap();
            oidc(&journal, &mut runtime, &settings).unwrap();
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
        oidc(&journal, &mut runtime, &settings).unwrap();
        for field in ["state_key_file", "active_credential_key", "credential_keys"] {
            assert_eq!(runtime["identity"]["oidc"][field], original[field]);
        }
        // A restart after key generation but before candidate persistence uses the original bytes.
        let mut replay = json!({"product_origin":"https://mdm.example.test","identity":{"tenant_id":tenant,"oidc":null}});
        oidc(&journal, &mut replay, &settings).unwrap();
        assert_eq!(runtime, replay);
    }
    #[test]
    fn removing_a_configured_channel_cannot_discard_its_fixed_identity() {
        let directory = tempfile::tempdir().unwrap();
        let journal =
            Journal::open(&directory.path().canonicalize().unwrap().join("operation")).unwrap();
        let settings = Channels {
            windows: None,
            apple: None,
            agent: crate::agent_pki::Config::Disabled {},
            providers: vec![],
            apple_material_roots: vec![],
        };
        for name in ["windows", "apple"] {
            let mut runtime = json!({"native_protocols":{name:{"identity":"retained"}}});
            let original = runtime.clone();
            assert!(matches!(
                channels(&journal, &mut runtime, &settings),
                Err(Error::Conflict)
            ));
            assert_eq!(runtime, original);
        }
    }
    #[test]
    fn recovery_recipient_rotation_retains_original_decryption_material() {
        let directory = tempfile::tempdir().unwrap();
        let old = Journal::open(&directory.path().canonicalize().unwrap().join("old")).unwrap();
        let next = Journal::open(&directory.path().canonicalize().unwrap().join("next")).unwrap();
        let mut runtime =
            json!({"identity":{"tenant_id":Uuid::new_v4()},"recovery_credentials":null});
        recovery(&old, &mut runtime, &Recipient::Generate).unwrap();
        let original = runtime["recovery_credentials"].clone();
        recovery(&next, &mut runtime, &Recipient::Generate).unwrap();
        let config: crate::recovery_credentials::Config =
            serde_json::from_value(runtime["recovery_credentials"].clone()).unwrap();
        let protection = config.open().unwrap();
        assert!(
            protection
                .recipient(original["active_recipient"].as_str().unwrap())
                .is_ok()
        );
        assert_ne!(
            protection.active_recipient().id(),
            original["active_recipient"].as_str().unwrap()
        );
        assert!(
            protection
                .active_recipient()
                .require_current(time::OffsetDateTime::now_utc().unix_timestamp())
                .is_ok()
        );
        assert!(
            protection
                .active_recipient()
                .require_current(time::OffsetDateTime::now_utc().unix_timestamp() + 366 * 86400)
                .is_err()
        );
        assert_eq!(
            runtime["recovery_credentials"]["key_files"],
            original["key_files"]
        );
    }
}
