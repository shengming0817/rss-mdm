//! 固定 CA 管理动作；应用宿主仅得到用途 JWK，绝不获得 admin 或离线 root 私钥。
mod client;
mod wire;
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, path::PathBuf};
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub origin: String,
    pub address: SocketAddr,
    pub tls_root_file: PathBuf,
    pub administrator_subject: String,
    pub administrator_certificate_file: PathBuf,
    pub administrator_key_file: PathBuf,
}

use crate::setup::{Error, Result, installation, local::Journal};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use rss_mdm_agent_wire::pki::{Issuer, Mode, Purpose, Trust};
use serde_json::json;
use sqlx::{Connection, PgConnection};
use uuid::Uuid;
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum KeySource {
    Generate,
    Import {
        kid: String,
        private_key_file: PathBuf,
    },
}
#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Preparation {
    Create,
    Import,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScepInput {
    pub certificate_file: PathBuf,
    pub private_key_file: PathBuf,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub installation: installation::Input,
    pub operation_id: Uuid,
    pub tenant_id: Uuid,
    pub purpose: Purpose,
    pub expected_revision: u64,
    pub device_origin: String,
    pub callback_origin: Option<String>,
    pub profile: Profile,
    pub preparation: Preparation,
    pub key: KeySource,
    pub issuer_certificate_file: PathBuf,
    pub root_certificate_file: PathBuf,
    pub root_crl_file: PathBuf,
    pub scep: Option<ScepInput>,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    Preparing,
    MaterialReserved,
    ProvisionerPrepared,
    WebhooksPrepared,
    Verified,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Receipt {
    pub operation_id: Uuid,
    pub tenant_id: Uuid,
    pub purpose: Purpose,
    pub stage: Stage,
    pub issuer: String,
    pub key_id: Option<String>,
    pub verified_at: Option<i64>,
    pub trust_digest: Option<String>,
    pub application: String,
    pub webhook_delivery: String,
}
fn clock() -> Result<i64> {
    use crate::clock::Clock;
    crate::clock::SystemClock
        .unix_seconds()
        .map_err(|_| Error::Storage)
}
fn names(purpose: Purpose) -> (&'static str, Option<&'static str>) {
    match purpose {
        Purpose::Windows => ("rss-windows", None),
        Purpose::Agent => ("rss-agent", None),
        Purpose::Apple => ("rss-apple-revocation", Some("rss")),
        Purpose::AgentBootstrap => (
            "rss-agent-bootstrap-revocation",
            Some("rss-agent-bootstrap"),
        ),
    }
}
fn origin(value: &str) -> Result<()> {
    let url = url::Url::parse(value).map_err(|_| Error::Input)?;
    if url.scheme() != "https"
        || url.origin().ascii_serialization() != value
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(Error::Input);
    }
    Ok(())
}
fn copy(journal: &Journal, name: &str, source: &std::path::Path, private: bool) -> Result<PathBuf> {
    let target = journal.path(name)?;
    if target.exists() {
        return Ok(target);
    }
    journal.secret(
        name,
        &crate::config::read(source, 131072, private).map_err(|_| Error::Input)?,
    )
}
fn certificate(path: &std::path::Path) -> Result<Vec<u8>> {
    let bytes = crate::config::read(path, 131072, false).map_err(|_| Error::Input)?;
    openssl::x509::X509::from_pem(&bytes)
        .or_else(|_| openssl::x509::X509::from_der(&bytes))
        .and_then(|c| c.to_der())
        .map_err(|_| Error::Input)
}
fn jwk(bytes: &[u8], kid: Option<&str>) -> Result<(String, serde_json::Value)> {
    use sha2::{Digest, Sha256};
    let key = openssl::pkey::PKey::private_key_from_pkcs8(bytes).map_err(|_| Error::Input)?;
    let rsa = key.rsa().map_err(|_| Error::Input)?;
    if !(2048..=4096).contains(&rsa.n().num_bits()) {
        return Err(Error::Input);
    }
    let n = URL_SAFE_NO_PAD.encode(rsa.n().to_vec());
    let e = URL_SAFE_NO_PAD.encode(rsa.e().to_vec());
    let canonical = json!({"e":e,"kty":"RSA","n":n});
    let kid = kid.map(str::to_owned).unwrap_or_else(|| {
        URL_SAFE_NO_PAD.encode(Sha256::digest(
            serde_json::to_vec(&canonical).expect("public JWK"),
        ))
    });
    if kid.is_empty() || kid.len() > 128 || kid.chars().any(char::is_control) {
        return Err(Error::Input);
    }
    Ok((
        kid.clone(),
        json!({"kty":"RSA","kid":kid,"alg":"RS256","use":"sig","n":n,"e":e}),
    ))
}
fn claims(purpose: Purpose) -> wire::Claims {
    let (default, max) = match purpose {
        Purpose::Windows => ("2160h", "2160h"),
        Purpose::Agent => ("8760h", "8760h"),
        Purpose::Apple => ("24h", "2160h"),
        Purpose::AgentBootstrap => ("1h", "24h"),
    };
    wire::Claims {
        x509: wire::X509Claims {
            enabled: true,
            durations: wire::Durations {
                default: default.into(),
                min: if purpose == Purpose::AgentBootstrap {
                    "1s"
                } else {
                    "5m"
                }
                .into(),
                max: max.into(),
            },
        },
        disable_renewal: true,
        ..Default::default()
    }
}
fn jwk_provisioner(purpose: Purpose, public: serde_json::Value) -> Result<wire::Provisioner> {
    let template = match purpose {
        Purpose::Windows => include_str!("../../../../../../deployment/windows-leaf.tpl"),
        Purpose::Agent => include_str!("../../../../../../deployment/agent-leaf.tpl"),
        _ => {
            r#"{"subject":{"commonName":"rss-mdm-provider-check"},"keyUsage":["digitalSignature"],"extKeyUsage":["clientAuth"],"basicConstraints":{"isCA":false}}"#
        }
    };
    Ok(wire::Provisioner {
        kind: "JWK".into(),
        name: names(purpose).0.into(),
        details: wire::Details {
            jwk: Some(wire::Jwk {
                public_key: STANDARD.encode(serde_json::to_vec(&public).map_err(|_| Error::Input)?),
                encrypted_private_key: None,
            }),
            scep: None,
        },
        claims: claims(purpose),
        x509_template: wire::Template {
            template: STANDARD.encode(template),
            data: String::new(),
        },
        ..Default::default()
    })
}
async fn ensure_provider(
    client: &client::Client,
    expected: &wire::Provisioner,
    mode: Preparation,
) -> Result<wire::Provisioner> {
    let actual = match client
        .get::<wire::Provisioner>(&expected.name, clock()?)
        .await?
    {
        Some(value) => value,
        None if mode == Preparation::Create => {
            let created: wire::Provisioner = client.create(expected, clock()?).await?;
            created.matches(expected)?;
            client
                .get::<wire::Provisioner>(&expected.name, clock()?)
                .await?
                .ok_or(Error::Storage)?
        }
        None => return Err(Error::Conflict),
    };
    actual.matches(expected)?;
    Ok(actual)
}
/// 仅准备真实 CA 用途材料；已有 trust 的激活仍必须经过业务管理会话和设备确认。
pub async fn run(input: Request) -> Result<Receipt> {
    if input.operation_id.is_nil()
        || input.tenant_id.is_nil()
        || (input.preparation == Preparation::Import && matches!(input.key, KeySource::Generate))
    {
        return Err(Error::Input);
    }
    origin(&input.device_origin)?;
    if names(input.purpose).1.is_some() != input.scep.is_some()
        || input.scep.is_some() != input.callback_origin.is_some()
    {
        return Err(Error::Input);
    }
    if let Some(callback) = &input.callback_origin {
        origin(callback)?;
    }
    let root = Journal::open(&input.installation.directory)?;
    if root
        .load::<Option<Uuid>>("backup-operation.json")?
        .flatten()
        .is_some()
    {
        return Err(Error::Busy);
    }
    let journal = Journal::open(
        &input
            .installation
            .directory
            .join(format!("ca-{}", input.operation_id)),
    )?;
    journal.secret(
        "request.json",
        &serde_json::to_vec(&input).map_err(|_| Error::Input)?,
    )?;
    if let Some(receipt) = journal.load::<Receipt>("receipt.json")?
        && receipt.stage == Stage::Verified
    {
        return Ok(receipt);
    }
    let runtime: crate::config::Config = root.load("runtime.json")?.ok_or(Error::Corrupt)?;
    let mut connection = PgConnection::connect_with(
        &input
            .installation
            .database("mdm_owner")?
            .options()
            .map_err(|_| Error::Input)?,
    )
    .await
    .map_err(|_| Error::Storage)?;
    if !crate::migration::owner_admitted(&mut connection)
        .await
        .map_err(|_| Error::Storage)?
    {
        return Err(Error::Input);
    }
    let installation = crate::migration::Installation {
        instance_id: runtime.identity.instance_id.clone(),
        target: runtime.flow.storage.target,
        lineage: runtime.flow.storage.lineage,
        audit_mode: runtime.audit.mode(),
    };
    crate::migration::verify_identity(&mut connection, &installation)
        .await
        .map_err(|_| Error::Conflict)?;
    let mut tx = connection.begin().await.map_err(|_| Error::Storage)?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(input.tenant_id.to_string())
        .execute(&mut *tx)
        .await
        .map_err(|_| Error::Storage)?;
    let tenant:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM public.mdm_tenants WHERE tenant_id=$1 AND NOT deleted AND tenant_id<>(SELECT management_tenant_id FROM public.mdm_installation))").bind(input.tenant_id).fetch_one(&mut *tx).await.map_err(|_|Error::Storage)?;
    if !tenant {
        return Err(Error::Conflict);
    }
    let previous: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT body FROM mdm_pki.trust WHERE tenant_id=$1 AND purpose=$2")
            .bind(input.tenant_id)
            .bind(rss_mdm_pki_service::registry::purpose(input.purpose))
            .fetch_optional(&mut *tx)
            .await
            .map_err(|_| Error::Storage)?;
    let previous: Option<Trust> = previous
        .map(|v| serde_json::from_slice(&v).map_err(|_| Error::Corrupt))
        .transpose()?;
    if previous.as_ref().map_or(0, |t| t.revision) != input.expected_revision
        || previous
            .as_ref()
            .is_some_and(|t| t.origin != input.device_origin)
    {
        return Err(Error::Conflict);
    }
    tx.rollback().await.map_err(|_| Error::Storage)?;
    connection.close().await.map_err(|_| Error::Storage)?;
    let issuer_path = copy(
        &journal,
        "issuer.pem",
        &input.issuer_certificate_file,
        false,
    )?;
    let root_path = copy(&journal, "root.pem", &input.root_certificate_file, false)?;
    let issuer = certificate(&issuer_path)?;
    let root_certificate = certificate(&root_path)?;
    let issuer_digest = rss_mdm_device_trust::digest(&issuer);
    let mut receipt = journal.load::<Receipt>("receipt.json")?.unwrap_or(Receipt {
        operation_id: input.operation_id,
        tenant_id: input.tenant_id,
        purpose: input.purpose,
        stage: Stage::Preparing,
        issuer: issuer_digest.clone(),
        key_id: None,
        verified_at: None,
        trust_digest: None,
        application: "pending_host_and_domain_application".into(),
        webhook_delivery: if input.scep.is_some() {
            "pending_channel_observation"
        } else {
            "not_applicable"
        }
        .into(),
    });
    if receipt.issuer != issuer_digest {
        return Err(Error::Conflict);
    }
    journal.save("receipt.json", &receipt)?;
    let key_file = journal.path("provisioner.pk8")?;
    if !key_file.exists() {
        if receipt.stage != Stage::Preparing {
            return Err(Error::Corrupt);
        }
        let bytes = match &input.key {
            KeySource::Generate => tokio::task::spawn_blocking(|| {
                openssl::rsa::Rsa::generate(2048)
                    .and_then(openssl::pkey::PKey::from_rsa)
                    .and_then(|p| p.private_key_to_pkcs8())
                    .map(zeroize::Zeroizing::new)
            })
            .await
            .map_err(|_| Error::Storage)?
            .map_err(|_| Error::Storage)?,
            KeySource::Import {
                private_key_file, ..
            } => crate::config::read(private_key_file, 32768, true).map_err(|_| Error::Input)?,
        };
        jwk(&bytes, None)?;
        journal.secret("provisioner.pk8", &bytes)?;
    }
    let private = crate::config::read(&key_file, 32768, true).map_err(|_| Error::Corrupt)?;
    let (kid, public) = jwk(
        &private,
        match &input.key {
            KeySource::Generate => None,
            KeySource::Import { kid, .. } => Some(kid),
        },
    )?;
    if receipt.key_id.as_ref().is_some_and(|old| old != &kid) {
        return Err(Error::Conflict);
    }
    receipt.key_id = Some(kid.clone());
    if receipt.stage < Stage::MaterialReserved {
        receipt.stage = Stage::MaterialReserved;
    }
    journal.save("receipt.json", &receipt)?;
    let tls_root = copy(
        &journal,
        "provider-tls-root.pem",
        &input.profile.tls_root_file,
        false,
    )?;
    let provider = rss_mdm_pki_service::StepCa::at_address(
        rss_mdm_pki_service::Configuration {
            origin: input.profile.origin.clone(),
            provisioner: names(input.purpose).0.into(),
            kid: kid.clone(),
        },
        &crate::config::read(&tls_root, 131072, false).map_err(|_| Error::Corrupt)?,
        &private,
        input.profile.address,
    )
    .map_err(|_| Error::Input)?;
    provider
        .verify_issuer(&issuer_digest)
        .await
        .map_err(|_| Error::Conflict)?;
    let crl = provider.published_crl().await.map_err(|_| Error::Storage)?;
    let root_crl = crate::config::read(&input.root_crl_file, 16 * 1024 * 1024, false)
        .map_err(|_| Error::Input)?;
    let root_crl = openssl::x509::X509Crl::from_pem(&root_crl)
        .or_else(|_| openssl::x509::X509Crl::from_der(&root_crl))
        .and_then(|c| c.to_der())
        .map_err(|_| Error::Input)?;
    let scep_name = names(input.purpose).1;
    let mut trust = previous.unwrap_or(Trust {
        version: 1,
        origin: input.device_origin.clone(),
        tenant: input.tenant_id,
        purpose: input.purpose,
        revision: 0,
        issuers: Vec::new(),
    });
    if trust.issuers.iter().any(|g| g.digest == issuer_digest) {
        return Err(Error::Conflict);
    }
    let mode = if trust.issuers.is_empty() {
        Mode::Active
    } else {
        Mode::Prepared
    };
    trust.revision = trust.revision.checked_add(1).ok_or(Error::Corrupt)?;
    trust.issuers.push(Issuer {
        digest: issuer_digest.clone(),
        mode,
        certificate: STANDARD.encode(&issuer),
        root: STANDARD.encode(&root_certificate),
        crl: STANDARD.encode(&crl),
        root_crl: STANDARD.encode(root_crl),
        provisioner: scep_name.unwrap_or(names(input.purpose).0).into(),
        kid: if scep_name.is_some() {
            String::new()
        } else {
            kid.clone()
        },
    });
    rss_mdm_device_trust::DeviceTrust::new(trust.clone(), input.purpose, clock()?)
        .map_err(|_| Error::Conflict)?;
    let scep = names(input.purpose)
        .1
        .map(|name| {
            scep_provisioner(
                input.purpose,
                input.scep.as_ref().ok_or(Error::Input)?,
                &journal,
                name,
                &issuer,
                &crl,
            )
        })
        .transpose()?;
    let client = client::Client::new(&input.profile, clock()?)?;
    ensure_provider(
        &client,
        &jwk_provisioner(input.purpose, public)?,
        input.preparation,
    )
    .await?;
    if receipt.stage < Stage::ProvisionerPrepared {
        receipt.stage = Stage::ProvisionerPrepared;
    }
    journal.save("receipt.json", &receipt)?;
    if let Some(expected) = &scep {
        prepare_scep(
            input.purpose,
            input.callback_origin.as_deref().ok_or(Error::Input)?,
            input.preparation,
            &journal,
            &client,
            expected,
        )
        .await?;
    } else if input.scep.is_some() {
        return Err(Error::Input);
    }
    if receipt.stage < Stage::WebhooksPrepared {
        receipt.stage = Stage::WebhooksPrepared;
    }
    journal.save("receipt.json", &receipt)?;
    provider
        .verify_provisioner()
        .await
        .map_err(|_| Error::Conflict)?;
    rss_mdm_device_trust::DeviceTrust::new(trust.clone(), input.purpose, clock()?)
        .map_err(|_| Error::Conflict)?;
    let bytes = serde_json::to_vec(&trust).map_err(|_| Error::Corrupt)?;
    let trust_file = journal.secret("trust.json", &bytes)?;
    journal.secret("runtime-provider.json",&serde_json::to_vec(&json!({"purpose":input.purpose,"issuer":issuer_digest,"origin":input.profile.origin,"tls_root_file":tls_root,"provisioner":names(input.purpose).0,"kid":kid,"provisioner_key_file":key_file,"scep_url":scep_name.map(|name|format!("{}/scep/{name}",input.profile.origin))})).map_err(|_|Error::Corrupt)?)?;
    let callbacks = if scep_name.is_some() {
        let challenge: serde_json::Value = journal
            .load("challenge-runtime.json")?
            .ok_or(Error::Corrupt)?;
        let notify: serde_json::Value =
            journal.load("notify-runtime.json")?.ok_or(Error::Corrupt)?;
        Some(
            journal.secret(
                "runtime-callbacks.json",
                &serde_json::to_vec(
                    &json!({"issuer":issuer_digest,"challenge":challenge,"notify":notify}),
                )
                .map_err(|_| Error::Corrupt)?,
            )?,
        )
    } else {
        None
    };
    journal.secret("application.json",&serde_json::to_vec(&json!({"expectedRevision":input.expected_revision,"trustFile":trust_file,"providerFile":journal.path("runtime-provider.json")?,"callbacksFile":callbacks,"purpose":input.purpose})).map_err(|_|Error::Corrupt)?)?;
    receipt.stage = Stage::Verified;
    receipt.verified_at = Some(clock()?);
    receipt.trust_digest = Some(rss_mdm_device_trust::digest(&bytes));
    journal.save("receipt.json", &receipt)?;
    Ok(receipt)
}

fn scep_provisioner(
    purpose: Purpose,
    source: &ScepInput,
    journal: &Journal,
    name: &str,
    issuer_der: &[u8],
    crl_der: &[u8],
) -> Result<wire::Provisioner> {
    use x509_cert::der::Decode;
    use x509_cert::ext::pkix::{BasicConstraints, KeyUsage};
    let certificate_file = copy(
        journal,
        "scep-decrypter.pem",
        &source.certificate_file,
        false,
    )?;
    let key_file = copy(
        journal,
        "scep-decrypter.key",
        &source.private_key_file,
        true,
    )?;
    let certificate_der = certificate(&certificate_file)?;
    let certificate = openssl::x509::X509::from_der(&certificate_der).map_err(|_| Error::Input)?;
    let bytes = crate::config::read(&key_file, 32768, true).map_err(|_| Error::Input)?;
    let key = openssl::pkey::PKey::private_key_from_pem(&bytes)
        .or_else(|_| openssl::pkey::PKey::private_key_from_pkcs8(&bytes))
        .map_err(|_| Error::Input)?;
    let issuer = openssl::x509::X509::from_der(issuer_der).map_err(|_| Error::Input)?;
    let issuer_key = issuer.public_key().map_err(|_| Error::Input)?;
    if key.id() != openssl::pkey::Id::RSA
        || !(2048..=4096).contains(&key.bits())
        || !certificate
            .public_key()
            .map_err(|_| Error::Input)?
            .public_eq(&key)
        || certificate
            .issuer_name()
            .to_der()
            .map_err(|_| Error::Input)?
            != issuer.subject_name().to_der().map_err(|_| Error::Input)?
        || !certificate.verify(&issuer_key).map_err(|_| Error::Input)?
    {
        return Err(Error::Input);
    }
    let leaf = x509_cert::Certificate::from_der(&certificate_der).map_err(|_| Error::Input)?;
    let now = clock()?;
    if !rss_mdm_certificate::apple::valid(&leaf, now)
        || leaf
            .tbs_certificate
            .get::<BasicConstraints>()
            .map_err(|_| Error::Input)?
            .is_some_and(|(_, v)| v.ca)
        || leaf
            .tbs_certificate
            .get::<KeyUsage>()
            .map_err(|_| Error::Input)?
            .is_none_or(|(_, v)| {
                !v.digital_signature() || !v.key_encipherment() || v.key_cert_sign() || v.crl_sign()
            })
    {
        return Err(Error::Input);
    }
    let issuer = x509_cert::Certificate::from_der(issuer_der).map_err(|_| Error::Input)?;
    let crl = rss_mdm_device_trust::crl(crl_der, &issuer, now).map_err(|_| Error::Input)?;
    if crl.revoked.contains(&rss_mdm_device_trust::serial(
        leaf.tbs_certificate.serial_number.as_bytes(),
    )) {
        return Err(Error::Input);
    }
    let template = if purpose == Purpose::AgentBootstrap {
        r#"{"subject":{{ toJson .Webhooks.rss.subject }},"notAfter":{{ toJson .Webhooks.rss.notAfter }},"keyUsage":["digitalSignature"],"extKeyUsage":["clientAuth"],"basicConstraints":{"isCA":false}}"#
    } else {
        r#"{"subject":{"commonName":{{ toJson .Webhooks.rss.subject }}},"keyUsage":["digitalSignature"],"extKeyUsage":["clientAuth"],"basicConstraints":{"isCA":false}}"#
    };
    Ok(wire::Provisioner {
        kind: "SCEP".into(),
        name: name.into(),
        details: wire::Details {
            jwk: None,
            scep: Some(wire::Scep {
                force_cn: false,
                challenge: String::new(),
                capabilities: Vec::new(),
                minimum_public_key_length: 2048,
                include_root: false,
                encryption_algorithm_identifier: 2,
                decrypter: wire::Decrypter {
                    certificate: STANDARD.encode(certificate.to_pem().map_err(|_| Error::Input)?),
                    key: STANDARD
                        .encode(key.private_key_to_pem_pkcs8().map_err(|_| Error::Input)?)
                        .into(),
                    key_uri: String::new(),
                    key_password: None,
                },
                exclude_intermediate: false,
            }),
        },
        claims: claims(purpose),
        x509_template: wire::Template {
            template: STANDARD.encode(template),
            data: String::new(),
        },
        ..Default::default()
    })
}
async fn prepare_scep(
    purpose: Purpose,
    callback_origin: &str,
    preparation: Preparation,
    journal: &Journal,
    client: &client::Client,
    expected: &wire::Provisioner,
) -> Result<()> {
    let existing = ensure_provider(client, expected, preparation).await?;
    let prefix = if purpose == Purpose::Apple {
        "/api/v1/apple/scep"
    } else {
        "/api/v1/agent/enroll/bootstrap/scep"
    };
    for hook in &existing.webhooks {
        let (phase, kind) = match hook.name.as_str() {
            "rss" => ("challenge", "SCEPCHALLENGE"),
            "rss_notify" => ("notify", "NOTIFYING"),
            _ => return Err(Error::Conflict),
        };
        hook.matches(
            &hook.name,
            &format!("{}{prefix}/{phase}", callback_origin),
            kind,
        )?;
    }
    for (phase, name, kind) in [
        ("challenge", "rss", "SCEPCHALLENGE"),
        ("notify", "rss_notify", "NOTIFYING"),
    ] {
        let url = format!("{}{prefix}/{phase}", callback_origin);
        let mut remote = client
            .get::<wire::Provisioner>(&expected.name, clock()?)
            .await?
            .ok_or(Error::Conflict)?;
        remote.matches(expected)?;
        if remote.webhooks.iter().filter(|h| h.name == name).count() > 1 {
            return Err(Error::Conflict);
        }
        let webhook = if let Some(index) = remote.webhooks.iter().position(|h| h.name == name) {
            remote.webhooks.remove(index)
        } else {
            if preparation == Preparation::Import {
                return Err(Error::Conflict);
            }
            client
                .webhook::<wire::Webhook>(
                    &expected.name,
                    &wire::Webhook {
                        name: name.into(),
                        id: String::new(),
                        url: url.clone(),
                        kind: kind.into(),
                        secret: None,
                        bearer_token: None,
                        basic_auth: None,
                        disable_tls_client_auth: false,
                        cert_type: "X509".into(),
                    },
                    clock()?,
                )
                .await?
        };
        webhook.matches(name, &url, kind)?;
        let secret = webhook.secret.as_ref().ok_or(Error::Corrupt)?;
        rss_mdm_pki_service::scep::key(secret.as_bytes()).map_err(|_| Error::Corrupt)?;
        // 重放比较原 ID/secret；创建响应丢失只从认证 GET 恢复，不删除重建。
        journal.secret(
            &format!("{phase}-webhook.json"),
            &serde_json::to_vec(&json!({"id":webhook.id,"secret":secret}))
                .map_err(|_| Error::Corrupt)?,
        )?;
        let key_file = journal.secret(&format!("{phase}-webhook.key"), secret.as_bytes())?;
        journal.secret(
            &format!("{phase}-runtime.json"),
            &serde_json::to_vec(&json!({"id":webhook.id,"secret_file":key_file}))
                .map_err(|_| Error::Corrupt)?,
        )?;
    }
    let remote = client
        .get::<wire::Provisioner>(&expected.name, clock()?)
        .await?
        .ok_or(Error::Conflict)?;
    remote.matches(expected)?;
    if remote.webhooks.len() != 2 {
        return Err(Error::Conflict);
    }
    Ok(())
}

#[cfg(test)]
#[path = "../../../../tests/setup/ca_admin.rs"]
mod tests;
