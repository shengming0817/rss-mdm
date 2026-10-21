//! 固定 CA 管理动作；应用宿主仅得到用途 JWK，绝不获得 admin 或离线 root 私钥。
mod client;
pub mod initialize;
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
#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Preparation {
    Create,
    Import,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScepInput {
    pub public_url: String,
    pub certificate_file: PathBuf,
    pub private_key_file: PathBuf,
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
    rebind: Option<&serde_json::Value>,
) -> Result<()> {
    origin(callback_origin)?;
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
        validate_webhook(
            hook,
            &format!("{}{prefix}/{phase}", callback_origin),
            kind,
            rebind.map(|p| &p[phase]),
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
        let mut webhook = if let Some(index) = remote.webhooks.iter().position(|h| h.name == name) {
            remote.webhooks.remove(index)
        } else {
            if preparation == Preparation::Import || rebind.is_some() {
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
        validate_webhook(&webhook, &url, kind, rebind.map(|p| &p[phase]))?;
        if webhook.url != url {
            webhook.url = url.clone();
            webhook = client
                .update_webhook(&expected.name, &webhook, clock()?)
                .await?;
        }
        validate_webhook(&webhook, &url, kind, rebind.map(|p| &p[phase]))?;
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

fn validate_webhook(
    hook: &wire::Webhook,
    url: &str,
    kind: &str,
    previous: Option<&serde_json::Value>,
) -> Result<()> {
    hook.matches(
        &hook.name,
        if previous.is_some() { &hook.url } else { url },
        kind,
    )?;
    if let Some(previous) = previous {
        let secret = crate::config::read(
            std::path::Path::new(previous["secret_file"].as_str().ok_or(Error::Corrupt)?),
            32768,
            true,
        )
        .map_err(|_| Error::Corrupt)?;
        if previous["id"] != hook.id
            || hook
                .secret
                .as_ref()
                .is_none_or(|s| s.as_bytes() != secret.as_slice())
        {
            return Err(Error::Conflict);
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "../../../../tests/setup/ca_admin.rs"]
mod tests;
