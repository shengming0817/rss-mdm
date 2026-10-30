//! 固定 linkedca v0.25 Provisioner 子集；敏感回执不实现 Debug。
use crate::installation::{Error, Result};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Provisioner {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub authority_id: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub name: String,
    pub details: Details,
    #[serde(default)]
    pub claims: Claims,
    #[serde(default)]
    pub x509_template: Template,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_template: Option<Template>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub webhooks: Vec<Webhook>,
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Details {
    #[serde(rename = "JWK", default, skip_serializing_if = "Option::is_none")]
    pub jwk: Option<Jwk>,
    #[serde(rename = "SCEP", default, skip_serializing_if = "Option::is_none")]
    pub scep: Option<Scep>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Jwk {
    pub public_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_private_key: Option<Zeroizing<String>>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Scep {
    #[serde(default)]
    pub force_cn: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub challenge: String,
    #[serde(default)]
    pub capabilities: Vec<String>,
    pub minimum_public_key_length: i32,
    #[serde(default)]
    pub include_root: bool,
    pub encryption_algorithm_identifier: i32,
    pub decrypter: Decrypter,
    #[serde(default)]
    pub exclude_intermediate: bool,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Decrypter {
    pub certificate: String,
    pub key: Zeroizing<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub key_uri: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_password: Option<Zeroizing<String>>,
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Claims {
    #[serde(default)]
    pub x509: X509Claims,
    #[serde(default)]
    pub ssh: SshClaims,
    #[serde(default)]
    pub disable_renewal: bool,
    #[serde(default)]
    pub allow_renewal_after_expiry: bool,
    #[serde(default)]
    pub disable_smallstep_extensions: bool,
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct X509Claims {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub durations: Durations,
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct SshClaims {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub user_durations: Durations,
    #[serde(default)]
    pub host_durations: Durations,
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Durations {
    #[serde(default)]
    pub default: String,
    #[serde(default)]
    pub min: String,
    #[serde(default)]
    pub max: String,
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Template {
    #[serde(default)]
    pub template: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub data: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Webhook {
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub id: String,
    pub url: String,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<Zeroizing<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bearer_token: Option<Bearer>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub basic_auth: Option<Basic>,
    #[serde(default)]
    pub disable_tls_client_auth: bool,
    #[serde(default)]
    pub cert_type: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Bearer {
    pub bearer_token: Zeroizing<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Basic {
    pub username: String,
    pub password: Zeroizing<String>,
}
impl Provisioner {
    pub fn matches(&self, expected: &Self) -> Result<()> {
        // 只排除服务器分配的身份/时间和独立核对的 webhook；其余安全配置必须精确一致。
        if (expected.kind == "JWK" && !self.webhooks.is_empty())
            // step-ca v0.30.2 encodes an active database record's zero time in readback.
            || self
                .deleted_at
                .as_deref()
                .is_some_and(|time| time != "0001-01-01T00:00:00Z")
            || self.kind != expected.kind
            || self.name != expected.name
            || self.policy.is_some()
            || self
                .ssh_template
                .as_ref()
                .is_some_and(|t| !t.template.is_empty() || !t.data.is_empty())
        {
            return Err(Error::Conflict);
        }
        use base64::Engine;
        if let (Some(actual), Some(expected)) = (&self.details.jwk, &expected.details.jwk) {
            if actual
                .encrypted_private_key
                .as_ref()
                .is_some_and(|v| !v.is_empty())
                || self.details.scep.is_some()
            {
                return Err(Error::Conflict);
            }
            let public = |v: &str| -> Result<serde_json::Value> {
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(v)
                    .map_err(|_| Error::Input)?;
                if bytes.len() > 32768 {
                    return Err(Error::Input);
                }
                serde_json::from_slice(&bytes).map_err(|_| Error::Input)
            };
            if public(&actual.public_key)? != public(&expected.public_key)? {
                return Err(Error::Conflict);
            }
        } else {
            let a = Zeroizing::new(serde_json::to_vec(&self.details).map_err(|_| Error::Corrupt)?);
            let b =
                Zeroizing::new(serde_json::to_vec(&expected.details).map_err(|_| Error::Corrupt)?);
            if a.as_slice() != b.as_slice() {
                return Err(Error::Conflict);
            }
        }
        let canonical = |v: &Self| -> Result<Zeroizing<Vec<u8>>> {
            serde_json::to_vec(&(&v.claims, &v.x509_template))
                .map(Zeroizing::new)
                .map_err(|_| Error::Corrupt)
        };
        if canonical(self)?.as_slice() != canonical(expected)?.as_slice() {
            return Err(Error::Conflict);
        }
        Ok(())
    }
}
impl Webhook {
    pub fn matches(&self, name: &str, url: &str, kind: &str) -> Result<()> {
        if self.name != name
            || self.url != url
            || self.kind != kind
            || self.id.is_empty()
            || self.id.len() > 128
            || self
                .secret
                .as_ref()
                .is_none_or(|s| s.is_empty() || s.len() > 4096)
            || self.bearer_token.is_some()
            || self.basic_auth.is_some()
            || self.disable_tls_client_auth
            || self.cert_type != "X509"
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }
}
