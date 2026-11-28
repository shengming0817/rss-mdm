//! Fixed RP backend exchange; Identity owns assertion and token verification.
use crate::Error;
use rss_request_context::TenantId;
use std::path::PathBuf;
fn invalid() -> Error {
    Error::Configuration
}
use rss_identity_core::{
    enterprise::EnterpriseTarget,
    federation::{ClaimMapping, ProviderCredentials, ProviderSettings, ProviderSettingsInput},
};
use rss_mdm_device_access_postgres::{
    Error as BusinessError,
    enterprise::broker::{Client, ExchangeToken, Pending},
};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Configuration {
    pub tenant: uuid::Uuid,
    pub target: EnterpriseTarget,
    pub provider: uuid::Uuid,
    pub issuer: String,
    pub client_secret_file: PathBuf,
    pub private_ca_file: Option<PathBuf>,
    pub private_cidrs: Vec<String>,
    pub backend_key_id: String,
    pub backend_secret_file: PathBuf,
}
pub struct Backend {
    target: EnterpriseTarget,
    provider: uuid::Uuid,
    tenant: TenantId,
    installed: rss_identity_core::federation::BoundProvider,
    transport: rss_identity_oidc::HttpOidc,
    fingerprint: String,
    backend_digest: [u8; 32],
}
impl Backend {
    pub fn load(
        input: &Configuration,
        instance: rss_identity_core::InstanceId,
        policy: rss_identity_oidc::TransportPolicy,
    ) -> Result<Self, Error> {
        let tenant = TenantId::parse(&input.tenant.to_string()).map_err(|_| invalid())?;
        input.target.validate().map_err(|_| invalid())?;
        if input.provider.is_nil()
            || input.target.scopes.contains("offline_access")
            || input.backend_key_id.is_empty()
            || input.backend_key_id.len() > 128
        {
            return Err(invalid());
        }
        let issuer = url::Url::parse(&input.issuer).map_err(|_| invalid())?;
        if issuer.scheme() != "https" {
            return Err(invalid());
        }
        let backend = rss_mdm_install_support::files::secret(&input.backend_secret_file)
            .map_err(|_| invalid())?;
        if backend.len() < 43
            || backend.len() > 256
            || !backend
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
        {
            return Err(invalid());
        }
        let settings = ProviderSettings::try_from(ProviderSettingsInput {
            issuer: input.issuer.clone(),
            client_id: input.target.client_id.clone(),
            redirect_uri: input.target.issuer.clone(),
            scopes: input.target.scopes.iter().cloned().collect(),
            jit: false,
            claims: ClaimMapping {
                subject: rss_identity_core::entra::SubjectMapping::Oidc,
                profile: Default::default(),
                groups: None,
                department_snapshot: None,
            },
        })
        .map_err(|_| invalid())?;
        let ca = input
            .private_ca_file
            .as_ref()
            .map(|p| {
                rss_mdm_install_support::files::read(p, 16384, false)
                    .map_err(|_| invalid())
                    .and_then(|v| String::from_utf8(v.to_vec()).map_err(|_| invalid()))
            })
            .transpose()?;
        let credentials = ProviderCredentials::new(
            rss_mdm_install_support::files::secret(&input.client_secret_file)
                .map_err(|_| invalid())?
                .to_string(),
            ca,
        )
        .map_err(|_| invalid())?;
        let access = if input.private_cidrs.is_empty() {
            vec![]
        } else {
            vec![rss_identity_oidc::PrivateProviderAccess {
                tenant,
                issuer: input.issuer.clone(),
                client_id: input.target.client_id.clone(),
                cidrs: input
                    .private_cidrs
                    .iter()
                    .map(|s| s.parse().map_err(|_| invalid()))
                    .collect::<Result<_, _>>()?,
            }]
        };
        let transport = crate::oidc::http(vec![], access, policy)?;
        use rss_identity_core::federation::{ProviderId, ProviderRevision, UpstreamOidc};
        // This immutable installation owns its transport and revision registry until shutdown.
        let installed = transport
            .revisions()
            .install(
                ProviderRevision {
                    instance,
                    tenant,
                    provider: ProviderId::parse(&input.provider.to_string())
                        .map_err(|_| invalid())?,
                    version: 1,
                },
                settings,
                credentials,
            )
            .map_err(|_| invalid())?;
        let fingerprint = format!(
            "{:x}",
            Sha256::digest(
                serde_json::to_vec(&(
                    input.tenant,
                    &input.target,
                    input.provider,
                    &input.issuer,
                    &input.private_cidrs,
                    &input.backend_key_id
                ))
                .map_err(|_| invalid())?
            )
        );
        Ok(Self {
            target: input.target.clone(),
            provider: input.provider,
            tenant,
            installed,
            transport,
            fingerprint,
            backend_digest: Sha256::digest(backend.as_bytes()).into(),
        })
    }
}

impl Client for Backend {
    fn tenant(&self) -> TenantId {
        self.tenant
    }
    fn target(&self) -> &EnterpriseTarget {
        &self.target
    }
    fn provider(&self) -> uuid::Uuid {
        self.provider
    }
    fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
    fn authenticate(&self, credential: &str) -> bool {
        credential.len() <= 256
            && bool::from(
                self.backend_digest
                    .ct_eq(&Sha256::digest(credential.as_bytes())),
            )
    }
    fn exchange<'a>(
        &'a self,
        assertion: &'a str,
        expires: i64,
        subject: &'a str,
        deadline: rss_request_context::Deadline,
    ) -> Pending<'a, ExchangeToken> {
        Box::pin(async move {
            let token = self
                .transport
                .exchange_enterprise(
                    rss_identity_oidc::enterprise::EnterpriseExchange {
                        provider: self.installed.clone(),
                        target: &self.target,
                        assertion,
                        assertion_expires_at: expires,
                        expected_subject: subject,
                    },
                    deadline,
                )
                .await
                .map_err(|_| BusinessError::CommitUnknown)?;
            Ok(ExchangeToken {
                token: Zeroizing::new(token.expose().to_owned()),
                subject: token.subject().to_owned(),
                expires_at: token.expires_at(),
            })
        })
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Deployment {
    pub key_id: String,
    pub signing_key_file: PathBuf,
    pub clients: Vec<Configuration>,
    pub administrators: Vec<Administrator>,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Administrator {
    pub configuration: rss_mdm_device_access_postgres::enterprise::keycloak::Configuration,
    pub client_secret_file: PathBuf,
    pub private_ca_file: Option<PathBuf>,
}
