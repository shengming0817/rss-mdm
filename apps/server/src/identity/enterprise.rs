//! Fixed RP backend exchange; Identity owns assertion and token verification.
use super::*;
use rss_identity_core::{
    enterprise::EnterpriseTarget,
    federation::{ClaimMapping, ProviderCredentials, ProviderSettings, ProviderSettingsInput},
};
use rss_mdm_registration_service::{
    Error as BusinessError,
    enterprise::broker::{Client, ExchangeToken, Pending},
};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Configuration {
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
    settings: ProviderSettings,
    credentials: ProviderCredentials,
    transport: rss_identity_oidc::HttpOidc,
    fingerprint: String,
    backend_digest: [u8; 32],
}
impl Backend {
    pub fn load(input: &Configuration, tenant: TenantId) -> Result<Self, Error> {
        Self::load_using(input, tenant, |access| {
            rss_identity_oidc::HttpOidc::new(vec![], access).map_err(|_| invalid())
        })
    }
    fn load_using(
        input: &Configuration,
        tenant: TenantId,
        transport: impl FnOnce(
            Vec<rss_identity_oidc::PrivateProviderAccess>,
        ) -> Result<rss_identity_oidc::HttpOidc, Error>,
    ) -> Result<Self, Error> {
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
        let backend = config::secret(&input.backend_secret_file)?;
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
                config::read(p, 16384, false)
                    .and_then(|v| String::from_utf8(v.to_vec()).map_err(|_| invalid()))
            })
            .transpose()?;
        let credentials =
            ProviderCredentials::new(config::secret(&input.client_secret_file)?.to_string(), ca)
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
        let transport = transport(access)?;
        let fingerprint = format!(
            "{:x}",
            Sha256::digest(
                serde_json::to_vec(&(
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
            settings,
            credentials,
            transport,
            fingerprint,
            backend_digest: Sha256::digest(backend.as_bytes()).into(),
        })
    }
}
#[cfg(all(test, feature = "integration"))]
impl Backend {
    pub fn for_loopback_test(input: &Configuration, tenant: TenantId) -> Result<Self, Error> {
        Self::load_using(input, tenant, |_| {
            rss_identity_oidc::HttpOidc::for_loopback_test(vec![]).map_err(|_| invalid())
        })
    }
}
impl Client for Backend {
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
    ) -> Pending<'a, ExchangeToken> {
        Box::pin(async move {
            let token = tokio::time::timeout(
                Duration::from_secs(8),
                self.transport.exchange_enterprise(
                    rss_identity_oidc::enterprise::EnterpriseExchange {
                        tenant: self.tenant,
                        provider: &self.settings,
                        credentials: &self.credentials,
                        target: &self.target,
                        assertion,
                        assertion_expires_at: expires,
                        expected_subject: subject,
                    },
                ),
            )
            .await
            .map_err(|_| BusinessError::CommitUnknown)?
            .map_err(|_| BusinessError::CommitUnknown)?;
            Ok(ExchangeToken {
                token: Zeroizing::new(token.expose().to_owned()),
                subject: token.subject().to_owned(),
                expires_at: token.expires_at(),
            })
        })
    }
}
