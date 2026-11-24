//! Host-owned OIDC assurance and network settings shared by embedded and standalone DA.
use super::Error;
use rss_request_context::TenantId;
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssuranceProfile {
    pub tenant_id: String,
    pub issuer: String,
    pub client_id: String,
    pub keycloak_totp: bool,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateProvider {
    pub tenant_id: String,
    pub issuer: String,
    pub client_id: String,
    pub cidrs: Vec<String>,
}
pub fn private_access(
    providers: &[PrivateProvider],
) -> Result<Vec<rss_identity_oidc::PrivateProviderAccess>, Error> {
    providers
        .iter()
        .map(|p| {
            let owner = TenantId::parse(&p.tenant_id).map_err(|_| Error::Configuration)?;
            Ok(rss_identity_oidc::PrivateProviderAccess {
                tenant: owner,
                issuer: p.issuer.clone(),
                client_id: p.client_id.clone(),
                cidrs: p
                    .cidrs
                    .iter()
                    .map(|s| s.parse().map_err(|_| Error::Configuration))
                    .collect::<Result<_, _>>()?,
            })
        })
        .collect()
}
fn profiles(
    profiles: &[AssuranceProfile],
) -> Result<Vec<rss_identity_oidc::TrustedAssuranceProfile>, Error> {
    profiles
        .iter()
        .map(|p| {
            Ok(rss_identity_oidc::TrustedAssuranceProfile {
                tenant: TenantId::parse(&p.tenant_id).map_err(|_| Error::Configuration)?,
                issuer: p.issuer.clone(),
                client_id: p.client_id.clone(),
                keycloak_totp: p.keycloak_totp,
            })
        })
        .collect::<Result<Vec<_>, Error>>()
}
pub fn transport(
    assurance: &[AssuranceProfile],
    providers: &[PrivateProvider],
    policy: rss_identity_oidc::TransportPolicy,
) -> Result<rss_identity_oidc::HttpOidc, Error> {
    rss_identity_oidc::HttpOidc::new(profiles(assurance)?, private_access(providers)?, policy)
        .map_err(|_| Error::Configuration)
}
