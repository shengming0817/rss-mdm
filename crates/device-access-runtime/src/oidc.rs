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
    http(profiles(assurance)?, private_access(providers)?, policy).map_err(|_| Error::Configuration)
}

pub(crate) fn http(
    profiles: Vec<rss_identity_oidc::TrustedAssuranceProfile>,
    access: Vec<rss_identity_oidc::PrivateProviderAccess>,
    policy: rss_identity_oidc::TransportPolicy,
) -> Result<rss_identity_oidc::HttpOidc, Error> {
    use std::time::Duration;
    let clock = provider_clock();
    let reuse = rss_identity_oidc::ReusePolicy {
        max_providers: 128,
        max_resident_bytes: 8 * 1024 * 1024,
        max_refreshes: 8,
        max_idle_per_host: 2,
        idle_timeout: Duration::from_secs(30),
        discovery_ttl: Duration::from_secs(300),
        jwks_ttl: Duration::from_secs(60),
        refresh_cooldown: Duration::from_secs(5),
    };
    rss_identity_oidc::HttpOidc::new(clock, profiles, access, policy, reuse)
        .map_err(|_| Error::Configuration)
}

pub fn provider_clock() -> rss_identity_oidc::ProviderClock {
    rss_identity_oidc::ProviderClock::new(
        rss_request_context::SharedExecutionTimer::new(
            rss_mdm_audit_integration::budget::RuntimeTimer,
        ),
        rss_mdm_audit_integration::budget::RuntimeTimer::wall_time,
    )
}
