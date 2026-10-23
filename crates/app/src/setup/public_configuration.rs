//! Static browser entry coordinates. The installation registry remains their authority.
//! ref: serde serde_core/src/ser/mod.rs@v1.0.228.
use super::{Error, Result};
use rss_identity_core::InstanceId;
use serde::Serialize;
use uuid::Uuid;

#[derive(Serialize)]
pub struct Inputs {
    #[serde(rename = "ui.json")]
    pub identity: IdentityConfig,
    #[serde(rename = "mdm.json")]
    pub mdm: MdmConfig,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityConfig {
    canonical_origin: String,
    oidc_enabled: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MdmConfig {
    service_id: Uuid,
    canonical_origin: String,
    tenant: Uuid,
    management_tenant: Uuid,
}

/// Read public locators only, without authenticating a browser or disclosing runtime inputs.
pub async fn read(config: &crate::config::Config) -> Result<Inputs> {
    let instance = InstanceId::parse(&config.identity.instance_id).map_err(|_| Error::Input)?;
    let management = crate::identity::management_tenant(&config.identity.database, instance)
        .await
        .map_err(|_| Error::Storage)?;
    project(
        &config.product_origin,
        config.identity.oidc.is_some(),
        &config.identity.tenant_id,
        &management.to_string(),
        &config.identity.instance_id,
    )
}

fn project(
    origin: &str,
    oidc_enabled: bool,
    tenant: &str,
    management: &str,
    service: &str,
) -> Result<Inputs> {
    let url = url::Url::parse(origin).map_err(|_| Error::Input)?;
    let canonical_uuid = |value: &str| {
        Uuid::parse_str(value)
            .ok()
            .filter(|id| !id.is_nil() && id.to_string() == value)
            .ok_or(Error::Input)
    };
    let tenant = canonical_uuid(tenant)?;
    let management_tenant = canonical_uuid(management)?;
    if tenant == management_tenant
        || url.scheme() != "https"
        || url.origin().ascii_serialization() != origin
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(Error::Input);
    }
    Ok(Inputs {
        identity: IdentityConfig {
            canonical_origin: origin.into(),
            oidc_enabled,
        },
        mdm: MdmConfig {
            service_id: canonical_uuid(service)?,
            canonical_origin: origin.into(),
            tenant,
            management_tenant,
        },
    })
}

#[cfg(test)]
#[path = "../../tests/setup/public_configuration.rs"]
mod tests;
