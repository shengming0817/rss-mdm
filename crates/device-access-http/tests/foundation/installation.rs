use super::*;
use rss_mdm_device_access_runtime::installation::{Composition, Standalone};
pub fn units() -> Vec<rss_mdm_install_support::Unit> {
    rss_mdm_device_access_runtime::installation::standalone_units(false)
}
pub fn host(
    inputs: &Inputs,
    tenant: rss_request_context::TenantId,
    management: Uuid,
) -> Result<Standalone> {
    Ok(Standalone {
        product: Composition {
            instance: Uuid::parse_str(&inputs.installation.instance_id)?,
            management_tenant: management,
        },
        target: inputs.installation.target,
        lineage: inputs.installation.lineage,
        tenants: vec![
            (tenant, 1),
            (
                rss_request_context::TenantId::parse(&management.to_string())?,
                rss_mdm_authorization_service::tenancy::MANAGEMENT_EPOCH,
            ),
        ],
        ledger: false,
    })
}
