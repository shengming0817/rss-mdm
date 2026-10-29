//! Pure endpoint presentation from one composed fact snapshot.
use crate::*;
use rss_mdm_authorization_service::{Permission, Snapshot, context::AuthorizedPrincipal};
use rss_mdm_inventory::{Catalog, Scalar, State as FieldState};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
const FIELDS: [&str; 4] = [
    "device.name",
    "device.network.apple.host_name",
    "device.network.apple.local_host_name",
    "device.serial_number",
];
pub(crate) fn project(
    catalog: &Catalog,
    assets: &[rss_mdm_inventory_service::assets::DeviceSummary],
    snapshot: &Snapshot,
    proof: &AuthorizedPrincipal,
    rows: &mut [Value],
) -> Result<()> {
    let raw = assets
        .iter()
        .map(|d| (d.scalars.device.clone(), &d.scalars))
        .collect::<BTreeMap<_, _>>();
    for endpoint in rows {
        let id = endpoint["id"].as_str().ok_or(Error::Storage)?.to_owned();
        let device = raw.get(&id).ok_or(Error::Storage)?;
        let sensitive = permits(snapshot, proof, Permission::InventorySensitiveRead, &id)?;
        let fields = device
            .fields
            .iter()
            .filter(|(key, _)| {
                catalog.definition(**key).is_ok_and(|d| {
                    d.sensitivity == rss_mdm_inventory::Sensitivity::Standard
                        || (d.sensitivity != rss_mdm_inventory::Sensitivity::Secret && sensitive)
                })
            })
            .map(|(k, v)| (k.as_str(), v))
            .collect::<BTreeMap<_, _>>();
        let names = FIELDS[..3]
            .iter()
            .filter_map(|key| fields.get(key).copied())
            .collect::<Vec<_>>();
        let selected = names
            .iter()
            .copied()
            .find(|f| {
                matches!(&f.state,FieldState::Known(Scalar::String(s)) if !s.trim().is_empty())
                    || matches!(f.state, FieldState::Conflict)
            })
            .or_else(|| names.first().copied());
        if let Some(name) = selected {
            endpoint["displayName"] = serde_json::to_value(name).map_err(|_| Error::Storage)?;
        }
        if let Some(serial) = fields.get("device.serial_number") {
            endpoint["serialNumber"] = serde_json::to_value(serial).map_err(|_| Error::Storage)?;
        }
        let mut platforms = BTreeSet::new();
        for source in endpoint["channels"].as_array().into_iter().flatten().chain(
            endpoint["enrollments"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|v| v["status"] == "pending"),
        ) {
            if let Some(platform) = source["platform"].as_str() {
                platforms.insert(platform.to_owned());
            }
        }
        endpoint["platform"] = json!({"state":if platforms.len()==1{"known"}else if platforms.is_empty(){"unknown"}else{"conflict"},"values":platforms});
        // Registration-user retains its existing enrollment read boundary.
    }
    Ok(())
}
fn permits(
    snapshot: &Snapshot,
    proof: &AuthorizedPrincipal,
    permission: Permission,
    device: &str,
) -> Result<bool> {
    match snapshot.require(proof, permission, permission.device().then_some(device)) {
        Ok(()) => Ok(true),
        Err(rss_mdm_authorization_service::error::AuthorizationError::Forbidden) => Ok(false),
        Err(error) => Err(error.into()),
    }
}
