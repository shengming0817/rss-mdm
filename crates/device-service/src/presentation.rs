//! Authorized directory/ detail presentation from the existing canonical owners.
use crate::*;
use rss_mdm_authorization_service::{
    Permission, Snapshot, context::AuthorizedPrincipal, session::SessionAuthority,
};
use rss_mdm_inventory::{Catalog, Platform, Scalar, Sensitivity, State as FieldState};
use rss_mdm_registration_service::{agent::current_user, device::registration_user};
use serde_json::{Value, json};
use sqlx::PgConnection;
use std::collections::{BTreeMap, BTreeSet};
const FIELDS: [&str; 4] = [
    "device.name",
    "device.network.apple.host_name",
    "device.network.apple.local_host_name",
    "device.serial_number",
];
pub(crate) type Bindings = BTreeMap<String, current_user::Binding>;

/// Load only directory scalar fields, in provider-sized batches; hidden fields never enter search.
pub(crate) async fn endpoints(
    c: &mut PgConnection,
    tenant: TenantId,
    watermark: i64,
    snapshot: &Snapshot,
    proof: &AuthorizedPrincipal,
    rows: &mut [Value],
) -> Result<Bindings> {
    let catalog = rss_mdm_inventory_postgres::catalog_at_in(c, tenant, watermark)
        .await
        .map_err(|_| Error::Storage)?;
    let definitions = catalog
        .fields()
        .filter(|d| FIELDS.contains(&d.key.as_str()))
        .cloned()
        .collect();
    let catalog = Catalog::new(definitions).map_err(|_| Error::Storage)?;
    let mut pending = Bindings::new();
    for chunk in rows.chunks_mut(250) {
        let ids = chunk
            .iter()
            .map(|e| e["id"].as_str().map(str::to_owned).ok_or(Error::Storage))
            .collect::<Result<Vec<_>>>()?;
        let reader = rss_mdm_inventory_service::assets::planning::SnapshotReader { tenant };
        let mut sensitive_ids = Vec::new();
        let mut standard_ids = Vec::new();
        let mut owner_ids = Vec::new();
        for id in &ids {
            if permits(snapshot, proof, Permission::InventorySensitiveRead, id)? {
                sensitive_ids.push(id.clone());
            } else {
                standard_ids.push(id.clone());
            }
            if permits(snapshot, proof, Permission::Enrollment, id)? {
                owner_ids.push(id.clone());
            }
        }
        let standard = Catalog::new(
            catalog
                .fields()
                .filter(|d| d.sensitivity == Sensitivity::Standard)
                .cloned()
                .collect(),
        )
        .map_err(|_| Error::Storage)?;
        let mut raw = BTreeMap::new();
        for (ids, catalog) in [(&standard_ids, &standard), (&sensitive_ids, &catalog)] {
            if !ids.is_empty() {
                for device in reader
                    .devices_on(c, watermark, ids, catalog, true)
                    .await
                    .map_err(|_| Error::Storage)?
                {
                    raw.insert(device.device.clone(), device);
                }
            }
        }
        let owners = registration_user::page_on(c, proof.tenant_id(), &owner_ids).await?;
        let bindings = current_user::bindings_on(c, proof.tenant_id(), &sensitive_ids).await?;
        for endpoint in chunk {
            let id = endpoint["id"].as_str().ok_or(Error::Storage)?.to_owned();
            let sensitive = sensitive_ids.contains(&id);
            let device = raw.get(&id).ok_or(Error::Storage)?;
            let fields = device
                .fields
                .iter()
                .filter(|(key, _)| {
                    catalog
                        .definition(**key)
                        .is_ok_and(|d| sensitive || d.sensitivity == Sensitivity::Standard)
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
                endpoint["serialNumber"] =
                    serde_json::to_value(serial).map_err(|_| Error::Storage)?;
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
            if owner_ids.contains(&id) {
                endpoint["registrationUser"] =
                    serde_json::to_value(owners.get(&id).ok_or(Error::Storage)?)
                        .map_err(|_| Error::Storage)?;
            }
        }
        pending.extend(bindings);
    }
    Ok(pending)
}
/// Resolve Identity only after releasing product authorization and asset locks.
pub(crate) async fn current_users(
    rows: &mut [Value],
    bindings: &Bindings,
    sessions: &SessionAuthority,
    cache: &mut BTreeMap<String, rss_mdm_agent_wire::runtime::CurrentUser>,
) -> Result<()> {
    for endpoint in rows {
        let id = endpoint["id"].as_str().ok_or(Error::Storage)?;
        if let Some(binding) = bindings.get(id) {
            let key = crate::cursor::digest(&(&binding.reference, binding.registration_valid))?;
            let mut value = if let Some(value) = cache.get(&key) {
                value.clone()
            } else {
                let value = current_user::resolve(binding, sessions).await?;
                cache.insert(key, value.clone());
                value
            };
            value.revision = binding.revision;
            value.confirmed_at = binding.confirmed_at;
            endpoint["currentUser"] = serde_json::to_value(value).map_err(|_| Error::Storage)?;
        }
    }
    Ok(())
}
fn scalar_matches(field: &Value, search: &str) -> bool {
    let matches = |state: &Value| {
        state["kind"] == "known"
            && state["value"]["kind"] == "string"
            && state["value"]["value"]
                .as_str()
                .is_some_and(|s| s.to_lowercase().contains(search))
    };
    matches(&field["state"])
        || (field["state"]["kind"] == "conflict"
            && field["sources"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|f| matches(&f["state"])))
}
pub(crate) fn matches(endpoint: &Value, search: Option<&str>, platform: Option<Platform>) -> bool {
    if let Some(platform) = platform {
        let platform = match platform {
            Platform::Windows => "windows",
            Platform::Macos => "macos",
        };
        if !endpoint["platform"]["values"]
            .as_array()
            .is_some_and(|values| values.iter().any(|v| v == platform))
        {
            return false;
        }
    }
    search.is_none_or(|search| {
        let search = search.trim().to_lowercase();
        scalar_matches(&endpoint["displayName"], &search)
            || scalar_matches(&endpoint["serialNumber"], &search)
            || ["registrationUser", "currentUser"].iter().any(|key| {
                endpoint[*key]["user"]["principalId"]
                    .as_str()
                    .is_some_and(|s| s.to_lowercase().contains(&search))
            })
    })
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
