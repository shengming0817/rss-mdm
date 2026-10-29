//! One product fact document, followed exclusively by pure owner projections.
use crate::views::Group;
use crate::*;
use rss_mdm_authorization_service::{Snapshot, context::AuthorizedPrincipal};
use rss_mdm_inventory::{Catalog, CollectionScope};
use rss_mdm_inventory_service::assets::{DeviceSummary, raw_snapshot};
use serde_json::Value;
use std::collections::BTreeMap;

pub(crate) struct Read {
    pub catalog: Catalog,
    pub assets: Vec<DeviceSummary>,
    pub groups: Vec<Group>,
}
#[derive(serde::Deserialize)]
struct Peer {
    kind: String,
    value: String,
    device: String,
}
pub(crate) fn decode_world(
    value: &Value,
    tenant: TenantId,
    ids: &[String],
) -> Result<(identity::World, Catalog, Vec<DeviceSummary>, Vec<Value>)> {
    let catalog = raw_snapshot::catalog(&value["assets"]).map_err(|_| Error::Storage)?;
    let assets = raw_snapshot::decode(
        tenant,
        ids,
        &catalog,
        &CollectionScope::Device,
        value["assets"].clone(),
    )
    .map_err(|_| Error::Storage)?;
    let primary = serde_json::from_value(value["primary"].clone()).map_err(|_| Error::Storage)?;
    let endpoints = identity::endpoint_facts(
        &assets.iter().map(|s| &s.scalars).collect::<Vec<_>>(),
        primary,
    )?;
    let peers: Vec<Peer> =
        serde_json::from_value(value["peers"].clone()).map_err(|_| Error::Storage)?;
    let world = identity::from_snapshot(
        value["watermark"].as_i64().ok_or(Error::Storage)?,
        endpoints,
        serde_json::from_value(value["associations"].clone()).map_err(|_| Error::Storage)?,
        peers
            .into_iter()
            .map(|p| (p.kind, p.value, p.device))
            .collect(),
    )?;
    let rows = serde_json::from_value(value["endpoints"].clone()).map_err(|_| Error::Storage)?;
    Ok((world, catalog, assets, rows))
}
pub(crate) fn decode(
    proof: &AuthorizedPrincipal,
    grant: &Snapshot,
    personnel: rss_identity_postgres::PersonnelRevision,
    value: &Value,
) -> Result<Read> {
    let objects = value["objects"].as_array().ok_or(Error::Storage)?;
    let ids = objects
        .iter()
        .flat_map(|o| o["devices"].as_array().into_iter().flatten())
        .map(|id| id.as_str().map(str::to_owned).ok_or(Error::Storage))
        .collect::<Result<Vec<_>>>()?;
    let tenant = TenantId::parse(proof.tenant_id()).map_err(|_| Error::Storage)?;
    let (world, catalog, assets, mut rows) = decode_world(&value["world"], tenant, &ids)?;
    presentation::project(&catalog, &assets, grant, proof, &mut rows)?;
    let relations = value["relationships"].as_array().ok_or(Error::Storage)?;
    for row in &mut rows {
        let id = row["id"].as_str().ok_or(Error::Storage)?.to_owned();
        let relation = relations
            .iter()
            .find(|r| r["device"] == id)
            .ok_or(Error::Storage)?;
        for key in ["registrationUser", "currentUser"] {
            if relation[key].is_null() {
                continue;
            }
            row[key] = relation[key].clone();
            let user = &row[key]["user"];
            if user.is_null() {
                continue;
            }
            if user["tenantId"] != proof.tenant_id() || user["instanceId"] != proof.instance_id() {
                return Err(Error::Storage);
            }
            let principal = user["principalId"]
                .as_str()
                .ok_or(Error::Storage)?
                .to_owned();
            let profiles = match personnel.profiles {
                rss_identity_postgres::PersonnelProfileScope::None => false,
                rss_identity_postgres::PersonnelProfileScope::All => true,
                rss_identity_postgres::PersonnelProfileScope::SelfOnly => {
                    principal == proof.principal_id()
                }
            };
            if (personnel.logins || profiles)
                && let Some(display) = value["displays"].get(&principal)
            {
                row[key]["display"] = display.clone();
                if !personnel.logins {
                    row[key]["display"]["login"] = Value::Null;
                }
                if !profiles {
                    row[key]["display"]["profiles"] = serde_json::json!([]);
                }
            }
        }
    }
    let mut endpoints = rows
        .into_iter()
        .map(|r| Ok((r["id"].as_str().ok_or(Error::Storage)?.to_owned(), r)))
        .collect::<Result<BTreeMap<_, _>>>()?;
    let mut groups = Vec::new();
    for object in objects {
        let key = object["key"].as_str().ok_or(Error::Storage)?;
        let (reference, association) = if let Some(id) = key.strip_prefix("association:") {
            let id = uuid::Uuid::parse_str(id).map_err(|_| Error::Storage)?;
            let a = world
                .associations
                .iter()
                .find(|a| a.id == id)
                .ok_or(Error::Storage)?;
            (ViewRef::Association(id), Some(world.effective(a.clone())))
        } else {
            (
                ViewRef::Endpoint(key.strip_prefix("endpoint:").ok_or(Error::Storage)?.into()),
                None,
            )
        };
        let mut selected = Vec::new();
        for id in object["devices"].as_array().ok_or(Error::Storage)? {
            let id = id.as_str().ok_or(Error::Storage)?;
            grant.require(
                proof,
                rss_mdm_authorization_service::Permission::InventoryRead,
                Some(id),
            )?;
            selected.push(endpoints.remove(id).ok_or(Error::Storage)?);
        }
        groups.push(Group {
            reference,
            association,
            endpoints: selected,
        });
    }
    Ok(Read {
        catalog,
        assets,
        groups,
    })
}
