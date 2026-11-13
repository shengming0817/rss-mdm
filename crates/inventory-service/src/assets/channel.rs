//! Current source registration owns channel facts; connection time and asset age are irrelevant.
use crate::{Error, Failure, database::db};
use rss_mdm_inventory::{ReportSource, Scalar, State};
use rss_request_context::TenantId;
use sqlx::Row;
use uuid::Uuid;

use rss_mdm_inventory::channel::{Current, Observation};
pub async fn detail_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: TenantId,
    device: rss_mdm_agent_wire::DeviceId,
    source: ReportSource,
) -> Result<Observation, Error> {
    Ok(details_in(profile, c, tenant, &[(device, source)])
        .await?
        .remove(&(device, source.as_str().to_owned()))
        .unwrap_or(Observation::Unavailable))
}
/// Resolve a fixed authorized page against current registration and source generations.
pub async fn details_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: TenantId,
    targets: &[(rss_mdm_agent_wire::DeviceId, ReportSource)],
) -> Result<std::collections::BTreeMap<(rss_mdm_agent_wire::DeviceId, String), Observation>, Error>
{
    use std::collections::BTreeMap;
    if targets.len() > 1000 {
        return Err(Error::Malformed);
    }
    if targets.is_empty() {
        return Ok(BTreeMap::new());
    }
    let locks = targets
        .iter()
        .map(|(device, source)| (*device, source.channel()))
        .collect::<Vec<_>>();
    crate::device::store::lock_channels(profile, c, &tenant.to_string(), &locks).await?;
    snapshot_details_in(profile, c, tenant, targets).await
}
/// Resolve the same facts on the caller's consistent snapshot, without acquiring mutation locks.
pub async fn snapshot_details_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: TenantId,
    targets: &[(rss_mdm_agent_wire::DeviceId, ReportSource)],
) -> Result<std::collections::BTreeMap<(rss_mdm_agent_wire::DeviceId, String), Observation>, Error>
{
    use std::collections::BTreeMap;
    if targets.len() > 1000 {
        return Err(Error::Malformed);
    }
    if targets.is_empty() {
        return Ok(BTreeMap::new());
    }
    let ids = targets.iter().map(|t| t.0).collect::<Vec<_>>();
    let sources = targets
        .iter()
        .map(|t| t.1.as_str().to_owned())
        .collect::<Vec<_>>();
    let channels = targets
        .iter()
        .map(|t| t.1.channel().as_str().to_owned())
        .collect::<Vec<_>>();
    let rows: Vec<(Uuid, String, Uuid)> =
        sqlx::query_as(crate::storage_profile::sql(profile).assets_channel_snapshot_details_in_1)
            .bind(tenant.to_string())
            .bind(ids.iter().map(|id| id.into_uuid()).collect::<Vec<_>>())
            .bind(sources)
            .bind(channels)
            .fetch_all(&mut *c)
            .await
            .map_err(db)?;
    let mut by_scope = BTreeMap::new();
    let mut scopes = Vec::new();
    for (device, source, epoch) in rows {
        let device = crate::database::device_id(device).map_err(db)?;
        let source = ReportSource::parse(&source).map_err(|_| Error::Malformed)?;
        let field = match source {
            ReportSource::AgentBuiltin => rss_mdm_inventory::builtin::MDM_ENROLLMENT,
            _ => rss_mdm_inventory::builtin::AGENT_INSTALLATION,
        };
        let scope = crate::device::scope_dataset(
            profile,
            tenant,
            &device,
            source.as_str(),
            epoch,
            field.as_str(),
        )?;
        by_scope.insert(
            scope.encode().map_err(|_| Error::Malformed)?,
            (device, source, field),
        );
        scopes.push(scope);
    }
    let keys = by_scope.keys().cloned().collect::<Vec<_>>();
    let rows =
        sqlx::query(crate::storage_profile::sql(profile).assets_channel_snapshot_details_in_2)
            .bind(tenant.to_string())
            .bind(keys)
            .fetch_all(&mut *c)
            .await
            .map_err(db)?;
    rss_mdm_query_postgres::observe_rows("assets.channel", &rows).map_err(db)?;
    let facts = rss_mdm_inventory_postgres::read_in(
        c,
        tenant,
        &scopes,
        &[
            rss_mdm_inventory::builtin::MDM_ENROLLMENT,
            rss_mdm_inventory::builtin::AGENT_INSTALLATION,
        ],
    )
    .await
    .map_err(|_| Error::Unavailable(Failure::InventoryQuery))?;
    let mut result = BTreeMap::new();
    for latest in rows {
        if !latest.try_get::<bool, _>("within_budget").map_err(db)? {
            return Err(Error::Unavailable(Failure::AssetBytesLimit));
        }
        let Some(scope) = latest.try_get::<Option<String>, _>("scope").map_err(db)? else {
            continue;
        };
        if latest.try_get::<String, _>("result").map_err(db)? != "snapshot" {
            continue;
        }
        let (device, source, field) = *by_scope.get(&scope).ok_or(Error::Malformed)?;
        let id: Uuid = latest.try_get("id").map_err(db)?;
        let attempt: crate::collection::Attempts =
            serde_json::from_str(latest.try_get("attempts").map_err(db)?)
                .map_err(|_| Error::Unavailable(Failure::InventoryQuery))?;
        let received_at = attempt
            .fields()
            .get(&field)
            .and_then(|f| f.received_at)
            .ok_or(Error::Malformed)?;
        let evidence: Option<rss_mdm_inventory::channel::AgentEvidence> = latest
            .try_get::<Option<String>, _>("evidence")
            .map_err(db)?
            .map(|s| {
                let value: serde_json::Value = serde_json::from_str(&s)?;
                // Raw device reports are not server-verified installation evidence.
                if source == ReportSource::AgentBuiltin && value.get("agentReport").is_some() {
                    Ok(None)
                } else {
                    serde_json::from_value(value)
                }
            })
            .transpose()
            .map_err(|_| Error::Malformed)?
            .flatten();
        let fact = facts.scalars.iter().find(|fact| {
            fact.scope == scope
                && fact.field == field
                && fact.fact.evidence.source.as_str() == source.as_str()
                && fact.fact.evidence.snapshot_id == id.to_string()
        });
        let observed = match fact {
            Some(fact) => match &fact.fact.state {
                State::Known(Scalar::String(value)) => Observation::Ready(Current {
                    state: value.clone(),
                    snapshot: id,
                    received_at,
                    evidence,
                }),
                _ => Observation::Unavailable,
            },
            None => Observation::ProjectionPending { evidence },
        };
        result.insert((device, source.as_str().to_owned()), observed);
    }
    Ok(result)
}
