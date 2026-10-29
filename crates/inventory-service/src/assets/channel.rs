//! Current source registration owns channel facts; connection time and asset age are irrelevant.
use crate::{Error, Failure, database::db};
use rss_mdm_inventory::{ReportSource, Scalar, State};
use rss_request_context::TenantId;
use sqlx::Row;
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct Current {
    pub state: String,
    pub snapshot: Uuid,
    pub received_at: i64,
    pub evidence: Option<crate::collection::channel::AgentEvidence>,
}

/// Observation readiness is distinct from a negative or unknown channel fact.
#[derive(Clone, Debug)]
pub enum Observation {
    Ready(Current),
    ProjectionPending {
        evidence: Option<crate::collection::channel::AgentEvidence>,
    },
    Unavailable,
}

pub async fn detail_in(
    c: &mut sqlx::PgConnection,
    tenant: TenantId,
    registration: Uuid,
    generation: i64,
    source: ReportSource,
) -> Result<Observation, Error> {
    Ok(details_in(c, tenant, &[(registration, generation, source)])
        .await?
        .remove(&(registration, generation, source.as_str().to_owned()))
        .unwrap_or(Observation::Unavailable))
}
/// Resolve a fixed authorized page against current registration and source generations.
pub async fn details_in(
    c: &mut sqlx::PgConnection,
    tenant: TenantId,
    targets: &[(Uuid, i64, ReportSource)],
) -> Result<std::collections::BTreeMap<(Uuid, i64, String), Observation>, Error> {
    use std::collections::BTreeMap;
    if targets.len() > 1000 {
        return Err(Error::Malformed);
    }
    if targets.is_empty() {
        return Ok(BTreeMap::new());
    }
    let ids = targets.iter().map(|t| t.0).collect::<Vec<_>>();
    let devices: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT id,device FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND id=ANY($2)",
    )
    .bind(tenant.to_string())
    .bind(&ids)
    .fetch_all(&mut *c)
    .await
    .map_err(db)?;
    let devices = devices.into_iter().collect::<BTreeMap<_, _>>();
    let locks = targets
        .iter()
        .filter_map(|(id, _, source)| devices.get(id).map(|d| (d.clone(), source.channel())))
        .collect::<Vec<_>>();
    crate::device::store::lock_channels(c, &tenant.to_string(), &locks).await?;
    snapshot_details_in(c, tenant, targets).await
}
/// Resolve the same facts on the caller's consistent snapshot, without acquiring mutation locks.
pub async fn snapshot_details_in(
    c: &mut sqlx::PgConnection,
    tenant: TenantId,
    targets: &[(Uuid, i64, ReportSource)],
) -> Result<std::collections::BTreeMap<(Uuid, i64, String), Observation>, Error> {
    use std::collections::BTreeMap;
    if targets.len() > 1000 {
        return Err(Error::Malformed);
    }
    if targets.is_empty() {
        return Ok(BTreeMap::new());
    }
    let ids = targets.iter().map(|t| t.0).collect::<Vec<_>>();
    let generations = targets.iter().map(|t| t.1).collect::<Vec<_>>();
    let sources = targets
        .iter()
        .map(|t| t.2.as_str().to_owned())
        .collect::<Vec<_>>();
    let channels = targets
        .iter()
        .map(|t| t.2.channel().as_str().to_owned())
        .collect::<Vec<_>>();
    let rows:Vec<(Uuid,i64,String,Uuid)>=sqlx::query_as("SELECT r.id,r.generation,s.source,s.epoch FROM unnest($2::uuid[],$3::bigint[],$4::text[],$5::text[]) t(id,generation,source,channel) JOIN mdm_access.registrations r ON r.tenant_id=$1::uuid AND r.id=t.id AND r.generation=t.generation AND r.channel=t.channel AND r.state='active' JOIN mdm_access.report_sources s ON s.tenant_id=r.tenant_id AND s.registration=r.id AND s.source=t.source AND s.enabled").bind(tenant.to_string()).bind(ids).bind(generations).bind(sources).bind(channels).fetch_all(&mut *c).await.map_err(db)?;
    let mut by_scope = BTreeMap::new();
    let mut scopes = Vec::new();
    for (registration, generation, source, epoch) in rows {
        let source = ReportSource::parse(&source).map_err(|_| Error::Malformed)?;
        let field = match source {
            ReportSource::AgentBuiltin => rss_mdm_inventory::builtin::MDM_ENROLLMENT,
            _ => rss_mdm_inventory::builtin::AGENT_INSTALLATION,
        };
        let scope = crate::device::scope_dataset(
            tenant,
            registration,
            source.as_str(),
            epoch,
            field.as_str(),
        )?;
        by_scope.insert(
            scope.encode().map_err(|_| Error::Malformed)?,
            (registration, generation, source, field),
        );
        scopes.push(scope);
    }
    let keys = by_scope.keys().cloned().collect::<Vec<_>>();
    let rows=sqlx::query("WITH selected AS MATERIALIZED(SELECT DISTINCT ON(scope) scope,id,result,attempts,evidence::text AS evidence FROM mdm_access.collection_runs WHERE tenant_id=$1::uuid AND scope=ANY($2) AND sealed_at IS NOT NULL ORDER BY scope,sequence DESC),budget AS(SELECT coalesce(sum(pg_column_size(selected)),0)<=16777216 AS ok FROM selected) SELECT selected.*,budget.ok AS within_budget FROM budget LEFT JOIN selected ON budget.ok").bind(tenant.to_string()).bind(keys).fetch_all(&mut *c).await.map_err(db)?;
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
        let (registration, generation, source, field) =
            *by_scope.get(&scope).ok_or(Error::Malformed)?;
        let id: Uuid = latest.try_get("id").map_err(db)?;
        let attempt: crate::collection::Attempts =
            serde_json::from_str(latest.try_get("attempts").map_err(db)?)
                .map_err(|_| Error::Unavailable(Failure::InventoryQuery))?;
        let received_at = attempt
            .fields()
            .get(&field)
            .and_then(|f| f.received_at)
            .ok_or(Error::Malformed)?;
        let evidence: Option<crate::collection::channel::AgentEvidence> = latest
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
        result.insert(
            (registration, generation, source.as_str().to_owned()),
            observed,
        );
    }
    Ok(result)
}
