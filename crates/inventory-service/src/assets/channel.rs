//! Current source registration owns channel facts; connection time and asset age are irrelevant.
use crate::{Error, Failure, database::db};
use rss_mdm_inventory::{FieldKey, ReportSource, Scalar, State};
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

pub async fn current_in(
    c: &mut sqlx::PgConnection,
    tenant: TenantId,
    registration: Uuid,
    generation: i64,
    source: ReportSource,
) -> Result<Option<String>, Error> {
    Ok(detail_in(c, tenant, registration, generation, source)
        .await?
        .map(|v| v.state))
}

pub async fn detail_in(
    c: &mut sqlx::PgConnection,
    tenant: TenantId,
    registration: Uuid,
    generation: i64,
    source: ReportSource,
) -> Result<Option<Current>, Error> {
    let device: Option<String> = sqlx::query_scalar("SELECT device FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND id=$2 AND generation=$3")
        .bind(tenant.to_string()).bind(registration).bind(generation).fetch_optional(&mut *c).await.map_err(db)?;
    let Some(device) = device else {
        return Ok(None);
    };
    crate::device::store::lock_channel(c, &tenant.to_string(), &device, source.channel()).await?;
    let epoch: Option<Uuid> = sqlx::query_scalar("SELECT s.epoch FROM mdm_access.report_sources s JOIN mdm_access.registrations r ON(r.tenant_id,r.id)=(s.tenant_id,s.registration) WHERE r.tenant_id=$1::uuid AND r.id=$2 AND r.generation=$3 AND r.state='active' AND r.channel=$4 AND s.source=$5 AND s.enabled")
        .bind(tenant.to_string()).bind(registration).bind(generation).bind(source.channel().as_str()).bind(source.as_str())
        .fetch_optional(&mut *c).await.map_err(db)?;
    let Some(epoch) = epoch else {
        return Ok(None);
    };
    let field = match source {
        ReportSource::AgentBuiltin => FieldKey::MdmEnrollment,
        _ => FieldKey::AgentInstallation,
    };
    let scope =
        crate::device::scope_dataset(tenant, registration, source.as_str(), epoch, field.as_str())?;
    let latest=sqlx::query("SELECT id,result,attempts FROM mdm_access.collection_runs WHERE tenant_id=$1::uuid AND registration=$2 AND source=$3 AND epoch=$4 AND scope=$5 AND sealed_at IS NOT NULL ORDER BY sequence DESC LIMIT 1")
        .bind(tenant.to_string()).bind(registration).bind(source.as_str()).bind(epoch).bind(scope.encode().map_err(|_|Error::Malformed)?)
        .fetch_optional(&mut *c).await.map_err(db)?;
    let Some(latest) = latest else {
        return Ok(None);
    };
    if latest.try_get::<String, _>("result").map_err(db)? != "snapshot" {
        return Ok(None);
    }
    let id: Uuid = latest.try_get("id").map_err(db)?;
    let attempt: crate::collection::ChannelAttempt =
        serde_json::from_str(latest.try_get("attempts").map_err(db)?)
            .map_err(|_| Error::Unavailable(Failure::InventoryQuery))?;
    let facts = rss_mdm_inventory_postgres::read_in(c, tenant, &[scope])
        .await
        .map_err(|_| Error::Unavailable(Failure::InventoryQuery))?;
    Ok(facts.into_iter().find_map(|fact| {
        if fact.field != field
            || fact.fact.evidence.source.as_str() != source.as_str()
            || fact.fact.evidence.snapshot_id != id.to_string()
        {
            return None;
        }
        match fact.fact.state {
            State::Known(Scalar::String(value)) => Some(Current {
                state: value,
                snapshot: id,
                received_at: attempt.received_at,
                evidence: attempt.evidence.clone(),
            }),
            _ => None,
        }
    }))
}
