//! Independent channel-state collection on the existing durable report stream.
use super::Attempts;
use crate::{
    Error, Failure,
    database::db,
    device::{self, DevicePrincipal},
};
use rss_mdm_inventory::{AgentInstallation, CollectedValue, ReportSource, Scalar};
use rss_observation::{Batch, Body, Change, Id, Scope};
use sqlx::{PgConnection, Row};
use uuid::Uuid;
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentEvidence {
    pub identity: String,
    pub publisher: Option<String>,
    pub version: Option<String>,
    pub architecture: Option<String>,
}
pub async fn start_in(
    c: &mut PgConnection,
    p: &DevicePrincipal,
    source: ReportSource,
) -> Result<(Uuid, Scope, i64), Error> {
    let live = device::store::revalidate_source(c, p, source).await?;
    let (sequence, _) = device::store::allocate_report_in(
        c,
        &p.tenant().to_string(),
        &p.registration().to_string(),
        source,
        live.epoch().as_str(),
        1,
        i64::from(u32::MAX),
    )
    .await
    .map_err(db)?
    .ok_or(Error::Conflict)?;
    let scope = device::scope_dataset(
        p.tenant(),
        p.registration(),
        source.as_str(),
        Uuid::parse_str(live.epoch().as_str()).map_err(|_| Error::Malformed)?,
        rss_mdm_inventory::builtin::AGENT_INSTALLATION.as_str(),
    )?;
    let id = Uuid::new_v4();
    let at: i64 = sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
        .fetch_one(&mut *c)
        .await
        .map_err(db)?;
    let definition = super::store::freeze_in(
        c,
        &scope,
        1,
        &[rss_mdm_inventory::builtin::AGENT_INSTALLATION],
    )
    .await?;
    let attempt = Attempts::new(definition);
    sqlx::query("INSERT INTO mdm_access.collection_runs(tenant_id,id,registration,source,epoch,scope,sequence,started_at,attempts,result,apple_deadline) VALUES($1::uuid,$2,$3,$4,$5::uuid,$6,$7,$8,$9,'pending',CASE WHEN $4='mdm.apple' THEN clock_timestamp()+interval '5 minutes' END)")
        .bind(p.tenant().to_string()).bind(id).bind(p.registration()).bind(source.as_str()).bind(scope.epoch().as_str()).bind(scope.encode().map_err(|_|Error::Malformed)?).bind(sequence).bind(at).bind(serde_json::to_string(&attempt).map_err(|_|Error::Malformed)?).execute(&mut *c).await.map_err(db)?;
    Ok((id, scope, sequence))
}
pub async fn finish_in(
    c: &mut PgConnection,
    p: &DevicePrincipal,
    id: Uuid,
    source: ReportSource,
    state: AgentInstallation,
    evidence: Option<AgentEvidence>,
) -> Result<Option<rss_mdm_audit_integration::Fact>, Error> {
    let live = device::store::revalidate_source(c, p, source).await?;
    let row=sqlx::query("SELECT scope,sequence,sealed_at,attempts FROM mdm_access.collection_runs WHERE tenant_id=$1::uuid AND id=$2 AND registration=$3 AND source=$4 AND epoch=$5::uuid FOR UPDATE")
        .bind(p.tenant().to_string()).bind(id).bind(p.registration()).bind(source.as_str()).bind(live.epoch().as_str()).fetch_optional(&mut *c).await.map_err(db)?.ok_or(Error::Conflict)?;
    if row
        .try_get::<Option<i64>, _>("sealed_at")
        .map_err(db)?
        .is_some()
    {
        return Ok(None);
    }
    let scope: Scope =
        serde_json::from_str(row.try_get("scope").map_err(db)?).map_err(|_| Error::Malformed)?;
    let at: i64 = sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
        .fetch_one(&mut *c)
        .await
        .map_err(db)?;
    let field = rss_mdm_inventory::builtin::AGENT_INSTALLATION;
    let progress: Attempts =
        serde_json::from_str(row.try_get("attempts").map_err(db)?).map_err(|_| Error::Malformed)?;
    let definition = progress.definition().clone();
    let value = CollectedValue::Value(Scalar::String(state.as_str().into()))
        .encode(definition.field(field).map_err(|_| Error::Malformed)?)
        .map_err(|_| Error::Malformed)?;
    let batch = Batch::new(
        Id::new(id.to_string()).map_err(|_| Error::Malformed)?,
        row.try_get::<i64, _>("sequence")
            .map_err(db)?
            .try_into()
            .map_err(|_| Error::Malformed)?,
        rss_contract::Timepoint::try_from(at).map_err(|_| Error::Malformed)?,
        definition.coverage().map_err(|_| Error::Malformed)?,
        Body::Snapshot(vec![Change::upsert(
            Id::new(field.as_str()).map_err(|_| Error::Malformed)?,
            value,
        )]),
    )
    .map_err(|_| Error::Malformed)?;
    let attempt = Attempts::reported(definition, batch.body(), at).map_err(|_| Error::Malformed)?;
    let batch = rss_mdm_inventory_postgres::seal_collection_in(
        c,
        rss_mdm_inventory_postgres::CollectionCompletion {
            scope: &scope,
            run: &id.to_string(),
            sequence: batch.sequence(),
            observed_at: at,
            progress: &attempt,
        },
    )
    .await
    .map_err(|_| Error::Malformed)?;
    let digest = super::store::fingerprint(&batch, &scope)?;
    sqlx::query("UPDATE mdm_access.collection_runs SET attempts=$3,result='snapshot',reason='complete',batch=$4,digest=$5,sealed_at=$6,delivery_pending=true,evidence=$7::jsonb WHERE tenant_id=$1::uuid AND id=$2")
        .bind(p.tenant().to_string()).bind(id).bind(serde_json::to_string(&attempt).map_err(|_|Error::Malformed)?).bind(batch.encode()).bind(&digest).bind(at).bind(serde_json::to_string(&evidence).map_err(|_|Error::Malformed)?).execute(&mut *c).await.map_err(db)?;
    crate::wake::notify(c).await.map_err(db)?;
    let audit =
        rss_mdm_audit_integration::RequestAudit::new(p.tenant().to_string(), "collection_finish");
    audit.identify_device(p.registration());
    audit.registration(p.registration());
    audit.operation(id, "collection_finish");
    audit.target(p.device());
    let fact = rss_mdm_audit_integration::Fact::business(
        &audit,
        &format!("channel-collection:{id}"),
        digest.as_bytes(),
        200,
        "success",
        None,
    )
    .map_err(|_| Error::Unavailable(Failure::Database))?;
    audit.finalize(None);
    Ok(Some(fact))
}
/// End incomplete collection without turning a timeout into an absence observation.
pub async fn abandon_in(
    c: &mut PgConnection,
    tenant: &str,
    id: Uuid,
    reason: &str,
) -> Result<Option<rss_mdm_audit_integration::Fact>, Error> {
    let at: i64 = sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
        .fetch_one(&mut *c)
        .await
        .map_err(db)?;
    let body:String=sqlx::query_scalar("SELECT attempts FROM mdm_access.collection_runs WHERE tenant_id=$1::uuid AND id=$2 FOR UPDATE").bind(tenant).bind(id).fetch_one(&mut *c).await.map_err(db)?;
    let mut attempt: Attempts = serde_json::from_str(&body).map_err(|_| Error::Malformed)?;
    attempt.finish();
    let registration=sqlx::query_scalar::<_,Uuid>("UPDATE mdm_access.collection_runs SET attempts=$3,result='failed',reason=$4,sealed_at=$5,delivery_pending=false WHERE tenant_id=$1::uuid AND id=$2 AND sealed_at IS NULL RETURNING registration")
        .bind(tenant).bind(id).bind(serde_json::to_string(&attempt).map_err(|_|Error::Malformed)?).bind(reason).bind(at).fetch_optional(&mut *c).await.map_err(db)?;
    let Some(registration) = registration else {
        return Ok(None);
    };
    let audit = rss_mdm_audit_integration::RequestAudit::new(tenant.into(), "collection_finish");
    audit.operation(id, "collection_finish");
    audit.identify_service("service:collection-finalizer");
    audit.registration(registration);
    let details = serde_json::json!({"collectionResult":"failed","reason":reason,"sealedAt":at});
    let fingerprint = serde_json::to_vec(&details).map_err(|_| Error::Malformed)?;
    let fact = rss_mdm_audit_integration::Fact::business(
        &audit,
        &format!("channel-collection:{id}"),
        &fingerprint,
        200,
        "failed",
        None,
    )
    .and_then(|fact| fact.with_details(details))
    .map_err(Error::from);
    audit.finalize(None);
    fact.map(Some)
}
