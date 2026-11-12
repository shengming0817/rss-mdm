//! Independent channel-state collection on the existing durable report stream.
use super::Attempts;
use crate::{
    Error, Failure,
    database::db,
    device::{self, DevicePrincipal},
};
use rss_mdm_inventory::channel::AgentEvidence;
use rss_mdm_inventory::{AgentInstallation, CollectedValue, ReportSource, Scalar};
use rss_observation::{Batch, Body, Change, Id, Scope};
use sqlx::{PgConnection, Row};
use uuid::Uuid;
pub async fn start_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    p: &DevicePrincipal,
    source: ReportSource,
    catalog_digest: [u8; 32],
) -> Result<(Uuid, Scope, i64), Error> {
    let live = device::store::revalidate_source(profile, c, p, source).await?;
    let (sequence, _) = device::store::allocate_report_in(
        profile,
        c,
        &p.tenant().to_string(),
        p.device(),
        source,
        live.epoch().as_str(),
        1,
        i64::from(u32::MAX),
    )
    .await
    .map_err(db)?
    .ok_or(Error::Conflict)?;
    let scope = device::scope_dataset(
        profile,
        p.tenant(),
        p.device(),
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
        profile,
        c,
        &scope,
        1,
        &[rss_mdm_inventory::builtin::AGENT_INSTALLATION],
    )
    .await?;
    let attempt = Attempts::new(definition);
    sqlx::query(crate::storage_profile::sql(profile).collection_channel_start_in_1)
        .bind(p.tenant().to_string())
        .bind(id)
        .bind(p.device().into_uuid())
        .bind(source.as_str())
        .bind(scope.epoch().as_str())
        .bind(scope.encode().map_err(|_| Error::Malformed)?)
        .bind(sequence)
        .bind(at)
        .bind(serde_json::to_string(&attempt).map_err(|_| Error::Malformed)?)
        .bind(serde_json::json!({"catalogDigest":catalog_digest}))
        .execute(&mut *c)
        .await
        .map_err(db)?;
    Ok((id, scope, sequence))
}
pub async fn finish_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    p: &DevicePrincipal,
    id: Uuid,
    source: ReportSource,
    state: AgentInstallation,
    evidence: Option<AgentEvidence>,
) -> Result<Option<rss_mdm_audit_integration::Fact>, Error> {
    let live = device::store::revalidate_source(profile, c, p, source).await?;
    let row = sqlx::query(crate::storage_profile::sql(profile).collection_channel_finish_in_1)
        .bind(p.tenant().to_string())
        .bind(id)
        .bind(p.device().into_uuid())
        .bind(source.as_str())
        .bind(live.epoch().as_str())
        .fetch_optional(&mut *c)
        .await
        .map_err(db)?
        .ok_or(Error::Conflict)?;
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
            trusted: true,
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
    sqlx::query(crate::storage_profile::sql(profile).collection_channel_finish_in_2)
        .bind(p.tenant().to_string())
        .bind(id)
        .bind(serde_json::to_string(&attempt).map_err(|_| Error::Malformed)?)
        .bind(batch.encode())
        .bind(&digest)
        .bind(at)
        .bind(serde_json::to_string(&evidence).map_err(|_| Error::Malformed)?)
        .execute(&mut *c)
        .await
        .map_err(db)?;
    crate::wake::notify(c).await.map_err(db)?;
    let audit = rss_mdm_audit_integration::RequestAudit::new(
        rss_mdm_audit_integration::Origin::Background,
        profile,
        p.tenant().to_string(),
        "collection_finish",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    audit.identify_device(p.device());
    audit.target_device(p.device());
    audit.owned_operation(
        rss_mdm_audit_integration::operation::OperationOwner::Collection,
        id,
        "collection_finish",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    audit.target_device(p.device());
    let fact = rss_mdm_audit_integration::Fact::business(
        &audit,
        rss_mdm_audit_integration::operation::OperationOwner::Collection,
        &format!("channel-collection:{id}"),
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
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    tenant: &str,
    id: Uuid,
    reason: &str,
) -> Result<Option<rss_mdm_audit_integration::Fact>, Error> {
    let at: i64 = sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
        .fetch_one(&mut *c)
        .await
        .map_err(db)?;
    let body: String =
        sqlx::query_scalar(crate::storage_profile::sql(profile).collection_channel_abandon_in_1)
            .bind(tenant)
            .bind(id)
            .fetch_one(&mut *c)
            .await
            .map_err(db)?;
    let mut attempt: Attempts = serde_json::from_str(&body).map_err(|_| Error::Malformed)?;
    attempt.finish();
    let device = sqlx::query_scalar::<_, Uuid>(
        crate::storage_profile::sql(profile).collection_channel_abandon_in_2,
    )
    .bind(tenant)
    .bind(id)
    .bind(serde_json::to_string(&attempt).map_err(|_| Error::Malformed)?)
    .bind(reason)
    .bind(at)
    .fetch_optional(&mut *c)
    .await
    .map_err(db)?;
    let device = device
        .map(crate::database::device_id)
        .transpose()
        .map_err(db)?;
    let Some(device) = device else {
        return Ok(None);
    };
    let audit = rss_mdm_audit_integration::RequestAudit::new(
        rss_mdm_audit_integration::Origin::Background,
        profile,
        tenant.into(),
        "collection_finish",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    audit.owned_operation(
        rss_mdm_audit_integration::operation::OperationOwner::Collection,
        id,
        "collection_finish",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    audit.identify_service("service:collection-finalizer");
    audit.target_device(&device);
    let details = serde_json::json!({"collectionResult":"failed","reason":reason,"sealedAt":at});

    let fact = rss_mdm_audit_integration::Fact::business(
        &audit,
        rss_mdm_audit_integration::operation::OperationOwner::Collection,
        &format!("channel-collection:{id}"),
        200,
        "failed",
        None,
    )
    .and_then(|fact| fact.with_details(details))
    .map_err(Error::from);
    audit.finalize(None);
    fact.map(Some)
}
