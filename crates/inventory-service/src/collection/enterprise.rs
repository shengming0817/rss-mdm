//! Durable task-output collection, on the command owner's borrowed transaction.
use rss_mdm_inventory::{CollectionDefinition, CollectionProgress};
use rss_observation::Body;
use sqlx::Row;
use uuid::Uuid;
pub struct Report {
    pub registration: Uuid,
    pub task: Uuid,
    pub attempt: Uuid,
    pub progress: CollectionProgress,
    pub now: i64,
}
pub async fn accept_in(
    c: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
    report: Report,
) -> Result<(), sqlx::Error> {
    let Report {
        registration,
        task,
        attempt,
        progress,
        now,
    } = report;
    let definition = progress.definition();
    let body = progress
        .body()
        .map_err(|_| sqlx::Error::Protocol("invalid collection progress".into()))?
        .ok_or_else(|| sqlx::Error::Protocol("unattempted task report".into()))?;
    let source = definition.source();
    if !matches!(
        source,
        rss_mdm_inventory::Source::AgentScript | rss_mdm_inventory::Source::AgentOsquery
    ) {
        return Err(sqlx::Error::Protocol(
            "invalid task collector source".into(),
        ));
    }
    rss_mdm_inventory_postgres::register_collection_in(c, tenant, &definition)
        .await
        .map_err(|_| sqlx::Error::Protocol("invalid task collector".into()))?;
    let row = sqlx::query("SELECT scope,sequence,attempts,sealed_at,evidence FROM mdm_access.collection_runs WHERE tenant_id=$1::uuid AND id=$2 AND registration=$3 FOR UPDATE")
        .bind(tenant.to_string()).bind(attempt).bind(registration).fetch_one(&mut *c).await?;
    let frozen: CollectionProgress = serde_json::from_str(row.try_get("attempts")?)
        .map_err(|_| sqlx::Error::Protocol("invalid reserved collection".into()))?;
    if frozen.definition() != definition
        || row.try_get::<serde_json::Value, _>("evidence")?["task"] != serde_json::json!(task)
    {
        return Err(sqlx::Error::Protocol(
            "collection reservation mismatch".into(),
        ));
    }
    // Cancellation/revocation already sealed this attempt. Late transport evidence cannot reopen it.
    if row.try_get::<Option<i64>, _>("sealed_at")?.is_some() {
        return Ok(());
    }
    let scope: rss_observation::Scope = serde_json::from_str(row.try_get("scope")?)
        .map_err(|_| sqlx::Error::Protocol("invalid reserved scope".into()))?;
    let sequence: i64 = row.try_get("sequence")?;
    let id = attempt;
    let result = match &body {
        Body::Snapshot(_) => "snapshot",
        Body::Partial(_) => "partial",
        Body::Failed { .. } => "failed",
        _ => {
            return Err(sqlx::Error::Protocol(
                "task collection requires a fresh result".into(),
            ));
        }
    };
    let batch = rss_mdm_inventory_postgres::seal_collection_in(
        c,
        rss_mdm_inventory_postgres::CollectionCompletion {
            scope: &scope,
            run: &id.to_string(),
            sequence: sequence as u64,
            observed_at: now,
            progress: &progress,
        },
    )
    .await
    .map_err(|_| sqlx::Error::Protocol("collection completion rejected".into()))?;
    let digest = batch
        .fingerprint(&scope)
        .map_err(|_| sqlx::Error::Protocol("invalid fingerprint".into()))?
        .iter()
        .map(|v| format!("{v:02x}"))
        .collect::<String>();
    let quality = progress;
    sqlx::query("UPDATE mdm_access.collection_runs SET sealed_at=$3,attempts=$4,result=$5,reason='complete',batch=$6,digest=$7,delivery_pending=true WHERE tenant_id=$1::uuid AND id=$2 AND sealed_at IS NULL")
        .bind(tenant.to_string()).bind(id).bind(now).bind(serde_json::to_string(&quality).expect("closed quality"))
        .bind(result).bind(batch.encode()).bind(digest).execute(&mut *c).await?;
    crate::wake::notify(c).await?;
    Ok(())
}

/// Reserve result identity, source epoch and ordering before an Offer leaves the transaction.
pub async fn start_in(
    c: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
    registration: Uuid,
    task: Uuid,
    attempt: Uuid,
    definition: CollectionDefinition,
    now: i64,
) -> Result<(), sqlx::Error> {
    let source = definition.source();
    rss_mdm_inventory_postgres::register_collection_in(c, tenant, &definition)
        .await
        .map_err(|_| sqlx::Error::Protocol("invalid task collector".into()))?;
    let (epoch, sequence) =
        crate::device::store::allocate_task_report_in(c, &tenant.to_string(), registration, source)
            .await?;
    let encode_error = |_| sqlx::Error::Protocol("invalid enterprise collection".into());
    let scope = crate::device::scope_dataset(
        tenant,
        registration,
        source.as_str(),
        Uuid::parse_str(&epoch).map_err(|_| sqlx::Error::Protocol("invalid epoch".into()))?,
        definition.dataset(),
    )
    .map_err(encode_error)?;
    let progress = CollectionProgress::new(definition);
    sqlx::query("INSERT INTO mdm_access.collection_runs(tenant_id,id,registration,source,epoch,scope,sequence,started_at,attempts,result,evidence) VALUES($1::uuid,$2,$3,$4,$5::uuid,$6,$7,$8,$9,'pending',$10)")
        .bind(tenant.to_string()).bind(attempt).bind(registration).bind(source.as_str()).bind(epoch)
        .bind(scope.encode().map_err(|_| sqlx::Error::Protocol("invalid scope".into()))?).bind(sequence).bind(now)
        .bind(serde_json::to_string(&progress).expect("closed progress"))
        .bind(serde_json::json!({"task":task,"attempt":attempt})).execute(c).await?;
    Ok(())
}
