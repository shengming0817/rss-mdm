//! Durable task-output collection, on the command owner's borrowed transaction.
use rss_mdm_inventory::CollectionProgress;
use rss_observation::Body;
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
    sqlx::query("INSERT INTO mdm_access.collection_runs(tenant_id,id,registration,source,epoch,scope,sequence,started_at,sealed_at,attempts,result,reason,batch,digest,delivery_pending,evidence) VALUES($1::uuid,$2::uuid,$3::uuid,$4,$5::uuid,$6,$7,$8,$8,$9,$10,'complete',$11,$12,true,$13::jsonb)")
                .bind(tenant.to_string()).bind(id.to_string()).bind(registration.to_string()).bind(source.as_str()).bind(epoch).bind(scope.encode().map_err(|_|sqlx::Error::Protocol("invalid scope".into()))?).bind(sequence).bind(now).bind(serde_json::to_string(&quality).expect("closed quality")).bind(result).bind(batch.encode()).bind(digest).bind(serde_json::json!({"task":task,"attempt":attempt}).to_string()).execute(&mut *c).await?;
    crate::wake::notify(c).await?;
    Ok(())
}
