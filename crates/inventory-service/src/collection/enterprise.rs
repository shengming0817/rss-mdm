//! Durable task-output collection, on the command owner's borrowed transaction.
use rss_mdm_inventory::{CollectionDefinition, CollectionProgress};
use rss_observation::Body;
use sqlx::Row;
use uuid::Uuid;
pub struct Report {
    pub device: String,
    pub task: Uuid,
    pub attempt: Uuid,
    pub progress: CollectionProgress,
    pub now: i64,
    pub observed_at: i64,
    pub project: bool,
    pub trusted: bool,
}
pub async fn accept_in(
    c: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
    report: Report,
) -> Result<(), sqlx::Error> {
    let Report {
        device: registration,
        task,
        attempt,
        progress,
        now,
        observed_at,
        project,
        trusted,
    } = report;
    let definition = progress.definition();
    let body = progress
        .body()
        .map_err(|_| sqlx::Error::Protocol("invalid collection progress".into()))?
        .ok_or_else(|| sqlx::Error::Protocol("unattempted task report".into()))?;
    let source = definition.source();
    if !matches!(
        source,
        rss_mdm_inventory::Source::AgentScript
            | rss_mdm_inventory::Source::AgentOsquery
            | rss_mdm_inventory::Source::AgentNative
    ) {
        return Err(sqlx::Error::Protocol(
            "invalid task collector source".into(),
        ));
    }
    rss_mdm_inventory_postgres::register_collection_in(c, tenant, definition)
        .await
        .map_err(|_| sqlx::Error::Protocol("invalid task collector".into()))?;
    let row = sqlx::query("SELECT scope, sequence, attempts, sealed_at, reason, batch, evidence FROM mdm_access.collection_runs WHERE tenant_id = CAST($1 AS uuid) AND id = $2 AND device = $3 FOR UPDATE")
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
    // A transport timeout without device evidence is not an immutable result. The command
    // owner proves original-attempt timing and independently decides current applicability.
    // Never replace published evidence or reopen cancellation/revocation.
    let late_timeout = trusted
        && row.try_get::<Option<&str>, _>("reason")? == Some("timeout")
        && row.try_get::<Option<Vec<u8>>, _>("batch")?.is_none();
    if row.try_get::<Option<i64>, _>("sealed_at")?.is_some() && !late_timeout {
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
            trusted,
            scope: &scope,
            run: &id.to_string(),
            sequence: sequence as u64,
            observed_at,
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
    sqlx::query("UPDATE mdm_access.collection_runs SET sealed_at=$3,attempts=$4,result=$5,reason='complete',batch=$6,digest=$7,delivery_pending=$8 WHERE tenant_id=$1::uuid AND id=$2 AND (sealed_at IS NULL OR (reason='timeout' AND batch IS NULL))")
        .bind(tenant.to_string()).bind(id).bind(now).bind(serde_json::to_string(&quality).expect("closed quality"))
        .bind(result).bind(batch.encode()).bind(digest).bind(project).execute(&mut *c).await?;
    crate::wake::notify(c).await?;
    Ok(())
}

/// Reserve result identity, source epoch and ordering before an Offer leaves the transaction.
pub async fn start_in(
    c: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
    registration: String,
    task: Uuid,
    attempt: Uuid,
    definition: CollectionDefinition,
    now: i64,
) -> Result<(), sqlx::Error> {
    let source = definition.source();
    rss_mdm_inventory_postgres::register_collection_in(c, tenant, &definition)
        .await
        .map_err(|_| sqlx::Error::Protocol("invalid task collector".into()))?;
    let (epoch, sequence) = crate::device::store::allocate_task_report_in(
        rss_mdm_install_support::StorageProfile::Mdm,
        c,
        &tenant.to_string(),
        &registration,
        source,
    )
    .await?;
    let encode_error = |_| sqlx::Error::Protocol("invalid enterprise collection".into());
    let scope = crate::device::scope_dataset(
        rss_mdm_install_support::StorageProfile::Mdm,
        tenant,
        &registration,
        source.as_str(),
        Uuid::parse_str(&epoch).map_err(|_| sqlx::Error::Protocol("invalid epoch".into()))?,
        definition.dataset(),
    )
    .map_err(encode_error)?;
    let progress = CollectionProgress::new(definition);
    sqlx::query("INSERT INTO mdm_access.collection_runs (tenant_id, id, device, source, epoch, scope, sequence, started_at, attempts, result, evidence) VALUES (CAST($1 AS uuid), $2, $3, $4, CAST($5 AS uuid), $6, $7, $8, $9, 'pending', $10)")
        .bind(tenant.to_string()).bind(attempt).bind(registration).bind(source.as_str()).bind(epoch)
        .bind(scope.encode().map_err(|_| sqlx::Error::Protocol("invalid scope".into()))?).bind(sequence).bind(now)
        .bind(serde_json::to_string(&progress).expect("closed progress"))
        .bind(serde_json::json!({"task":task,"attempt":attempt})).execute(c).await?;
    Ok(())
}

/// Interpret Script field mappings at the Inventory boundary. Process success and
/// original-attempt trust are decided by Script; projection remains independent.
pub fn script_progress(
    definition: &CollectionDefinition,
    mappings: &std::collections::BTreeMap<String, rss_mdm_agent_wire::runtime::ValueMapping>,
    result: &rss_mdm_agent_wire::runtime::TaskResult,
    trusted: bool,
) -> crate::transaction::Result<CollectionProgress> {
    use crate::transaction::stored;
    use rss_mdm_inventory::{FieldKey, NativeValue};
    let mut values = std::collections::BTreeMap::new();
    for (name, pointer) in mappings {
        let key = stored(FieldKey::parse(name))?;
        let field = stored(definition.field(key))?;
        let outcome = if trusted {
            super::native::mapped_value(field, pointer, result.output())
        } else {
            NativeValue::Failed
        };
        values.insert(key, outcome);
    }
    stored(CollectionProgress::native(
        definition.clone(),
        values,
        result.collected_at(),
    ))
}

/// Seal only the original pending attempt without manufacturing device evidence.
pub async fn abandon_in(
    c: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
    attempt: Uuid,
    reason: &'static str,
) -> Result<Option<rss_mdm_audit_integration::Fact>, sqlx::Error> {
    let tenant = tenant.to_string();
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_access.collection_runs WHERE tenant_id=$1::uuid AND id=$2 AND sealed_at IS NULL AND (source IN('agent.script','agent.osquery','agent.native') OR evidence ? 'nativeTemplate'))")
        .bind(&tenant).bind(attempt).fetch_one(&mut *c).await?;
    if !exists {
        return Ok(None);
    }
    let mut run = super::store::load_on(
        rss_mdm_install_support::StorageProfile::Mdm,
        c,
        &tenant,
        attempt,
    )
    .await
    .map_err(|_| sqlx::Error::Protocol("invalid pending collection".into()))?;
    super::store::seal(
        rss_mdm_install_support::StorageProfile::Mdm,
        c,
        &mut run,
        reason,
    )
    .await
    .map_err(|_| sqlx::Error::Protocol("collection termination failed".into()))
}
