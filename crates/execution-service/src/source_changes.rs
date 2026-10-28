//! Execution owns device-source consumption; Scope has its own independent checkpoint.
use crate::transaction::*;
use rss_transactional_messaging_postgres::PgTransaction;
use std::sync::Arc;
pub async fn pending_in(tx: &mut PgTransaction<'_>) -> Result<bool> {
    let tenant = tx.tenant_id().to_string();
    Ok(tx.with_connection(move |c|Box::pin(async move {
        sqlx::query_scalar("SELECT coalesce((SELECT revision FROM mdm.asset_clock WHERE tenant_id=$1::uuid),0)>coalesce((SELECT consumed FROM mdm_commands.device_source_dispatch WHERE tenant_id=$1::uuid),0)").bind(tenant).fetch_one(c).await
    })).await?)
}
pub async fn advance_in(
    tx: &mut PgTransaction<'_>,
    messaging: &rss_reconcile_postgres::PgMessagingStore,
    source: Arc<dyn crate::source_authority::SourceAuthority>,
) -> Result<()> {
    tx.with_connection(|c| Box::pin(verify_storage(c))).await?;
    let tenant = tx.tenant_id().to_string();
    let (consumed,mut watermark,mut cursor)=tx.with_connection(move |c|Box::pin(async move {
        sqlx::query("INSERT INTO mdm_commands.device_source_dispatch(tenant_id) VALUES($1::uuid) ON CONFLICT DO NOTHING").bind(&tenant).execute(&mut *c).await?;
        sqlx::query_as::<_,(i64,i64,Option<String>)>("SELECT consumed,watermark,cursor FROM mdm_commands.device_source_dispatch WHERE tenant_id=$1::uuid FOR UPDATE").bind(tenant).fetch_one(c).await
    })).await?;
    if consumed == watermark {
        let tenant = tx.tenant_id().to_string();
        watermark=tx.with_connection(move |c|Box::pin(async move {
            sqlx::query_scalar("SELECT coalesce(max(revision),$2) FROM (SELECT revision FROM mdm.asset_changes WHERE tenant_id=$1::uuid AND revision>$2 ORDER BY revision LIMIT 1000) page").bind(tenant).bind(consumed).fetch_one(c).await
        })).await?;
        cursor = None;
        if watermark == consumed {
            return Ok(());
        }
    }
    device_page_in(tx, messaging, source, consumed, watermark, cursor).await
}
async fn device_page_in(
    tx: &mut PgTransaction<'_>,
    messaging: &rss_reconcile_postgres::PgMessagingStore,
    source: std::sync::Arc<dyn crate::source_authority::SourceAuthority>,
    consumed: i64,
    watermark: i64,
    cursor: Option<String>,
) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    let devices = tx
        .with_connection(move |c| {
            Box::pin(async move {
                sqlx::query_scalar::<_, String>(
                    r#"WITH changed AS (
                    SELECT DISTINCT coalesce(c.identity->>'device',r.device) COLLATE "C" AS device
                    FROM mdm.asset_changes c LEFT JOIN mdm_access.registrations r
                      ON r.tenant_id=c.tenant_id AND r.id::text=c.identity->>'registration'
                    WHERE c.tenant_id=$1::uuid AND c.revision>$2 AND c.revision<=$3
                      AND (c.kind IN('device','registration','source','credential')
                        OR 'channel.agent.installation'=ANY(c.fields))
                ) SELECT device FROM changed WHERE device IS NOT NULL
                    AND ($4::text IS NULL OR device>$4::text COLLATE "C")
                    ORDER BY device COLLATE "C" LIMIT 33"#,
                )
                .bind(tenant)
                .bind(consumed)
                .bind(watermark)
                .bind(cursor)
                .fetch_all(c)
                .await
            })
        })
        .await?;
    for device in devices.iter().take(32) {
        // Wake effects and the page cursor commit together. A retry reads
        // the durable cursor rather than repeating an acknowledged page.
        crate::wake::wake_native_in(messaging, source.clone(), tx, device).await?;
    }
    if devices.len() > 32 {
        cursor_in(tx, consumed, watermark, Some(devices[31].clone())).await
    } else {
        cursor_in(tx, watermark, watermark, None).await
    }
}
async fn cursor_in(
    tx: &mut PgTransaction<'_>,
    consumed: i64,
    watermark: i64,
    cursor: Option<String>,
) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c|Box::pin(async move {
        sqlx::query("UPDATE mdm_commands.device_source_dispatch SET consumed=$2,watermark=$3,cursor=$4 WHERE tenant_id=$1::uuid").bind(tenant).bind(consumed).bind(watermark).bind(cursor).execute(c).await?;Ok(())
    })).await?;
    Ok(())
}
pub async fn health_in(tx: &mut PgTransaction<'_>) -> Result<(u64, u64, bool)> {
    let tenant = tx.tenant_id().to_string();
    let row=tx.with_connection(move |c|Box::pin(async move {
        sqlx::query_as::<_,(i64,i64,Option<String>)>("SELECT consumed,watermark,failure FROM mdm_commands.device_source_dispatch WHERE tenant_id=$1::uuid").bind(tenant).fetch_optional(c).await
    })).await?;
    Ok(row.map_or((0, 0, false), |(c, w, f)| (c as u64, w as u64, f.is_some())))
}
pub async fn clear_failure_in(tx: &mut PgTransaction<'_>) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c|Box::pin(async move {sqlx::query("UPDATE mdm_commands.device_source_dispatch SET failure=NULL WHERE tenant_id=$1::uuid AND failure IS NOT NULL").bind(tenant).execute(c).await?;Ok(())})).await?;
    Ok(())
}
pub async fn fail_in(
    tx: &mut PgTransaction<'_>,
    audit_store: &rss_mdm_audit_integration::AuditStore,
) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    let generation=tx.with_connection(move |c|Box::pin(async move {
        sqlx::query_scalar::<_,i64>("INSERT INTO mdm_commands.device_source_dispatch(tenant_id,failure,failure_generation) VALUES($1::uuid,'automation_suspended',1) ON CONFLICT(tenant_id) DO UPDATE SET failure=excluded.failure,failure_generation=device_source_dispatch.failure_generation+1 WHERE device_source_dispatch.failure IS NULL RETURNING failure_generation").bind(tenant).fetch_optional(c).await
    })).await?;
    if let Some(generation) = generation {
        let audit = rss_mdm_audit_integration::RequestAudit::new(
            tx.tenant_id().to_string(),
            "automation_failed",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.identify_service("service:execution-inputs");
        audit.target("asset_ingress");
        let fact = rss_mdm_audit_integration::Fact::business(
            &audit,
            &format!("device-ingress:{generation}:failed"),
            200,
            "failed",
            None,
        )?;
        audit_store.append_in(tx, &fact).await?;
        audit.finalize(None);
    }
    Ok(())
}
pub async fn verify_storage(c: &mut sqlx::PgConnection) -> std::result::Result<(), sqlx::Error> {
    let valid: bool = sqlx::query_scalar(include_str!("source-changes-admission.sql"))
        .fetch_one(c)
        .await?;
    if !valid {
        return Err(sqlx::Error::Protocol(
            "Execution input checkpoint rejected".into(),
        ));
    }
    Ok(())
}
