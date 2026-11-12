//! Configuration owns its independent, commit-ordered source checkpoint.
use crate::transaction::*;
use rss_transactional_messaging_postgres::PgTransaction;
use sqlx::Row;
use std::sync::Arc;
pub async fn pending_in(
    tx: &mut PgTransaction<'_>,
    source: Arc<rss_mdm_scope_service::channels::ChannelTargets>,
) -> Result<bool> {
    let source_tenant = tx.tenant_id();
    let revision = tx
        .with_connection(move |c| {
            Box::pin(async move {
                Ok(source
                    .required_objects()?
                    .change_head(c, source_tenant)
                    .await)
            })
        })
        .await??;
    let tenant = tx.tenant_id().to_string();
    Ok(tx.with_connection(move |c|Box::pin(async move {
        sqlx::query_scalar("WITH input_cut AS MATERIALIZED (SELECT * FROM mdm.asset_cut_context((SELECT from_cut FROM mdm_planning.configuration_source_dispatch WHERE tenant_id=$1::uuid))) SELECT EXISTS(SELECT FROM mdm.asset_changes WHERE tenant_id=$1::uuid AND NOT coalesce((SELECT mdm.asset_context_contains(epoch,visibility,ancestors,source_epoch,writer_xid) FROM input_cut),false)) OR $2>coalesce((SELECT relation_consumed FROM mdm_planning.configuration_source_dispatch WHERE tenant_id=$1::uuid),0)").bind(tenant).bind(revision).fetch_one(c).await
    })).await?)
}
pub async fn advance_in(
    tx: &mut PgTransaction<'_>,
    service: &super::Transactions,
    source: Arc<rss_mdm_scope_service::channels::ChannelTargets>,
    candidate: &rss_mdm_inventory::AssetCut,
) -> Result<()> {
    tx.with_connection(|c| Box::pin(verify_storage(c))).await?;
    let tenant = tx.tenant_id().to_string();
    let row=tx.with_connection(move|c|Box::pin(async move {
        sqlx::query("INSERT INTO mdm_planning.configuration_source_dispatch(tenant_id) VALUES($1::uuid) ON CONFLICT DO NOTHING").bind(&tenant).execute(&mut *c).await?;
        sqlx::query("SELECT from_cut,to_cut,event_after,page_through,cursor FROM mdm_planning.configuration_source_dispatch WHERE tenant_id=$1::uuid FOR UPDATE").bind(tenant).fetch_one(c).await
    })).await?;
    let from: Option<serde_json::Value> = row.try_get("from_cut")?;
    let to: serde_json::Value = row
        .try_get::<Option<serde_json::Value>, _>("to_cut")?
        .unwrap_or_else(|| candidate.to_json());
    let after: i64 = row.try_get("event_after")?;
    let cursor: Option<String> = row.try_get("cursor")?;
    let through = match row.try_get::<Option<i64>, _>("page_through")? {
        Some(value) => Some(value),
        None => {
            let tenant = tx.tenant_id().to_string();
            let f = from.clone();
            let t = to.clone();
            tx.with_connection(move|c|Box::pin(async move {
                sqlx::query_scalar::<_,Option<i64>>("WITH asset_cut_2 AS MATERIALIZED (SELECT * FROM mdm.asset_cut_context($2)),asset_cut_3 AS MATERIALIZED (SELECT * FROM mdm.asset_cut_context($3)) SELECT max(revision) FROM (SELECT revision FROM mdm.asset_changes WHERE tenant_id=$1::uuid AND NOT coalesce((SELECT mdm.asset_context_contains(epoch,visibility,ancestors,source_epoch,writer_xid) FROM asset_cut_2),false) AND coalesce((SELECT mdm.asset_context_contains(epoch,visibility,ancestors,source_epoch,writer_xid) FROM asset_cut_3),false) AND revision>$4 ORDER BY revision LIMIT 1000) page")
                    .bind(tenant).bind(f).bind(t).bind(after).fetch_one(c).await
            })).await?
        }
    };
    let Some(through) = through else {
        let tenant = tx.tenant_id().to_string();
        tx.with_connection(move|c|Box::pin(async move {
            sqlx::query("UPDATE mdm_planning.configuration_source_dispatch SET from_cut=$2,to_cut=NULL,event_after=0,page_through=NULL,cursor=NULL WHERE tenant_id=$1::uuid").bind(tenant).bind(to).execute(c).await?;Ok(())
        })).await?;
        return relation_page_in(tx, service, source).await;
    };
    let tenant = tx.tenant_id().to_string();
    let frozen = to.clone();
    tx.with_connection(move|c|Box::pin(async move {
        sqlx::query("UPDATE mdm_planning.configuration_source_dispatch SET to_cut=$2,page_through=$3 WHERE tenant_id=$1::uuid").bind(tenant).bind(frozen).bind(through).execute(c).await?;Ok(())
    })).await?;
    let tenant = tx.tenant_id().to_string();
    let devices=tx.with_connection(move|c|Box::pin(async move {
        sqlx::query_scalar::<_,String>(r#"WITH asset_cut_2 AS MATERIALIZED (SELECT * FROM mdm.asset_cut_context($2)),asset_cut_3 AS MATERIALIZED (SELECT * FROM mdm.asset_cut_context($3)),changed AS (
            SELECT DISTINCT (a.identity->>'device') COLLATE "C" AS device
            FROM mdm.asset_changes a WHERE a.tenant_id=$1::uuid AND NOT coalesce((SELECT mdm.asset_context_contains(epoch,visibility,ancestors,a.source_epoch,a.writer_xid) FROM asset_cut_2),false) AND coalesce((SELECT mdm.asset_context_contains(epoch,visibility,ancestors,a.source_epoch,a.writer_xid) FROM asset_cut_3),false) AND a.revision>$4 AND a.revision<=$5
            AND (a.kind IN('device','source','credential'))
        ) SELECT device FROM changed WHERE device IS NOT NULL AND ($6::text IS NULL OR device>$6 COLLATE "C") ORDER BY device COLLATE "C" LIMIT 33"#)
            .bind(tenant).bind(from).bind(to).bind(after).bind(through).bind(cursor).fetch_all(c).await
    })).await?;
    service
        .wake_devices_in(tx, &devices[..devices.len().min(32)])
        .await?;
    let more = devices.len() > 32;
    let next = more.then(|| devices[31].clone());
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move|c|Box::pin(async move {
        sqlx::query("UPDATE mdm_planning.configuration_source_dispatch SET event_after=$2,page_through=$3,cursor=$4 WHERE tenant_id=$1::uuid")
            .bind(tenant).bind(if more {after}else{through}).bind(more.then_some(through)).bind(next).execute(c).await?;Ok(())
    })).await?;
    relation_page_in(tx, service, source).await
}
pub async fn clear_failure_in(tx: &mut PgTransaction<'_>) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |c|Box::pin(async move {sqlx::query("UPDATE mdm_planning.configuration_source_dispatch SET failure=NULL WHERE tenant_id=$1::uuid AND failure IS NOT NULL").bind(tenant).execute(c).await?;Ok(())})).await?;
    Ok(())
}
pub async fn fail_in(
    tx: &mut PgTransaction<'_>,
    audit_store: &rss_mdm_audit_integration::AuditStore,
) -> Result<()> {
    let tenant = tx.tenant_id().to_string();
    let generation=tx.with_connection(move |c|Box::pin(async move {
        sqlx::query_scalar::<_,i64>("INSERT INTO mdm_planning.configuration_source_dispatch(tenant_id,failure,failure_generation) VALUES($1::uuid,'automation_suspended',1) ON CONFLICT(tenant_id) DO UPDATE SET failure=excluded.failure,failure_generation=configuration_source_dispatch.failure_generation+1 WHERE configuration_source_dispatch.failure IS NULL RETURNING failure_generation").bind(tenant).fetch_optional(c).await
    })).await?;
    if let Some(generation) = generation {
        let audit = rss_mdm_audit_integration::RequestAudit::new(
            rss_mdm_audit_integration::Origin::Background,
            rss_mdm_audit_integration::StorageProfile::Mdm,
            tx.tenant_id().to_string(),
            "automation_failed",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.identify_service("service:configuration-inputs");
        audit.target("asset_ingress");
        let fact = rss_mdm_audit_integration::Fact::business(
            &audit,
            rss_mdm_audit_integration::operation::OperationOwner::Configuration,
            &format!("configuration-ingress:{generation}:failed"),
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
            "Configuration input checkpoint rejected".into(),
        ));
    }
    Ok(())
}

async fn relation_page_in(
    tx: &mut PgTransaction<'_>,
    service: &super::Transactions,
    source: Arc<rss_mdm_scope_service::channels::ChannelTargets>,
) -> Result<()> {
    let tenant = tx.tenant_id();
    let t = tenant.to_string();
    let (consumed,mut watermark,mut cursor):(i64,i64,Option<i64>)=tx.with_connection(move|c|Box::pin(async move {
        sqlx::query_as("SELECT relation_consumed,relation_watermark,relation_cursor FROM mdm_planning.configuration_source_dispatch WHERE tenant_id=$1::uuid FOR UPDATE").bind(t).fetch_one(c).await
    })).await?;
    if consumed == watermark {
        let reader = source.clone();
        watermark = tx
            .with_connection(move |c| {
                Box::pin(async move { Ok(reader.required_objects()?.change_head(c, tenant).await) })
            })
            .await??;
        cursor = None;
    }
    if watermark < consumed {
        return Err(crate::Error::Conflict.into());
    }
    if watermark == consumed {
        return Ok(());
    }
    let reader = source.clone();
    let after = cursor.unwrap_or(consumed);
    let changes = tx
        .with_connection(move |c| {
            Box::pin(async move {
                Ok(reader
                    .required_objects()?
                    .changes(c, tenant, after, watermark, 64)
                    .await)
            })
        })
        .await??;
    let position = changes.last().map_or(watermark, |c| c.position);
    let finished = changes.len() < 64 || position == watermark;
    let devices = changes
        .into_iter()
        .filter(|c| c.kind == rss_mdm_inventory_service::objects::ObjectChangeKind::IdentityChanged)
        .flat_map(|c| c.old_devices.into_iter().chain(c.new_devices))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    service.wake_devices_in(tx, &devices).await?;
    let t = tenant.to_string();
    tx.with_connection(move|c|Box::pin(async move {
        sqlx::query("UPDATE mdm_planning.configuration_source_dispatch SET relation_consumed=$2,relation_watermark=$3,relation_cursor=$4 WHERE tenant_id=$1::uuid").bind(t).bind(if finished{watermark}else{consumed}).bind(watermark).bind((!finished).then_some(position)).execute(c).await?;Ok(())
    })).await?;
    Ok(())
}
