//! Recovery reservation/asset incarnation only; no full backup/restore claim.
use super::{advance_asset_history, reserve_restore};
use crate::authority_t2_support::Inputs;
use anyhow::Result;
use sqlx::Connection;
use uuid::Uuid;

#[tokio::test]
#[ignore = "T2: empty target and actual persistent restore incarnation"]
async fn restore_reservation_and_asset_epoch_survive_reentry_without_second_rotation() -> Result<()>
{
    let inputs = Inputs::load()?;
    let mut connection =
        sqlx::PgConnection::connect_with(&inputs.database("recovery", "postgres").options()?)
            .await?;
    let operation = Uuid::new_v4();
    let manifest = "foundation-current-backup-manifest";
    reserve_restore(&mut connection, operation, manifest).await?;
    reserve_restore(&mut connection, operation, manifest).await?;
    assert!(
        reserve_restore(&mut connection, Uuid::new_v4(), manifest)
            .await
            .is_err()
    );
    assert!(
        reserve_restore(&mut connection, operation, "other-manifest")
            .await
            .is_err()
    );
    // Use the one production installer for the current schema. The recovery marker
    // is established on the empty target, never fabricated on an installed database.
    crate::migration::migrate(
        &inputs.database("recovery", "mdm_owner").options()?,
        &inputs.installation(),
    )
    .await?;
    let before: Uuid = sqlx::query_scalar("SELECT id FROM mdm.asset_epochs WHERE active")
        .fetch_one(&mut connection)
        .await?;
    let pool = inputs.pool("recovery", "postgres").await?;
    let tenant = rss_request_context::TenantId::parse(&Uuid::new_v4().to_string())?;
    crate::authority_t2_support::seed_tenant(&pool, tenant).await?;
    let mut field = rss_mdm_inventory::builtin::fields()
        .into_iter()
        .find(|f| f.key.as_str() == "device.os.name")
        .expect("builtin field");
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant.to_string())
        .execute(&mut *tx)
        .await?;
    rss_mdm_inventory_postgres::publish_field_in(&mut tx, tenant, 0, &field).await?;
    tx.commit().await?;
    let frozen = rss_mdm_inventory_postgres::capture_asset_cut(&pool, tenant).await?;
    let epoch = advance_asset_history(&mut connection, operation).await?;
    field.version += 1;
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant.to_string())
        .execute(&mut *tx)
        .await?;
    rss_mdm_inventory_postgres::publish_field_in(&mut tx, tenant, 1, &field).await?;
    tx.commit().await?;
    let current = rss_mdm_inventory_postgres::capture_asset_cut(&pool, tenant).await?;
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant.to_string())
        .execute(&mut *tx)
        .await?;
    let counts:(i64,i64)=sqlx::query_as("WITH old AS MATERIALIZED(SELECT * FROM mdm.asset_cut_context($2)),new AS MATERIALIZED(SELECT * FROM mdm.asset_cut_context($3)) SELECT count(*) FILTER(WHERE mdm.asset_visible($2,e.revision)),count(*) FILTER(WHERE coalesce((SELECT CASE WHEN e.source_epoch=epoch THEN pg_visible_in_snapshot(e.writer_xid,visibility) ELSE e.source_epoch=ANY(ancestors) END FROM new),false) AND NOT coalesce((SELECT CASE WHEN e.source_epoch=epoch THEN pg_visible_in_snapshot(e.writer_xid,visibility) ELSE e.source_epoch=ANY(ancestors) END FROM old),false)) FROM mdm.asset_changes e WHERE e.tenant_id=$1::uuid").bind(tenant.to_string()).bind(frozen.to_json()).bind(current.to_json()).fetch_one(&mut *tx).await?;
    assert_eq!(
        counts,
        (1, 1),
        "old fixed inputs stay immutable while the successor cut includes the restored baseline and new facts"
    );
    tx.rollback().await?;
    pool.close().await;
    assert_ne!(epoch, before);
    assert_eq!(
        advance_asset_history(&mut connection, operation).await?,
        epoch
    );
    assert!(
        advance_asset_history(&mut connection, Uuid::new_v4())
            .await
            .is_err()
    );
    let state: (Uuid, Uuid, i64) = sqlx::query_as("SELECT (SELECT id FROM mdm.asset_epochs WHERE active),(SELECT asset_epoch FROM public.mdm_restore_operation WHERE singleton),(SELECT count(*) FROM mdm.asset_epochs WHERE restore_operation=$1)")
        .bind(operation).fetch_one(&mut connection).await?;
    assert_eq!(state, (epoch, epoch, 1));
    connection.close().await?;
    Ok(())
}
