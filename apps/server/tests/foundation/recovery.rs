//! Recovery reservation/asset incarnation only; no full backup/restore claim.
use super::{advance_asset_history, reserve_restore};
use crate::foundation_t2::support::Inputs;
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
    let epoch = advance_asset_history(&mut connection, operation).await?;
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
