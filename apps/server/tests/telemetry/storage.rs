//! Product installation and pool ownership seams; RSS owns its storage algorithm matrix.
use super::*;
use anyhow::{Result, ensure};
use sqlx::Connection;

#[tokio::test]
#[ignore = "MODULE=telemetry.storage: empty PG17 and Timescale databases, real roles and restart admission"]
async fn explicit_installations_replay_and_reopen_without_runtime_ddl() -> Result<()> {
    let requests: Vec<crate::setup::providers::telemetry::Request> =
        serde_json::from_slice(&std::fs::read(std::env::var("MDM_TELEMETRY_PROVIDERS")?)?)?;
    ensure!(
        requests.len() == 4,
        "all four telemetry profiles are required"
    );
    for request in requests {
        let receipt = crate::setup::providers::telemetry::prepare(request.clone()).await?;
        ensure!(receipt.admitted);
        let replay = crate::setup::providers::telemetry::prepare(request.clone()).await?;
        ensure!(receipt.installation_id == replay.installation_id);
        let tenant = TenantId::parse(&request.tenant)?;
        let backend = request.configuration.open_backend(tenant).await?;
        let cutoff = || Deadline::from_timeout(&SystemClock, Duration::from_secs(10)).unwrap();
        backend.close(cutoff()).await?;
        let reopened = request.configuration.open_backend(tenant).await?;
        reopened.close(cutoff()).await?;
        let mut owner = sqlx::PgConnection::connect_with(&request.administrator.options()?).await?;
        let identity: uuid::Uuid =
            sqlx::query_scalar("SELECT id FROM public.mdm_telemetry_installation")
                .fetch_one(&mut owner)
                .await?;
        ensure!(identity == receipt.installation_id);
        let restricted:bool=sqlx::query_scalar("SELECT NOT rolsuper AND NOT rolbypassrls AND NOT rolcreaterole AND NOT rolcreatedb FROM pg_roles WHERE rolname=$1")
            .bind(&request.configuration.database().user).fetch_one(&mut owner).await?;
        ensure!(restricted);
        if matches!(
            request.configuration.backend,
            crate::telemetry::Storage::Postgres { .. }
        ) {
            use crate::setup::providers::telemetry::{
                Partition, PhysicalAction, PhysicalRequest, maintain,
            };
            let live = request.configuration.open_backend(tenant).await?;
            let last = request
                .partitions
                .iter()
                .map(|p| p.end_micros)
                .max()
                .unwrap();
            let physical = PhysicalRequest {
                installation: request.clone(),
                operation_id: uuid::Uuid::new_v4(),
                action: PhysicalAction::PreparePartitions {
                    partitions: vec![Partition {
                        start_micros: last,
                        end_micros: last + 86400000000,
                    }],
                },
            };
            // Idle runtime pools and active operator connections are allowed.
            let first = maintain(physical.clone()).await?;
            ensure!(maintain(physical.clone()).await? == first);
            let mut blocked = physical.clone();
            blocked.operation_id = uuid::Uuid::new_v4();
            blocked.action = PhysicalAction::PreparePartitions {
                partitions: vec![Partition {
                    start_micros: last + 86400000000,
                    end_micros: last + 172800000000,
                }],
            };
            let mut lock = owner.begin().await?;
            sqlx::raw_sql("LOCK TABLE rss_timeseries.samples IN ACCESS SHARE MODE")
                .execute(&mut *lock)
                .await?;
            ensure!(
                maintain(blocked.clone()).await.is_err(),
                "bounded parent lock timeout"
            );
            lock.rollback().await?;
            ensure!(
                maintain(blocked).await?["state"] == "complete",
                "same operation recovers after rollback"
            );
            live.close(cutoff()).await?;
        }
        let mut changed = request.clone();
        changed.owner.push_str("_changed");
        ensure!(
            crate::setup::providers::telemetry::prepare(changed)
                .await
                .is_err()
        );
        let retained: uuid::Uuid =
            sqlx::query_scalar("SELECT id FROM public.mdm_telemetry_installation")
                .fetch_one(&mut owner)
                .await?;
        ensure!(retained == identity);
        owner.close().await?;
    }
    Ok(())
}
