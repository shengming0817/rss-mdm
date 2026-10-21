//! Product installation and pool ownership seams; RSS owns its storage algorithm matrix.
use super::*;
use anyhow::{Result, ensure};
use sqlx::Connection;

#[tokio::test]
#[ignore = "MODULE=telemetry.storage: empty PG16 and Timescale databases, real roles and restart admission"]
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
