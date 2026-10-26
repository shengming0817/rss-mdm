//! Native source validation and endpoint recovery share the real Registration fence.
use super::*;
use sqlx::Connection;

pub(super) async fn challenge_during_recovery(
    host: &crate::windows::test_support::Host,
    router: &Router,
    config: &rss_mdm_registration_service::agent::bootstrap::Configuration,
    request: &Value,
) -> Result<(StatusCode, Value)> {
    let mut observer =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    let (ready, paused) = tokio::sync::oneshot::channel();
    let resume = Arc::new(tokio::sync::Notify::new());
    host.commands
        .service
        .pause_managed_admission(ready, resume.clone());
    let concurrent = async {
        let holder = tokio::time::timeout(Duration::from_secs(5), paused).await??;
        let key = serde_json::to_string(&(case_tenant(), case_device()))?;
        let fenced: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='advisory' AND granted AND classid::bigint=((hashtextextended($2,2790)>>32)&4294967295) AND objid::bigint=(hashtextextended($2,2790)&4294967295) AND objsubid=1)")
            .bind(holder).bind(key).fetch_one(&mut observer).await?;
        ensure!(fenced, "native source did not retain its endpoint fence");
        let release = async {
            let waiting = tokio::time::timeout(Duration::from_secs(3), async {
                loop {
                    let blocked: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND usename='mdm_command_runtime' AND $1=ANY(pg_blocking_pids(pid)) AND query LIKE '%2790%')")
                        .bind(holder).fetch_one(&mut observer).await?;
                    if blocked { break Ok::<_, anyhow::Error>(()); }
                    tokio::task::yield_now().await;
                }
            }).await;
            // Release even on failure; never abandon a paused production transaction.
            resume.notify_one();
            waiting??;
            Ok::<_, anyhow::Error>(())
        };
        let (recovery, released) = tokio::join!(
            host.commands
                .service
                .recover_endpoint_fixture(case_device()),
            release,
        );
        released?;
        recovery?;
        Ok::<_, anyhow::Error>(())
    };
    let (challenge, recovery) = tokio::join!(
        bootstrap::webhook_response(router, config, "challenge", request),
        concurrent,
    );
    resume.notify_one();
    observer.close().await?;
    recovery?;
    challenge
}
