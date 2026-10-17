use crate::device::t2::*;
#[tokio::test]
#[ignore = "MODULE=device.revocation: real registration state and PostgreSQL"]
async fn revocation_wins_waiting_report_authorization() -> anyhow::Result<()> {
    let (access, service, admin_a, mut root) = fixture().await?;
    let fourth_proof = proof(case_a(), Channel::Mdm, 4);
    let (_, fourth) = bind(
        &service,
        &admin_a,
        &fourth_proof,
        crate::test_support::case::name("same-serial"),
        0,
    )
    .await?;
    let authorized = service
        .authorize_report(&fourth_proof, ReportSource::MdmWindows)
        .await?;
    assert_eq!(authorized.0.registration(), fourth.registration);
    // Revocation wins the row lock: an authorization waiting behind it must fail.
    let mut revoke_tx = root.begin().await?;
    sqlx::query("UPDATE mdm_access.registrations SET state='revoked' WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(case_a()).bind(fourth.registration.to_string()).execute(&mut *revoke_tx).await?;
    let authorize = service.authorize_report(&fourth_proof, ReportSource::MdmWindows);
    let release = async {
        let observed = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND pg_backend_pid()=ANY(pg_blocking_pids(pid)) AND query LIKE '%FOR SHARE OF r%')").fetch_one(&mut *revoke_tx).await?;
                if waiting { return Ok::<_, sqlx::Error>(()); }
                sqlx::query("SELECT pg_stat_clear_snapshot()").execute(&mut *revoke_tx).await?;
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }).await;
        revoke_tx.commit().await?;
        observed.context("report authorization must wait behind this revocation")??;
        Ok::<_, anyhow::Error>(())
    };
    let (result, committed) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(authorize, release)
    })
    .await?;
    committed?;
    assert!(matches!(result, Err(Error::Unauthorized)));
    root.close().await?;
    access.close().await;
    Ok(())
}
