use crate::device::t2::*;
#[tokio::test]
#[ignore = "MODULE=device.revocation: real registration state and PostgreSQL"]
async fn revocation_wins_waiting_report_authorization() -> anyhow::Result<()> {
    let (access, service, admin_a, mut root) = fixture().await?;
    let fourth_proof = proof(A, Channel::Mdm, 4);
    let (_, fourth) = bind(&service, &admin_a, &fourth_proof, "same-serial", 0).await?;
    // Revocation wins the row lock: an authorization waiting behind it must fail.
    let mut revoke_tx = root.begin().await?;
    sqlx::query("UPDATE mdm_access.registrations SET state='revoked' WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(A).bind(fourth.registration.to_string()).execute(&mut *revoke_tx).await?;
    let authorize = service.authorize_report(&fourth_proof, ReportSource::MdmWindows);
    let release = async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        revoke_tx.commit().await
    };
    let (result, committed) = tokio::join!(authorize, release);
    committed?;
    assert!(result.is_err());
    root.close().await?;
    access.close().await;
    Ok(())
}
