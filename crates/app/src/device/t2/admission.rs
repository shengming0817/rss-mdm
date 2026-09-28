use super::*;
#[tokio::test]
#[ignore = "MODULE=device.admission: real registration state and PostgreSQL"]
async fn runtime_role_cannot_mutate_history_or_bypass_tenants() -> anyhow::Result<()> {
    let (access, service, admin_a, root) = fixture().await?;
    bind(
        &service,
        &admin_a,
        &proof(A, Channel::Mdm, 1),
        "role-boundary",
        0,
    )
    .await?;
    // Minimum role remains closed to audit/history mutation and tenant bypass.
    let mut runtime = PgConnection::connect_with(&options("mdm_access")?).await?;
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM mdm_access.registrations")
        .fetch_one(&mut runtime)
        .await?;
    assert_eq!(count, 0);
    for statement in [
        "DELETE FROM mdm_access.registrations",
        "UPDATE mdm_access.credentials SET locator=repeat('0',64)",
        "UPDATE mdm_audit.receipts SET canonical=canonical",
    ] {
        assert!(runtime.execute(statement).await.is_err());
    }
    runtime.close().await?;
    root.close().await?;
    access.close().await;
    Ok(())
}
