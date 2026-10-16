use super::*;
#[tokio::test]
#[ignore = "MODULE=device.admission: real registration state and PostgreSQL"]
async fn runtime_role_cannot_mutate_history_or_bypass_tenants() -> anyhow::Result<()> {
    let (access, service, admin_a, mut root) = fixture().await?;
    bind(
        &service,
        &admin_a,
        &proof(case_a(), Channel::Mdm, 1),
        crate::test_support::case::name("role-boundary"),
        0,
    )
    .await?;
    let snapshot = "SELECT jsonb_build_array(        (SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]') FROM mdm_access.registrations r WHERE tenant_id=$1::uuid),        (SELECT coalesce(jsonb_agg(to_jsonb(c) ORDER BY to_jsonb(c)::text),'[]') FROM mdm_access.credentials c WHERE tenant_id=$1::uuid))";
    let before: serde_json::Value = sqlx::query_scalar(snapshot)
        .bind(case_a())
        .fetch_one(&mut root)
        .await?;
    assert!(!before[0].as_array().unwrap().is_empty());
    assert!(!before[1].as_array().unwrap().is_empty());
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
        let error = runtime.execute(statement).await.unwrap_err();
        assert_eq!(
            error.as_database_error().and_then(|e| e.code()).as_deref(),
            Some("42501"),
            "{statement}: {error}"
        );
    }
    let after: serde_json::Value = sqlx::query_scalar(snapshot)
        .bind(case_a())
        .fetch_one(&mut root)
        .await?;
    assert_eq!(
        after, before,
        "denied mutations must preserve the real registration and credential"
    );
    runtime.close().await?;
    root.close().await?;
    access.close().await;
    Ok(())
}
