use super::*;
#[tokio::test]
#[ignore = "MODULE=device.admission: real registration state and PostgreSQL"]
async fn runtime_role_cannot_mutate_history_or_read_without_tenant() -> anyhow::Result<()> {
    let mut root = PgConnection::connect_with(&options("postgres")?).await?;
    let mut tx = root.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(case_a())
        .execute(&mut *tx)
        .await?;
    let device = crate::test_support::case::name("role-boundary");
    let grant = Uuid::new_v4();
    let request = Uuid::new_v4();
    let registration = Uuid::new_v4();
    let password = crate::enrollment::Password::new("A".repeat(43))?.digest(case_a(), device)?;
    sqlx::query("INSERT INTO mdm_access.grants(tenant_id,id,actor,instance,device,purpose,state,expires_at) VALUES($1::uuid,$2,'fixture',$3,$4,'enrollment','consumed',clock_timestamp()+interval '300 seconds')")
        .bind(case_a()).bind(grant).bind(crate::test_support::identity::INSTANCE).bind(device).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_access.requests(tenant_id,id,grant_id,state,source,windows_profile,expected_generation,expires_at,issuance_operation,password_digest,password_version,credential_ref) VALUES($1::uuid,$2,$3,'bound','mdm.windows','Device',0,clock_timestamp()+interval '300 seconds',gen_random_uuid(),$4,1,gen_random_uuid())")
        .bind(case_a()).bind(request).bind(grant).bind(password).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_access.devices(tenant_id,id) VALUES($1::uuid,$2)")
        .bind(case_a())
        .bind(device)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO mdm_access.registrations(tenant_id,id,device,channel,generation,request_id,state,purpose,epoch) VALUES($1::uuid,$2,$3,'mdm',1,$4,'active','primary',$5)")
        .bind(case_a()).bind(registration).bind(device).bind(request).bind(Uuid::new_v4()).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_access.credentials(tenant_id,id,registration,channel,locator,state) VALUES($1::uuid,$2,$3,'mdm',$4,'active')")
        .bind(case_a()).bind(Uuid::new_v4()).bind(registration).bind(format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())).execute(&mut *tx).await?;
    tx.commit().await?;
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
        "UPDATE mdm_audit.receipts SET source_bytes=source_bytes",
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
    Ok(())
}
