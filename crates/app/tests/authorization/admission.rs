use super::*;

#[tokio::test]
#[ignore = "MODULE=authorization.admission: real authorization contract"]
async fn permission_drift_corrupt_policy_and_stalled_postgres() -> Result<()> {
    let Fixture {
        config,
        router,
        mut admin,
        mut member,
        store,
        ..
    } = fixture().await?;
    let rule_id = Uuid::new_v4();
    pg(&format!(
        "INSERT INTO mdm_access.authorization_rules(tenant_id,instance,id,revision,document) VALUES('{TENANT}','{INSTANCE}','{rule_id}',1,NULL)",
        TENANT = case_tenant()
    ))?;
    // Corrupt stored policy is an unavailable authorization authority, never an ignored rule.
    pg(&format!(
        "UPDATE mdm_access.authorization_rules SET document='{{\"broken\":true}}' WHERE tenant_id='{TENANT}' AND id='{rule_id}'",
        TENANT = case_tenant()
    ))?;
    let corrupt = member
        .call(&router, Method::GET, "/api/v1/authorization", None)
        .await?;
    pg(&format!(
        "UPDATE mdm_access.authorization_rules SET document=NULL WHERE tenant_id='{TENANT}' AND id='{rule_id}'",
        TENANT = case_tenant()
    ))?;
    ensure!(corrupt.0 == StatusCode::SERVICE_UNAVAILABLE && corrupt.1.get("grants").is_none());
    // Runtime admission and data access both fail closed on PG permission drift.
    pg("REVOKE SELECT ON mdm_access.authorization_rules FROM mdm_access")?;
    let denied = member
        .call(&router, Method::GET, "/api/v1/authorization", None)
        .await?;
    let context = admin
        .call(
            &router,
            Method::GET,
            &format!(
                "/api/identity-host/v1/tenants/{TENANT}/context",
                TENANT = case_tenant()
            ),
            None,
        )
        .await?;
    let reconnect = crate::Database::connect(config.access_database.options()?).await;
    pg("GRANT SELECT ON mdm_access.authorization_rules TO mdm_access")?;
    ensure!(
        denied.0 == StatusCode::SERVICE_UNAVAILABLE
            && denied.1.get("grants").is_none()
            && reconnect.is_err()
            && context.0 == StatusCode::OK
            && context.1["navigation"]["manageAccounts"] == true
    );
    let identity = crate::test_support::identity::identity(case_tenant()).await?;
    let stale = crate::authorization::context::AuthorizedPrincipal::new(
        identity
            .authority
            .inspect_session(
                identity.tenant,
                rss_identity_core::session::SessionSecret::parse(
                    member.cookies["__Host-identity-session"].clone(),
                )?,
                crate::identity::deadline(),
            )
            .await?,
    )?
    .load_authorization(&store)
    .await?;
    // Stop protocol replies after BEGIN/query, beyond the pool acquire timeout.
    use sqlx::Connection;
    let mut holder =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    sqlx::raw_sql("BEGIN; LOCK TABLE mdm_access.authorization_rules IN ACCESS EXCLUSIVE MODE")
        .execute(&mut holder)
        .await?;
    let container = std::env::var("MDM_TEST_PG_CONTAINER")?;
    let freeze = async {
        let deadline = rss_request_context::Clock::now(&crate::lifecycle::RuntimeTimer)
            + Duration::from_millis(750);
        loop {
            sqlx::query("SELECT pg_stat_clear_snapshot()")
                .execute(&mut holder)
                .await?;
            let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename='mdm_access' AND wait_event_type='Lock' AND query LIKE 'WITH rules AS MATERIALIZED%')").fetch_one(&mut holder).await?;
            if waiting {
                break;
            }
            ensure!(
                rss_request_context::Clock::now(&crate::lifecycle::RuntimeTimer) < deadline,
                "snapshot did not enter SQL"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        command(&["pause", &container], None)?;
        tokio::time::sleep(Duration::from_millis(3200)).await;
        command(&["unpause", &container], None)?;
        sqlx::query("ROLLBACK").execute(&mut holder).await?;
        anyhow::Ok(())
    };
    let (stalled, frozen) = tokio::join!(
        tokio::time::timeout(
            Duration::from_secs(4),
            crate::authorization::store::authorization_snapshot(&store, &stale)
        ),
        freeze
    );
    frozen?;
    holder.close().await?;
    ensure!(matches!(
        stalled,
        Ok(Err(crate::Error::Unavailable(
            crate::Failure::RequestDeadline
        )))
    ));
    ensure!(
        member
            .call(&router, Method::GET, "/api/v1/authorization", None)
            .await?
            .0
            == StatusCode::OK
    );

    Ok(())
}
