use super::*;

#[tokio::test]
#[ignore = "MODULE=authorization.admission: real authorization contract"]
async fn permission_drift_corrupt_policy_and_stalled_postgres() -> Result<()> {
    let authority = authority::Authority::open().await?;
    let config: Config = serde_json::from_value(authority.base.clone())?;
    let policy = Arc::new(
        crate::authorization::identity_management::IdentityManagementPolicy::new(INSTANCE)?,
    );
    let router = authority.router(
        authority
            .authorization()
            .merge(rss_mdm_management_http::identity_context_routes(policy)),
    )?;
    let mut admin = authority.browser("admin")?;
    let mut member = authority.browser("other")?;
    let store = authority.authorization.clone();
    let resources = authority.resources;
    resources.finish(async {
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
        .await;
    pg(&format!(
        "UPDATE mdm_access.authorization_rules SET document=NULL WHERE tenant_id='{TENANT}' AND id='{rule_id}'",
        TENANT = case_tenant()
    ))?;
    let corrupt = corrupt?;
    ensure!(
        corrupt.0 == StatusCode::SERVICE_UNAVAILABLE,
        "corrupt policy response: {corrupt:?}"
    );
    ensure!(
        corrupt.1.get("grants").is_none(),
        "corrupt policy leaked grants: {corrupt:?}"
    );
    // Runtime admission and data access both fail closed on PG permission drift.
    pg("REVOKE SELECT ON mdm_access.authorization_rules FROM mdm_access")?;
    let denied = member
        .call(&router, Method::GET, "/api/v1/authorization", None)
        .await;
    let context = admin
        .call(
            &router,
            Method::GET,
            &format!(
                "/api/v1/identity-host/tenants/{TENANT}/context",
                TENANT = case_tenant()
            ),
            None,
        )
        .await;
    let reconnect = crate::Database::connect(config.access_options()?, &config.audit).await;
    pg("GRANT SELECT ON mdm_access.authorization_rules TO mdm_access")?;
    let denied = denied?;
    let context = context?;
    ensure!(
        denied.0 == StatusCode::SERVICE_UNAVAILABLE,
        "permission drift response: {denied:?}"
    );
    ensure!(
        denied.1.get("grants").is_none(),
        "permission drift leaked grants: {denied:?}"
    );
    ensure!(
        matches!(reconnect, Err(crate::Error::Unavailable(crate::Failure::AccessAdmission))),
        "permission drift admitted a new access store"
    );
    ensure!(
        context.0 == StatusCode::SERVICE_UNAVAILABLE,
        "permission drift navigation: {context:?}"
    );
    ensure!(
        context.1.get("navigation").is_none() && context.1.get("grants").is_none(),
        "permission drift leaked navigation: {context:?}"
    );
    let restored = admin
        .call(
            &router,
            Method::GET,
            &format!("/api/v1/identity-host/tenants/{}/context", case_tenant()),
            None,
        )
        .await?;
    ensure!(
        restored.0 == StatusCode::OK,
        "restored navigation response: {restored:?}"
    );
    ensure!(
        restored.1["navigation"]["manageAccounts"] == true,
        "restored navigation: {restored:?}"
    );
    // The union rejects undeclared objects, grants and permissive tenant policies.
    for (drift, restore) in [
        ("GRANT UPDATE(configuration) ON mdm_access.enrollment_intents TO mdm_access", "REVOKE UPDATE(configuration) ON mdm_access.enrollment_intents FROM mdm_access"),
        ("GRANT UPDATE(state) ON mdm_access.grants TO mdm_access", "REVOKE UPDATE(state) ON mdm_access.grants FROM mdm_access"),
        ("ALTER POLICY expired_only ON mdm_access.management_sessions USING(true)", "ALTER POLICY expired_only ON mdm_access.management_sessions USING(expires_at<clock_timestamp())"),

        (
            "GRANT INSERT ON mdm_access.asset_authority_history TO mdm_access",
            "REVOKE INSERT ON mdm_access.asset_authority_history FROM mdm_access",
        ),
        (
            "REVOKE SELECT ON mdm_access.asset_authority_history FROM mdm_access",
            "GRANT SELECT ON mdm_access.asset_authority_history TO mdm_access",
        ),
        (
            "GRANT INSERT ON mdm_access.collection_history TO mdm_access",
            "REVOKE INSERT ON mdm_access.collection_history FROM mdm_access",
        ),
        (
            "REVOKE SELECT ON mdm_access.collection_history FROM mdm_access",
            "GRANT SELECT ON mdm_access.collection_history TO mdm_access",
        ),
        (
            "GRANT UPDATE (instance) ON mdm_access.authorization_rules TO mdm_access",
            "REVOKE UPDATE (instance) ON mdm_access.authorization_rules FROM mdm_access",
        ),
        (
            "CREATE TABLE mdm_agent.unexpected(tenant_id uuid)",
            "DROP TABLE mdm_agent.unexpected",
        ),
        (
            "CREATE POLICY bypass ON mdm_access.authorization_rules USING(true)",
            "DROP POLICY bypass ON mdm_access.authorization_rules",
        ),
        (
            "GRANT SELECT ON mdm_access.authorization_rules TO mdm_access WITH GRANT OPTION",
            "REVOKE GRANT OPTION FOR SELECT ON mdm_access.authorization_rules FROM mdm_access",
        ),
    ] {
        pg(drift)?;
        let rejected = crate::Database::connect(config.access_options()?, &config.audit).await;
        pg(restore)?;
        ensure!(matches!(rejected, Err(crate::Error::Unavailable(crate::Failure::AccessAdmission))), "undeclared access privilege admitted: {drift}");
        crate::Database::connect(config.access_options()?, &config.audit).await?.close().await;
    }
    // Authorization, Compliance and Group do not consume this Apple table.
    // Command does consume it and must reject the drift; its admission tests own that proof.
    pg("ALTER TABLE mdm_apple.devices NO FORCE ROW LEVEL SECURITY")?;
    let isolated = async {
        let mut authority = crate::test_support::authority::Authority::open().await?;
        let mut owners = std::mem::take(&mut authority.resources);
        let tenant = authority.identity.tenant;
        let runtime = crate::planning::test_support::runtime(tenant).await;
        owners.resource(SourceResource(runtime.clone()));
        let key = crate::cursor_keys::load(&runtime, tenant).await?;
        let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(5));
        let audit = Arc::new(authority.audit.on_runtime(runtime.clone(), tenant, &budget.control()).await?);
        let planning = rss_mdm_policy_service::application::Application::new(audit.clone(), runtime, tenant, Arc::new(crate::clock::SystemClock), &key,
            Arc::new(rss_mdm_device_service::planning::PlanningObjects::new(audit))).await?;
        let compliance = crate::planning::test_support::compliance(&planning).await;
        owners.finish(async {
            let router = authority.router(authority.authorization().nest("/api/v1",
                rss_mdm_management_http::compliance::http::routes().with_state(compliance)))?;
            let mut browser = authority.browser("admin")?;
            identity::seed_grants(case_tenant(), &prepared_subject(&browser)?, vec![crate::authorization::Grant { operation: crate::authorization::Permission::ComplianceRuleRead, scope: crate::authorization::Scope::Tenant }]).await?;
            ensure!(browser.call(&router, Method::GET, "/api/v1/authorization", None).await?.0 == StatusCode::OK);
            let rules = browser.call(&router, Method::GET, "/api/v1/compliance-rules", None).await?;
            ensure!(rules.0 == StatusCode::OK && rules.1["items"].is_array(), "isolated Compliance query: {rules:?}");
            ensure!(crate::planning::test_support::group_store(&planning).await.get(rss_mdm_group::GroupId::parse(&Uuid::new_v4().to_string())?, crate::identity::deadline()).await?.is_none());
            Ok(())
        }).await
    }.await;
    let complete_app = crate::Database::connect(config.access_options()?, &config.audit).await;
    pg("ALTER TABLE mdm_apple.devices FORCE ROW LEVEL SECURITY")?;
    isolated?;
    ensure!(matches!(complete_app, Err(crate::Error::Unavailable(crate::Failure::AccessAdmission))), "full App admitted a damaged Apple contract");
    let (identity, identity_resources) =
        crate::test_support::identity::identity(case_tenant()).await?;
    identity_resources.finish(async {
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
    let mut paused = false;
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
        paused = true;
        tokio::time::sleep(Duration::from_millis(3200)).await;
        anyhow::Ok(())
    };
    let (stalled, frozen) = tokio::join!(
        tokio::time::timeout(
            Duration::from_secs(4),
            crate::authorization::store::authorization_snapshot(&store, &stale)
        ),
        freeze
    );
    // Cleanup precedes propagating either task's failure, so an observation error
    // cannot strand the isolated PG instance or its exclusive table lock.
    let unpaused = if paused {
        command(&["unpause", &container], None)
    } else {
        Ok(String::new())
    };
    if let Err(error) = unpaused {
        drop(holder);
        anyhow::bail!("PG unpause cleanup failed: {error}; stalled scenario: {frozen:?}");
    }
    let cleanup = tokio::time::timeout(Duration::from_secs(2), async {
        let rolled_back = sqlx::query("ROLLBACK").execute(&mut holder).await;
        let closed = holder.close().await;
        rolled_back?;
        closed?;
        anyhow::Ok(())
    })
    .await;
    frozen?;
    cleanup.map_err(|_| anyhow::anyhow!("stalled PG cleanup deadline"))??;
    ensure!(matches!(
        stalled,
        Ok(Err(rss_mdm_authorization_service::Error::Deadline))
    ));
    ensure!(
        member
            .call(&router, Method::GET, "/api/v1/authorization", None)
            .await?
            .0
            == StatusCode::OK
    );

    Ok(())
    }).await
    }).await
}
