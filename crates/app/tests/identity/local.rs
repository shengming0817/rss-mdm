#![allow(
    clippy::cognitive_complexity,
    reason = "test scenarios preserve distinct recovery assertions"
)]
use crate::test_support::{http::*, process::*, runtime::*, *};
use anyhow::Context;
#[tokio::test]
#[ignore = "MODULE=identity.local: real authority and PostgreSQL"]
async fn local_identity_mdm_authorization_and_revocation() -> Result<()> {
    let mut fixture = authority::Authority::open().await?;
    let fixture_resources = std::mem::take(&mut fixture.resources);
    fixture_resources
        .finish(async {
            let initial = fixture.router(fixture.authorization().merge(fixture.enrollment()))?;
            let management = fixture.identity.management_tenant.to_string();
            let mut initializer = Browser::default();
            let login = initializer
                .call(
                    &initial,
                    Method::POST,
                    &format!("/api/v1/identity/tenants/{management}/login"),
                    Some(json!({"login":"bootstrap","password":PASSWORD})),
                )
                .await?;
            ensure!(login.0 == StatusCode::OK);
            let principal = login.1["identity"]["principalId"]
                .as_str()
                .context("management initializer")?;
            let disabled = initializer
                .call(
                    &initial,
                    Method::POST,
                    &format!("/api/v1/identity/tenants/{management}/accounts/{principal}/enabled"),
                    Some(json!({"enabled":false})),
                )
                .await?;
            ensure!(disabled.0 == StatusCode::FORBIDDEN);
            ensure!(
                initializer
                    .call(
                        &initial,
                        Method::GET,
                        &format!("/api/v1/identity/tenants/{management}/session"),
                        None
                    )
                    .await?
                    .0
                    == StatusCode::OK
            );
            let mut browser = Browser::default();
            ensure!(browser.login_password(&initial, "other", PASSWORD).await? == StatusCode::OK);
            let credential = &browser.cookies["__Host-identity-session"];
            for (method, path) in [
                (Method::GET, "/api/v1/authorization".to_owned()),
                (
                    Method::GET,
                    format!(
                        "/api/v1/identity/tenants/{TENANT}/session",
                        TENANT = case_tenant()
                    ),
                ),
                (Method::POST, "/api/v1/enrollments".to_owned()),
            ] {
                for cookie in [
                    format!("__Host-identity-session={credential}; broken"),
                    format!(
                        "__Host-identity-session={credential}; __Host-identity-session={credential}"
                    ),
                ] {
                    let request = Request::builder()
                        .method(method.clone())
                        .uri(&path)
                        .header("host", "mdm.example.test")
                        .header("origin", "https://mdm.example.test")
                        .header("x-identity-request", "1")
                        .header("x-csrf-token", browser.csrf.as_ref().unwrap())
                        .header("cookie", cookie)
                        .body(Body::empty())?;
                    let response = initial.clone().oneshot(request).await?;
                    ensure!(
                        response.status() == StatusCode::BAD_REQUEST,
                        "strict host cookie boundary: {method} {path} returned {}",
                        response.status()
                    );
                    ensure!(!response.headers().contains_key("set-cookie"));
                }
            }
            let (_, me) = browser
                .call(&initial, Method::GET, "/api/v1/authorization", None)
                .await?;
            ensure!(
                me["instanceId"] == INSTANCE
                    && me["tenantId"] == case_tenant()
                    && me["grants"] == json!([])
            );
            let subject = me["principalId"].as_str().unwrap();
            // Reconstruct the authority and routes to prove session persistence across host restarts.
            let mut restarted = authority::Authority::open().await?;
            let restarted_resources = std::mem::take(&mut restarted.resources);
            restarted_resources
                .finish(async {
                    let authorized = restarted.router(restarted.authorization())?;
                    Box::pin(native_accounts(
                        &initial,
                        &authorized,
                        &mut browser,
                        subject,
                    ))
                    .await?;
                    println!("MDM_LOCAL_AUTHORITY_MATRIX_PASSED");
                    Ok(())
                })
                .await
        })
        .await
}

async fn native_accounts(
    admin_router: &Router,
    product: &Router,
    browser: &mut Browser,
    principal: &str,
) -> Result<()> {
    let tenant = format!("/api/v1/identity/tenants/{TENANT}", TENANT = case_tenant());
    let mut admin = Browser::default();
    ensure!(
        admin
            .login_password(admin_router, "admin", PASSWORD)
            .await?
            == StatusCode::OK
    );
    let account = format!("{tenant}/accounts/{principal}");
    ensure!(
        browser
            .call(product, Method::GET, &format!("{tenant}/accounts"), None)
            .await?
            .0
            == StatusCode::FORBIDDEN
    );
    // A business-tenant administrator is not the installation initializer.
    // Prove actual revocation using the independent member, leaving admin live
    // to exercise the remaining membership/password/session revocation matrix.
    set_management_grants(principal, json!(["identity_accounts_manage"])).await?;
    ensure!(
        browser
            .call(product, Method::GET, &format!("{tenant}/accounts"), None)
            .await?
            .0
            == StatusCode::OK
    );
    set_management_grants(principal, json!([])).await?;
    let target_state = || {
        pg(&format!(
            "SELECT jsonb_build_object('account',(SELECT to_jsonb(a) FROM identity_authority.accounts a WHERE tenant_id='{tenant}' AND principal_id='{target}'),'membership',(SELECT to_jsonb(m) FROM identity_authority.memberships m WHERE tenant_id='{tenant}' AND principal_id='{target}'),'sessions',(SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY session_id),'[]'::jsonb) FROM identity_authority.sessions s WHERE tenant_id='{tenant}' AND principal_id='{target}'))::text",
            tenant = case_tenant(),
            target = case_admin()
        ))
    };
    let before = target_state()?;
    let denied = browser
        .call(
            product,
            Method::POST,
            &format!("{tenant}/accounts/{}/enabled", case_admin()),
            Some(json!({"enabled":false})),
        )
        .await?;
    ensure!(
        denied.0 == StatusCode::FORBIDDEN,
        "revoked account manager: {denied:?}"
    );
    ensure!(
        before == target_state()?,
        "denied account disable mutated identity state"
    );
    // Passive product queries do not extend idle; the current cookie survives a process restart.
    let before = pg(&format!(
        "SELECT jsonb_agg(idle_expires_at ORDER BY session_id)::text FROM identity_authority.sessions WHERE tenant_id='{TENANT}' AND principal_id='{principal}'",
        TENANT = case_tenant()
    ))?;
    for _ in 0..2 {
        ensure!(
            browser
                .call(product, Method::GET, "/api/v1/authorization", None)
                .await?
                .0
                == StatusCode::OK
        );
    }
    ensure!(
        before
            == pg(&format!(
                "SELECT jsonb_agg(idle_expires_at ORDER BY session_id)::text FROM identity_authority.sessions WHERE tenant_id='{TENANT}' AND principal_id='{principal}'",
                TENANT = case_tenant()
            ))?
    );
    // Successful authentication cannot be reused while the authority becomes unavailable.
    pg("REVOKE SELECT ON identity_authority.sessions FROM mdm_identity_runtime")?;
    let denied = browser
        .call(product, Method::GET, "/api/v1/authorization", None)
        .await?;
    pg("GRANT SELECT ON identity_authority.sessions TO mdm_identity_runtime")?;
    ensure!(denied.0 == StatusCode::SERVICE_UNAVAILABLE && denied.1.get("roles").is_none());
    let (identity, identity_resources) =
        crate::test_support::identity::identity(case_tenant()).await?;
    identity_resources.finish(async {
    let credentials = crate::enrollment::credentials::Credentials::new(monotonic(), 16);
    let cache = |browser: &Browser| -> Result<uuid::Uuid> {
        Ok(
            credentials.insert(rss_mdm_authorization_service::credential::RequestCredential::Cookie(rss_identity_core::session::SessionSecret::parse(
                browser.cookies["__Host-identity-session"].clone(),
            )?))?,
        )
    };
    for state in ["membership", "enabled"] {
        let reference = cache(browser)?;
        ensure!(
            admin
                .call(
                    admin_router,
                    Method::POST,
                    &format!("{account}/{state}"),
                    Some(json!({"enabled":false}))
                )
                .await?
                .0
                == StatusCode::OK
        );
        ensure!(
            browser
                .call(product, Method::GET, "/api/v1/authorization", None)
                .await?
                .0
                == StatusCode::UNAUTHORIZED
        );
        ensure!(
            admin
                .call(
                    admin_router,
                    Method::POST,
                    &format!("{account}/{state}"),
                    Some(json!({"enabled":true}))
                )
                .await?
                .0
                == StatusCode::OK
        );
        ensure!(matches!(identity
                .authenticate(credentials.get(reference)?)
                .await, Err(crate::Error::Unauthorized)));
        *browser = Browser::default();
        ensure!(browser.login_password(product, "other", PASSWORD).await? == StatusCode::OK);
    }
    let reference = cache(browser)?;
    let mut stale = browser.clone();
    ensure!(
        browser
            .call(
                product,
                Method::POST,
                &format!("{tenant}/session/refresh"),
                None
            )
            .await?
            .0
            == StatusCode::OK
    );
    ensure!(matches!(identity
            .authenticate(credentials.get(reference)?)
            .await, Err(crate::Error::Unauthorized)));
    let logout_reference = cache(browser)?;
    ensure!(
        stale
            .call(product, Method::GET, "/api/v1/authorization", None)
            .await?
            .0
            == StatusCode::UNAUTHORIZED
    );
    ensure!(
        browser
            .call(
                product,
                Method::POST,
                &format!("{tenant}/session/logout"),
                None
            )
            .await?
            .0
            == StatusCode::NO_CONTENT
    );
    ensure!(
        browser
            .call(product, Method::GET, "/api/v1/authorization", None)
            .await?
            .0
            == StatusCode::UNAUTHORIZED
    );
    ensure!(matches!(identity
            .authenticate(credentials.get(logout_reference)?)
            .await, Err(crate::Error::Unauthorized)));
    *browser = Browser::default();
    ensure!(browser.login_password(product, "other", PASSWORD).await? == StatusCode::OK);
    let password_reference = cache(browser)?;
    ensure!(
        admin
            .call(
                admin_router,
                Method::POST,
                &format!("{account}/password"),
                Some(json!({"password":"Changed-fixture-password-2026!"}))
            )
            .await?
            .0
            == StatusCode::OK
    );
    ensure!(
        browser
            .call(product, Method::GET, "/api/v1/authorization", None)
            .await?
            .0
            == StatusCode::UNAUTHORIZED
    );
    ensure!(matches!(identity
            .authenticate(credentials.get(password_reference)?)
            .await, Err(crate::Error::Unauthorized)));
    ensure!(
        admin
            .call(
                admin_router,
                Method::POST,
                &format!("{account}/password"),
                Some(json!({"password":PASSWORD}))
            )
            .await?
            .0
            == StatusCode::OK
    );
    // The component owns its atomic security event; a second product audit cannot
    // overwrite a committed account mutation or discard the native response.
    pg("REVOKE INSERT ON mdm_audit.receipts FROM mdm_access,mdm_flow_runtime")?;
    let created = admin
        .call(
            admin_router,
            Method::POST,
            &format!("{tenant}/accounts"),
            Some(json!({"login":"managed-user","password":PASSWORD})),
        )
        .await;
    pg("GRANT INSERT ON mdm_audit.receipts TO mdm_access,mdm_flow_runtime")?;
    let created = created?;
    ensure!(created.0 == StatusCode::CREATED && created.1["principalId"].is_string());
    let mut managed = Browser::default();
    ensure!(managed.login(admin_router, "managed-user").await? == StatusCode::OK);
    ensure!(managed.call(admin_router, Method::POST, &format!("{tenant}/account/password"), Some(json!({"currentPassword":PASSWORD,"password":"Self-changed-fixture-password-2026!"}))).await?.0 == StatusCode::OK);
    let wrong_tenant = &format!("/api/v1/identity/tenants/{}/session", case::peer());
    ensure!(
        admin
            .call(admin_router, Method::GET, wrong_tenant, None)
            .await?
            .0
            == StatusCode::UNAUTHORIZED
    );
    // Product planning policy asks the component for Recent(300s), including native accounts.
    pg(&format!(
        "UPDATE identity_authority.sessions SET local_authenticated_at=local_authenticated_at-301 WHERE tenant_id='{TENANT}' AND principal_id='{ADMIN}'",
        ADMIN = case_admin(),
        TENANT = case_tenant()
    ))?;
    let stale_management = admin
        .call(
            admin_router,
            Method::POST,
            &format!("{tenant}/accounts"),
            Some(json!({"login":"stale-must-not-create","password":PASSWORD})),
        )
        .await;
    let passive = admin
        .call(
            admin_router,
            Method::GET,
            &format!("{tenant}/accounts"),
            None,
        )
        .await;
    pg(&format!(
        "UPDATE identity_authority.sessions SET local_authenticated_at=local_authenticated_at+301 WHERE tenant_id='{TENANT}' AND principal_id='{ADMIN}'",
        ADMIN = case_admin(),
        TENANT = case_tenant()
    ))?;
    let stale_management = stale_management?;
    ensure!(
        stale_management.0 == StatusCode::FORBIDDEN
            && stale_management.1["code"] == "reauthentication_required"
    );
    ensure!(passive?.0 == StatusCode::OK);
    ensure!(pg("SELECT count(*) FROM identity_authority.local_credentials WHERE login_key='stale-must-not-create'")?.trim() == "0");
    let container = std::env::var("MDM_TEST_PG_CONTAINER")?;
    let reference = cache(&admin)?;
    command(&["pause", &container], None)?;
    let (http, enrollment) = tokio::join!(
        admin.call(admin_router, Method::GET, "/api/v1/authorization", None),
        identity.authenticate(credentials.get(reference)?)
    );
    command(&["unpause", &container], None)?;
    let http = http?;
    ensure!(
        http.0 == StatusCode::SERVICE_UNAVAILABLE
            && http.1.get("roles").is_none()
            && matches!(enrollment, Err(crate::Error::Unavailable(crate::Failure::IdentityStorage)))
    );
    Ok(())
    }).await
}
