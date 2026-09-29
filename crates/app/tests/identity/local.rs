#![allow(
    clippy::cognitive_complexity,
    reason = "test scenarios preserve distinct recovery assertions"
)]
use crate::test_support::*;
#[tokio::test]
#[ignore = "MODULE=identity.local: real authority and PostgreSQL"]
async fn local_identity_mdm_authorization_and_revocation() -> Result<()> {
    let fixture = authority::Authority::open().await?;
    let initial = fixture.router(fixture.authorization().merge(fixture.enrollment()))?;
    let mut browser = Browser::default();
    ensure!(browser.login(&initial, "other").await? == StatusCode::OK);
    let credential = &browser.cookies["__Host-identity-session"];
    for (method, path) in [
        (Method::GET, "/api/v1/authorization".to_owned()),
        (Method::GET, format!("/api/v2/tenants/{TENANT}/session")),
        (Method::POST, "/api/v3/enrollments".to_owned()),
    ] {
        for cookie in [
            format!("__Host-identity-session={credential}; broken"),
            format!("__Host-identity-session={credential}; __Host-identity-session={credential}"),
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
    ensure!(me["instanceId"] == INSTANCE && me["tenantId"] == TENANT && me["grants"] == json!([]));
    let subject = me["principalId"].as_str().unwrap();
    // Reconstruct the authority and routes to prove session persistence across host restarts.
    let restarted = authority::Authority::open().await?;
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
}

async fn native_accounts(
    admin_router: &Router,
    product: &Router,
    browser: &mut Browser,
    principal: &str,
) -> Result<()> {
    let tenant = format!("/api/v2/tenants/{TENANT}");
    let mut admin = Browser::default();
    ensure!(admin.login(admin_router, "admin").await? == StatusCode::OK);
    let account = format!("{tenant}/accounts/{principal}");
    ensure!(
        browser
            .call(product, Method::GET, &format!("{tenant}/accounts"), None)
            .await?
            .0
            == StatusCode::FORBIDDEN
    );
    ensure!(
        admin
            .call(
                admin_router,
                Method::POST,
                &format!("{tenant}/accounts/{ADMIN}/enabled"),
                Some(json!({"enabled":false}))
            )
            .await?
            .0
            == StatusCode::FORBIDDEN
    );
    // Passive product queries do not extend idle; the current cookie survives a process restart.
    let before = pg(&format!(
        "SELECT jsonb_agg(idle_expires_at ORDER BY session_id)::text FROM identity_authority.sessions WHERE tenant_id='{TENANT}' AND principal_id='{principal}'"
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
                "SELECT jsonb_agg(idle_expires_at ORDER BY session_id)::text FROM identity_authority.sessions WHERE tenant_id='{TENANT}' AND principal_id='{principal}'"
            ))?
    );
    // Successful authentication cannot be reused while the authority becomes unavailable.
    pg("REVOKE SELECT ON identity_authority.sessions FROM mdm_identity_runtime")?;
    let denied = browser
        .call(product, Method::GET, "/api/v1/authorization", None)
        .await?;
    pg("GRANT SELECT ON identity_authority.sessions TO mdm_identity_runtime")?;
    ensure!(denied.0 == StatusCode::SERVICE_UNAVAILABLE && denied.1.get("roles").is_none());
    let identity = crate::test_support::identity::identity(TENANT).await?;
    let credentials = crate::enrollment::credentials::Credentials::new(monotonic(), 16);
    let cache = |browser: &Browser| -> Result<uuid::Uuid> {
        Ok(
            credentials.insert(rss_identity_core::session::SessionSecret::parse(
                browser.cookies["__Host-identity-session"].clone(),
            )?)?,
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
        ensure!(
            identity
                .authenticate(credentials.get(reference)?)
                .await
                .is_err()
        );
        *browser = Browser::default();
        ensure!(browser.login(product, "other").await? == StatusCode::OK);
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
    ensure!(
        identity
            .authenticate(credentials.get(reference)?)
            .await
            .is_err()
    );
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
    ensure!(
        identity
            .authenticate(credentials.get(logout_reference)?)
            .await
            .is_err()
    );
    *browser = Browser::default();
    ensure!(browser.login(product, "other").await? == StatusCode::OK);
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
    ensure!(
        identity
            .authenticate(credentials.get(password_reference)?)
            .await
            .is_err()
    );
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
    let wrong_tenant = "/api/v2/tenants/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/session";
    ensure!(
        admin
            .call(admin_router, Method::GET, wrong_tenant, None)
            .await?
            .0
            == StatusCode::UNAUTHORIZED
    );
    // Product planning policy asks the component for Recent(300s), including native accounts.
    pg(&format!(
        "UPDATE identity_authority.sessions SET auth_time=auth_time-301,absolute_expires_at=absolute_expires_at-301 WHERE tenant_id='{TENANT}' AND principal_id='{ADMIN}'"
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
        "UPDATE identity_authority.sessions SET auth_time=auth_time+301,absolute_expires_at=absolute_expires_at+301 WHERE tenant_id='{TENANT}' AND principal_id='{ADMIN}'"
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
            && enrollment.is_err()
    );
    Ok(())
}
