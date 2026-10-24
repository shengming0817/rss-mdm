use super::*;
use crate::audit_test_support::audit_count;
use anyhow::Context;

#[tokio::test]
#[ignore = "MODULE=authorization.rules: real authorization contract"]
async fn rules_cas_replay_revocation_and_escalation() -> Result<()> {
    let Fixture {
        resources,
        base,
        router,
        mut admin,
        mut member,
        subject,
        store,
        ..
    } = fixture().await?;
    resources.finish(async {
    ensure!(
        member
            .call(&router, Method::GET, "/api/v1/authorization/rules", None)
            .await?
            .0
            == StatusCode::FORBIDDEN
    );
    for (suffix, action, allowed) in [
        ("", "authorization_effective_read", true),
        ("/rules", "authorization_rules_read", false),
        ("/user-groups", "authorization_groups_read", false),
        ("/departments", "authorization_departments_read", false),
    ] {
        let path = format!("/api/v1/authorization{suffix}");
        for (browser, expected) in [
            (&mut admin, 200),
            (&mut member, if allowed { 200 } else { 403 }),
        ] {
            let before = audit_count(|r| r.action() == action && r.status() == expected).await?;
            ensure!(
                browser
                    .call(&router, Method::GET, &path, None)
                    .await?
                    .0
                    .as_u16()
                    == expected
            );
            let after = audit_count(|r| r.action() == action && r.status() == expected).await?;
            ensure!(
                after == before + 1,
                "authorization read audit action missing: {action}"
            );
        }
    }
    let rule_id = Uuid::new_v4();
    let key = Uuid::new_v4();
    let path = format!("/api/v1/authorization/rules/{rule_id}");
    let value = json!({"subject":user(&subject),"grants":[grant("enrollment",json!({"kind":"device","id":"a"})),grant("inventory_read",json!({"kind":"device","id":"a"})),grant("device_wipe",json!({"kind":"device","id":"b"}))]});
    let created = put(&mut admin, &router, &path, key, 0, value.clone()).await?;
    ensure!(created.0 == StatusCode::OK && created.1["revision"] == 1);
    ensure!(
        put(&mut admin, &router, &path, key, 0, value.clone())
            .await?
            == created
    );
    ensure!(
        put(&mut admin, &router, &path, key, 0, Value::Null)
            .await?
            .0
            == StatusCode::CONFLICT
    );
    let effective = member.call(&router, Method::GET, "/api/v1/authorization", None).await?;
    ensure!(effective.0 == StatusCode::OK);
    for permission in ["enrollment", "inventory_read"] {
        ensure!(effective.1["grants"].as_array().unwrap().iter().any(|g| g["operation"] == permission && g["scope"] == json!({"kind":"device","id":"a"}) && g["ruleId"] == json!(rule_id) && g["ruleRevision"] == 1));
    }
    for (device, expected) in [("a", StatusCode::NOT_FOUND), ("b", StatusCode::FORBIDDEN)] {
        ensure!(
            member
                .call(
                    &router,
                    Method::GET,
                    &format!("/api/v1/devices/{device}/inventory"),
                    None
                )
                .await?
                .0
                == expected
        );
    }
    for (device, expected) in [
        ("a", StatusCode::FORBIDDEN),
        ("b", StatusCode::NOT_IMPLEMENTED),
    ] {
        ensure!(
            member
                .call(
                    &router,
                    Method::POST,
                    &format!("/api/v1/devices/{device}/actions"),
                    Some(json!({"action":"wipe"}))
                )
                .await?
                .0
                == expected
        );
    }
    let mut a = admin.clone();
    let mut b = admin.clone();
    use sqlx::Connection;
    let mut root = sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?).await?;
    let mut hold = root.begin().await?;
    rss_mdm_authorization_service::lock_on(&mut hold, case_tenant(), INSTANCE).await?;
    let release = async {
        let observed = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let waiting: bool = sqlx::query_scalar("WITH RECURSIVE blocked(pid) AS (SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND pg_backend_pid()=ANY(pg_blocking_pids(pid)) UNION SELECT a.pid FROM pg_stat_activity a JOIN blocked b ON b.pid=ANY(pg_blocking_pids(a.pid)) WHERE a.datname=current_database()) SELECT count(*)=2 FROM blocked").fetch_one(&mut *hold).await?;
                if waiting { return Ok::<_, sqlx::Error>(()); }
                sqlx::query("SELECT pg_stat_clear_snapshot()").execute(&mut *hold).await?;
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }).await;
        hold.rollback().await?;
        observed.context("both CAS requests must overlap")??;
        Ok::<_, anyhow::Error>(())
    };
    let (first, second, released) = tokio::join!(
        put(&mut a, &router, &path, Uuid::new_v4(), 1, value.clone()),
        put(&mut b, &router, &path, Uuid::new_v4(), 1, value.clone()),
        release
    );
    released?;
    root.close().await?;
    let current = admin.call(&router, Method::GET, "/api/v1/authorization/rules", None).await?;
    ensure!(current.0 == StatusCode::OK);
    ensure!(current.1["items"].as_array().unwrap().iter().find(|r| r["id"] == json!(rule_id)).context("CAS rule")?["revision"] == 2);
    let mut statuses = [first?.0.as_u16(), second?.0.as_u16()];
    statuses.sort();
    ensure!(statuses == [200, 409]);
    ensure!(
        put(&mut admin, &router, &path, Uuid::new_v4(), 2, Value::Null)
            .await?
            .0
            == StatusCode::OK
    );
    // Returning an old receipt never restores a revoked document.
    ensure!(
        put(&mut admin, &router, &path, key, 0, value.clone())
            .await?
            == created
    );
    ensure!(
        put(&mut admin, &router, &path, Uuid::new_v4(), 3, value)
            .await?
            .0
            == StatusCode::CONFLICT
    );
    let (restarted, _, app_resources) = app_with_access(&base, database(&base).await?).await?;
    app_resources.finish(async {
    ensure!(
        member
            .call(
                &restarted,
                Method::POST,
                "/api/v1/devices/b/actions",
                Some(json!({"action":"wipe"}))
            )
            .await?
            .0
            == StatusCode::FORBIDDEN
    );
    ensure!(
        audit_count(|r| r.source() == "mdm.business"
            && r.operation() == Some(key.to_string().as_str())
            && r.result() == "success").await?
            == 1
    );
    // A proof loaded before revocation cannot later mutate authorization state.
    let writer_id = Uuid::new_v4();
    let writer_path = format!("/api/v1/authorization/rules/{writer_id}");
    let writer_rule = json!({"subject":user(&subject),"grants":[grant("authorization_write",json!({"kind":"tenant"}))]});
    ensure!(
        put(
            &mut admin,
            &router,
            &writer_path,
            Uuid::new_v4(),
            0,
            writer_rule
        )
        .await?
        .0 == StatusCode::OK
    );
    let (identity, identity_resources) = crate::test_support::identity::identity(case_tenant()).await?;
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
    .load_authorization(store.authorization())
    .await?;
    ensure!(
        put(
            &mut admin,
            &router,
            &writer_path,
            Uuid::new_v4(),
            1,
            Value::Null
        )
        .await?
        .0 == StatusCode::OK
    );
    let audit =
        rss_mdm_audit_integration::RequestAudit::new(case_tenant().into(), "authorization_write");
    let foreign_audit = rss_mdm_audit_integration::RequestAudit::new(
        Uuid::new_v4().to_string(),
        "authorization_write",
    );
    ensure!(matches!(
        stale.bind_audit(&foreign_audit),
        Err(rss_mdm_authorization_service::Error::Forbidden)
    ));
    ensure!(foreign_audit.snapshot().actor.is_none());
    foreign_audit.finalize(None);
    stale.bind_audit(&audit).unwrap();
    let stale_key = Uuid::new_v4();
    let rejected = crate::authorization::store::change_rule(store.audit_store_fixture(&crate::config::AuditConfig::Plain).await?.as_ref(), &stale, Uuid::new_v4(), crate::authorization::Change {
        operation_id:stale_key, expected_revision:0, value:Some(serde_json::from_value(json!({"subject":user(&subject),"grants":[grant("group_read",json!({"kind":"tenant"}))]}))?)
    }, &audit).await;
    audit.finalize(None);
    let stale_denied = matches!(
        rejected,
        Err(rss_mdm_authorization_service::Error::Forbidden)
    );
    // Membership administration cannot confer a group's unrelated authority.
    let privilege_group = Uuid::new_v4();
    let privilege_group_path = format!("/api/v1/authorization/user-groups/{privilege_group}");
    ensure!(
        put(
            &mut admin,
            &router,
            &privilege_group_path,
            Uuid::new_v4(),
            0,
            json!({"name":"privileged","enabled":true,"members":[]})
        )
        .await?
        .0 == StatusCode::OK
    );
    let group_rule = format!("/api/v1/authorization/rules/{}", Uuid::new_v4());
    ensure!(put(&mut admin, &router, &group_rule, Uuid::new_v4(), 0, json!({"subject":{"kind":"user_group","id":privilege_group},"grants":[grant("authorization_write",json!({"kind":"tenant"}))]})).await?.0 == StatusCode::OK);
    let member_rule = format!("/api/v1/authorization/rules/{}", Uuid::new_v4());
    ensure!(put(&mut admin, &router, &member_rule, Uuid::new_v4(), 0, json!({"subject":user(&subject),"grants":[grant("user_group_write",json!({"kind":"tenant"}))]})).await?.0 == StatusCode::OK);
    let escalation_key = Uuid::new_v4();
    let escalation = put(
        &mut member,
        &router,
        &privilege_group_path,
        escalation_key,
        1,
        json!({"name":"privileged","enabled":true,"members":[user(&subject)["user"].clone()]}),
    )
    .await?;
    let escalation_denied = escalation.0 == StatusCode::FORBIDDEN;
    let group = admin.call(&router, Method::GET, &format!("{privilege_group_path}/members"), None).await?;
    ensure!(group.0 == StatusCode::OK && group.1["revision"] == 1 && group.1["items"] == json!([]));
    for operation in [stale_key, escalation_key] {
        ensure!(pg(&format!("SELECT count(*) FROM mdm_access.authorization_operations WHERE tenant_id='{}' AND operation_id='{operation}'", case_tenant()))?.trim() == "0");
        ensure!(audit_count(|r| r.source() == "mdm.business" && r.operation() == Some(operation.to_string().as_str()) && r.result() == "success").await? == 0);
    }

    ensure!(
        stale_denied && escalation_denied,
        "stale writer denied={stale_denied}; group escalation denied={escalation_denied}"
    );

    Ok(())
    }).await
    }).await
    }).await
}
#[tokio::test]
#[ignore = "real Identity + PG with independently constructed capability routers"]
async fn capability_routes_without_application_preserve_revocation_and_atomicity() -> Result<()> {
    use crate::authorization::http::{AuthenticationState, HttpState};
    use crate::enrollment::{EnrollmentService, credentials::Credentials};
    use axum::middleware;
    let config = crate::test_support::identity::config(case_tenant())?;
    let (identity, identity_resources) =
        crate::test_support::identity::identity(case_tenant()).await?;
    let identity = Arc::new(identity);
    identity_resources.finish(async {
    let access =
        Arc::new(crate::database::Database::connect(config.access_options()?).await?);
    let monotonic: Arc<dyn rss_observation::Clock> = Arc::new(crate::Monotonic(|| {
        rss_request_context::Clock::now(&crate::lifecycle::RuntimeTimer)
    }));
    let requests = Arc::new(tokio::sync::Semaphore::new(4));
    let authentication = Arc::new(AuthenticationState {
        identity: identity.browser(),
        access: access.authorization_store(),
        requests: requests.clone(),
    });
    let enrollment = Arc::new(crate::enrollment::http::HttpState {
        channels: Arc::new(crate::test_support::authority::RegistrationChannels),
        native: Arc::new(crate::enrollment_progress::EnrollmentProgress {
            sessions: Arc::new(
                rss_mdm_authorization_service::session::SessionAuthority::new(
                    identity.authority.clone(),
                    identity.tenant,
                ),
            ),
            windows: None,
            apple: None,
        }),
        service: Arc::new(EnrollmentService::new(
            access.registration(),
            Arc::new(Credentials::new(monotonic.clone(), 16)),
            access.audit_store_fixture(&config.audit).await?,
        )),
        devices: Arc::new(crate::device::DeviceService::new(
            access.registration(),
            case_tenant().into(),
            access
                .audit_store_fixture(&crate::config::AuditConfig::Plain)
                .await?,
        )),
        apple: false,
        windows: true,
    });
    let protected = Router::new()
        .nest(
            "/api/v1",
            crate::authorization::http::routes().with_state(Arc::new(HttpState {
                audit_store: access.audit_store_fixture(&config.audit).await?,
            })).into_axum(),
        )
        .nest(
            "/api/v1",
            crate::enrollment::http::routes().with_state(enrollment).into_axum(),
        )
        .route_layer(middleware::from_fn_with_state(
            authentication,
            crate::authorization::http::protect,
        ));
    let router = protected
        .merge(identity.routes())
        .layer(middleware::from_fn_with_state(
            rss_mdm_management_http::boundary::Envelope {
                admission: Arc::new(tokio::sync::Semaphore::new(32)),
                host: "mdm.example.test".into(),
                clock: monotonic,
                audit_store: access.audit_store_fixture(&config.audit).await?,
                requests,
                tenant: case_tenant().into(),
            },
            rss_mdm_management_http::boundary::admit,
        ));
    let router = router.layer(axum::Extension(rss_identity_http_axum::ClientAddress(
        "127.0.0.1".parse()?,
    )));
    let mut anonymous = Browser::default();
    ensure!(
        anonymous
            .call(&router, Method::GET, "/api/v1/authorization", None)
            .await?
            .0
            == StatusCode::UNAUTHORIZED
    );
    let mut admin = Browser::default();
    // Reuse the real seed session: this scenario does not test login and must not
    // consume the shared administrator's bounded password-attempt allowance.
    let secret = crate::test_support::identity::credential(&identity, "admin")?;
    admin
        .cookies
        .insert("__Host-identity-session".into(), secret.expose().into());
    admin.csrf = Some(secret.csrf());
    ensure!(
        admin
            .call(&router, Method::GET, "/api/v1/authorization", None)
            .await?
            .0
            == StatusCode::OK
    );
    let mut member = crate::test_support::authority::Authority::prepared_browser("other")?;
    let subject = prepared_subject(&member)?;
    crate::test_support::identity::seed_grants(
        case_tenant(),
        &subject,
        crate::test_support::identity::device_grants(
            Some("foundation-device"),
            &["enrollment", "credentials"],
        )?,
    )
    .await?;
    let payload = json!({"deviceId":"foundation-device","password":crate::enrollment::random(),"source":"mdm.windows","windowsProfile":"Device"});
    member.operation = Some(Uuid::new_v4());
    let created = member
        .call(
            &router,
            Method::POST,
            "/api/v1/enrollments",
            Some(payload.clone()),
        )
        .await?;
    ensure!(
        created.0 == StatusCode::OK,
        "enrollment creation: {created:?}"
    );
    let path = format!(
        "/api/v1/enrollments/{}",
        created.1["enrollmentId"].as_str().unwrap()
    );
    ensure!(
        member
            .call(
                &router,
                Method::POST,
                "/api/v1/enrollments",
                Some(payload.clone())
            )
            .await?
            == created
    );
    ensure!(member.call(&router, Method::GET, &path, None).await?.0 == StatusCode::OK);
    // Failed audit rolls the lifecycle mutation back, even through the narrow router.
    member.operation = Some(Uuid::new_v4());
    pg("REVOKE INSERT ON mdm_audit.receipts FROM mdm_access")?;
    let cancel_key = member.operation.unwrap();
    let rejected = member
        .call(
            &router,
            Method::POST,
            &format!("{path}/cancel"),
            Some(json!({})),
        )
        .await;
    pg("GRANT INSERT(tenant_id,source_id,event_id,fingerprint,source_bytes,message_id,reserved,enqueued_at) ON mdm_audit.receipts TO mdm_access")?;
    let rejected = rejected?;
    ensure!(rejected.0 == StatusCode::SERVICE_UNAVAILABLE);
    ensure!(rejected.1["code"] == "service_unavailable");
    ensure!(pg(&format!("SELECT count(*) FROM mdm_access.registration_operations WHERE tenant_id='{}' AND operation_id='{cancel_key}'", case_tenant()))?.trim() == "0");
    ensure!(audit_count(|r| r.source() == "mdm.business" && r.operation() == Some(cancel_key.to_string().as_str()) && r.result() == "success").await? == 0);

    ensure!(member.call(&router, Method::GET, &path, None).await?.1["status"] == "pending");
    crate::test_support::identity::change_grants(case_tenant(), &subject, vec![]).await?;
    ensure!(member.call(&router, Method::GET, &path, None).await?.0 == StatusCode::FORBIDDEN);
    ensure!(
        member
            .call(&router, Method::POST, "/api/v1/enrollments", Some(payload))
            .await?
            .0
            == StatusCode::FORBIDDEN
    );
    access.close().await;
    Ok(())
    }).await
}

mod route_permissions;
