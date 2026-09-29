use super::*;

#[tokio::test]
#[ignore = "MODULE=authorization.rules: real authorization contract"]
async fn rules_cas_replay_revocation_and_escalation() -> Result<()> {
    let Fixture {
        base,
        reader,
        router,
        mut admin,
        mut member,
        subject,
        store,
        ..
    } = fixture().await?;
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
            let before = audit_count(|r| r.action() == action && r.status() == expected)?;
            ensure!(
                browser
                    .call(&router, Method::GET, &path, None)
                    .await?
                    .0
                    .as_u16()
                    == expected
            );
            let after = audit_count(|r| r.action() == action && r.status() == expected)?;
            ensure!(
                after == before + 1,
                "authorization read audit action missing: {action}"
            );
        }
    }
    let rule_id = Uuid::new_v4();
    let key = Uuid::new_v4();
    let path = format!("/api/v1/authorization/rules/{rule_id}");
    let value = json!({"subject":user(&subject),"grants":[grant("inventory_read",json!({"kind":"device","id":"a"})),grant("device_wipe",json!({"kind":"device","id":"b"}))]});
    let created = put(&mut admin, &router, &path, key, 0, value.clone()).await?;
    ensure!(created.0 == StatusCode::OK && created.1["revision"] == 1);
    ensure!(
        put(&mut admin, &router, &path, key, 0, value.clone())
            .await?
            .1
            == created.1
    );
    ensure!(
        put(&mut admin, &router, &path, key, 0, Value::Null)
            .await?
            .0
            == StatusCode::CONFLICT
    );
    for (device, expected) in [("a", StatusCode::NOT_FOUND), ("b", StatusCode::FORBIDDEN)] {
        ensure!(
            member
                .call(
                    &router,
                    Method::GET,
                    &format!("/api/v2/devices/{device}/inventory"),
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
    let (first, second) = tokio::join!(
        put(&mut a, &router, &path, Uuid::new_v4(), 1, value.clone()),
        put(&mut b, &router, &path, Uuid::new_v4(), 1, value.clone())
    );
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
            .1
            == created.1
    );
    ensure!(
        put(&mut admin, &router, &path, Uuid::new_v4(), 3, value)
            .await?
            .0
            == StatusCode::CONFLICT
    );
    let restarted = app(&base, reader.clone()).await?;
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
            && r.result() == "success")?
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
    let rejected = crate::authorization::store::change_rule(store.audit_store(&crate::config::AuditConfig::Plain).await?.as_ref(), &stale, Uuid::new_v4(), crate::authorization::Change {
        operation_id:Uuid::new_v4(), expected_revision:0, value:Some(serde_json::from_value(json!({"subject":user(&subject),"grants":[grant("group_read",json!({"kind":"tenant"}))]}))?)
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
    let escalation = put(
        &mut member,
        &router,
        &privilege_group_path,
        Uuid::new_v4(),
        1,
        json!({"name":"privileged","enabled":true,"members":[user(&subject)["user"].clone()]}),
    )
    .await?;
    let escalation_denied = escalation.0 == StatusCode::FORBIDDEN;
    ensure!(
        stale_denied && escalation_denied,
        "stale writer denied={stale_denied}; group escalation denied={escalation_denied}"
    );

    Ok(())
}
#[tokio::test]
#[ignore = "real Identity + PG with independently constructed capability routers"]
async fn capability_routes_without_application_preserve_revocation_and_atomicity() -> Result<()> {
    use crate::authorization::http::{AuthenticationState, HttpState};
    use crate::enrollment::{EnrollmentService, credentials::Credentials};
    use axum::middleware;
    let config = crate::test_support::identity::config(case_tenant())?;
    let identity = Arc::new(crate::test_support::identity::identity(case_tenant()).await?);
    let access =
        Arc::new(crate::database::Database::connect(config.access_database.options()?).await?);
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
        service: Arc::new(EnrollmentService::new(
            access.registration(),
            Arc::new(Credentials::new(monotonic.clone(), 16)),
            access.audit_store(&config.audit).await?,
        )),
        devices: Arc::new(crate::device::DeviceService::new(
            access.registration(),
            case_tenant().into(),
            access
                .audit_store(&crate::config::AuditConfig::Plain)
                .await?,
        )),
        apple: false,
        windows: false,
    });
    let protected = Router::new()
        .nest(
            "/api/v1",
            crate::authorization::http::routes().with_state(Arc::new(HttpState {
                audit_store: access.audit_store(&config.audit).await?,
            })),
        )
        .nest(
            "/api/v3",
            crate::enrollment::http::routes().with_state(enrollment),
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
                audit_store: access.audit_store(&config.audit).await?,
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
    ensure!(
        admin
            .call(
                &router,
                Method::POST,
                &format!("/api/v2/tenants/{TENANT}/accounts", TENANT = case_tenant()),
                Some(json!({"login":"foundation-member","password":PASSWORD}))
            )
            .await?
            .0
            == StatusCode::CREATED
    );
    let mut member = Browser::default();
    ensure!(member.login(&router, "foundation-member").await? == StatusCode::OK);
    let subject = browser_subject(&member, &router).await?;
    crate::test_support::identity::set_grants(
        case_tenant(),
        &subject,
        crate::test_support::identity::device_grants(
            Some("foundation-device"),
            &["enrollment", "credentials"],
        )?,
    )
    .await?;
    let payload = json!({"deviceId":"foundation-device","password":crate::enrollment::random(),"source":"agent.builtin"});
    member.operation = Some(Uuid::new_v4());
    let created = member
        .call(
            &router,
            Method::POST,
            "/api/v3/enrollments",
            Some(payload.clone()),
        )
        .await?;
    ensure!(
        created.0 == StatusCode::OK,
        "enrollment creation: {created:?}"
    );
    let path = format!(
        "/api/v3/enrollments/{}",
        created.1["enrollmentId"].as_str().unwrap()
    );
    ensure!(
        member
            .call(
                &router,
                Method::POST,
                "/api/v3/enrollments",
                Some(payload.clone())
            )
            .await?
            .1
            == created.1
    );
    ensure!(member.call(&router, Method::GET, &path, None).await?.0 == StatusCode::OK);
    // Failed audit rolls the lifecycle mutation back, even through the narrow router.
    member.operation = Some(Uuid::new_v4());
    pg("REVOKE INSERT ON mdm_audit.receipts FROM mdm_access")?;
    let rejected = member
        .call(
            &router,
            Method::POST,
            &format!("{path}/cancel"),
            Some(json!({})),
        )
        .await;
    pg("GRANT INSERT ON mdm_audit.receipts TO mdm_access")?;
    let rejected = rejected?;
    ensure!(rejected.0 == StatusCode::INTERNAL_SERVER_ERROR);
    ensure!(rejected.1["code"] == "audit_contract_error");
    ensure!(member.call(&router, Method::GET, &path, None).await?.1["status"] == "pending");
    crate::test_support::identity::set_grants(case_tenant(), &subject, vec![]).await?;
    ensure!(member.call(&router, Method::GET, &path, None).await?.0 == StatusCode::FORBIDDEN);
    ensure!(
        member
            .call(&router, Method::POST, "/api/v3/enrollments", Some(payload))
            .await?
            .0
            == StatusCode::FORBIDDEN
    );
    access.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "MODULE=authorization.rules: enrollment does not imply device wipe"]
async fn enrollment_grant_does_not_authorize_wipe() -> Result<()> {
    let fixture = authority::Authority::open().await?;
    let (router, _) = app_with_access(&fixture.base, fixture.access.clone()).await?;
    let mut browser = fixture.browser("other")?;
    set_device_grants(
        &mut browser,
        &router,
        crate::test_support::case::name("device-1"),
        &["inventory_read", "enrollment"],
    )
    .await?;
    ensure!(
        browser
            .call(
                &router,
                Method::POST,
                &format!("{DEVICE}/actions", DEVICE = case_device()),
                Some(json!({"action":"wipe"}))
            )
            .await?
            .0
            == StatusCode::FORBIDDEN
    );
    Ok(())
}

mod route_permissions;
