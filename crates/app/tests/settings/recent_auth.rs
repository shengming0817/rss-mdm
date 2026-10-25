use crate::test_support::{http::*, runtime::*, *};
#[tokio::test]
#[ignore = "MODULE=settings.recent_auth: six consumers reject old authentication on a newly issued live session"]
async fn sensitive_operations_use_authentication_time() -> Result<()> {
    identity::seed_grants(
        case_tenant(),
        case_admin(),
        [
            crate::authorization::Permission::RegistrationConfigurationRead,
            crate::authorization::Permission::RegistrationConfigurationWrite,
            crate::authorization::Permission::StorageConfigurationRead,
            crate::authorization::Permission::StorageConfigurationWrite,
            crate::authorization::Permission::WebhookRead,
            crate::authorization::Permission::WebhookWrite,
        ]
        .into_iter()
        .map(|operation| crate::authorization::Grant {
            operation,
            scope: crate::authorization::Scope::Tenant,
        })
        .collect(),
    )
    .await?;
    let mut fixture = authority::Authority::open().await?;
    let directory = crate::test_support::settings::directory(&mut fixture).await?;
    let tenant = fixture.identity.tenant;
    let protection = directory.protection.clone();
    let clock = directory.clock.clone();
    let sessions = Arc::new(
        rss_mdm_authorization_service::session::SessionAuthority::new(
            fixture.identity.authority.clone(),
            tenant,
        ),
    );
    let (execution, queries, _) = command::command_service(
        fixture.audit.clone(),
        sessions.clone(),
        rss_device_command_postgres::CommandClock::Postgres,
    )
    .await?;
    fixture
        .resources
        .resource(rss_mdm_execution_service::Resource(execution.clone()));
    let devices = Arc::new(crate::device::DeviceService::new(
        fixture.registration.clone(),
        case_tenant().into(),
        fixture.audit.clone(),
    ));
    let requests = Arc::new(tokio::sync::Semaphore::new(32));
    let apple = Arc::new(rss_mdm_apple_channel::HttpState {
        query_cursor: rss_mdm_query::cursor::CursorCodec::new(&[31; 32]).expect("fixture cursor"),
        platform_sso: None,
        platform_objects: Arc::new(rss_mdm_device_service::planning::PlanningObjects::new(
            fixture.audit.clone(),
        )),
        material_roots: Arc::new(vec![]),
        account_authority: rss_mdm_apple_channel::account_enrollment::authority(),
        authentication: rss_mdm_apple_channel::account_enrollment::Authentication {
            authority: fixture.identity.authority.clone(),
            http: fixture.identity.browser().http.clone(),
            origin: "https://mdm.example.test".into(),
        },
        mount: crate::device::ChannelMount::new(
            tenant,
            rss_mdm_inventory::ReportSource::MdmApple,
            rss_mdm_registration_service::Purpose::Primary,
        ),
        audit_store: fixture.audit.clone(),
        access: directory.apple_store.clone(),
        apple: None,
        clock: Arc::new(crate::clock::InventoryClock(clock.clone())),
        execution: execution.clone(),
        protection: protection.clone(),
        credentials: fixture.credentials.clone(),
        devices: devices.clone(),
        identity: sessions.clone(),
        requests: requests.clone(),
    });
    let windows = Arc::new(rss_mdm_windows_channel::HttpState {
        query_cursor: rss_mdm_query::cursor::CursorCodec::new(&[31; 32]).expect("fixture cursor"),
        protection: protection.clone(),
        mount: crate::device::ChannelMount::new(
            tenant,
            rss_mdm_inventory::ReportSource::MdmWindows,
            rss_mdm_registration_service::Purpose::Primary,
        ),
        audit_store: fixture.audit.clone(),
        access: directory.windows.clone(),
        clock: Arc::new(crate::clock::InventoryClock(clock)),
        execution: execution.clone(),
        credentials: fixture.credentials.clone(),
        devices,
        identity: sessions,
        requests,
        windows: None,
    });
    let writes = rss_mdm_management_http::mail::routes(
        Arc::new(rss_mdm_mail_service::authority::Authority {
            tenant,
            protection: protection.clone(),
            audit: fixture.audit.clone(),
        }),
        rss_mdm_query::cursor::CursorCodec::new(&[31; 32])?,
    )
    .merge(
        rss_mdm_management_http::content::connections::routes(
            rss_mdm_query::cursor::CursorCodec::new(&[31; 32])?,
        )
        .with_state(Arc::new(
            rss_mdm_content_service::connections::authority::Authority {
                tenant,
                protection,
                audit: fixture.audit.clone(),
            },
        )),
    )
    .merge(rss_mdm_management_http::webhooks::routes(
        directory.webhooks.clone(),
    ))
    .merge(
        rss_mdm_management_http::execution::routes(
            queries,
            rss_mdm_query::cursor::CursorCodec::new(&[29; 32])?,
        )
        .with_state(Arc::new(
            rss_mdm_management_http::execution::http::HttpState {
                execution,
                apple: false,
                windows: false,
            },
        )),
    )
    .into_axum();
    let native = rss_mdm_apple_channel::management_routes(apple)
        .route_layer(axum::middleware::from_fn(
            crate::api::apple_management_settlement,
        ))
        .merge(rss_mdm_windows_channel::wns_materials::routes(windows))
        .into_axum();
    let protected = fixture.protect(Router::new().nest("/api/v1", writes).merge(native))?;
    let router = crate::test_support::settings::catalog(&fixture, directory)?.merge(protected);
    let resources = std::mem::take(&mut fixture.resources);
    resources.finish(async {
        let mut browser=Browser::default();
        ensure!(browser.login_password(&router,"admin",identity::PASSWORD).await?==StatusCode::OK);
        let session_path=format!("/api/v1/identity/tenants/{}/session",case_tenant());
        let before=browser.call(&router,Method::GET,&session_path,None).await?;
        ensure!(before.0==StatusCode::OK);
        let catalog=browser.call(&router,Method::GET,"/api/v1/settings/catalog",None).await?;
        ensure!(catalog.0==StatusCode::OK);
        let ids=["apns-key","wns","storage","smtp","task-key","webhook-own"];
        for id in ids {
            let entry = catalog.1["items"].as_array().unwrap().iter().find(|e| e["id"] == id).expect("required settings entry");
            ensure!(entry["actions"].as_array().unwrap().iter().any(|a| a["name"] == "configure"), "fresh configure action missing: {id}");
        }
        verify_material_history(&router,&mut browser).await?;
        identity::age_prepared_admin_session()?;
        let after=browser.call(&router,Method::GET,&session_path,None).await?;
        ensure!(after.0==StatusCode::OK && after.1["session"]["issuedAt"]==before.1["session"]["issuedAt"]);
        let cases=[
            ("/api/v1/apple/materials/apns/keys",json!({"expectedRevision":1000000,"source":{"kind":"generate"}}),StatusCode::UNAUTHORIZED),
            ("/api/v1/windows/wns",json!({"expectedRevision":1000000,"packageFamilyName":"fixture","sid":"fixture","clientSecret":"fixture"}),StatusCode::UNAUTHORIZED),
            ("/api/v1/storage/connections",json!({"expectedRevision":1000000,"profile":"fixture","source":{"kind":"generate"}}),StatusCode::FORBIDDEN),
            ("/api/v1/smtp",json!({"expectedRevision":1000000,"profile":"fixture","sender":"a@example.test","recipient":"b@example.test","username":"fixture","password":"fixture"}),StatusCode::FORBIDDEN),
            ("/api/v1/task-signing/trust",json!({"action":"prepare","expectedRevision":1000000}),StatusCode::UNAUTHORIZED),
            ("/api/v1/webhooks/materials",json!({"reference":"fixture","expectedRevision":1000000,"configurationSha256":"00".repeat(32),"endpoint":"https://example.test/hook","networkReference":"fixture","source":{"kind":"generate"}}),StatusCode::FORBIDDEN),
        ];
        for (path,input,status) in &cases {
            browser.operation=Some(uuid::Uuid::new_v4());
            let response=browser.call(&router,Method::POST,path,Some(input.clone())).await?;
            ensure!(response.0==*status,"recent authentication at {path}: {}",response.0);
        }
        let catalog=browser.call(&router,Method::GET,"/api/v1/settings/catalog",None).await?;
        ensure!(catalog.0==StatusCode::OK);
        for id in ids {
            let entry = catalog.1["items"].as_array().unwrap().iter().find(|e| e["id"] == id).expect("required settings entry");
            ensure!(!entry["actions"].as_array().unwrap().iter().any(|a|a["name"]=="configure"), "old authentication offered configuration: {id}");
        }
        // Restore only authentication time; the same session, permissions and request reach CAS.
        crate::test_support::process::pg(&format!(
            "UPDATE identity_authority.sessions SET local_authenticated_at=local_authenticated_at+301 WHERE tenant_id='{}' AND principal_id='{}'",
            case_tenant(), case_admin(),
        ))?;
        for (path,input,_) in cases {
            browser.operation=Some(uuid::Uuid::new_v4());
            let response=browser.call(&router,Method::POST,path,Some(input)).await?;
            ensure!(response.0==StatusCode::CONFLICT, "fresh authentication must reach owner revision/configuration conflict at {path}: {response:?}");
        }
        Ok(())
    }).await
}

/// History metadata is seeded directly; only the 65th Apple key exercises creation.
/// Unselected archived rows are never used as runtime credentials.
async fn verify_material_history(router: &Router, browser: &mut Browser) -> Result<()> {
    use crate::test_support::process::pg;
    let tenant = case_tenant();
    pg(&format!(
        r#"
INSERT INTO mdm_mail.heads VALUES('{tenant}',65,NULL) ON CONFLICT(tenant_id) DO UPDATE SET revision=greatest(mdm_mail.heads.revision,65);
INSERT INTO mdm_mail.versions(tenant_id,revision,operation_id,fingerprint_key,fingerprint,profile,sender,recipient,credentials)
SELECT '{tenant}',n,gen_random_uuid(),'history',decode(repeat('00',32),'hex'),'history','a@example.test','b@example.test',decode('00','hex') FROM generate_series(1,65)n ON CONFLICT DO NOTHING;
INSERT INTO mdm_content_connections.heads VALUES('{tenant}',65,NULL) ON CONFLICT(tenant_id) DO UPDATE SET revision=greatest(mdm_content_connections.heads.revision,65);
INSERT INTO mdm_content_connections.versions(tenant_id,revision,operation_id,profile,generated,credentials,fingerprint_key,fingerprint)
SELECT '{tenant}',n,gen_random_uuid(),'history',true,decode('00','hex'),'history',decode(repeat('00',32),'hex') FROM generate_series(1,65)n ON CONFLICT DO NOTHING;
INSERT INTO mdm_wns.heads VALUES('{tenant}',65,NULL) ON CONFLICT(tenant_id) DO UPDATE SET revision=greatest(mdm_wns.heads.revision,65);
INSERT INTO mdm_wns.versions(tenant_id,revision,operation_id,actor,fingerprint_key,fingerprint,pfn,sid_digest,configuration,material)
SELECT '{tenant}',n,gen_random_uuid(),'history','history',decode(repeat('00',32),'hex'),'history',decode(repeat('00',32),'hex'),decode(repeat('00',32),'hex'),decode('00','hex') FROM generate_series(1,65)n ON CONFLICT DO NOTHING;
INSERT INTO mdm_apple_runtime.heads(tenant_id,purpose,revision) VALUES('{tenant}','apns',64) ON CONFLICT(tenant_id,purpose) DO UPDATE SET revision=greatest(mdm_apple_runtime.heads.revision,64);
INSERT INTO mdm_apple_runtime.versions(tenant_id,purpose,revision,key_id,public_digest,private_key,csr)
SELECT '{tenant}','apns',n,gen_random_uuid(),repeat('0',64),decode('00','hex'),'history metadata' FROM generate_series(1,64)n ON CONFLICT DO NOTHING;
"#
    ))?;
    browser.operation = Some(uuid::Uuid::new_v4());
    let created = browser
        .call(
            router,
            Method::POST,
            "/api/v1/apple/materials/apns/keys",
            Some(json!({"expectedRevision":64,"source":{"kind":"generate"}})),
        )
        .await?;
    ensure!(
        created.0.is_success(),
        "65th Apple key rejected: {} {}",
        created.0,
        created.1
    );
    for path in [
        "/api/v1/smtp",
        "/api/v1/storage/connections",
        "/api/v1/windows/wns",
        "/api/v1/apple/materials/apns",
    ] {
        let current = browser.call(router, Method::GET, path, None).await?;
        ensure!(
            current.0 == StatusCode::OK
                && current.1["versionCount"] == 65
                && current.1.get("versions").is_none(),
            "current state at {path}: {} {}",
            current.0,
            current.1
        );
        let mut cursor = None;
        let mut revisions = Vec::new();
        loop {
            let url = match &cursor {
                Some(c) => format!("{path}/versions?limit=17&cursor={c}"),
                None => format!("{path}/versions?limit=17"),
            };
            let page = browser.call(router, Method::GET, &url, None).await?;
            ensure!(
                page.0 == StatusCode::OK,
                "history {url}: {} {}",
                page.0,
                page.1
            );
            let items = page.1["items"].as_array().unwrap();
            ensure!(items.len() <= 17);
            for row in items {
                ensure!(
                    row.get("privateKey").is_none()
                        && row.get("credentials").is_none()
                        && row.get("secret").is_none()
                );
                revisions.push(row["revision"].as_i64().unwrap());
            }
            cursor = page.1["nextCursor"].as_str().map(str::to_owned);
            if cursor.is_none() {
                break;
            }
            ensure!(revisions.len() <= 65, "history did not terminate");
        }
        ensure!(
            revisions == (1..=65).rev().collect::<Vec<i64>>(),
            "incomplete history at {path}"
        );
    }
    Ok(())
}
