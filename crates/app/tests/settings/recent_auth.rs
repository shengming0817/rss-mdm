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
    let writes = rss_mdm_management_http::mail::routes(Arc::new(
        rss_mdm_mail_service::authority::Authority {
            tenant,
            protection: protection.clone(),
            audit: fixture.audit.clone(),
        },
    ))
    .merge(
        rss_mdm_management_http::content::connections::routes().with_state(Arc::new(
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
