use crate::audit_test_support::audit_count;
use crate::test_support::planning_http::*;
use crate::test_support::{http::*, process::*, runtime::*, *};
#[tokio::test]
#[ignore = "make t2 MODULE=authorization.rules"]
async fn each_route_requires_its_exact_capability() -> Result<()> {
    let mut fixture = authority::Authority::open().await?;
    let fixture_resources = std::mem::take(&mut fixture.resources);
    fixture_resources.finish(async {
    let session = &fixture.browser("other")?;
    let id = uuid::Uuid::new_v4();
    let source = "missing-source";
    let release = format!("/api/v1/software/publications/{id}");
    let op = |input: Value| {
        Some(json!({"operationId":uuid::Uuid::new_v4(),"expectedRevision":999,"input":input}))
    };
    let mut cases = vec![
        (
            "group_read",
            Method::GET,
            format!("/api/v1/groups/{id}"),
            None,
        ),
        (
            "group_write",
            Method::POST,
            format!("/api/v1/groups/{id}"),
            op(json!({"action":"edit","presentation":{"name":"denied","description":""}})),
        ),
        (
            "group_recompute",
            Method::POST,
            format!("/api/v1/groups/{id}"),
            op(json!({"action":"recompute"})),
        ),
        (
            "scope_read",
            Method::GET,
            format!("/api/v1/scopes/{id}"),
            None,
        ),
        (
            "scope_write",
            Method::POST,
            format!("/api/v1/scopes/{id}"),
            op(json!({"action":"delete"})),
        ),
        (
            "policy_read",
            Method::GET,
            format!("/api/v1/policies/{id}"),
            None,
        ),
        (
            "policy_write",
            Method::POST,
            format!("/api/v1/policies/{id}"),
            op(json!({"action":"disable"})),
        ),
        (
            "resource_read",
            Method::GET,
            format!("/api/v1/resources/{id}"),
            None,
        ),
        (
            "resource_write",
            Method::POST,
            format!("/api/v1/resources/{id}"),
            op(json!({"action":"activate","version":"missing"})),
        ),
        ("release_read", Method::GET, release.clone(), None),
        ("release_publish",Method::POST,"/api/v1/software/publications".into(),Some(json!({"operationId":id,"expectedRevision":0,"input":{"action":"publish","resource":"missing","version":"v1","expectedResourceRevision":1,"resourceDigest":vec![1;32],"target":source,"targetDigest":vec![2;32]}}))),
        (
            "release_withdraw",
            Method::POST,
            release.clone(),
            op(json!({"action":"withdraw"})),
        ),
        (
            "release_recover",
            Method::POST,
            release,
            op(json!({"action":"retry"})),
        ),
    ];
    cases.extend([
        (
            "group_read",
            Method::POST,
            format!("/api/v1/groups/{id}/previews"),
            op(json!({})),
        ),
        (
            "release_recover",
            Method::POST,
            format!("/api/v1/software/publications/{id}"),
            op(json!({"action":"recover"})),
        ),
    ]);
    let expected_denied = cases.iter().filter(|(permission, _, _, _)| matches!(*permission,
        "group_write" | "group_recompute" | "scope_write" | "policy_write" | "resource_write" | "release_publish" | "release_withdraw" | "release_recover")).count();
    let counts = || {
        pg(&format!(
            "SELECT jsonb_build_array((SELECT count(*) FROM mdm_group.groups WHERE tenant_id='{tenant}'),(SELECT count(*) FROM mdm_planning.operations WHERE tenant_id='{tenant}')+(SELECT count(*) FROM mdm_assets.operations WHERE tenant_id='{tenant}')+(SELECT count(*) FROM mdm_resource_catalog.operations WHERE tenant_id='{tenant}')+(SELECT count(*) FROM mdm_publication.operations WHERE tenant_id='{tenant}'),(SELECT count(*) FROM mdm_scope.scope_versions WHERE tenant_id='{tenant}'),(SELECT count(*) FROM mdm_policy.work WHERE tenant_id='{tenant}'),(SELECT count(*) FROM mdm_policy.policies WHERE tenant_id='{tenant}'),(SELECT count(*) FROM mdm_software_composition.subjects WHERE tenant_id='{tenant}'))::text",
            tenant = case_tenant()
        ))
    };
    // Exercise every permission change against the same running service. Rebuilding
    // full applications per grant needlessly multiplies component connection pools.
        let config: Config = serde_json::from_value(fixture.base.clone())?;
    let tenant = fixture.identity.tenant;
    let runtime = crate::planning::test_support::runtime(tenant).await;
    let mut app_resources = Resources::default();
    app_resources.resource(SourceResource(runtime.clone()));
    let key = crate::cursor_keys::load(&runtime, tenant).await?;
    let clock = Arc::new(crate::clock::SystemClock);
    let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(5));
    let audit = Arc::new(fixture.audit.on_runtime(runtime.clone(), tenant, &budget.control()).await?);
    let planning = Arc::new(rss_mdm_policy_service::application::Application::new(audit.clone(), runtime.clone(), tenant, clock.clone(), &key, Arc::new(rss_mdm_device_service::planning::PlanningObjects::new(audit.clone()))).await?);
    let groups = Arc::new(crate::planning::test_support::groups(&planning).await);
    let routes = rss_mdm_management_http::planning::http::routes().with_state(Arc::new(rss_mdm_management_http::planning::http::HttpState { scopes:crate::planning::test_support::scopes(&planning).await, groups }));
    let content = None;
    let catalog = crate::resource_assembly::catalog(audit.clone(), runtime.clone(), tenant, clock.clone()).await?;
    let content_access = Arc::new(rss_mdm_content_service::service::Access {
        sessions: rss_mdm_authorization_service::session::SessionAuthority::new(fixture.identity.authority.clone(), tenant), authorization: fixture.authorization.clone(),
        runtime: runtime.clone(), audit_store: audit.clone(), tenant, content: content.clone(), clock: Arc::new(crate::clock::ContentClock(clock.clone())),
        catalog: Arc::new(rss_mdm_software_service::catalog::Reader::new(tenant)),
    });
    let routes = routes.merge(rss_mdm_management_http::resource_catalog::http::routes().with_state(Arc::new(rss_mdm_management_http::resource_catalog::http::HttpState { catalog: catalog.clone(), content: content_access.clone() })));
    let command_runtime = crate::planning::test_support::runtime_role(tenant, "mdm_command_runtime").await;
    app_resources.resource(SourceResource(command_runtime.clone()));
    let protection = config.native_protector()?;
    let inputs = Arc::new(rss_mdm_execution_service::Inputs::new(rss_mdm_execution_service::InputDependencies {
        software_distribution: config.software_distribution, product_origin: config.product_origin.clone(), recovery_enabled: config.recovery_credentials.is_some(), protection: protection.clone(),
        software: Arc::new(rss_mdm_software_service::preparation::Preparation::new(rss_mdm_software_service::catalog::Reader::new(tenant), Default::default())),
        bootstrap: None, enrollment_entries: config.enrollment_entries.clone(), runtime: command_runtime.clone(), tenant, content: content.clone(), signing_enabled: false,
        agent_installation: Arc::new(crate::channel_status::Channels::new(&config)),
    }));
    let queries = Arc::new(rss_mdm_execution_service::queries::Queries::new(std::sync::Arc::new(crate::lifecycle::RuntimeTimer),rss_mdm_execution_service::queries::Dependencies {
        source: Arc::new(rss_mdm_execution_service::scope::source::ExecutionSource { objects: planning.objects.clone(), policies:Arc::new(rss_mdm_policy_service::management::source::PolicySource{objects:planning.objects.clone()}), mdm_software_enabled: config.software_distribution.mdm_enabled }),
        protection: protection.clone(), agent_store: Arc::new(rss_mdm_agent_channel::Bindings), apple_results: Arc::new(rss_mdm_apple_channel::flow_store::Store { protection }),
        policy_reader: rss_mdm_policy_postgres::PolicyReader::bind(command_runtime.clone(), tenant), runtime: command_runtime, tenant, inputs: inputs.clone(), signed: false, content_available: content.is_some(),
    }));
    let policies = Arc::new(rss_mdm_policy_service::management::Policies::new(rss_mdm_policy_service::management::Dependencies {
profile_validator: std::sync::Arc::new(rss_mdm_telemetry_service::profile_validation::ProfileValidator),
cursor_key: (key).to_vec(),
runtime: runtime.clone(),
reconcile_messaging: rss_reconcile_postgres::PgMessagingStore::new(runtime.clone(), tenant, crate::identity::deadline()).await?,
audit_store: audit.clone(),
tenant,
policy_store: Arc::new(rss_mdm_policy_postgres::PolicyStore::new(runtime.clone(), tenant, crate::identity::deadline()).await?),
inputs,
}));
    let routes = routes.merge(rss_mdm_management_http::planning::policies::http::routes(queries, rss_mdm_query::cursor::CursorCodec::new(&[31; 32]).expect("fixture cursor")).with_state(policies));
    let publications = Arc::new(rss_mdm_software_service::management::publication::service::PublicationDirectory {
        cursor: rss_mdm_query::cursor::CursorCodec::new(&key)?, services: Default::default(), tenant,
        runtime: runtime.clone(), audit_store: audit, clock: Arc::new(crate::clock::FlowClock(clock)),
    });
    let routes = routes.merge(rss_mdm_management_http::software_publication::http::routes()
        .with_state(Arc::new(rss_mdm_management_http::software_publication::http::HttpState { publications, access: fixture.authorization.clone() })));
    let router = fixture.router(rss_mdm_http_contract::Router::new().nest("/api/v1", routes))?;

    app_resources.finish(async {
    let member = prepared_subject(session)?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let hosted = router.clone();
    let _server = Server(tokio::spawn(
        async move { axum::serve(listener, hosted).await },
    ));
    let mut browser = Browser {
        network: Some((
            Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
            format!("http://{address}"),
        )),
        ..session.clone()
    };
    for (needed, method, path, body) in &cases {
        let wrong = match *needed {
            "group_read" => "group_write",
            "group_write" | "group_recompute" => "group_read",
            "scope_read" => "scope_write",
            "scope_write" => "scope_read",
            "policy_read" => "policy_write",
            "policy_write" => "policy_read",
            "resource_read" => "resource_write",
            "resource_write" => "resource_read",
            "release_read" => "release_publish",
            "release_publish" | "release_withdraw" | "release_recover" => "release_read",
            _ => unreachable!(),
        };
        seed_management_grants(&member, json!([wrong])).await?;
        let before = counts()?;
        let denied = browser.call(&router, method.clone(), path, body.clone()).await?;
        ensure!(denied.0 == StatusCode::FORBIDDEN && denied.1["code"] == "permission_denied", "{wrong} allowed {needed}: {denied:?}");
        ensure!(before == counts()?, "denied capability mutated product state");
        change_management_grants(&member, json!([needed])).await?;
        let accepted = browser.call(&router, method.clone(), path, body.clone()).await?;
        let (status, code) = match (*needed, method == Method::GET) {
            ("group_read" | "group_recompute", _) => (StatusCode::NOT_FOUND, "group_not_found"),
            ("scope_read" | "scope_write", _) => (StatusCode::NOT_FOUND, "scope_not_found"),
            ("policy_read", _) => (StatusCode::NOT_FOUND, "policy_not_found"),
            ("resource_read", _) => (StatusCode::NOT_FOUND, "resource_not_found"),
            ("release_read" | "release_withdraw" | "release_recover", _) => (StatusCode::NOT_FOUND, "software_publication_not_found"),
            ("release_publish", _) => (StatusCode::NOT_FOUND, "software_source_not_found"),
            _ => (StatusCode::CONFLICT, "operation_conflict"),
        };
        ensure!(accepted.0 == status && accepted.1["code"] == code, "{needed} wrong domain result: {accepted:?}");
    }
    ensure!(
        audit_count(|r| r.target() == id.to_string()
            && r.result() == "denied"
            && matches!(r.action(), "management_read" | "management_write")
            && r.actor().is_some()
            && r.payload["instance"] == INSTANCE).await?
        .to_string()
            == expected_denied.to_string(),
        "denied action/target/actor audit incomplete"
    );

    Ok(())
    }).await

    }).await
}
